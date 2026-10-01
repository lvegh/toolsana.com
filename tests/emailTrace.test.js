/**
 * Trace-email parsing and scoring (services/emailTrace). No network access.
 */

const {
  parseAuthenticationResults,
  calculateSpamScore,
  authenticationWarnings,
  classifyIP,
  extractHopIP,
  extractTimestamp,
  computeTimings,
  reverseIPForDnsbl,
  classifyDnsblAnswer,
} = require('../src/services/emailTrace');

const header = (auth) => [
  'Delivered-To: me@example.com',
  'Received: from mail.sender.example (mail.sender.example [203.0.113.5])',
  '\tby mx.example.com with ESMTPS id abc',
  '\tfor <me@example.com>; Tue, 29 Sep 2026 10:00:05 +0000 (UTC)',
  `Authentication-Results: mx.example.com;`,
  `\t${auth}`,
  'From: Alice <alice@sender.example>',
  'Subject: hi',
].join('\r\n');

describe('parseAuthenticationResults', () => {
  it('reads statuses including none and softfail', () => {
    const a = parseAuthenticationResults(header('spf=pass smtp.mailfrom=alice@sender.example; dkim=none; dmarc=none header.from=sender.example'));
    expect(a.spf.status).toBe('pass');
    expect(a.dkim.status).toBe('none');
    expect(a.dmarc.status).toBe('none');
    expect(a.dkim.pass).toBeNull(); // none is not a failure
  });

  it('prefers a passing DKIM signature and reads the DMARC policy', () => {
    const a = parseAuthenticationResults(header('dkim=fail header.d=x.example header.s=old; dkim=pass header.d=sender.example header.s=s1; spf=softfail; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=sender.example'));
    expect(a.dkim.status).toBe('pass');
    expect(a.dkim.selector).toBe('s1');
    expect(a.spf.status).toBe('softfail');
    expect(a.dmarc.policy).toBe('reject');
  });

  it('reports missing when there is no Authentication-Results header', () => {
    const a = parseAuthenticationResults('Received: from x by y; Tue, 29 Sep 2026 10:00:05 +0000\r\nFrom: a@b.example');
    expect(a.present).toBe(false);
    expect(a.spf.status).toBe('missing');
  });
});

describe('calculateSpamScore', () => {
  const auth = (spf, dkim, dmarc) => ({ spf: { status: spf }, dkim: { status: dkim }, dmarc: { status: dmarc } });

  it('spf=pass dkim=none is low risk (was 8.0 "Likely spam")', () => {
    const a = auth('pass', 'none', 'missing');
    expect(calculateSpamScore(a, 0)).toBe(1.0);
    expect(authenticationWarnings(a)).toEqual([]);
  });

  it('all pass scores 0', () => {
    expect(calculateSpamScore(auth('pass', 'pass', 'pass'), 0)).toBe(0);
  });

  it('counts each failure once', () => {
    const a = auth('fail', 'fail', 'fail');
    expect(calculateSpamScore(a, 0)).toBe(7.5);
    expect(authenticationWarnings(a)).toHaveLength(3);
  });

  it('softfail and temperror are softer than fail', () => {
    expect(calculateSpamScore(auth('softfail', 'pass', 'pass'), 0)).toBe(1.0);
    expect(calculateSpamScore(auth('temperror', 'pass', 'pass'), 0)).toBe(0.5);
    const w = authenticationWarnings(auth('softfail', 'pass', 'pass'));
    expect(w[0].severity).toBe('medium');
  });

  it('adds listed IPs and caps at 10', () => {
    expect(calculateSpamScore(auth('pass', 'pass', 'pass'), 2)).toBe(3.0);
    expect(calculateSpamScore(auth('fail', 'fail', 'fail'), 5)).toBe(10);
  });
});

describe('hops', () => {
  it('extracts the from-clause IP, including private and IPv6 literals', () => {
    expect(extractHopIP('Received: from mail.sender.example (mail.sender.example [203.0.113.5]) by mx.example.com (10.1.2.3)')).toBe('203.0.113.5');
    expect(extractHopIP('Received: from internal (unknown [10.0.0.7]) by relay.example.com')).toBe('10.0.0.7');
    expect(extractHopIP('Received: from x.example ([IPv6:2001:db8::25]) by y.example')).toBe('2001:db8::25');
    expect(extractHopIP('Received: by 2002:a05:6a10:ab4b:b0:4a4:e3f4:b1c0 with SMTP id x')).toBe('2002:a05:6a10:ab4b:b0:4a4:e3f4:b1c0');
    expect(extractHopIP('Received: from localhost by mx.example.com; Tue, 29 Sep 2026 10:00:00 +0000')).toBeNull();
  });

  it('classifies private addresses', () => {
    expect(classifyIP('10.0.0.7')).toBe('private');
    expect(classifyIP('192.168.1.1')).toBe('private');
    expect(classifyIP('fd00::1')).toBe('private');
    expect(classifyIP('203.0.113.5')).toBe('private'); // TEST-NET-3 is reserved
    expect(classifyIP('8.8.8.8')).toBe('public');
  });

  it('computes per-hop delay and total time', () => {
    const hops = [
      { timestamp: extractTimestamp('Received: from a by b; Tue, 29 Sep 2026 10:00:00 +0000') },
      { timestamp: extractTimestamp('Received: from b by c; Tue, 29 Sep 2026 10:00:05 +0000 (UTC)') },
      { timestamp: null },
      { timestamp: extractTimestamp('Received: from c by d; Tue, 29 Sep 2026 10:01:10 +0000') },
    ];
    const t = computeTimings(hops);
    expect(hops[1].delay).toBe('5s');
    expect(hops[2].delay).toBeNull();
    expect(hops[3].delaySeconds).toBe(65);
    expect(t).toEqual({ totalSeconds: 70, totalTime: '1m 10s' });
  });
});

describe('DNSBL helpers', () => {
  it('reverses IPv4 and IPv6 (nibble format)', () => {
    expect(reverseIPForDnsbl('1.2.3.4')).toBe('4.3.2.1');
    expect(reverseIPForDnsbl('2001:db8::1')).toBe('1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2');
    expect(reverseIPForDnsbl('not-an-ip')).toBeNull();
  });

  it('only 127.0.0.x listing codes count; 127.255.255.x is "unavailable"', () => {
    expect(classifyDnsblAnswer(['127.0.0.2'])).toBe('listed');
    expect(classifyDnsblAnswer(['127.0.0.11'])).toBe('listed');
    expect(classifyDnsblAnswer(['127.255.255.254'])).toBe('unavailable');
    expect(classifyDnsblAnswer(['127.255.255.252'])).toBe('unavailable');
    expect(classifyDnsblAnswer(['104.21.3.4'])).toBe('clean');
    expect(classifyDnsblAnswer(['127.0.0.1'])).toBe('clean');
  });
});
