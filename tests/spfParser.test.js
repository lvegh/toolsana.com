/**
 * SPF lookup counting (RFC 7208 section 4.6.4) against an in-memory resolver.
 * No network access.
 */

const { analyzeSPFRecord, parseTerm } = require('../src/services/spfParser');

const nxdomain = () => Object.assign(new Error('queryTxt ENOTFOUND'), { code: 'ENOTFOUND' });
const nodata = () => Object.assign(new Error('ENODATA'), { code: 'ENODATA' });
const servfail = () => Object.assign(new Error('ESERVFAIL'), { code: 'ESERVFAIL' });

/**
 * zone: { name: { txt?: string[], a?: string[], aaaa?: string[], mx?: string[] , servfail?: true } }
 */
function fakeResolver(zone) {
  const calls = [];
  const get = (name) => zone[name.toLowerCase()];
  const answer = (name, key) => {
    calls.push(`${key}:${name}`);
    const z = get(name);
    if (!z) throw nxdomain();
    if (z.servfail) throw servfail();
    const v = z[key];
    if (!v || v.length === 0) throw nodata();
    return v;
  };
  return {
    calls,
    resolveTxt: async (n) => answer(n, 'txt').map((s) => [s]),
    resolve4: async (n) => answer(n, 'a'),
    resolve6: async (n) => answer(n, 'aaaa'),
    resolveMx: async (n) => answer(n, 'mx').map((exchange, i) => ({ exchange, priority: 10 * (i + 1) })),
  };
}

/** Build a chain of include domains, each costing `per` lookups of its own. */
function providerZone() {
  const zone = {};
  // p1..p6: each record has two nested includes (3 lookups per top-level include)
  for (let i = 1; i <= 6; i++) {
    zone[`p${i}.example`] = { txt: [`v=spf1 include:n${i}a.example include:n${i}b.example ~all`] };
    zone[`n${i}a.example`] = { txt: ['v=spf1 ip4:192.0.2.1 -all'] };
    zone[`n${i}b.example`] = { txt: ['v=spf1 ip4:198.51.100.0/24 -all'] };
  }
  return zone;
}

describe('parseTerm', () => {
  it('parses mechanisms, cidr and modifiers', () => {
    expect(parseTerm('-all')).toMatchObject({ kind: 'mechanism', type: 'all', qualifier: '-' });
    expect(parseTerm('a:mail.example.com/24')).toMatchObject({ type: 'a', domain: 'mail.example.com', cidr: '/24' });
    expect(parseTerm('mx/24')).toMatchObject({ type: 'mx', domain: null, cidr: '/24' });
    expect(parseTerm('ip6:2a01:111:f400::/48')).toMatchObject({ type: 'ip6', value: '2a01:111:f400::/48' });
    expect(parseTerm('redirect=_spf.example.com')).toMatchObject({ kind: 'modifier', name: 'redirect', value: '_spf.example.com' });
    expect(parseTerm('include')).toMatchObject({ kind: 'invalid' });
    expect(parseTerm('foo:bar')).toMatchObject({ kind: 'invalid' });
  });
});

describe('analyzeSPFRecord lookup counting', () => {
  it('counts nested includes: 4 top-level includes that cost 12 lookups are over the limit', async () => {
    const zone = providerZone();
    zone['over.example'] = { txt: ['v=spf1 include:p1.example include:p2.example include:p3.example include:p4.example -all'] };
    const r = await analyzeSPFRecord('over.example', { resolver: fakeResolver(zone) });
    expect(r.dnsLookups).toBe(12);
    expect(r.valid).toBe(false);
    expect(r.issues.some((i) => /Too many DNS lookups: 12/.test(i.message))).toBe(true);
    // The 11th lookup happens inside p4: p4 itself is #10, its first nested include is #11.
    expect(r.limitExceededAt).toEqual({ term: 'include:n4a.example', inRecordOf: 'p4.example', via: ['include:p4.example'] });
    expect(r.lookupBreakdown).toEqual([
      { term: 'include:p1.example', lookups: 3 },
      { term: 'include:p2.example', lookups: 3 },
      { term: 'include:p3.example', lookups: 3 },
      { term: 'include:p4.example', lookups: 3 },
    ]);
    // Only the top-level mechanisms are listed.
    expect(r.mechanisms.map((m) => m.original)).toEqual(['include:p1.example', 'include:p2.example', 'include:p3.example', 'include:p4.example', '-all']);
  });

  it('a record at 9 lookups is valid with a warning', async () => {
    const zone = providerZone();
    zone['ok.example'] = { txt: ['v=spf1 include:p1.example include:p2.example include:p3.example -all'] };
    const r = await analyzeSPFRecord('ok.example', { resolver: fakeResolver(zone) });
    expect(r.dnsLookups).toBe(9);
    expect(r.valid).toBe(true);
    expect(r.warnings.some((w) => /high: 9 of 10/.test(w.message))).toBe(true);
  });

  it('counts redirect= and does not warn about a missing "all" when redirect is present', async () => {
    const zone = {
      'r.example': { txt: ['v=spf1 redirect=_spf.r.example'] },
      '_spf.r.example': { txt: ['v=spf1 a mx ip4:192.0.2.0/24 -all'], a: ['192.0.2.10'], mx: ['mx1.r.example'] },
      'mx1.r.example': { a: ['192.0.2.25'] },
    };
    const r = await analyzeSPFRecord('r.example', { resolver: fakeResolver(zone) });
    // redirect (1) + a (1) + mx (1); MX host address lookups are not counted
    expect(r.dnsLookups).toBe(3);
    expect(r.modifiers.redirect).toBe('_spf.r.example');
    expect(r.warnings.some((w) => /no "all" mechanism/.test(w.message))).toBe(false);
    expect(r.allowedIPs.ipv4).toEqual(expect.arrayContaining(['192.0.2.10', '192.0.2.25', '192.0.2.0/24']));
    expect(r.valid).toBe(true);
  });

  it('ignores redirect= when the record has an all mechanism', async () => {
    const zone = {
      'x.example': { txt: ['v=spf1 ip4:192.0.2.1 redirect=other.example -all'] },
      'other.example': { txt: ['v=spf1 include:a.example include:b.example -all'] },
    };
    const res = fakeResolver(zone);
    const r = await analyzeSPFRecord('x.example', { resolver: res });
    expect(r.dnsLookups).toBe(0);
    expect(res.calls).not.toContain('txt:other.example');
  });

  it('counts ptr and exists', async () => {
    const zone = { 'p.example': { txt: ['v=spf1 ptr exists:%{i}.spf.p.example -all'] } };
    const r = await analyzeSPFRecord('p.example', { resolver: fakeResolver(zone) });
    expect(r.dnsLookups).toBe(2);
  });

  it('flags more than 2 void lookups as permerror', async () => {
    const zone = { 'v.example': { txt: ['v=spf1 a:gone1.example a:gone2.example mx:gone3.example -all'] } };
    const r = await analyzeSPFRecord('v.example', { resolver: fakeResolver(zone) });
    expect(r.voidLookups).toBe(3);
    expect(r.valid).toBe(false);
    expect(r.issues.some((i) => /void lookups/.test(i.message))).toBe(true);
  });

  it('an include whose target has no SPF record is a permerror', async () => {
    const zone = {
      'i.example': { txt: ['v=spf1 include:nospf.example -all'] },
      'nospf.example': { txt: ['google-site-verification=abc'] },
    };
    const r = await analyzeSPFRecord('i.example', { resolver: fakeResolver(zone) });
    expect(r.valid).toBe(false);
    expect(r.issues.some((i) => /has no SPF record/.test(i.message))).toBe(true);
  });

  it('a SERVFAIL on an include is a temporary warning, not a permerror', async () => {
    const zone = {
      't.example': { txt: ['v=spf1 include:broken.example -all'] },
      'broken.example': { servfail: true },
    };
    const r = await analyzeSPFRecord('t.example', { resolver: fakeResolver(zone) });
    expect(r.valid).toBe(true);
    expect(r.dnsLookupsIsLowerBound).toBe(true);
    expect(r.warnings.some((w) => /temperror/.test(w.message))).toBe(true);
  });

  it('counts the same include reached twice, and detects loops', async () => {
    const zone = {
      'd.example': { txt: ['v=spf1 include:shared.example include:other.example -all'] },
      'other.example': { txt: ['v=spf1 include:shared.example -all'] },
      'shared.example': { txt: ['v=spf1 ip4:192.0.2.1 -all'] },
      'loop.example': { txt: ['v=spf1 include:loop2.example -all'] },
      'loop2.example': { txt: ['v=spf1 include:loop.example -all'] },
    };
    const d = await analyzeSPFRecord('d.example', { resolver: fakeResolver(zone) });
    expect(d.dnsLookups).toBe(3);
    expect(d.valid).toBe(true);
    const l = await analyzeSPFRecord('loop.example', { resolver: fakeResolver(zone) });
    expect(l.valid).toBe(false);
    expect(l.issues.some((i) => /loops back/.test(i.message))).toBe(true);
  });

  it('flags +all and ignores a nested ~all', async () => {
    const zone = {
      'plus.example': { txt: ['v=spf1 +all'] },
      'nested.example': { txt: ['v=spf1 include:prov.example -all'] },
      'prov.example': { txt: ['v=spf1 ip4:192.0.2.0/24 ?all'] },
    };
    const plus = await analyzeSPFRecord('plus.example', { resolver: fakeResolver(zone) });
    expect(plus.valid).toBe(false);
    const nested = await analyzeSPFRecord('nested.example', { resolver: fakeResolver(zone) });
    expect(nested.valid).toBe(true);
    expect(nested.warnings.some((w) => /\?all/.test(w.message))).toBe(false);
  });

  it('throws the DNS error for a domain that does not exist', async () => {
    await expect(analyzeSPFRecord('missing.example', { resolver: fakeResolver({}) })).rejects.toMatchObject({ code: 'ENOTFOUND' });
  });
});
