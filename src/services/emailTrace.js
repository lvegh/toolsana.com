/**
 * Pure helpers for POST /api/email/trace-email (routes/email.js).
 *
 * Kept free of network and Redis access so the scoring and parsing rules can
 * be unit-tested (tests/emailTrace.test.js).
 */

const net = require('net');
const { isPrivateOrReservedIp } = require('../utils/ssrfGuard');

// ---------------------------------------------------------------------------
// Authentication-Results
// ---------------------------------------------------------------------------

// RFC 8601 result keywords
const FAIL_RESULTS = new Set(['fail', 'permerror']);
const TEMP_RESULTS = new Set(['temperror']);
const SOFT_RESULTS = new Set(['softfail']);

/**
 * Pull the first Authentication-Results header (the receiving server's, which
 * sits at the top) including folded continuation lines.
 */
function extractAuthResultsHeader(headers) {
  const lines = String(headers || '').split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (/^Authentication-Results:/i.test(lines[i])) {
      let text = lines[i].replace(/^Authentication-Results:/i, '');
      for (let j = i + 1; j < lines.length && /^[ \t]/.test(lines[j]); j++) {
        text += ' ' + lines[j].trim();
      }
      return text;
    }
  }
  return null;
}

function methodResults(authText, method) {
  const re = new RegExp(`(?:^|[\\s;])${method}=([a-z]+)([^;]*)`, 'gi');
  const out = [];
  let m;
  while ((m = re.exec(authText)) !== null) {
    out.push({ result: m[1].toLowerCase(), props: m[2] || '' });
  }
  return out;
}

function prop(props, name) {
  const m = new RegExp(`${name.replace('.', '\\.')}=([^\\s;()]+)`, 'i').exec(props);
  return m ? m[1] : null;
}

/**
 * @returns {{ spf, dkim, dmarc }} each { status, pass, ... }.
 *   status: the RFC 8601 result keyword ('pass', 'fail', 'softfail', 'neutral',
 *   'none', 'temperror', 'permerror', 'policy'), or 'missing' when the header
 *   (or that method) is absent.
 *   pass: true for pass, false for fail/permerror, null otherwise (legacy field).
 */
function parseAuthenticationResults(headers) {
  const authText = extractAuthResultsHeader(headers);
  const legacyPass = (status) => (status === 'pass' ? true : FAIL_RESULTS.has(status) ? false : null);

  if (authText === null) {
    return {
      present: false,
      spf: { status: 'missing', pass: null, domain: null },
      dkim: { status: 'missing', pass: null, selector: null, domain: null },
      dmarc: { status: 'missing', pass: null, policy: null, domain: null }
    };
  }

  const spfR = methodResults(authText, 'spf')[0];
  const spfStatus = spfR ? spfR.result : 'missing';
  const spf = {
    status: spfStatus,
    pass: legacyPass(spfStatus),
    domain: spfR ? prop(spfR.props, 'smtp.mailfrom') || prop(spfR.props, 'smtp.helo') : null
  };

  // Several DKIM signatures can be reported; one passing signature is enough.
  const dkimAll = methodResults(authText, 'dkim');
  const dkimR = dkimAll.find((r) => r.result === 'pass') || dkimAll[0];
  const dkimStatus = dkimR ? dkimR.result : 'missing';
  const dkim = {
    status: dkimStatus,
    pass: legacyPass(dkimStatus),
    selector: dkimR ? prop(dkimR.props, 'header.s') : null,
    domain: dkimR ? prop(dkimR.props, 'header.d') || prop(dkimR.props, 'header.i') : null
  };

  const dmarcR = methodResults(authText, 'dmarc')[0];
  const dmarcStatus = dmarcR ? dmarcR.result : 'missing';
  let policy = null;
  if (dmarcR) {
    const p = /\bp=([a-z]+)/i.exec(dmarcR.props) || /\baction=([a-z]+)/i.exec(dmarcR.props) || /policy\.[a-z]+=([^\s;]+)/i.exec(dmarcR.props);
    policy = p ? p[1].toLowerCase() : null;
  }
  const dmarc = {
    status: dmarcStatus,
    pass: legacyPass(dmarcStatus),
    policy,
    domain: dmarcR ? prop(dmarcR.props, 'header.from') : null
  };

  return { present: true, spf, dkim, dmarc };
}

/**
 * Classify an auth status: 'pass' | 'fail' | 'soft' | 'temp' | 'absent'.
 * Only fail/permerror are failures. softfail is a softer warning, temperror a
 * transient error; none/neutral/missing simply mean "not present".
 */
function classifyAuthStatus(status) {
  if (status === 'pass') return 'pass';
  if (FAIL_RESULTS.has(status)) return 'fail';
  if (SOFT_RESULTS.has(status)) return 'soft';
  if (TEMP_RESULTS.has(status)) return 'temp';
  return 'absent';
}

const SCORE_WEIGHTS = {
  spf: { fail: 2.5, soft: 1.0, temp: 0.5, absent: 0.5 },
  dkim: { fail: 2.0, soft: 1.0, temp: 0.5, absent: 0.5 },
  dmarc: { fail: 3.0, soft: 1.0, temp: 0.5, absent: 0.5 }
};
const LISTED_IP_WEIGHT = 1.5;

/**
 * Toolsana's own 0-10 heuristic. Each authentication method contributes once
 * (no double counting through the warnings list) and each blacklisted sending
 * IP adds a fixed amount. "Not present" results add only a little: plenty of
 * legitimate mail is unsigned or sent from domains without DMARC.
 */
function calculateSpamScore(authentication, listedIpCount = 0) {
  let score = 0;
  for (const method of ['spf', 'dkim', 'dmarc']) {
    const cls = classifyAuthStatus(authentication[method] && authentication[method].status);
    if (cls !== 'pass') score += SCORE_WEIGHTS[method][cls];
  }
  score += LISTED_IP_WEIGHT * listedIpCount;
  return Math.min(10, parseFloat(score.toFixed(1)));
}

/**
 * Warnings derived from authentication results: { severity, message }.
 */
function authenticationWarnings(authentication) {
  const out = [];
  const spf = classifyAuthStatus(authentication.spf.status);
  const dkim = classifyAuthStatus(authentication.dkim.status);
  const dmarc = classifyAuthStatus(authentication.dmarc.status);

  if (spf === 'fail') out.push({ severity: 'high', message: `SPF ${authentication.spf.status} - the sending server is not authorized by the sender domain` });
  else if (spf === 'soft') out.push({ severity: 'medium', message: 'SPF softfail - the sending server is probably not authorized by the sender domain' });
  else if (spf === 'temp') out.push({ severity: 'low', message: 'SPF temperror - the receiving server could not complete the SPF check' });

  if (dkim === 'fail') out.push({ severity: 'high', message: `DKIM ${authentication.dkim.status} - the signature did not verify; the message may have been altered in transit` });
  else if (dkim === 'temp') out.push({ severity: 'low', message: 'DKIM temperror - the receiving server could not fetch the signing key' });

  if (dmarc === 'fail') out.push({ severity: 'high', message: `DMARC ${authentication.dmarc.status} - the From domain was not authenticated; the message may be spoofed` });
  else if (dmarc === 'temp') out.push({ severity: 'low', message: 'DMARC temperror - the receiving server could not complete the DMARC check' });

  return out;
}

// ---------------------------------------------------------------------------
// Received headers / hops
// ---------------------------------------------------------------------------

/**
 * 'public' | 'private' (RFC 1918 / ULA / CGNAT / loopback / link-local / reserved)
 */
function classifyIP(ip) {
  if (!net.isIP(ip)) return 'invalid';
  return isPrivateOrReservedIp(ip) ? 'private' : 'public';
}

/**
 * Extract the relaying server's IP from one Received header. Prefers the
 * address in the "from" clause (between "from" and "by"), e.g.
 * "from mail.example.com (mail.example.com [203.0.113.5])". Falls back to any
 * address in the header.
 */
function extractHopIP(receivedHeader) {
  const text = String(receivedHeader || '');
  const byIdx = text.search(/\sby\s/i);
  const fromPart = /^Received:\s*from\s/i.test(text) || /^from\s/i.test(text)
    ? text.slice(0, byIdx > 0 ? byIdx : text.length)
    : '';

  const candidates = (segment) => {
    const found = [];
    // Bracketed literals: [203.0.113.5] or [IPv6:2001:db8::1]
    const bracket = /\[(?:IPv6:)?([0-9a-fA-F:.]+)\]/g;
    let m;
    while ((m = bracket.exec(segment)) !== null) found.push(m[1]);
    // Bare tokens
    const tokens = segment.split(/[\s()[\];,<>=]+/);
    for (const t of tokens) {
      const tok = t.replace(/^IPv6:/i, '');
      if (tok) found.push(tok);
    }
    return found.filter((c) => net.isIP(c));
  };

  const fromIPs = fromPart ? candidates(fromPart) : [];
  if (fromIPs.length > 0) return fromIPs[0];
  const any = candidates(text);
  return any.length > 0 ? any[0] : null;
}

function extractTimestamp(receivedHeader) {
  const text = String(receivedHeader || '');
  const semi = text.lastIndexOf(';');
  if (semi < 0) return null;
  const raw = text.slice(semi + 1).replace(/\([^)]*\)\s*$/, '').trim();
  if (!raw) return null;
  const t = Date.parse(raw);
  return Number.isNaN(t) ? null : new Date(t).toISOString();
}

function formatDuration(seconds) {
  if (seconds === null || seconds === undefined || !Number.isFinite(seconds)) return null;
  const sign = seconds < 0 ? '-' : '';
  let s = Math.round(Math.abs(seconds));
  const h = Math.floor(s / 3600);
  s -= h * 3600;
  const m = Math.floor(s / 60);
  s -= m * 60;
  if (h > 0) return `${sign}${h}h ${m}m ${s}s`;
  if (m > 0) return `${sign}${m}m ${s}s`;
  return `${sign}${s}s`;
}

/**
 * Given hops in chronological order (each with an ISO `timestamp` or null),
 * add per-hop `delaySeconds`/`delay` and return { totalSeconds, totalTime }.
 * A negative delay means the two servers' clocks disagree.
 */
function computeTimings(hops) {
  let prev = null;
  for (const hop of hops) {
    const t = hop.timestamp ? Date.parse(hop.timestamp) : NaN;
    if (!Number.isNaN(t) && prev !== null) {
      hop.delaySeconds = Math.round((t - prev) / 1000);
      hop.delay = formatDuration(hop.delaySeconds);
    } else {
      hop.delaySeconds = null;
      hop.delay = null;
    }
    if (!Number.isNaN(t)) prev = t;
  }
  const times = hops.map((h) => (h.timestamp ? Date.parse(h.timestamp) : NaN)).filter((t) => !Number.isNaN(t));
  if (times.length < 2) return { totalSeconds: null, totalTime: null };
  const totalSeconds = Math.round((times[times.length - 1] - times[0]) / 1000);
  return { totalSeconds, totalTime: formatDuration(totalSeconds) };
}

// ---------------------------------------------------------------------------
// DNSBL
// ---------------------------------------------------------------------------

/**
 * Reverse an IP for DNSBL / Team Cymru queries.
 * IPv4: 1.2.3.4 -> 4.3.2.1
 * IPv6: 2001:db8::1 -> 1.0.0.0. ... .8.b.d.0.1.0.0.2 (32 nibbles, RFC 5782)
 */
function reverseIPForDnsbl(ip) {
  const kind = net.isIP(ip);
  if (kind === 4) return ip.split('.').reverse().join('.');
  if (kind === 6) {
    const groups = expandIPv6(ip);
    if (!groups) return null;
    const hex = groups.map((g) => g.toString(16).padStart(4, '0')).join('');
    return hex.split('').reverse().join('.');
  }
  return null;
}

function expandIPv6(input) {
  let ip = String(input).split('%')[0];
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':');
    const v4 = ip.slice(lastColon + 1).split('.').map(Number);
    if (v4.length !== 4 || v4.some((n) => !(n >= 0 && n <= 255))) return null;
    ip = ip.slice(0, lastColon + 1) + ((v4[0] << 8) | v4[1]).toString(16) + ':' + ((v4[2] << 8) | v4[3]).toString(16);
  }
  const halves = ip.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  let groups;
  if (halves.length === 2) {
    const missing = 8 - head.length - tail.length;
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8 || !groups.every((g) => /^[0-9a-f]{1,4}$/i.test(g))) return null;
  return groups.map((g) => parseInt(g, 16));
}

/**
 * Interpret a DNSBL answer.
 * - 127.0.0.2 - 127.0.0.255: listed
 * - 127.255.255.x: the list refused our query (Spamhaus: public/open resolver,
 *   rate limit) - this says nothing about the IP
 * - anything else (wildcard / sinkhole answers): not a listing
 * @returns {'listed'|'unavailable'|'clean'}
 */
function classifyDnsblAnswer(addresses) {
  const list = Array.isArray(addresses) ? addresses : [];
  if (list.some((a) => /^127\.255\.255\.\d{1,3}$/.test(a))) return 'unavailable';
  if (list.some((a) => {
    const m = /^127\.0\.0\.(\d{1,3})$/.exec(a);
    return m && Number(m[1]) >= 2 && Number(m[1]) <= 255;
  })) return 'listed';
  return 'clean';
}

module.exports = {
  extractAuthResultsHeader,
  parseAuthenticationResults,
  classifyAuthStatus,
  calculateSpamScore,
  authenticationWarnings,
  classifyIP,
  extractHopIP,
  extractTimestamp,
  formatDuration,
  computeTimings,
  reverseIPForDnsbl,
  classifyDnsblAnswer,
};
