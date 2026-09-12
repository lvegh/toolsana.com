/**
 * Centralized SSRF guard.
 *
 * The routes that fetch user-supplied URLs (fetch, link-checker, canonical,
 * http-headers, cors, seo, dns) previously screened the request target with
 * hand-rolled string/regex matching on the raw hostname. That approach missed
 * whole reserved ranges (169.254.0.0/16 cloud metadata, the rest of 127.0.0.0/8,
 * 100.64.0.0/10 CGNAT), was defeated by IPv6 v4-mapped forms (::ffff:127.0.0.1),
 * and — critically — never resolved hostnames, so any domain with an A record
 * pointing at a private IP sailed straight through.
 *
 * This module screens the *resolved* address(es): if the host is an IP literal
 * it is range-checked directly; otherwise it is resolved via DNS and EVERY
 * returned address must be public. The range check is IP-arithmetic based
 * (CIDR), not string matching, and normalizes IPv6-embedded IPv4 down to v4.
 *
 * Residual risk: this validates at check time; the subsequent outbound request
 * re-resolves the name, leaving a narrow DNS-rebinding TOCTOU window. Closing it
 * fully requires pinning the validated IP into the connection (custom lookup).
 * The checks here still close every statically-reachable bypass.
 */

const net = require('net');
const dns = require('dns').promises;
const { Agent } = require('undici');

const GENERIC_PRIVATE_ERROR = 'Access to private/local networks is not allowed';

/** Parse a dotted-quad IPv4 string to an unsigned 32-bit integer, or null. */
function ipv4ToLong(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let long = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    long = long * 256 + n;
  }
  return long >>> 0;
}

/** IPv4 CIDR blocks that must never be reachable from a user-supplied target. */
const BLOCKED_V4 = [
  ['0.0.0.0', 8],       // "this" network
  ['10.0.0.0', 8],      // RFC1918 private
  ['100.64.0.0', 10],   // RFC6598 CGNAT / shared address space
  ['127.0.0.0', 8],     // loopback (whole /8, not just 127.0.0.1)
  ['169.254.0.0', 16],  // link-local — includes 169.254.169.254 cloud IMDS
  ['172.16.0.0', 12],   // RFC1918 private
  ['192.0.0.0', 24],    // IETF protocol assignments
  ['192.0.2.0', 24],    // TEST-NET-1
  ['192.168.0.0', 16],  // RFC1918 private
  ['198.18.0.0', 15],   // benchmarking
  ['198.51.100.0', 24], // TEST-NET-2
  ['203.0.113.0', 24],  // TEST-NET-3
  ['224.0.0.0', 4],     // multicast
  ['240.0.0.0', 4],     // reserved (includes 255.255.255.255 broadcast)
].map(([base, bits]) => {
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return { network: (ipv4ToLong(base) & mask) >>> 0, mask };
});

function isPrivateV4(ip) {
  const long = ipv4ToLong(ip);
  if (long === null) return true; // fail closed on anything unparseable
  return BLOCKED_V4.some(({ network, mask }) => ((long & mask) >>> 0) === network);
}

/** Expand an IPv6 string (possibly with embedded IPv4) to 8 numeric hextets, or null. */
function expandV6(input) {
  let ip = input.split('%')[0]; // drop zone id

  // Fold a trailing dotted-quad (::ffff:1.2.3.4, ::1.2.3.4, 64:ff9b::1.2.3.4)
  // into two hextets so the whole address is uniformly hex.
  if (ip.includes('.')) {
    const lastColon = ip.lastIndexOf(':');
    const tail = ip.slice(lastColon + 1);
    const long = ipv4ToLong(tail);
    if (long === null) return null;
    const hi = (long >>> 16) & 0xffff;
    const lo = long & 0xffff;
    ip = ip.slice(0, lastColon + 1) + hi.toString(16) + ':' + lo.toString(16);
  }

  const halves = ip.split('::');
  if (halves.length > 2) return null;

  const head = halves[0] ? halves[0].split(':') : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];

  let groups;
  if (halves.length === 2) {
    const missing = 8 - (head.length + tail.length);
    if (missing < 0) return null;
    groups = [...head, ...Array(missing).fill('0'), ...tail];
  } else {
    groups = head;
  }
  if (groups.length !== 8) return null;

  const out = [];
  for (const g of groups) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
    out.push(parseInt(g, 16) & 0xffff);
  }
  return out;
}

function embeddedV4(g) {
  return `${(g[6] >> 8) & 0xff}.${g[6] & 0xff}.${(g[7] >> 8) & 0xff}.${g[7] & 0xff}`;
}

function isPrivateV6(ip) {
  const g = expandV6(ip);
  if (!g) return true; // fail closed

  const isZeroPrefix = g[0] === 0 && g[1] === 0 && g[2] === 0 && g[3] === 0 && g[4] === 0;

  // IPv4-mapped ::ffff:a.b.c.d — check the embedded IPv4.
  if (isZeroPrefix && g[5] === 0xffff) return isPrivateV4(embeddedV4(g));

  // Everything in ::/96 (::1 loopback, :: unspecified, deprecated v4-compatible).
  if (isZeroPrefix && g[5] === 0) return true;

  // NAT64 well-known prefix 64:ff9b::/96 — check the embedded IPv4.
  if (g[0] === 0x64 && g[1] === 0xff9b && g[2] === 0 && g[3] === 0 && g[4] === 0 && g[5] === 0) {
    return isPrivateV4(embeddedV4(g));
  }

  const firstByte = (g[0] >> 8) & 0xff;
  if ((firstByte & 0xfe) === 0xfc) return true;                       // fc00::/7 unique-local
  if (firstByte === 0xfe && (g[0] & 0x00c0) === 0x0080) return true;  // fe80::/10 link-local
  if (firstByte === 0xff) return true;                               // ff00::/8 multicast

  return false;
}

/**
 * True if `ip` (an IPv4 or IPv6 literal) is loopback, private, link-local,
 * CGNAT, multicast, or otherwise reserved. Fails closed: a non-IP string,
 * or anything it cannot parse, is treated as private.
 */
function isPrivateOrReservedIp(ip) {
  if (typeof ip !== 'string') return true;
  const kind = net.isIP(ip);
  if (kind === 4) return isPrivateV4(ip);
  if (kind === 6) return isPrivateV6(ip);
  return true;
}

/** Strip surrounding brackets from an IPv6 literal host (`[::1]` -> `::1`). */
function stripBrackets(host) {
  return host.replace(/^\[/, '').replace(/\]$/, '');
}

/**
 * Resolve `hostname` (an IP literal or a domain) and confirm every resolved
 * address is public. Returns { valid, addresses } or { valid:false, error }.
 */
async function screenHostname(hostname) {
  const host = stripBrackets(String(hostname || '').trim().toLowerCase());
  if (!host) return { valid: false, error: 'Invalid host' };

  if (net.isIP(host)) {
    if (isPrivateOrReservedIp(host)) return { valid: false, error: GENERIC_PRIVATE_ERROR };
    return { valid: true, addresses: [host] };
  }

  let addresses;
  try {
    const results = await dns.lookup(host, { all: true, verbatim: true });
    addresses = results.map((r) => r.address);
  } catch {
    return { valid: false, error: 'Host could not be resolved' };
  }
  if (!addresses.length) return { valid: false, error: 'Host could not be resolved' };

  for (const addr of addresses) {
    if (isPrivateOrReservedIp(addr)) return { valid: false, error: GENERIC_PRIVATE_ERROR };
  }
  return { valid: true, addresses };
}

/**
 * Screen a full URL string. Enforces http/https (unless requireHttp is false),
 * then resolves and range-checks the host.
 * Returns { valid, url, hostname, addresses } or { valid:false, error }.
 */
async function checkPublicUrl(rawUrl, { requireHttp = true } = {}) {
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    return { valid: false, error: 'Invalid URL format' };
  }
  if (requireHttp && !['http:', 'https:'].includes(url.protocol)) {
    return { valid: false, error: 'Only HTTP and HTTPS URLs are allowed' };
  }
  const res = await screenHostname(url.hostname);
  if (!res.valid) return res;
  return { valid: true, url, hostname: url.hostname, addresses: res.addresses };
}

/** Screen a bare hostname/domain (no scheme). Resolves and range-checks. */
async function checkPublicHostname(hostname) {
  return screenHostname(hostname);
}

/**
 * Build a `lookup` function that pins a connection to an already-screened address.
 *
 * Screening resolves the name, then the socket resolves it AGAIN to connect —
 * so a low-TTL record can answer "public" to the check and "private" to the
 * connection. Passing this as `options.lookup` to http.request / https.request /
 * tls.connect closes that window: the socket dials the address we vetted.
 *
 * Keep `hostname` (not the IP) as the request's host so SNI, the Host header,
 * and certificate validation still see the real name.
 *
 * Node calls `lookup` with TWO different contracts. With `autoSelectFamily`
 * (the default since Node 20) it passes `{ all: true }` and expects an ARRAY of
 * `{ address, family }`; otherwise it expects `(err, address, family)`.
 * Answering with the wrong shape fails as "Invalid IP address: undefined".
 */
function pinnedLookup(address) {
  const family = net.isIP(address);
  return (_hostname, options, callback) => {
    if (options && options.all) {
      return callback(null, [{ address, family }]);
    }
    return callback(null, address, family);
  };
}

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Error thrown by safeFetch when a hop resolves to a private/reserved address.
 * Carries `code = 'SSRF_BLOCKED'` so routes can map it to HTTP 403.
 */
class SsrfBlockedError extends Error {
  constructor(message, blockedUrl) {
    super(message);
    this.name = 'SsrfBlockedError';
    this.code = 'SSRF_BLOCKED';
    this.blockedUrl = blockedUrl;
  }
}

/**
 * fetch() that screens EVERY hop, not just the initial URL.
 *
 * Screening only the user-supplied URL is insufficient: with `redirect:'follow'`
 * an attacker-controlled public host can 302 to 169.254.169.254 and the runtime
 * follows it, bypassing the guard entirely. This follows redirects manually and
 * re-screens each Location before requesting it.
 *
 * Returns { response, redirectChain, finalUrl }. Throws SsrfBlockedError if any
 * hop is private/reserved, or a TOO_MANY_REDIRECTS error past `maxRedirects`.
 * Method/body are downgraded to GET on 301/302/303 per RFC 9110; 307/308
 * preserve both.
 */
async function safeFetch(rawUrl, options = {}, { maxRedirects = 5 } = {}) {
  const baseOptions = { ...options };
  delete baseOptions.redirect; // we follow manually so each hop can be screened
  let currentUrl = String(rawUrl);
  let method = (options.method || 'GET').toUpperCase();
  let body = options.body;
  const redirectChain = [];

  // IP pinning closes the DNS-rebinding TOCTOU: without it we screen the
  // resolved address, then the connection re-resolves the name and an attacker
  // with a low-TTL record can return a private IP for that second lookup. The
  // dispatcher below dials ONLY addresses we already screened for that exact
  // hostname, and fails closed for any hostname we did not screen.
  let pinned = null; // { hostname, addresses: [{ address, family }] }
  const dispatcher = new Agent({
    connect: {
      lookup: (hostname, _opts, cb) => {
        if (pinned && pinned.hostname === hostname) {
          return cb(null, pinned.addresses);
        }
        return cb(new SsrfBlockedError(`Unscreened host: ${hostname}`, hostname));
      },
    },
    // Keep sockets from lingering: the dispatcher is per-call, so long-lived
    // keep-alive sockets would accumulate.
    keepAliveTimeout: 1,
    keepAliveMaxTimeout: 1,
  });

  for (let hop = 0; hop <= maxRedirects; hop++) {
    const guard = await checkPublicUrl(currentUrl);
    if (!guard.valid) {
      throw new SsrfBlockedError(guard.error, currentUrl);
    }

    pinned = {
      hostname: guard.url.hostname.replace(/^\[/, '').replace(/\]$/, ''),
      addresses: guard.addresses.map((address) => ({
        address,
        family: net.isIP(address),
      })),
    };

    const requestOptions = { ...baseOptions, method, redirect: 'manual', dispatcher };
    if (body !== undefined && !['GET', 'HEAD'].includes(method)) {
      requestOptions.body = body;
    } else {
      delete requestOptions.body;
    }

    const response = await fetch(guard.url.toString(), requestOptions);

    if (!REDIRECT_STATUSES.has(response.status)) {
      return { response, redirectChain, finalUrl: currentUrl };
    }

    const location = response.headers.get('location');
    if (!location) {
      // A 3xx with no Location is not actionable — hand it back as the result.
      return { response, redirectChain, finalUrl: currentUrl };
    }

    let nextUrl;
    try {
      nextUrl = new URL(location, currentUrl).toString();
    } catch {
      return { response, redirectChain, finalUrl: currentUrl };
    }

    redirectChain.push({ from: currentUrl, to: nextUrl, status: response.status });

    // RFC 9110: 303 always becomes GET; 301/302 historically downgrade POST to
    // GET (matching browser + undici `follow` behaviour). 307/308 preserve.
    if (response.status === 303 || (method === 'POST' && (response.status === 301 || response.status === 302))) {
      method = 'GET';
      body = undefined;
    }

    currentUrl = nextUrl;
  }

  const err = new Error(`Too many redirects (max ${maxRedirects})`);
  err.code = 'TOO_MANY_REDIRECTS';
  throw err;
}

module.exports = {
  isPrivateOrReservedIp,
  screenHostname,
  checkPublicUrl,
  checkPublicHostname,
  pinnedLookup,
  safeFetch,
  SsrfBlockedError,
  GENERIC_PRIVATE_ERROR,
};
