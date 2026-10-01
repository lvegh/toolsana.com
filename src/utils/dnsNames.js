/**
 * Domain-name helpers shared by the DNS and email routes (dns.js, email.js).
 *
 * validatePublicDomain() replaces the old per-route "suspicious pattern" lists,
 * which were unanchored substring regexes: /10\./ rejected top10.com and
 * mail.web10.net, /127\./ rejected site127.io, and the TLD rule [a-z]{2,}
 * rejected every punycode TLD (xn--p1ai, xn--80asehdb, ...). The rules below
 * only match IP literals or whole labels.
 *
 * organizationalDomain() is a deliberately small public-suffix heuristic for
 * the DMARC org-domain fallback. It is not the full Public Suffix List; it
 * covers the common two-label country suffixes (co.uk, com.au, ...).
 */

const net = require('net');

// One DNS label: letters/digits/hyphens, no leading or trailing hyphen, 1-63 chars.
const LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
// TLD: alphabetic (2-63) or an IDN A-label (xn--...).
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

// Names that only exist on private networks. Matched as whole labels / suffixes.
const PRIVATE_TLDS = new Set(['localhost', 'local', 'internal', 'lan', 'home', 'corp', 'intranet', 'localdomain', 'test', 'invalid', 'example']);
const PRIVATE_SUFFIXES = ['home.arpa'];

/**
 * Strip protocol, path, query, port and a trailing dot from user input and
 * lower-case it. Does not validate.
 */
function normalizeDomainInput(input) {
  let clean = String(input || '').trim().toLowerCase();
  clean = clean.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme
  clean = clean.replace(/[/?#].*$/, ''); // path / query / fragment
  clean = clean.replace(/^[^@]*@/, ''); // user@ (URLs) - keeps the host part
  if (!clean.startsWith('[')) clean = clean.replace(/:\d*$/, ''); // port
  clean = clean.replace(/\.$/, ''); // trailing root dot
  return clean;
}

/**
 * Validate a public DNS name.
 * @returns {{ valid: true, cleanDomain: string } | { valid: false, error: string, reason: 'format'|'ip'|'private' }}
 */
function validatePublicDomain(input) {
  if (!input || typeof input !== 'string') {
    return { valid: false, error: 'Domain is required', reason: 'format' };
  }
  const clean = normalizeDomainInput(input);
  const bare = clean.replace(/^\[|\]$/g, '');

  // IP literals are never valid here (these endpoints take domain names), and
  // private ones are reported as such.
  if (net.isIP(bare)) {
    return { valid: false, error: 'Enter a domain name, not an IP address', reason: 'ip' };
  }

  if (clean.length === 0 || clean.length > 253) {
    return { valid: false, error: 'Invalid domain format', reason: 'format' };
  }
  const labels = clean.split('.');
  if (labels.length < 2 || !labels.every((l) => LABEL_RE.test(l))) {
    return { valid: false, error: 'Invalid domain format', reason: 'format' };
  }
  const tld = labels[labels.length - 1];
  if (!TLD_RE.test(tld)) {
    return { valid: false, error: 'Invalid domain format', reason: 'format' };
  }

  if (labels.includes('localhost') || PRIVATE_TLDS.has(tld) || PRIVATE_SUFFIXES.some((s) => clean === s || clean.endsWith('.' + s))) {
    return { valid: false, error: 'Checking local or private network domains is not allowed', reason: 'private' };
  }

  return { valid: true, cleanDomain: clean };
}

// Second-level labels that act as public suffixes under many ccTLDs
// (co.uk, com.au, org.br, ac.jp, ...). Heuristic only.
const GENERIC_SLDS = new Set(['co', 'com', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'mil', 'nom', 'sch', 'ltd', 'plc', 'gen', 'biz', 'info', 'nic', 'me', 'gob', 'gouv']);

/**
 * Registrable ("organizational") domain by heuristic: the last two labels,
 * or the last three when the second-level label is a generic public-suffix
 * label under a two-letter ccTLD (example.co.uk, shop.example.com.au).
 */
function organizationalDomain(domain) {
  const labels = String(domain || '').toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const tld = labels[labels.length - 1];
  const sld = labels[labels.length - 2];
  const take = tld.length === 2 && GENERIC_SLDS.has(sld) ? 3 : 2;
  return labels.slice(-take).join('.');
}

module.exports = {
  normalizeDomainInput,
  validatePublicDomain,
  organizationalDomain,
};
