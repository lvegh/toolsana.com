/**
 * Domain validation shared by dns.js (mx/ns lookup) and email.js (SPF checker).
 * Regression: the old unanchored patterns rejected top10.com, mail.web10.net
 * and site127.io, and the TLD rule rejected punycode TLDs.
 */

const { validatePublicDomain, organizationalDomain, normalizeDomainInput } = require('../src/utils/dnsNames');

describe('validatePublicDomain', () => {
  it.each([
    'top10.com',
    'mail.web10.net',
    'site127.io',
    'a10.b127.c192.example.org',
    'xn--80ak6aa92e.com',
    'example.xn--p1ai',
    'xn--e1afmkfd.xn--80asehdb',
    'sub.example.co.uk',
    'google.com',
  ])('accepts %s', (domain) => {
    const r = validatePublicDomain(domain);
    expect(r.valid).toBe(true);
    expect(r.cleanDomain).toBe(domain);
  });

  it.each([
    ['10.0.0.1', 'ip'],
    ['127.0.0.1', 'ip'],
    ['8.8.8.8', 'ip'],
    ['localhost', 'format'],
    ['foo.localhost', 'private'],
    ['printer.local', 'private'],
    ['db.internal', 'private'],
    ['router.home.arpa', 'private'],
  ])('rejects %s', (domain, reason) => {
    const r = validatePublicDomain(domain);
    expect(r.valid).toBe(false);
    expect(r.reason).toBe(reason);
  });

  it.each([
    'bad_domain.com',
    '-lead.com',
    'trail-.com',
    'example.c0m',
    'example.',
    '',
    'a'.repeat(64) + '.com',
  ])('rejects malformed %p', (domain) => {
    expect(validatePublicDomain(domain).valid).toBe(false);
  });

  it('normalizes URLs, ports and case', () => {
    expect(normalizeDomainInput('HTTPS://Example.COM:8443/path?q=1')).toBe('example.com');
    expect(validatePublicDomain('https://top10.com/').cleanDomain).toBe('top10.com');
  });
});

describe('organizationalDomain', () => {
  it.each([
    ['example.com', 'example.com'],
    ['mail.example.com', 'example.com'],
    ['a.b.example.com', 'example.com'],
    ['shop.example.co.uk', 'example.co.uk'],
    ['example.co.uk', 'example.co.uk'],
    ['x.example.com.au', 'example.com.au'],
    ['news.example.de', 'example.de'],
  ])('%s -> %s', (input, expected) => {
    expect(organizationalDomain(input)).toBe(expected);
  });
});
