/**
 * Tests for the centralized SSRF guard.
 *
 * These are deliberately network-independent: host screening is exercised with
 * IP literals (which short-circuit DNS) or a mocked dns.lookup, and safeFetch
 * runs against a mocked global fetch. Nothing here touches the real internet,
 * so the suite is safe for CI.
 */

const dns = require('dns').promises;
const {
  isPrivateOrReservedIp,
  screenHostname,
  checkPublicUrl,
  safeFetch,
  SsrfBlockedError,
  GENERIC_PRIVATE_ERROR,
} = require('../src/utils/ssrfGuard');

/** Minimal stand-in for a fetch Response — safeFetch only reads status/headers. */
const mockResponse = (status, headers = {}) => {
  const lower = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v])
  );
  return {
    status,
    statusText: '',
    headers: { get: (k) => (k.toLowerCase() in lower ? lower[k.toLowerCase()] : null) },
    text: async () => '',
  };
};

describe('isPrivateOrReservedIp', () => {
  describe('IPv4 blocked ranges', () => {
    it.each([
      ['127.0.0.1', 'loopback'],
      ['127.0.0.2', 'loopback beyond .1 — missed by the old exact-match guard'],
      ['127.255.255.255', 'top of loopback /8'],
      ['10.0.0.1', 'RFC1918 /8'],
      ['172.16.0.1', 'RFC1918 /12 low'],
      ['172.31.255.255', 'RFC1918 /12 high'],
      ['192.168.1.1', 'RFC1918 /16'],
      ['169.254.169.254', 'cloud metadata (IMDS)'],
      ['169.254.1.1', 'link-local'],
      ['100.64.0.1', 'CGNAT /10'],
      ['0.0.0.0', 'unspecified'],
      ['224.0.0.1', 'multicast'],
      ['255.255.255.255', 'broadcast'],
      ['192.0.2.1', 'TEST-NET-1'],
      ['198.18.0.1', 'benchmarking'],
    ])('blocks %s (%s)', (ip) => {
      expect(isPrivateOrReservedIp(ip)).toBe(true);
    });
  });

  describe('IPv4 public addresses', () => {
    it.each([
      ['8.8.8.8'],
      ['1.1.1.1'],
      ['104.20.23.154'],
      ['172.15.0.1'],   // just below the RFC1918 /12
      ['172.32.0.1'],   // just above the RFC1918 /12
      ['172.200.0.1'],  // regression: the old "172.2" prefix wrongly blocked this
      ['172.255.0.1'],  // regression: same
      ['100.128.0.1'],  // just above CGNAT
      ['11.0.0.1'],
    ])('allows %s', (ip) => {
      expect(isPrivateOrReservedIp(ip)).toBe(false);
    });
  });

  describe('IPv6', () => {
    it.each([
      ['::1', 'loopback'],
      ['::', 'unspecified'],
      ['fc00::1', 'unique-local'],
      ['fd12:3456::1', 'unique-local'],
      ['fe80::1', 'link-local'],
      ['ff02::1', 'multicast'],
      ['::ffff:127.0.0.1', 'v4-mapped loopback — defeated the old string checks'],
      ['::ffff:169.254.169.254', 'v4-mapped IMDS'],
      ['::ffff:10.0.0.1', 'v4-mapped RFC1918'],
      ['64:ff9b::7f00:1', 'NAT64-embedded loopback'],
    ])('blocks %s (%s)', (ip) => {
      expect(isPrivateOrReservedIp(ip)).toBe(true);
    });

    it.each([
      ['2606:4700:4700::1111'],
      ['2001:4860:4860::8888'],
      ['::ffff:8.8.8.8'],
      ['64:ff9b::0808:0808'],
    ])('allows %s', (ip) => {
      expect(isPrivateOrReservedIp(ip)).toBe(false);
    });
  });

  describe('fails closed', () => {
    it.each([['not-an-ip'], [''], ['999.999.999.999'], ['::gggg'], [null], [undefined], [42]])(
      'treats %p as private',
      (input) => {
        expect(isPrivateOrReservedIp(input)).toBe(true);
      }
    );
  });
});

describe('screenHostname', () => {
  it('accepts a public IP literal without resolving', async () => {
    const spy = jest.spyOn(dns, 'lookup');
    const res = await screenHostname('8.8.8.8');
    expect(res.valid).toBe(true);
    expect(res.addresses).toEqual(['8.8.8.8']);
    expect(spy).not.toHaveBeenCalled();
  });

  it('rejects a private IP literal', async () => {
    const res = await screenHostname('169.254.169.254');
    expect(res.valid).toBe(false);
    expect(res.error).toBe(GENERIC_PRIVATE_ERROR);
  });

  it('strips brackets from IPv6 literals', async () => {
    expect((await screenHostname('[::1]')).valid).toBe(false);
    expect((await screenHostname('[2606:4700:4700::1111]')).valid).toBe(true);
  });

  it('resolves a hostname and accepts it when every address is public', async () => {
    jest.spyOn(dns, 'lookup').mockResolvedValue([
      { address: '104.20.23.154', family: 4 },
      { address: '2606:4700:10::6814:179a', family: 6 },
    ]);
    const res = await screenHostname('example.com');
    expect(res.valid).toBe(true);
    expect(res.addresses).toHaveLength(2);
  });

  it('blocks a hostname that resolves to a private IP (DNS-rebinding class)', async () => {
    jest.spyOn(dns, 'lookup').mockResolvedValue([{ address: '169.254.169.254', family: 4 }]);
    const res = await screenHostname('metadata.attacker.test');
    expect(res.valid).toBe(false);
    expect(res.error).toBe(GENERIC_PRIVATE_ERROR);
  });

  it('blocks when ANY resolved address is private, not just the first', async () => {
    jest.spyOn(dns, 'lookup').mockResolvedValue([
      { address: '8.8.8.8', family: 4 },
      { address: '127.0.0.1', family: 4 },
    ]);
    expect((await screenHostname('split.attacker.test')).valid).toBe(false);
  });

  it('fails closed when resolution throws', async () => {
    jest.spyOn(dns, 'lookup').mockRejectedValue(new Error('ENOTFOUND'));
    const res = await screenHostname('does-not-exist.invalid');
    expect(res.valid).toBe(false);
    expect(res.error).toMatch(/could not be resolved/i);
  });

  it('fails closed on an empty resolution result', async () => {
    jest.spyOn(dns, 'lookup').mockResolvedValue([]);
    expect((await screenHostname('empty.test')).valid).toBe(false);
  });
});

describe('checkPublicUrl', () => {
  it('rejects non-http(s) protocols', async () => {
    for (const url of ['file:///etc/passwd', 'gopher://8.8.8.8/', 'ftp://8.8.8.8/']) {
      const res = await checkPublicUrl(url);
      expect(res.valid).toBe(false);
      expect(res.error).toMatch(/HTTP and HTTPS/);
    }
  });

  it('rejects malformed URLs', async () => {
    const res = await checkPublicUrl('http://[not a url');
    expect(res.valid).toBe(false);
    expect(res.error).toMatch(/Invalid URL/);
  });

  it('allows a public http URL and returns the parsed URL', async () => {
    const res = await checkPublicUrl('http://8.8.8.8/path?q=1');
    expect(res.valid).toBe(true);
    expect(res.url.pathname).toBe('/path');
  });

  it('blocks numeric-encoded loopback forms once the URL parser normalizes them', async () => {
    // new URL() canonicalizes 0177.0.0.1 / 2130706433 / 0x7f.0.0.1 to 127.0.0.1
    for (const url of ['http://0177.0.0.1/', 'http://2130706433/', 'http://0x7f.0.0.1/']) {
      const res = await checkPublicUrl(url);
      expect(res.valid).toBe(false);
      expect(res.error).toBe(GENERIC_PRIVATE_ERROR);
    }
  });
});

describe('safeFetch', () => {
  beforeEach(() => {
    global.fetch = jest.fn();
  });

  it('returns the response when there is no redirect', async () => {
    global.fetch.mockResolvedValue(mockResponse(200));
    const { response, redirectChain } = await safeFetch('http://8.8.8.8/');
    expect(response.status).toBe(200);
    expect(redirectChain).toEqual([]);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('blocks a private target up front', async () => {
    await expect(safeFetch('http://169.254.169.254/')).rejects.toMatchObject({
      code: 'SSRF_BLOCKED',
    });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('blocks a redirect from a public host to a private one', async () => {
    global.fetch.mockResolvedValueOnce(
      mockResponse(302, { location: 'http://169.254.169.254/latest/meta-data/' })
    );
    await expect(safeFetch('http://8.8.8.8/')).rejects.toBeInstanceOf(SsrfBlockedError);
    // the redirect target must never be requested
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('blocks a redirect to a hostname that resolves privately', async () => {
    global.fetch.mockResolvedValueOnce(
      mockResponse(302, { location: 'http://metadata.attacker.test/' })
    );
    jest.spyOn(dns, 'lookup').mockResolvedValue([{ address: '169.254.169.254', family: 4 }]);
    await expect(safeFetch('http://8.8.8.8/')).rejects.toMatchObject({ code: 'SSRF_BLOCKED' });
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('follows a public redirect and records the chain', async () => {
    global.fetch
      .mockResolvedValueOnce(mockResponse(302, { location: 'http://1.1.1.1/next' }))
      .mockResolvedValueOnce(mockResponse(200));
    const { response, redirectChain, finalUrl } = await safeFetch('http://8.8.8.8/');
    expect(response.status).toBe(200);
    expect(redirectChain).toEqual([
      { from: 'http://8.8.8.8/', to: 'http://1.1.1.1/next', status: 302 },
    ]);
    expect(finalUrl).toBe('http://1.1.1.1/next');
  });

  it('resolves relative Location headers against the current URL', async () => {
    global.fetch
      .mockResolvedValueOnce(mockResponse(301, { location: '/moved' }))
      .mockResolvedValueOnce(mockResponse(200));
    const { finalUrl } = await safeFetch('http://8.8.8.8/start');
    expect(finalUrl).toBe('http://8.8.8.8/moved');
  });

  it('screens every hop, not just the first', async () => {
    global.fetch
      .mockResolvedValueOnce(mockResponse(302, { location: 'http://1.1.1.1/a' }))
      .mockResolvedValueOnce(mockResponse(302, { location: 'http://127.0.0.1/b' }));
    await expect(safeFetch('http://8.8.8.8/')).rejects.toMatchObject({ code: 'SSRF_BLOCKED' });
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  it('downgrades POST to GET and drops the body on 302 (RFC 9110)', async () => {
    global.fetch
      .mockResolvedValueOnce(mockResponse(302, { location: 'http://1.1.1.1/next' }))
      .mockResolvedValueOnce(mockResponse(200));
    await safeFetch('http://8.8.8.8/', { method: 'POST', body: 'a=1' });
    const second = global.fetch.mock.calls[1][1];
    expect(second.method).toBe('GET');
    expect(second.body).toBeUndefined();
  });

  it('preserves method and body across a 307', async () => {
    global.fetch
      .mockResolvedValueOnce(mockResponse(307, { location: 'http://1.1.1.1/next' }))
      .mockResolvedValueOnce(mockResponse(200));
    await safeFetch('http://8.8.8.8/', { method: 'POST', body: 'a=1' });
    const second = global.fetch.mock.calls[1][1];
    expect(second.method).toBe('POST');
    expect(second.body).toBe('a=1');
  });

  it('throws TOO_MANY_REDIRECTS past the hop limit instead of looping forever', async () => {
    global.fetch.mockResolvedValue(mockResponse(302, { location: 'http://1.1.1.1/loop' }));
    await expect(safeFetch('http://8.8.8.8/', {}, { maxRedirects: 3 })).rejects.toMatchObject({
      code: 'TOO_MANY_REDIRECTS',
    });
    expect(global.fetch).toHaveBeenCalledTimes(4); // initial + 3 hops
  });

  it('returns a 3xx that carries no Location header rather than looping', async () => {
    global.fetch.mockResolvedValue(mockResponse(302));
    const { response } = await safeFetch('http://8.8.8.8/');
    expect(response.status).toBe(302);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });

  it('always requests with manual redirect handling and a pinned dispatcher', async () => {
    global.fetch.mockResolvedValue(mockResponse(200));
    await safeFetch('http://8.8.8.8/', { redirect: 'follow' });
    const opts = global.fetch.mock.calls[0][1];
    // the caller's redirect:'follow' must not survive — that is the bypass
    expect(opts.redirect).toBe('manual');
    expect(opts.dispatcher).toBeDefined();
  });
});
