/**
 * Tests for /api/fetch (routes/fetch.js) and the safeFetch deadline /
 * redirect-body handling in utils/ssrfGuard.js.
 *
 * Network-independent: dns.lookup and global fetch are mocked, and the route
 * is exercised over a loopback socket with its auth/rate-limit/logging
 * middleware stubbed out.
 */

jest.mock('../src/utils/logger', () => ({
  info: () => {}, warn: () => {}, error: () => {}, debug: () => {}, http: () => {},
}));
jest.mock('../src/middleware/rateLimit', () => ({ basicRateLimit: (req, res, next) => next() }));
jest.mock('../src/middleware/enhancedSecurity', () => ({ enhancedSecurityWithRateLimit: (mw) => mw }));
jest.mock('../src/utils/outboundLog', () => ({ logOutbound: () => {} }));

const http = require('http');
const dns = require('dns').promises;
const { ReadableStream } = require('stream/web');
const { TextEncoder } = require('util');
const { Headers } = require('undici');
const express = require('express');
const { safeFetch, checkPublicUrl } = require('../src/utils/ssrfGuard');
const fetchRouter = require('../src/routes/fetch');

const realFetch = global.fetch;

/** Response stand-in whose body records cancellation. */
const mockResponse = (status, { headers = {}, text = '', statusText = '' } = {}) => {
  const bytes = new TextEncoder().encode(text);
  let cancelled = false;
  const body = new ReadableStream({
    start(controller) {
      if (bytes.length) controller.enqueue(bytes);
      controller.close();
    },
    cancel() { cancelled = true; },
  });
  return {
    status,
    statusText,
    ok: status >= 200 && status < 300,
    headers: new Headers(headers),
    body,
    bodyUsed: false,
    get cancelled() { return cancelled; },
  };
};

const neverResolves = () => new Promise(() => {});

afterEach(() => {
  jest.restoreAllMocks();
  global.fetch = realFetch;
});

describe('DNS resolution respects the deadline', () => {
  it('checkPublicUrl reports DNS_TIMEOUT (fail closed) when lookup hangs', async () => {
    jest.spyOn(dns, 'lookup').mockImplementation(neverResolves);
    const guard = await checkPublicUrl('http://slow.test/', { timeoutMs: 50 });
    expect(guard.valid).toBe(false);
    expect(guard.code).toBe('DNS_TIMEOUT');
  });

  it('checkPublicUrl stops at an aborted signal without resolving', async () => {
    const spy = jest.spyOn(dns, 'lookup');
    const guard = await checkPublicUrl('http://example.test/', { signal: AbortSignal.abort() });
    expect(guard).toMatchObject({ valid: false, code: 'ABORTED' });
    expect(spy).not.toHaveBeenCalled();
  });

  it('safeFetch rejects with the signal reason when DNS outlives the signal', async () => {
    jest.spyOn(dns, 'lookup').mockImplementation(neverResolves);
    global.fetch = jest.fn();
    const ac = new AbortController();
    setTimeout(() => ac.abort(), 30);
    await expect(safeFetch('http://slow.test/', { signal: ac.signal })).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('safeFetch caps a lookup even without a signal', async () => {
    jest.spyOn(dns, 'lookup').mockImplementation(neverResolves);
    global.fetch = jest.fn();
    await expect(safeFetch('http://slow.test/', {}, { lookupTimeoutMs: 30 })).rejects.toMatchObject({
      name: 'AbortError',
      code: 'DNS_TIMEOUT',
    });
  });

  it('removes its abort listener after a successful lookup', async () => {
    jest.spyOn(dns, 'lookup').mockResolvedValue([{ address: '8.8.8.8', family: 4 }]);
    const ac = new AbortController();
    const add = jest.spyOn(ac.signal, 'addEventListener');
    const remove = jest.spyOn(ac.signal, 'removeEventListener');
    expect((await checkPublicUrl('http://ok.test/', { signal: ac.signal })).valid).toBe(true);
    expect(remove).toHaveBeenCalledTimes(add.mock.calls.length);
  });
});

describe('safeFetch redirect hops', () => {
  it('cancels the body of a followed 3xx', async () => {
    const hop = mockResponse(302, { headers: { location: 'http://1.1.1.1/next' }, text: 'moved' });
    global.fetch = jest.fn()
      .mockResolvedValueOnce(hop)
      .mockResolvedValueOnce(mockResponse(200));
    await safeFetch('http://8.8.8.8/');
    expect(hop.cancelled).toBe(true);
  });

  it('cancels the 3xx body and still blocks a redirect to a private address', async () => {
    const hop = mockResponse(302, { headers: { location: 'http://169.254.169.254/' }, text: 'x' });
    global.fetch = jest.fn().mockResolvedValueOnce(hop);
    await expect(safeFetch('http://8.8.8.8/')).rejects.toMatchObject({ code: 'SSRF_BLOCKED' });
    expect(hop.cancelled).toBe(true);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });
});

describe('/api/fetch route', () => {
  let server;
  let base;

  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.use('/api/fetch', fetchRouter);
    server = await new Promise((resolve) => {
      const s = app.listen(0, '127.0.0.1', () => resolve(s));
    });
    base = `http://127.0.0.1:${server.address().port}/api/fetch`;
  });

  afterAll(() => new Promise((resolve) => server.close(resolve)));

  /** Call the route over loopback with node:http (global.fetch is mocked). */
  const call = (method, path, payload) => new Promise((resolve, reject) => {
    const data = payload ? JSON.stringify(payload) : null;
    const req = http.request(`${base}${path}`, {
      method,
      headers: data ? { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) } : {},
    }, (res) => {
      let text = '';
      res.on('data', (c) => { text += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* plain text */ }
        resolve({ status: res.statusCode, text, json });
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });

  it.each(['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'])('forwards the body for %s', async (method) => {
    global.fetch = jest.fn().mockResolvedValue(mockResponse(200, { text: 'ok' }));
    const res = await call('POST', '', { url: 'http://8.8.8.8/items', method, body: '{"ids":[1]}' });
    expect(res.status).toBe(200);
    expect(global.fetch.mock.calls[0][1]).toMatchObject({ method, body: '{"ids":[1]}' });
  });

  it.each(['GET', 'HEAD'])('never sends a body for %s', async (method) => {
    global.fetch = jest.fn().mockResolvedValue(mockResponse(200));
    await call('POST', '', { url: 'http://8.8.8.8/', method, body: 'ignored' });
    expect(global.fetch.mock.calls[0][1].body).toBeUndefined();
  });

  it('adds upstreamStatus to the error body while keeping the old status and message', async () => {
    global.fetch = jest.fn().mockResolvedValue(mockResponse(404, { statusText: 'Not Found' }));
    const res = await call('GET', `?url=${encodeURIComponent('http://8.8.8.8/robots.txt')}`);
    expect(res.status).toBe(400);
    expect(res.json).toMatchObject({
      success: false,
      message: 'Failed to fetch URL: 404 Not Found',
      upstreamStatus: 404,
      upstreamStatusText: 'Not Found',
    });
  });

  it('maps an upstream 5xx to 502 with upstreamStatus', async () => {
    global.fetch = jest.fn().mockResolvedValue(mockResponse(503, { statusText: 'Service Unavailable' }));
    const res = await call('GET', `?url=${encodeURIComponent('http://8.8.8.8/robots.txt')}`);
    expect(res.status).toBe(502);
    expect(res.json.upstreamStatus).toBe(503);
  });

  it('returns 413 for an oversized body that has no Content-Length', async () => {
    global.fetch = jest.fn().mockResolvedValue(mockResponse(200, { text: 'a'.repeat(1024 * 1024 + 1) }));
    const res = await call('GET', `?url=${encodeURIComponent('http://8.8.8.8/robots.txt')}`);
    expect(res.status).toBe(413);
  });

  it('returns 403 when a redirect points at a private address', async () => {
    global.fetch = jest.fn().mockResolvedValueOnce(
      mockResponse(302, { headers: { location: 'http://127.0.0.1/' } })
    );
    const res = await call('POST', '', { url: 'http://8.8.8.8/', method: 'DELETE', body: 'x' });
    expect(res.status).toBe(403);
    expect(global.fetch).toHaveBeenCalledTimes(1);
  });
});
