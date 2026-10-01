const express = require('express');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { checkPublicUrl, safeFetch, discardBody } = require('../utils/ssrfGuard');
const { logOutbound } = require('../utils/outboundLog');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');

const router = express.Router();

const FETCH_TIMEOUT_MS = 10000; // one deadline for DNS, connect, headers and body
const MAX_CONTENT_BYTES = 1024 * 1024; // 1MB

/** True when a guard result failed because the deadline ran out during DNS. */
function isGuardTimeout(guard) {
  return guard.code === 'ABORTED' || guard.code === 'DNS_TIMEOUT';
}

/**
 * Error for an upstream site that answered with a non-2xx status. Keeps the
 * historical status mapping and message (clients parse "Failed to fetch URL:
 * <code>") and adds the upstream code as structured fields.
 */
function sendUpstreamError(res, response) {
  return res.status(response.status >= 400 && response.status < 500 ? 400 : 502).json({
    success: false,
    message: `Failed to fetch URL: ${response.status} ${response.statusText}`,
    timestamp: new Date().toISOString(),
    upstreamStatus: response.status,
    upstreamStatusText: response.statusText,
  });
}

/**
 * Read a response body as UTF-8 text, stopping (and cancelling the stream) as
 * soon as it exceeds `maxBytes`. A missing or lying Content-Length must not let
 * an upstream make us buffer an unbounded body.
 * Returns { text } or { tooLarge: true }.
 */
async function readTextCapped(response, maxBytes) {
  if (!response.body) return { text: '' };
  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8');
  let received = 0;
  let text = '';
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      try { await reader.cancel(); } catch { /* stream already closed */ }
      return { tooLarge: true };
    }
    text += decoder.decode(value, { stream: true });
  }
  text += decoder.decode();
  return { text };
}

/**
 * GET /api/fetch
 * Fetch external URL content (mainly for robots.txt and similar text files)
 */
router.get('/', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { url } = req.query;

    if (!url) {
      return sendError(res, 'URL parameter is required', 400);
    }

    // One deadline for the whole operation, DNS included: a host whose
    // resolver never answers must not outlive the advertised 10 s timeout.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
      // Validate URL + screen the resolved host against private/reserved ranges
      // (protocol enforcement, DNS resolution, and CIDR checks live in ssrfGuard).
      const guard = await checkPublicUrl(url, { signal: controller.signal });
      if (!guard.valid) {
        if (isGuardTimeout(guard)) {
          return sendError(res, 'Request timeout', 408);
        }
        const status = guard.error === 'Access to private/local networks is not allowed' ? 403 : 400;
        return sendError(res, guard.error, status);
      }
      const targetUrl = guard.url;

      logOutbound({ tool: 'api-fetch', targetUrl: targetUrl.toString(), method: 'GET', req });

      // safeFetch re-screens every redirect hop — a public host must not be able
      // to 302 us onto a private address.
      const { response } = await safeFetch(targetUrl.toString(), {
        method: 'GET',
        headers: {
          'User-Agent': 'ToolzyHub-Fetcher/1.0 (robots.txt fetcher)',
          'Accept': 'text/plain, text/html, application/octet-stream, */*',
          'Accept-Encoding': 'gzip, deflate',
        },
        signal: controller.signal,
      });

      if (!response.ok) {
        await discardBody(response);
        return sendUpstreamError(res, response);
      }

      // Check content length to prevent abuse
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > MAX_CONTENT_BYTES) {
        await discardBody(response);
        return sendError(res, 'Content too large (max 1MB)', 413);
      }

      // Read the content (streamed, capped at 1MB even without Content-Length)
      let read;
      try {
        read = await readTextCapped(response, MAX_CONTENT_BYTES);
      } catch (error) {
        if (controller.signal.aborted) {
          return sendError(res, 'Request timeout', 408);
        }
        return sendError(res, 'Failed to read response content', 502);
      }
      if (read.tooLarge) {
        return sendError(res, 'Content too large (max 1MB)', 413);
      }

      // Return the fetched content
      return res.set({
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'public, max-age=300', // 5 minute cache
      }).send(read.text);

    } catch (fetchError) {
      if (fetchError.code === 'SSRF_BLOCKED') {
        return sendError(res, fetchError.message, 403);
      }

      if (fetchError.code === 'TOO_MANY_REDIRECTS') {
        return sendError(res, fetchError.message, 502);
      }

      if (fetchError.name === 'AbortError' || controller.signal.aborted) {
        return sendError(res, 'Request timeout', 408);
      }

      if (fetchError.code === 'ENOTFOUND') {
        return sendError(res, 'Domain not found', 404);
      }

      if (fetchError.code === 'ECONNREFUSED') {
        return sendError(res, 'Connection refused', 503);
      }

      return sendError(res, `Network error: ${fetchError.message}`, 502);
    } finally {
      clearTimeout(timeoutId);
    }

  } catch (error) {
    console.error('Fetch endpoint error:', error);
    return sendError(res, 'Internal server error', 500);
  }
});

/**
 * GET /api/fetch/info
 * Get fetch service information
 */
/**
 * POST /api/fetch
 * Proxy HTTP requests to external URLs (for API testing tools)
 */
router.post('/', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  const startTime = Date.now();

  try {
    const { url, method = 'GET', headers = {}, body } = req.body;

    if (!url) {
      return sendError(res, 'URL is required in request body', 400);
    }

    // Validate HTTP method
    const allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
    const upperMethod = method.toUpperCase();
    if (!allowedMethods.includes(upperMethod)) {
      return sendError(res, `HTTP method '${method}' is not allowed`, 400);
    }

    // One deadline for the whole operation, DNS included.
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

    try {
      // Validate URL + screen the resolved host against private/reserved ranges.
      const guard = await checkPublicUrl(url, { signal: controller.signal });
      if (!guard.valid) {
        if (isGuardTimeout(guard)) {
          return sendError(res, 'Request timeout (10s limit)', 408);
        }
        const status = guard.error === 'Access to private/local networks is not allowed' ? 403 : 400;
        return sendError(res, guard.error, status);
      }
      const targetUrl = guard.url;

      // This is the relay path: arbitrary method, headers and body to a
      // caller-chosen host. Record where it went before we send it.
      logOutbound({
        tool: 'api-fetch',
        targetUrl: targetUrl.toString(),
        method: upperMethod,
        req,
        extra: { hasBody: Boolean(body), customHeaderCount: Object.keys(headers || {}).length },
      });

      // Sanitize and prepare headers
      const fetchHeaders = {
        'User-Agent': 'ToolzyHub-API-Tester/1.0',
      };

      // Add custom headers (with security filtering)
      const dangerousHeaders = ['host', 'connection', 'content-length', 'transfer-encoding'];
      if (headers && typeof headers === 'object') {
        Object.entries(headers).forEach(([key, value]) => {
          const lowerKey = key.toLowerCase();
          if (!dangerousHeaders.includes(lowerKey)) {
            fetchHeaders[key] = String(value);
          }
        });
      }

      // Make the request. safeFetch re-screens every redirect hop so a public
      // host cannot bounce us onto a private address.
      const fetchOptions = {
        method: upperMethod,
        headers: fetchHeaders,
        signal: controller.signal,
      };

      // Forward the body for every method that may carry one. Only GET and
      // HEAD are forbidden a body by fetch(); DELETE and OPTIONS bodies are
      // legal and some APIs (bulk delete, search-by-body) rely on them.
      if (!['GET', 'HEAD'].includes(upperMethod) && body) {
        fetchOptions.body = body;
      }

      const { response } = await safeFetch(targetUrl.toString(), fetchOptions);

      // Check content length to prevent abuse
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > MAX_CONTENT_BYTES) {
        await discardBody(response);
        return sendError(res, 'Response too large (max 1MB)', 413);
      }

      // Read response content (streamed, capped at 1MB even without Content-Length)
      let read;
      try {
        read = await readTextCapped(response, MAX_CONTENT_BYTES);
      } catch (error) {
        if (controller.signal.aborted) {
          return sendError(res, 'Request timeout (10s limit)', 408);
        }
        return sendError(res, 'Failed to read response content', 502);
      }
      if (read.tooLarge) {
        return sendError(res, 'Response too large (max 1MB)', 413);
      }

      const endTime = Date.now();
      const responseTime = endTime - startTime;

      // Collect response headers
      const responseHeaders = {};
      response.headers.forEach((value, key) => {
        responseHeaders[key] = value;
      });

      // Return the response in the format expected by API tester
      return res.json({
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
        body: read.text,
        time: responseTime,
      });

    } catch (fetchError) {
      if (fetchError.code === 'SSRF_BLOCKED') {
        return sendError(res, fetchError.message, 403);
      }

      if (fetchError.code === 'TOO_MANY_REDIRECTS') {
        return sendError(res, fetchError.message, 502);
      }

      if (fetchError.name === 'AbortError' || controller.signal.aborted) {
        return sendError(res, 'Request timeout (10s limit)', 408);
      }

      if (fetchError.code === 'ENOTFOUND') {
        return sendError(res, 'Domain not found', 404);
      }

      if (fetchError.code === 'ECONNREFUSED') {
        return sendError(res, 'Connection refused', 503);
      }

      return sendError(res, `Network error: ${fetchError.message}`, 502);
    } finally {
      clearTimeout(timeoutId);
    }

  } catch (error) {
    console.error('Fetch proxy endpoint error:', error);
    return sendError(res, 'Internal server error', 500);
  }
});

router.get('/info', basicRateLimit, (req, res) => {
  const info = {
    service: 'External URL Fetcher',
    version: '1.0.0',
    description: 'Fetch content from external URLs with security restrictions',
    features: [
      'Robots.txt file fetching',
      'Text content retrieval',
      'HTTP proxy for API testing',
      'Security filtering for private networks',
      'Content size limits (1MB max)',
      'Request timeout protection (10s)',
      'Rate limiting'
    ],
    limitations: [
      'Only HTTP/HTTPS protocols allowed',
      'Private/local network access blocked',
      'Maximum content size: 1MB',
      'Request timeout: 10 seconds',
      'Rate limited to prevent abuse'
    ],
    usage: {
      get_endpoint: 'GET /api/fetch?url=<URL>',
      post_endpoint: 'POST /api/fetch',
      post_body: {
        url: 'string (required)',
        method: 'string (optional, default: GET)',
        headers: 'object (optional)',
        body: 'string (optional)'
      },
      example_get: '/api/fetch?url=https://example.com/robots.txt',
      example_post: {
        url: 'https://api.example.com/endpoint',
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{"key":"value"}'
      }
    }
  };

  sendSuccess(res, 'Fetch service information', info);
});

module.exports = router;