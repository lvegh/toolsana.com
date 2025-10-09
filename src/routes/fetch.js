const express = require('express');
const { URL } = require('url');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');

const router = express.Router();

/**
 * GET /api/fetch
 * Fetch external URL content (mainly for robots.txt and similar text files)
 */
router.get('/', basicRateLimit, async (req, res) => {
  try {
    const { url } = req.query;

    if (!url) {
      return sendError(res, 'URL parameter is required', 400);
    }

    // Validate and clean URL
    let targetUrl;
    try {
      targetUrl = new URL(url);
    } catch (error) {
      return sendError(res, 'Invalid URL format', 400);
    }

    // Security: Only allow HTTP/HTTPS protocols
    if (!['http:', 'https:'].includes(targetUrl.protocol)) {
      return sendError(res, 'Only HTTP and HTTPS URLs are allowed', 400);
    }

    // Security: Block private/local IPs and localhost
    const hostname = targetUrl.hostname.toLowerCase();
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '0.0.0.0' ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('10.') ||
      hostname.startsWith('172.16.') ||
      hostname.startsWith('172.17.') ||
      hostname.startsWith('172.18.') ||
      hostname.startsWith('172.19.') ||
      hostname.startsWith('172.2') ||
      hostname.startsWith('172.30.') ||
      hostname.startsWith('172.31.') ||
      hostname === '::1' ||
      hostname.startsWith('fc00') ||
      hostname.startsWith('fe80')
    ) {
      return sendError(res, 'Access to private/local networks is not allowed', 403);
    }

    // Fetch the content with timeout and size limits
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

    try {
      const response = await fetch(targetUrl.toString(), {
        method: 'GET',
        headers: {
          'User-Agent': 'ToolzyHub-Fetcher/1.0 (robots.txt fetcher)',
          'Accept': 'text/plain, text/html, application/octet-stream, */*',
          'Accept-Encoding': 'gzip, deflate',
        },
        signal: controller.signal,
        redirect: 'follow',
        // Note: fetch in Node.js doesn't have a direct size limit, but we'll check content-length
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        return sendError(res, `Failed to fetch URL: ${response.status} ${response.statusText}`, response.status >= 400 && response.status < 500 ? 400 : 502);
      }

      // Check content length to prevent abuse
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > 1024 * 1024) { // 1MB limit
        return sendError(res, 'Content too large (max 1MB)', 413);
      }

      // Get content type to ensure we're fetching text content
      const contentType = response.headers.get('content-type') || '';
      
      // Read the content
      let content;
      try {
        content = await response.text();
      } catch (error) {
        return sendError(res, 'Failed to read response content', 502);
      }

      // Additional size check after reading
      if (content.length > 1024 * 1024) { // 1MB limit
        return sendError(res, 'Content too large (max 1MB)', 413);
      }

      // Return the fetched content
      return res.set({
        'Content-Type': 'text/plain; charset=utf-8',
        'Cache-Control': 'public, max-age=300', // 5 minute cache
      }).send(content);

    } catch (fetchError) {
      clearTimeout(timeoutId);
      
      if (fetchError.name === 'AbortError') {
        return sendError(res, 'Request timeout', 408);
      }
      
      if (fetchError.code === 'ENOTFOUND') {
        return sendError(res, 'Domain not found', 404);
      }
      
      if (fetchError.code === 'ECONNREFUSED') {
        return sendError(res, 'Connection refused', 503);
      }
      
      return sendError(res, `Network error: ${fetchError.message}`, 502);
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
router.post('/', basicRateLimit, async (req, res) => {
  const startTime = Date.now();

  try {
    const { url, method = 'GET', headers = {}, body } = req.body;

    if (!url) {
      return sendError(res, 'URL is required in request body', 400);
    }

    // Validate and clean URL
    let targetUrl;
    try {
      targetUrl = new URL(url);
    } catch (error) {
      return sendError(res, 'Invalid URL format', 400);
    }

    // Security: Only allow HTTP/HTTPS protocols
    if (!['http:', 'https:'].includes(targetUrl.protocol)) {
      return sendError(res, 'Only HTTP and HTTPS URLs are allowed', 400);
    }

    // Security: Block private/local IPs and localhost
    const hostname = targetUrl.hostname.toLowerCase();
    if (
      hostname === 'localhost' ||
      hostname === '127.0.0.1' ||
      hostname === '0.0.0.0' ||
      hostname.startsWith('192.168.') ||
      hostname.startsWith('10.') ||
      hostname.startsWith('172.16.') ||
      hostname.startsWith('172.17.') ||
      hostname.startsWith('172.18.') ||
      hostname.startsWith('172.19.') ||
      hostname.startsWith('172.2') ||
      hostname.startsWith('172.30.') ||
      hostname.startsWith('172.31.') ||
      hostname === '::1' ||
      hostname.startsWith('fc00') ||
      hostname.startsWith('fe80')
    ) {
      return sendError(res, 'Access to private/local networks is not allowed', 403);
    }

    // Validate HTTP method
    const allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'];
    const upperMethod = method.toUpperCase();
    if (!allowedMethods.includes(upperMethod)) {
      return sendError(res, `HTTP method '${method}' is not allowed`, 400);
    }

    // Prepare fetch options
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000); // 10 second timeout

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

    try {
      // Make the request
      const fetchOptions = {
        method: upperMethod,
        headers: fetchHeaders,
        signal: controller.signal,
        redirect: 'follow',
      };

      // Add body for methods that support it
      if (['POST', 'PUT', 'PATCH'].includes(upperMethod) && body) {
        fetchOptions.body = body;
      }

      const response = await fetch(targetUrl.toString(), fetchOptions);

      clearTimeout(timeoutId);

      // Check content length to prevent abuse
      const contentLength = response.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > 1024 * 1024) { // 1MB limit
        return sendError(res, 'Response too large (max 1MB)', 413);
      }

      // Read response content
      let responseBody;
      try {
        responseBody = await response.text();
      } catch (error) {
        return sendError(res, 'Failed to read response content', 502);
      }

      // Additional size check after reading
      if (responseBody.length > 1024 * 1024) { // 1MB limit
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
        body: responseBody,
        time: responseTime,
      });

    } catch (fetchError) {
      clearTimeout(timeoutId);

      if (fetchError.name === 'AbortError') {
        return sendError(res, 'Request timeout (10s limit)', 408);
      }

      if (fetchError.code === 'ENOTFOUND') {
        return sendError(res, 'Domain not found', 404);
      }

      if (fetchError.code === 'ECONNREFUSED') {
        return sendError(res, 'Connection refused', 503);
      }

      return sendError(res, `Network error: ${fetchError.message}`, 502);
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