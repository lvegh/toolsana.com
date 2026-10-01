const express = require('express');
const { URL } = require('url');
const { basicRateLimit } = require('../middleware/rateLimit');
const { safeFetch, GENERIC_PRIVATE_ERROR } = require('../utils/ssrfGuard');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');

const router = express.Router();

const MAX_REDIRECTS = 5;
const FETCH_TIMEOUT_MS = 10000;

// Servers that refuse HEAD answer one of these; retry the same URL with GET.
const HEAD_REJECTED_STATUSES = new Set([405, 501]);

/** Headers -> plain object with lowercase names; set-cookie stays an array. */
const headersToObject = (headers) => {
  const out = {};
  headers.forEach((value, key) => {
    out[key.toLowerCase()] = value;
  });
  const cookies = typeof headers.getSetCookie === 'function' ? headers.getSetCookie() : [];
  if (cookies.length > 0) {
    out['set-cookie'] = cookies;
  }
  return out;
};

// Fetch HTTP headers from target URL, following redirects so the headers
// scored are the final page's, not a 301's. safeFetch re-screens every hop
// against private/reserved ranges and pins the screened address.
const fetchHeaders = async (targetUrl) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  const startTime = Date.now();

  const request = async (method) => {
    const result = await safeFetch(targetUrl, {
      method,
      headers: {
        'User-Agent': 'ToolzyHub-HeaderChecker/1.0 (+https://toolsana.com)',
        'Accept': '*/*'
      },
      signal: controller.signal
    }, { maxRedirects: MAX_REDIRECTS });
    // Only the headers are needed; don't download a GET body.
    if (result.response.body) {
      await result.response.body.cancel().catch(() => {});
    }
    return result;
  };

  try {
    let method = 'HEAD';
    let result = await request(method);
    if (HEAD_REJECTED_STATUSES.has(result.response.status)) {
      method = 'GET';
      result = await request(method);
    }

    const { response, redirectChain, finalUrl } = result;
    return {
      statusCode: response.status,
      statusText: response.statusText || '',
      headers: headersToObject(response.headers),
      responseTime: Date.now() - startTime,
      finalUrl,
      redirectChain,
      method
    };
  } finally {
    clearTimeout(timeoutId);
  }
};

// POST /api/http-headers/check
router.post('/check', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        success: false,
        message: 'URL is required'
      });
    }

    // Validate URL format
    let validatedUrl;
    try {
      validatedUrl = new URL(url);
      if (!['http:', 'https:'].includes(validatedUrl.protocol)) {
        throw new Error('Invalid URL protocol');
      }
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid URL format. Please use http:// or https://'
      });
    }

    // Fetch headers from target URL
    const response = await fetchHeaders(validatedUrl.toString());

    const result = {
      // Final URL after redirects: the response whose headers are reported.
      url: response.finalUrl,
      requestedUrl: validatedUrl.toString(),
      redirectChain: response.redirectChain,
      method: response.method,
      status: response.statusCode,
      statusText: response.statusText,
      headers: response.headers,
      responseTime: response.responseTime,
      timestamp: new Date().toISOString()
    };

    res.json({
      success: true,
      data: result
    });

  } catch (error) {
    console.error('HTTP header check failed:', error);

    let errorMessage = 'Failed to fetch headers';
    let statusCode = 500;

    // undici wraps network failures as TypeError('fetch failed', { cause }).
    const code = error.code || (error.cause && error.cause.code);

    if (error.code === 'SSRF_BLOCKED') {
      if (error.message === GENERIC_PRIVATE_ERROR) {
        statusCode = 403;
        errorMessage = 'Domain not allowed for security reasons';
      } else if (error.message === 'Host could not be resolved') {
        statusCode = 404;
        errorMessage = 'Domain not found';
      } else {
        statusCode = 400;
        errorMessage = error.message;
      }
    } else if (error.code === 'TOO_MANY_REDIRECTS') {
      statusCode = 502;
      errorMessage = `Too many redirects (more than ${MAX_REDIRECTS})`;
    } else if (error.name === 'AbortError' || error.name === 'TimeoutError' || error.message.includes('timeout')) {
      statusCode = 408;
      errorMessage = 'Request timeout - server took too long to respond';
    } else if (code === 'ENOTFOUND') {
      statusCode = 404;
      errorMessage = 'Domain not found';
    } else if (code === 'ECONNREFUSED') {
      statusCode = 502;
      errorMessage = 'Connection refused by server';
    } else if (code === 'ECONNRESET') {
      statusCode = 502;
      errorMessage = 'Connection reset by server';
    } else if (code === 'CERT_HAS_EXPIRED') {
      statusCode = 495;
      errorMessage = 'SSL certificate has expired';
    } else if (code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE' || code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
               code === 'SELF_SIGNED_CERT_IN_CHAIN' || code === 'ERR_TLS_CERT_ALTNAME_INVALID') {
      statusCode = 495;
      errorMessage = 'SSL certificate verification failed';
    }

    res.status(statusCode).json({
      success: false,
      message: errorMessage,
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

module.exports = router;