const express = require('express');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { basicRateLimit } = require('../middleware/rateLimit');
const { checkPublicHostname, pinnedLookup } = require('../utils/ssrfGuard');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');

const router = express.Router();

// Fetch HTTP headers from target URL
const fetchHeaders = (targetUrl) => {
  // eslint-disable-next-line no-async-promise-executor -- checkPublicHostname never rejects
  return new Promise(async (resolve, reject) => {
    try {
      const urlObj = new URL(targetUrl);

      // Screen the resolved host against private/reserved ranges
      const guard = await checkPublicHostname(urlObj.hostname);
      if (!guard.valid) {
        reject(new Error('Domain not allowed for security reasons'));
        return;
      }

      const startTime = Date.now();

      const options = {
        hostname: urlObj.hostname,
        // Dial the address checkPublicHostname already vetted. Connecting by
        // name would re-resolve and reopen the DNS-rebinding window the check
        // above exists to close. hostname stays set so SNI/Host/cert checks
        // still see the real name.
        lookup: pinnedLookup(guard.addresses[0]),

        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: 'HEAD',
        headers: {
          'User-Agent': 'ToolzyHub-HeaderChecker/1.0 (+https://toolsana.com)',
          'Accept': '*/*',
          'Connection': 'close'
        },
        timeout: 10000
      };

      const httpModule = urlObj.protocol === 'https:' ? https : http;

      const req = httpModule.request(options, (res) => {
        const responseTime = Date.now() - startTime;

        // Collect response headers
        const responseHeaders = {};

        // Convert header names to lowercase for consistent access
        Object.keys(res.headers).forEach(key => {
          responseHeaders[key.toLowerCase()] = res.headers[key];
        });

        resolve({
          statusCode: res.statusCode,
          statusText: res.statusMessage || 'OK',
          headers: responseHeaders,
          responseTime
        });

        // Consume response body to avoid hanging
        res.on('data', () => {});
        res.on('end', () => {});
      });

      req.on('error', (error) => {
        reject(error);
      });

      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });

      req.end();

    } catch (error) {
      reject(error);
    }
  });
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
      url: validatedUrl.toString(),
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

    if (error.message.includes('Domain not allowed')) {
      statusCode = 403;
      errorMessage = 'Domain not allowed for security reasons';
    } else if (error.message.includes('timeout')) {
      statusCode = 408;
      errorMessage = 'Request timeout - server took too long to respond';
    } else if (error.code === 'ENOTFOUND') {
      statusCode = 404;
      errorMessage = 'Domain not found';
    } else if (error.code === 'ECONNREFUSED') {
      statusCode = 502;
      errorMessage = 'Connection refused by server';
    } else if (error.code === 'ECONNRESET') {
      statusCode = 502;
      errorMessage = 'Connection reset by server';
    } else if (error.code === 'CERT_HAS_EXPIRED') {
      statusCode = 495;
      errorMessage = 'SSL certificate has expired';
    } else if (error.code === 'UNABLE_TO_VERIFY_LEAF_SIGNATURE') {
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