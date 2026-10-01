const express = require('express');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { basicRateLimit } = require('../middleware/rateLimit');
const { checkPublicHostname, pinnedLookup } = require('../utils/ssrfGuard');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');

const router = express.Router();

// The request the checker simulates. The preflight asks the target whether a
// page on the origin may send this; the verdict answers exactly that question.
const PREFLIGHT_METHOD = 'POST';
const PREFLIGHT_REQUEST_HEADERS = ['content-type', 'authorization'];

// Fetch standard: CORS-safelisted methods never need Access-Control-Allow-Methods.
const SAFELISTED_METHODS = new Set(['GET', 'HEAD', 'POST']);

const splitList = (value) => String(value || '')
  .split(',')
  .map((item) => item.trim())
  .filter(Boolean);

/**
 * Evaluate the preflight the way a browser does (Fetch standard, CORS-preflight
 * fetch): a 2xx status, an Access-Control-Allow-Origin matching the serialized
 * origin (or `*`), the method allowed, and every requested header allowed.
 * `*` in Allow-Methods / Allow-Headers counts only for non-credentialed
 * requests, and `*` never covers Authorization.
 */
const evaluatePreflight = (statusCode, headers, origin) => {
  const allowOrigin = headers['access-control-allow-origin'];
  const statusOk = statusCode >= 200 && statusCode < 300;
  const originAllowed = allowOrigin === '*' || allowOrigin === origin;

  const allowedMethods = splitList(headers['access-control-allow-methods']).map((m) => m.toUpperCase());
  const methodAllowed = SAFELISTED_METHODS.has(PREFLIGHT_METHOD) ||
    allowedMethods.includes(PREFLIGHT_METHOD) ||
    allowedMethods.includes('*');

  const allowedHeaders = splitList(headers['access-control-allow-headers']).map((h) => h.toLowerCase());
  const headerWildcard = allowedHeaders.includes('*');
  const missingHeaders = PREFLIGHT_REQUEST_HEADERS.filter((h) =>
    !allowedHeaders.includes(h) && !(headerWildcard && h !== 'authorization'));

  return {
    status: statusCode,
    statusOk,
    method: PREFLIGHT_METHOD,
    requestHeaders: PREFLIGHT_REQUEST_HEADERS,
    originAllowed,
    methodAllowed,
    headersAllowed: missingHeaders.length === 0,
    missingHeaders,
    allowed: statusOk && originAllowed && methodAllowed && missingHeaders.length === 0,
  };
};

// Analyze CORS headers for security and compliance
const analyzeCorsHeaders = (headers, origin, targetUrl, statusCode) => {
  const corsHeaders = {
    'access-control-allow-origin': headers['access-control-allow-origin'],
    'access-control-allow-methods': headers['access-control-allow-methods'],
    'access-control-allow-headers': headers['access-control-allow-headers'],
    'access-control-allow-credentials': headers['access-control-allow-credentials'],
    'access-control-max-age': headers['access-control-max-age'],
    'access-control-expose-headers': headers['access-control-expose-headers']
  };

  const preflight = evaluatePreflight(statusCode, headers, origin);
  const issues = [];
  const recommendations = [];
  let score = 100;

  // Check if CORS is enabled
  if (!corsHeaders['access-control-allow-origin']) {
    const noCorsIssues = [`Cross-origin request from ${origin} to ${targetUrl} would be BLOCKED - No CORS headers found`];
    if (!preflight.statusOk) {
      noCorsIssues.push(`Preflight (OPTIONS) returned HTTP ${statusCode}; browsers require a 2xx response`);
    }
    return {
      corsEnabled: false,
      crossOriginAllowed: false,
      preflight,
      headers: [
        { name: 'Access-Control-Allow-Origin', value: '', required: true, status: 'missing' },
        { name: 'Access-Control-Allow-Methods', value: '', required: false, status: 'missing' },
        { name: 'Access-Control-Allow-Headers', value: '', required: false, status: 'missing' },
        { name: 'Access-Control-Allow-Credentials', value: '', required: false, status: 'missing' },
        { name: 'Access-Control-Max-Age', value: '', required: false, status: 'missing' },
        { name: 'Access-Control-Expose-Headers', value: '', required: false, status: 'missing' }
      ],
      issues: noCorsIssues,
      recommendations: ['Add Access-Control-Allow-Origin header to enable CORS'],
      score: 0
    };
  }

  // Prepare header analysis
  const headerAnalysis = [
    {
      name: 'Access-Control-Allow-Origin',
      value: corsHeaders['access-control-allow-origin'] || '',
      required: true,
      status: corsHeaders['access-control-allow-origin'] ? 'present' : 'missing'
    },
    {
      name: 'Access-Control-Allow-Methods',
      value: corsHeaders['access-control-allow-methods'] || '',
      required: false,
      status: corsHeaders['access-control-allow-methods'] ? 'present' : 'missing'
    },
    {
      name: 'Access-Control-Allow-Headers',
      value: corsHeaders['access-control-allow-headers'] || '',
      required: false,
      status: corsHeaders['access-control-allow-headers'] ? 'present' : 'missing'
    },
    {
      name: 'Access-Control-Allow-Credentials',
      value: corsHeaders['access-control-allow-credentials'] || '',
      required: false,
      status: corsHeaders['access-control-allow-credentials'] ? 'present' : 'missing'
    },
    {
      name: 'Access-Control-Max-Age',
      value: corsHeaders['access-control-max-age'] || '',
      required: false,
      status: corsHeaders['access-control-max-age'] ? 'present' : 'missing'
    },
    {
      name: 'Access-Control-Expose-Headers',
      value: corsHeaders['access-control-expose-headers'] || '',
      required: false,
      status: corsHeaders['access-control-expose-headers'] ? 'present' : 'missing'
    }
  ];

  // Analyze Access-Control-Allow-Origin against the specific origin
  const allowOrigin = corsHeaders['access-control-allow-origin'];
  const allowCredentials = corsHeaders['access-control-allow-credentials'];

  // Preflight status: anything but 2xx fails the preflight in every browser.
  if (!preflight.statusOk) {
    issues.push(`❌ Preflight (OPTIONS) returned HTTP ${statusCode}; browsers require a 2xx response, so the request would be BLOCKED`);
    recommendations.push('Make the server answer OPTIONS requests for this URL with a 2xx status (usually 204) and the CORS headers');
    score -= 30;
  }

  // Check if the specific origin would be allowed
  if (allowOrigin === '*') {
    if (allowCredentials === 'true') {
      issues.push('Security Risk: Cannot use wildcard (*) for Access-Control-Allow-Origin when credentials are allowed');
      recommendations.push('Specify exact origins instead of using wildcard when allowing credentials');
      headerAnalysis[3].status = 'invalid';
      score -= 30;
    } else {
      issues.push('Security Warning: Wildcard (*) allows any origin to access your resources');
      recommendations.push('Consider specifying exact origins instead of wildcard for better security');
      score -= 15;
    }
  } else if (allowOrigin && allowOrigin !== 'null') {
    // Browsers compare the header byte-for-byte with the serialized origin
    // (scheme://host[:port], no trailing slash).
    if (preflight.originAllowed) {
      issues.push(`✅ Origin ${origin} matches Access-Control-Allow-Origin`);
    } else {
      issues.push(`❌ Cross-origin request BLOCKED: Origin ${origin} does not match allowed origin ${allowOrigin}`);
      recommendations.push(`Add ${origin} to Access-Control-Allow-Origin or use a wildcard (*) if appropriate`);
      score -= 25;
    }

    try {
      // Validate the allowed origin format
      new URL(allowOrigin);
    } catch {
      issues.push('Invalid Access-Control-Allow-Origin format');
      recommendations.push('Ensure Access-Control-Allow-Origin contains a valid URL');
      headerAnalysis[0].status = 'invalid';
      score -= 20;
    }
  } else {
    issues.push(`❌ Cross-origin request BLOCKED: No valid origin specified`);
    score -= 30;
  }

  // Analyze Access-Control-Allow-Methods
  const allowMethods = corsHeaders['access-control-allow-methods'];
  if (!allowMethods) {
    issues.push('Access-Control-Allow-Methods header is missing');
    recommendations.push('Add Access-Control-Allow-Methods to specify allowed HTTP methods');
    score -= 10;
  } else {
    const methods = allowMethods.toLowerCase().split(',').map(m => m.trim());
    const dangerousMethods = ['trace', 'connect'];
    const foundDangerous = methods.filter(m => dangerousMethods.includes(m));
    
    if (foundDangerous.length > 0) {
      issues.push(`Potentially dangerous HTTP methods allowed: ${foundDangerous.join(', ')}`);
      recommendations.push('Avoid allowing TRACE and CONNECT methods unless specifically needed');
      score -= 10;
    }
  }
  if (!preflight.methodAllowed) {
    issues.push(`❌ Access-Control-Allow-Methods does not allow ${preflight.method}`);
    recommendations.push(`Add ${preflight.method} to Access-Control-Allow-Methods`);
    score -= 20;
  }

  // Analyze Access-Control-Allow-Headers
  const allowHeaders = corsHeaders['access-control-allow-headers'];
  if (allowHeaders) {
    if (allowHeaders.trim() === '*') {
      issues.push('Security Warning: Wildcard (*) allows any headers in requests');
      recommendations.push('Specify exact header names instead of wildcard for better security');
      score -= 10;
    }
  }
  if (!preflight.headersAllowed) {
    issues.push(`❌ Access-Control-Allow-Headers does not allow the requested header(s): ${preflight.missingHeaders.join(', ')}`);
    recommendations.push(`List ${preflight.missingHeaders.join(', ')} in Access-Control-Allow-Headers (a * wildcard never covers Authorization)`);
    score -= 20;
  }

  // Analyze Access-Control-Max-Age
  const maxAge = corsHeaders['access-control-max-age'];
  if (!maxAge) {
    recommendations.push('Add Access-Control-Max-Age to cache preflight requests and improve performance');
    score -= 5;
  } else {
    const maxAgeValue = parseInt(maxAge);
    if (isNaN(maxAgeValue) || maxAgeValue < 0) {
      issues.push('Invalid Access-Control-Max-Age value');
      recommendations.push('Access-Control-Max-Age should be a positive integer (seconds)');
      headerAnalysis[4].status = 'invalid';
      score -= 10;
    } else if (maxAgeValue > 86400) {
      issues.push('Access-Control-Max-Age is very high (>24 hours)');
      recommendations.push('Consider using a shorter cache time for preflight requests');
      score -= 5;
    }
  }

  // Check for credentials configuration
  if (allowCredentials === 'true') {
    if (!allowHeaders || !allowHeaders.toLowerCase().includes('authorization')) {
      recommendations.push('Consider explicitly allowing Authorization header when credentials are enabled');
    }
  }

  if (preflight.allowed) {
    issues.unshift(`✅ Cross-origin ${preflight.method} request with ${preflight.requestHeaders.join(', ')} headers ALLOWED`);
  }

  // Ensure score doesn't go below 0
  score = Math.max(0, score);

  return {
    corsEnabled: true,
    crossOriginAllowed: preflight.allowed,
    preflight,
    headers: headerAnalysis,
    issues,
    recommendations,
    score
  };
};

// Make CORS preflight request to check headers
const checkCorsHeaders = (targetUrl, originUrl) => {
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

      const options = {
        hostname: urlObj.hostname,
        // Dial the address checkPublicHostname already vetted. Connecting by
        // name would re-resolve and reopen the DNS-rebinding window the check
        // above exists to close. hostname stays set so SNI/Host/cert checks
        // still see the real name.
        lookup: pinnedLookup(guard.addresses[0]),

        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: 'OPTIONS',
        headers: {
          'Origin': originUrl,
          'Access-Control-Request-Method': PREFLIGHT_METHOD,
          'Access-Control-Request-Headers': PREFLIGHT_REQUEST_HEADERS.join(', '),
          'User-Agent': 'ToolzyHub-CorsChecker/1.0 (+https://toolzyhub.app)',
          'Accept': '*/*',
          'Connection': 'close'
        },
        timeout: 10000
      };
      
      const httpModule = urlObj.protocol === 'https:' ? https : http;
      
      const req = httpModule.request(options, (res) => {
        // Collect response headers (CORS headers are in the response)
        const responseHeaders = {};
        
        // Convert header names to lowercase for consistent access
        Object.keys(res.headers).forEach(key => {
          responseHeaders[key.toLowerCase()] = res.headers[key];
        });
        
        resolve({
          statusCode: res.statusCode,
          headers: responseHeaders
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

// POST /api/cors/check
router.post('/check', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { originUrl, targetUrl } = req.body;
    
    if (!originUrl || !targetUrl) {
      return res.status(400).json({
        success: false,
        message: 'Both originUrl and targetUrl are required'
      });
    }
    
    // Validate URL formats
    let validatedOriginUrl, validatedTargetUrl;
    try {
      validatedOriginUrl = new URL(originUrl);
      if (!['http:', 'https:'].includes(validatedOriginUrl.protocol)) {
        throw new Error('Invalid origin URL protocol');
      }
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid origin URL format'
      });
    }
    
    try {
      validatedTargetUrl = new URL(targetUrl);
      if (!['http:', 'https:'].includes(validatedTargetUrl.protocol)) {
        throw new Error('Invalid target URL protocol');
      }
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid target URL format'
      });
    }
    
    // The Origin header is the serialized origin: scheme://host[:port], with
    // no path and no trailing slash. URL.toString() adds a trailing "/", which
    // correctly configured servers reject, so use URL.origin.
    const origin = validatedOriginUrl.origin;

    // Make CORS preflight request
    const corsResponse = await checkCorsHeaders(validatedTargetUrl.toString(), origin);
    
    // Analyze CORS headers
    const analysis = analyzeCorsHeaders(corsResponse.headers, origin, validatedTargetUrl.toString(), corsResponse.statusCode);
    
    const result = {
      originUrl: origin,
      targetUrl: validatedTargetUrl.toString(),
      statusCode: corsResponse.statusCode,
      ...analysis,
      timestamp: new Date().toISOString()
    };
    
    res.json({
      success: true,
      data: result
    });
    
  } catch (error) {
    console.error('CORS check failed:', error);
    
    let errorMessage = 'Failed to check CORS headers';
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
    }
    
    res.status(statusCode).json({
      success: false,
      message: errorMessage
    });
  }
});

module.exports = router;
// exported for tests
module.exports.analyzeCorsHeaders = analyzeCorsHeaders;
module.exports.evaluatePreflight = evaluatePreflight;