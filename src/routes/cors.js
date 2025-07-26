const express = require('express');
const https = require('https');
const http = require('http');
const { URL } = require('url');
const { basicRateLimit } = require('../middleware/rateLimit');

const router = express.Router();

// Domain validation helper
const isValidDomain = (hostname) => {
  // Block private/local networks
  const privateRanges = [
    /^localhost$/i,
    /^127\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^::1$/,
    /^fc00:/i,
    /^fe80:/i,
  ];
  
  return !privateRanges.some(range => range.test(hostname));
};

// Analyze CORS headers for security and compliance
const analyzeCorsHeaders = (headers, originUrl, targetUrl) => {
  const corsHeaders = {
    'access-control-allow-origin': headers['access-control-allow-origin'],
    'access-control-allow-methods': headers['access-control-allow-methods'],
    'access-control-allow-headers': headers['access-control-allow-headers'],
    'access-control-allow-credentials': headers['access-control-allow-credentials'],
    'access-control-max-age': headers['access-control-max-age'],
    'access-control-expose-headers': headers['access-control-expose-headers']
  };

  const issues = [];
  const recommendations = [];
  let score = 100;
  let crossOriginAllowed = false;

  // Check if CORS is enabled
  if (!corsHeaders['access-control-allow-origin']) {
    return {
      corsEnabled: false,
      crossOriginAllowed: false,
      headers: [
        { name: 'Access-Control-Allow-Origin', value: '', required: true, status: 'missing' },
        { name: 'Access-Control-Allow-Methods', value: '', required: false, status: 'missing' },
        { name: 'Access-Control-Allow-Headers', value: '', required: false, status: 'missing' },
        { name: 'Access-Control-Allow-Credentials', value: '', required: false, status: 'missing' },
        { name: 'Access-Control-Max-Age', value: '', required: false, status: 'missing' },
        { name: 'Access-Control-Expose-Headers', value: '', required: false, status: 'missing' }
      ],
      issues: [`Cross-origin request from ${originUrl} to ${targetUrl} would be BLOCKED - No CORS headers found`],
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

  // Check if the specific origin would be allowed
  if (allowOrigin === '*') {
    crossOriginAllowed = true;
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
    // Check if the specific origin matches
    try {
      const originUrlObj = new URL(originUrl);
      const originFormatted = `${originUrlObj.protocol}//${originUrlObj.host}`;
      
      if (allowOrigin === originFormatted) {
        crossOriginAllowed = true;
        issues.push(`✅ Cross-origin request ALLOWED: Origin ${originUrl} matches allowed origin`);
      } else {
        crossOriginAllowed = false;
        issues.push(`❌ Cross-origin request BLOCKED: Origin ${originUrl} does not match allowed origin ${allowOrigin}`);
        recommendations.push(`Add ${originFormatted} to Access-Control-Allow-Origin or use a wildcard (*) if appropriate`);
        score -= 25;
      }
      
      // Validate the allowed origin format
      new URL(allowOrigin);
    } catch {
      issues.push('Invalid Access-Control-Allow-Origin format');
      recommendations.push('Ensure Access-Control-Allow-Origin contains a valid URL');
      headerAnalysis[0].status = 'invalid';
      score -= 20;
    }
  } else {
    crossOriginAllowed = false;
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

  // Analyze Access-Control-Allow-Headers
  const allowHeaders = corsHeaders['access-control-allow-headers'];
  if (allowHeaders) {
    if (allowHeaders === '*') {
      issues.push('Security Warning: Wildcard (*) allows any headers in requests');
      recommendations.push('Specify exact header names instead of wildcard for better security');
      score -= 10;
    }
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
    if (!allowHeaders || !allowHeaders.includes('authorization')) {
      recommendations.push('Consider explicitly allowing Authorization header when credentials are enabled');
    }
  }

  // Ensure score doesn't go below 0
  score = Math.max(0, score);

  return {
    corsEnabled: true,
    crossOriginAllowed,
    headers: headerAnalysis,
    issues,
    recommendations,
    score
  };
};

// Make CORS preflight request to check headers
const checkCorsHeaders = (targetUrl, originUrl) => {
  return new Promise((resolve, reject) => {
    try {
      const urlObj = new URL(targetUrl);
      
      // Validate domain
      if (!isValidDomain(urlObj.hostname)) {
        reject(new Error('Domain not allowed for security reasons'));
        return;
      }
      
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: 'OPTIONS',
        headers: {
          'Origin': originUrl,
          'Access-Control-Request-Method': 'POST',
          'Access-Control-Request-Headers': 'Content-Type, Authorization',
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
router.post('/check', basicRateLimit, async (req, res) => {
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
    
    // Make CORS preflight request
    const corsResponse = await checkCorsHeaders(validatedTargetUrl.toString(), validatedOriginUrl.toString());
    
    // Analyze CORS headers
    const analysis = analyzeCorsHeaders(corsResponse.headers, validatedOriginUrl.toString(), validatedTargetUrl.toString());
    
    const result = {
      originUrl: validatedOriginUrl.toString(),
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