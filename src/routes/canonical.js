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

// Extract canonical URL from HTML
const extractCanonicalUrl = (html, baseUrl) => {
  try {
    // Look for canonical link tag (case insensitive)
    const canonicalRegex = /<link[^>]*rel\s*=\s*["']canonical["'][^>]*href\s*=\s*["']([^"']+)["'][^>]*>/i;
    const altCanonicalRegex = /<link[^>]*href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["']canonical["'][^>]*>/i;
    
    const match = html.match(canonicalRegex) || html.match(altCanonicalRegex);
    
    if (!match) {
      return null;
    }
    
    let canonicalUrl = match[1];
    
    // Handle relative URLs
    if (canonicalUrl.startsWith('//')) {
      const baseUrlObj = new URL(baseUrl);
      canonicalUrl = `${baseUrlObj.protocol}${canonicalUrl}`;
    } else if (canonicalUrl.startsWith('/')) {
      const baseUrlObj = new URL(baseUrl);
      canonicalUrl = `${baseUrlObj.protocol}//${baseUrlObj.host}${canonicalUrl}`;
    } else if (!canonicalUrl.startsWith('http')) {
      const baseUrlObj = new URL(baseUrl);
      canonicalUrl = `${baseUrlObj.protocol}//${baseUrlObj.host}/${canonicalUrl}`;
    }
    
    return canonicalUrl;
  } catch (error) {
    console.error('Error extracting canonical URL:', error);
    return null;
  }
};

// Analyze canonical URL for issues
const analyzeCanonical = (canonicalUrl, originalUrl) => {
  const issues = [];
  const recommendations = [];
  
  if (!canonicalUrl) {
    return {
      hasCanonical: false,
      canonicalUrl: null,
      isValid: false,
      issues: ['No canonical tag found on the page'],
      recommendations: ['Add a canonical tag to specify the preferred URL version']
    };
  }
  
  try {
    const canonicalUrlObj = new URL(canonicalUrl);
    const originalUrlObj = new URL(originalUrl);
    
    // Check for protocol mismatch
    if (originalUrlObj.protocol === 'https:' && canonicalUrlObj.protocol === 'http:') {
      issues.push('Canonical URL uses HTTP instead of HTTPS');
      recommendations.push('Update canonical URL to use HTTPS protocol');
    }
    
    // Check for query parameters in canonical URL
    if (canonicalUrlObj.search) {
      issues.push('Canonical URL contains query parameters');
      recommendations.push('Remove tracking parameters from canonical URLs');
    }
    
    // Check for fragment identifiers
    if (canonicalUrlObj.hash) {
      issues.push('Canonical URL contains fragment identifier (#)');
      recommendations.push('Remove fragment identifiers from canonical URLs');
    }
    
    // Check for trailing slash consistency
    const canonicalPath = canonicalUrlObj.pathname;
    const originalPath = originalUrlObj.pathname;
    
    if (canonicalPath.endsWith('/') !== originalPath.endsWith('/') && 
        canonicalPath !== '/' && originalPath !== '/') {
      issues.push('Trailing slash inconsistency between canonical and current URL');
      recommendations.push('Ensure consistent trailing slash usage');
    }
    
    // Check if canonical points to a different domain
    if (canonicalUrlObj.hostname !== originalUrlObj.hostname) {
      issues.push('Canonical URL points to a different domain');
      recommendations.push('Verify this cross-domain canonical is intentional');
    }
    
    return {
      hasCanonical: true,
      canonicalUrl,
      isValid: issues.length === 0,
      issues,
      recommendations
    };
    
  } catch (error) {
    return {
      hasCanonical: true,
      canonicalUrl,
      isValid: false,
      issues: ['Invalid canonical URL format'],
      recommendations: ['Ensure canonical URL is properly formatted']
    };
  }
};

// Fetch webpage and extract canonical URL
const fetchCanonicalUrl = (url) => {
  return new Promise((resolve, reject) => {
    try {
      const urlObj = new URL(url);
      
      // Validate domain
      if (!isValidDomain(urlObj.hostname)) {
        reject(new Error('Domain not allowed for security reasons'));
        return;
      }
      
      const options = {
        hostname: urlObj.hostname,
        port: urlObj.port || (urlObj.protocol === 'https:' ? 443 : 80),
        path: urlObj.pathname + urlObj.search,
        method: 'GET',
        headers: {
          'User-Agent': 'ToolzyHub-CanonicalChecker/1.0 (+https://toolzyhub.app)',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'identity',
          'DNT': '1',
          'Connection': 'close'
        },
        timeout: 10000
      };
      
      const httpModule = urlObj.protocol === 'https:' ? https : http;
      
      const req = httpModule.request(options, (res) => {
        let data = '';
        let contentLength = 0;
        const maxSize = 1024 * 1024; // 1MB limit
        
        res.on('data', (chunk) => {
          contentLength += chunk.length;
          if (contentLength > maxSize) {
            req.destroy();
            reject(new Error('Response too large'));
            return;
          }
          data += chunk;
        });
        
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(data);
          } else if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            // Handle redirects (limit to prevent infinite loops)
            reject(new Error(`Redirect to ${res.headers.location}`));
          } else {
            reject(new Error(`HTTP ${res.statusCode}: ${res.statusMessage}`));
          }
        });
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

// POST /api/canonical/check
router.post('/check', basicRateLimit, async (req, res) => {
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
        throw new Error('Invalid protocol');
      }
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid URL format'
      });
    }
    
    // Fetch webpage HTML
    const html = await fetchCanonicalUrl(validatedUrl.toString());
    
    // Extract canonical URL
    const canonicalUrl = extractCanonicalUrl(html, validatedUrl.toString());
    
    // Analyze canonical URL
    const analysis = analyzeCanonical(canonicalUrl, validatedUrl.toString());
    
    const result = {
      ...analysis,
      currentUrl: validatedUrl.toString(),
      timestamp: new Date().toISOString()
    };
    
    res.json({
      success: true,
      data: result
    });
    
  } catch (error) {
    console.error('Canonical URL check failed:', error);
    
    let errorMessage = 'Failed to check canonical URL';
    let statusCode = 500;
    
    if (error.message.includes('Domain not allowed')) {
      statusCode = 403;
      errorMessage = 'Domain not allowed for security reasons';
    } else if (error.message.includes('timeout')) {
      statusCode = 408;
      errorMessage = 'Request timeout - server took too long to respond';
    } else if (error.message.includes('Response too large')) {
      statusCode = 413;
      errorMessage = 'Response too large';
    } else if (error.message.includes('HTTP')) {
      statusCode = 502;
      errorMessage = `Server error: ${error.message}`;
    } else if (error.code === 'ENOTFOUND') {
      statusCode = 404;
      errorMessage = 'Domain not found';
    } else if (error.code === 'ECONNREFUSED') {
      statusCode = 502;
      errorMessage = 'Connection refused by server';
    }
    
    res.status(statusCode).json({
      success: false,
      message: errorMessage
    });
  }
});

module.exports = router;