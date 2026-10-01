const express = require('express');
const { URL } = require('url');
const { basicRateLimit } = require('../middleware/rateLimit');
const { safeFetch, GENERIC_PRIVATE_ERROR } = require('../utils/ssrfGuard');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');

const router = express.Router();

const MAX_REDIRECTS = 5;
const MAX_HTML_BYTES = 1024 * 1024; // 1MB
const FETCH_TIMEOUT_MS = 10000;

// Decode the HTML character references that can appear in an attribute value.
// A canonical href like `/p?a=1&amp;b=2` means `/p?a=1&b=2`.
const NAMED_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: '\u00a0' };
const decodeHtmlAttribute = (value) => value.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (match, ref) => {
  if (ref[0] === '#') {
    const code = ref[1] === 'x' || ref[1] === 'X' ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10);
    if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return match;
    try {
      return String.fromCodePoint(code);
    } catch {
      return match;
    }
  }
  const key = ref.toLowerCase();
  return Object.prototype.hasOwnProperty.call(NAMED_ENTITIES, key) ? NAMED_ENTITIES[key] : match;
});

// Extract canonical URL from HTML
const extractCanonicalUrl = (html, pageUrl) => {
  try {
    // Look for canonical link tag (case insensitive)
    const canonicalRegex = /<link[^>]*rel\s*=\s*["']canonical["'][^>]*href\s*=\s*["']([^"']+)["'][^>]*>/i;
    const altCanonicalRegex = /<link[^>]*href\s*=\s*["']([^"']+)["'][^>]*rel\s*=\s*["']canonical["'][^>]*>/i;
    
    const match = html.match(canonicalRegex) || html.match(altCanonicalRegex);
    
    if (!match) {
      return null;
    }
    
    const href = decodeHtmlAttribute(match[1].trim());

    // Relative hrefs resolve like any other link: against <base href> when the
    // page has one, otherwise against the page's own (final, post-redirect)
    // URL. "page.html" on /blog/post/ is /blog/post/page.html, not /page.html.
    let base = pageUrl;
    const baseMatch = html.match(/<base[^>]*href\s*=\s*["']([^"']+)["'][^>]*>/i);
    if (baseMatch) {
      try {
        base = new URL(decodeHtmlAttribute(baseMatch[1].trim()), pageUrl).toString();
      } catch {
        base = pageUrl;
      }
    }

    return new URL(href, base).toString();
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

// Fetch the page, following redirects the way a crawler does. safeFetch
// re-screens every hop against private/reserved ranges and pins the screened
// address into the connection. Returns { html, finalUrl, redirectChain, status }.
const fetchCanonicalUrl = async (url) => {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const { response, redirectChain, finalUrl } = await safeFetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'ToolzyHub-CanonicalChecker/1.0 (+https://toolzyhub.app)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'DNT': '1'
      },
      signal: controller.signal
    }, { maxRedirects: MAX_REDIRECTS });

    if (response.status < 200 || response.status >= 300) {
      if (response.body) await response.body.cancel().catch(() => {});
      const err = new Error(`HTTP ${response.status}: ${response.statusText || ''}`.trim());
      err.httpStatus = response.status;
      throw err;
    }

    // Read at most MAX_HTML_BYTES; the canonical tag lives in <head>.
    const chunks = [];
    let total = 0;
    if (response.body) {
      const reader = response.body.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > MAX_HTML_BYTES) {
          await reader.cancel().catch(() => {});
          throw new Error('Response too large');
        }
        chunks.push(Buffer.from(value));
      }
    }

    return {
      html: Buffer.concat(chunks).toString('utf8'),
      finalUrl,
      redirectChain,
      status: response.status
    };
  } finally {
    clearTimeout(timeoutId);
  }
};

// POST /api/canonical/check
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
        throw new Error('Invalid protocol');
      }
    } catch (error) {
      return res.status(400).json({
        success: false,
        message: 'Invalid URL format'
      });
    }
    
    // Fetch webpage HTML (following redirects)
    const page = await fetchCanonicalUrl(validatedUrl.toString());
    
    // Extract canonical URL, resolved against the page it was found on
    const canonicalUrl = extractCanonicalUrl(page.html, page.finalUrl);
    
    // Analyze against the final URL: that is the page whose canonical was read.
    const analysis = analyzeCanonical(canonicalUrl, page.finalUrl);

    if (page.redirectChain.length > 0) {
      analysis.issues.push(
        `The URL you entered redirects (${page.redirectChain.length} hop${page.redirectChain.length === 1 ? '' : 's'}); the canonical tag was read from the final page ${page.finalUrl}`
      );
    }
    
    const result = {
      ...analysis,
      requestedUrl: validatedUrl.toString(),
      currentUrl: page.finalUrl,
      redirectChain: page.redirectChain,
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
    
    const causeCode = error.cause && error.cause.code;

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
    } else if (error.name === 'AbortError' || error.name === 'TimeoutError') {
      statusCode = 408;
      errorMessage = 'Request timeout - server took too long to respond';
    } else if (causeCode === 'ENOTFOUND') {
      statusCode = 404;
      errorMessage = 'Domain not found';
    } else if (causeCode === 'ECONNREFUSED') {
      statusCode = 502;
      errorMessage = 'Connection refused by server';
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
// exported for tests
module.exports.extractCanonicalUrl = extractCanonicalUrl;
module.exports.decodeHtmlAttribute = decodeHtmlAttribute;