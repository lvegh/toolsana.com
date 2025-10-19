const express = require('express');
const { URL } = require('url');
const cheerio = require('cheerio');
const crypto = require('crypto');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { redisUtils } = require('../config/redis');

// Dynamic import for ESM module p-limit
let pLimit = null;
const getPLimit = async () => {
  if (!pLimit) {
    const module = await import('p-limit');
    pLimit = module.default;
  }
  return pLimit;
};

const router = express.Router();

// Configuration
const FREE_TIER_CONFIG = {
  maxDepth: 999999, // Effectively unlimited depth - stop when maxPages is reached
  maxPages: 2000,
  maxConcurrency: 10,
  timeout: 10000, // 10 seconds per request
  maxContentSize: 5 * 1024 * 1024, // 5MB limit for HTML pages
  jobTTL: 3600, // Job expires after 1 hour
};

/**
 * Validate URL and check security
 */
function validateUrl(urlString) {
  try {
    // Normalize URL - add https:// if no protocol provided
    let normalizedUrl = urlString.trim();
    if (!normalizedUrl.match(/^https?:\/\//i)) {
      normalizedUrl = `https://${normalizedUrl}`;
    }

    const url = new URL(normalizedUrl);

    // Only allow HTTP/HTTPS
    if (!['http:', 'https:'].includes(url.protocol)) {
      return { valid: false, error: 'Only HTTP and HTTPS URLs are allowed' };
    }

    // Block private/local IPs
    const hostname = url.hostname.toLowerCase();
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
      return { valid: false, error: 'Access to private/local networks is not allowed' };
    }

    return { valid: true, url, normalizedUrl };
  } catch (error) {
    return { valid: false, error: 'Invalid URL format' };
  }
}

/**
 * Resolve relative URL to absolute
 */
function resolveUrl(baseUrl, relativeUrl) {
  try {
    return new URL(relativeUrl, baseUrl).toString();
  } catch {
    return null;
  }
}

/**
 * Check if URL is same domain
 */
function isSameDomain(url1, url2) {
  try {
    const domain1 = new URL(url1).hostname;
    const domain2 = new URL(url2).hostname;
    return domain1 === domain2;
  } catch {
    return false;
  }
}

/**
 * Fetch HTML content with timeout
 */
async function fetchHtml(url, timeout = FREE_TIER_CONFIG.timeout) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'User-Agent': 'ToolzyHub-LinkChecker/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      },
      signal: controller.signal,
      redirect: 'follow',
    });

    clearTimeout(timeoutId);

    // Check content type
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('text/html') && !contentType.includes('application/xhtml')) {
      return { success: false, error: 'Not an HTML page' };
    }

    // Check content size
    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength) > FREE_TIER_CONFIG.maxContentSize) {
      return { success: false, error: 'Content too large' };
    }

    const html = await response.text();

    if (html.length > FREE_TIER_CONFIG.maxContentSize) {
      return { success: false, error: 'Content too large' };
    }

    return { success: true, html, status: response.status };
  } catch (error) {
    clearTimeout(timeoutId);

    if (error.name === 'AbortError') {
      return { success: false, error: 'Request timeout' };
    }
    return { success: false, error: error.message };
  }
}

/**
 * Detect bot protection mechanisms on a page
 * Returns detection results for Cloudflare, reCAPTCHA, JS-heavy pages, etc.
 */
function detectBotProtection(html) {
  const detections = {
    cloudflare: false,
    recaptcha: false,
    jsRequired: false,
    emptyBody: false,
    details: []
  };

  // Count different HTML elements for diagnostics
  const linkCount = (html.match(/<a[\s>]/gi) || []).length;
  const scriptTags = (html.match(/<script/gi) || []).length;
  const divCount = (html.match(/<div[\s>]/gi) || []).length;

  // Check for empty or minimal body content
  const bodyMatch = html.match(/<body[^>]*>(.*?)<\/body>/is);
  const bodyContent = bodyMatch ? bodyMatch[1].trim() : '';
  const contentWithoutScripts = html.replace(/<script[^>]*>.*?<\/script>/gis, '');

  if (!bodyContent || bodyContent.length < 100) {
    detections.emptyBody = true;
    detections.details.push(`Page has minimal or no body content (${bodyContent.length} chars)`);
  }

  // Add diagnostic information
  detections.details.push(`Found ${linkCount} <a> tags, ${scriptTags} <script> tags, ${divCount} <div> tags`);

  // Cloudflare protection patterns
  const cloudflarePatterns = [
    /Checking your browser/i,
    /cf-browser-verification/i,
    /cf-challenge/i,
    /Ray ID:/i,
    /__cf_chl_/i,
    /challenge-platform/i,
    /cf-wrapper/i,
    /cf_clearance/i
  ];

  for (const pattern of cloudflarePatterns) {
    if (pattern.test(html)) {
      detections.cloudflare = true;
      detections.details.push(`Cloudflare protection detected (matched: ${pattern})`);
      break;
    }
  }

  // reCAPTCHA detection
  const recaptchaPatterns = [
    /google\.com\/recaptcha/i,
    /g-recaptcha/i,
    /grecaptcha/i
  ];

  for (const pattern of recaptchaPatterns) {
    if (pattern.test(html)) {
      detections.recaptcha = true;
      detections.details.push('reCAPTCHA detected on page');
      break;
    }
  }

  // JavaScript-heavy page detection (common for SPAs)
  // If there are many scripts but little actual content
  if (scriptTags > 5 && contentWithoutScripts.length < 500) {
    detections.jsRequired = true;
    detections.details.push(`Page appears to be JavaScript-rendered (${scriptTags} scripts, ${contentWithoutScripts.length} chars without scripts)`);
  }

  // Check for common SPA frameworks
  const spaIndicators = [
    { pattern: /react/i, name: 'React' },
    { pattern: /vue\.js/i, name: 'Vue.js' },
    { pattern: /angular/i, name: 'Angular' },
    { pattern: /next\.js/i, name: 'Next.js' },
    { pattern: /gatsby/i, name: 'Gatsby' }
  ];

  for (const indicator of spaIndicators) {
    if (indicator.pattern.test(html) && linkCount < 5) {
      detections.jsRequired = true;
      detections.details.push(`${indicator.name} framework detected with minimal static HTML`);
      break;
    }
  }

  // Check if any protection was detected
  const hasProtection = detections.cloudflare || detections.recaptcha || detections.jsRequired || detections.emptyBody;

  return {
    detected: hasProtection,
    ...detections
  };
}

/**
 * Extract links from HTML
 */
function extractLinks(html, baseUrl, options) {
  const $ = cheerio.load(html);
  const links = new Set();

  // Helper to add link if valid
  const addLink = (url, type) => {
    if (url) {
      links.add(JSON.stringify({ url, type, source: baseUrl }));
    }
  };

  // Extract hyperlinks (always)
  $('a[href]').each((_, element) => {
    const href = $(element).attr('href');
    if (href && !href.startsWith('javascript:') && !href.startsWith('mailto:') && !href.startsWith('tel:')) {
      const absoluteUrl = resolveUrl(baseUrl, href.split('#')[0]); // Remove fragment
      addLink(absoluteUrl, 'hyperlink');
    }
  });

  // === HIGH PRIORITY LINKS (Always checked) ===

  // Favicon (always check - critical for branding)
  $('link[rel="icon"], link[rel="shortcut icon"], link[rel="apple-touch-icon"]').each((_, element) => {
    const href = $(element).attr('href');
    if (href) {
      const absoluteUrl = resolveUrl(baseUrl, href);
      addLink(absoluteUrl, 'favicon');
    }
  });

  // Canonical URL (always check - critical for SEO)
  $('link[rel="canonical"]').each((_, element) => {
    const href = $(element).attr('href');
    if (href) {
      const absoluteUrl = resolveUrl(baseUrl, href);
      addLink(absoluteUrl, 'canonical');
    }
  });

  // Iframes (always check - embedded content)
  $('iframe[src]').each((_, element) => {
    const src = $(element).attr('src');
    if (src && !src.startsWith('data:') && !src.startsWith('javascript:')) {
      const absoluteUrl = resolveUrl(baseUrl, src);
      addLink(absoluteUrl, 'iframe');
    }
  });

  // RSS/Atom feeds (always check - important for content)
  $('link[rel="alternate"][type*="rss"], link[rel="alternate"][type*="atom"]').each((_, element) => {
    const href = $(element).attr('href');
    if (href) {
      const absoluteUrl = resolveUrl(baseUrl, href);
      addLink(absoluteUrl, 'feed');
    }
  });

  // PWA Manifest (always check)
  $('link[rel="manifest"]').each((_, element) => {
    const href = $(element).attr('href');
    if (href) {
      const absoluteUrl = resolveUrl(baseUrl, href);
      addLink(absoluteUrl, 'manifest');
    }
  });

  // === IMAGES & MEDIA (Optional - with checkImages) ===
  if (options.checkImages) {
    // Regular images
    $('img[src]').each((_, element) => {
      const src = $(element).attr('src');
      if (src && !src.startsWith('data:')) {
        const absoluteUrl = resolveUrl(baseUrl, src);
        addLink(absoluteUrl, 'image');
      }
    });

    // Srcset images (responsive images)
    $('img[srcset]').each((_, element) => {
      const srcset = $(element).attr('srcset');
      if (srcset) {
        // Parse srcset: "url1 1x, url2 2x" or "url1 300w, url2 600w"
        const sources = srcset.split(',').map(s => s.trim().split(/\s+/)[0]);
        sources.forEach(src => {
          if (src && !src.startsWith('data:')) {
            const absoluteUrl = resolveUrl(baseUrl, src);
            addLink(absoluteUrl, 'image-srcset');
          }
        });
      }
    });

    // Video sources
    $('video[src]').each((_, element) => {
      const src = $(element).attr('src');
      if (src && !src.startsWith('data:')) {
        const absoluteUrl = resolveUrl(baseUrl, src);
        addLink(absoluteUrl, 'video');
      }
    });

    $('video source[src]').each((_, element) => {
      const src = $(element).attr('src');
      if (src && !src.startsWith('data:')) {
        const absoluteUrl = resolveUrl(baseUrl, src);
        addLink(absoluteUrl, 'video');
      }
    });

    // Audio sources
    $('audio[src]').each((_, element) => {
      const src = $(element).attr('src');
      if (src && !src.startsWith('data:')) {
        const absoluteUrl = resolveUrl(baseUrl, src);
        addLink(absoluteUrl, 'audio');
      }
    });

    $('audio source[src]').each((_, element) => {
      const src = $(element).attr('src');
      if (src && !src.startsWith('data:')) {
        const absoluteUrl = resolveUrl(baseUrl, src);
        addLink(absoluteUrl, 'audio');
      }
    });
  }

  // === CSS/JS & PERFORMANCE (Optional - with checkCssJs) ===
  if (options.checkCssJs) {
    // CSS files
    $('link[rel="stylesheet"][href]').each((_, element) => {
      const href = $(element).attr('href');
      if (href) {
        const absoluteUrl = resolveUrl(baseUrl, href);
        addLink(absoluteUrl, 'stylesheet');
      }
    });

    // JavaScript files
    $('script[src]').each((_, element) => {
      const src = $(element).attr('src');
      if (src) {
        const absoluteUrl = resolveUrl(baseUrl, src);
        addLink(absoluteUrl, 'script');
      }
    });

    // Preload resources
    $('link[rel="preload"][href]').each((_, element) => {
      const href = $(element).attr('href');
      if (href) {
        const absoluteUrl = resolveUrl(baseUrl, href);
        addLink(absoluteUrl, 'preload');
      }
    });

    // Prefetch resources
    $('link[rel="prefetch"][href]').each((_, element) => {
      const href = $(element).attr('href');
      if (href) {
        const absoluteUrl = resolveUrl(baseUrl, href);
        addLink(absoluteUrl, 'prefetch');
      }
    });

    // DNS prefetch
    $('link[rel="dns-prefetch"][href]').each((_, element) => {
      const href = $(element).attr('href');
      if (href) {
        // dns-prefetch can be just a domain
        const absoluteUrl = resolveUrl(baseUrl, href);
        addLink(absoluteUrl, 'dns-prefetch');
      }
    });

    // Preconnect
    $('link[rel="preconnect"][href]').each((_, element) => {
      const href = $(element).attr('href');
      if (href) {
        const absoluteUrl = resolveUrl(baseUrl, href);
        addLink(absoluteUrl, 'preconnect');
      }
    });
  }

  // Convert Set back to array of objects
  return Array.from(links).map(linkStr => JSON.parse(linkStr));
}

/**
 * Check a single link status
 * Uses browser-like headers and falls back to GET if HEAD fails
 */
async function checkLink(linkObj, timeout = FREE_TIER_CONFIG.timeout) {
  const startTime = Date.now();

  // Browser-like headers to avoid bot detection
  const browserHeaders = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1',
    'Cache-Control': 'max-age=0',
    'Sec-Fetch-Dest': 'document',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-Site': 'none',
  };

  try {
    // Try HEAD first (faster for most sites)
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    let response = await fetch(linkObj.url, {
      method: 'HEAD',
      headers: browserHeaders,
      signal: controller.signal,
      redirect: 'manual', // Don't follow redirects, track them
    });

    clearTimeout(timeoutId);

    // If HEAD fails with 400/403/405, retry with GET (for social media sites)
    if ([400, 403, 405].includes(response.status)) {
      const getController = new AbortController();
      const getTimeoutId = setTimeout(() => getController.abort(), timeout);

      response = await fetch(linkObj.url, {
        method: 'GET',
        headers: browserHeaders,
        signal: getController.signal,
        redirect: 'manual',
      });

      clearTimeout(getTimeoutId);
    }

    // Track redirect chain
    const redirectChain = [];
    let currentUrl = linkObj.url;
    let redirectCount = 0;
    const maxRedirects = 5;

    while ([301, 302, 303, 307, 308].includes(response.status) && redirectCount < maxRedirects) {
      const location = response.headers.get('location');
      if (!location) break;

      redirectChain.push({
        from: currentUrl,
        to: resolveUrl(currentUrl, location),
        status: response.status,
      });

      currentUrl = resolveUrl(currentUrl, location);
      redirectCount++;

      // Follow the redirect
      const redirectController = new AbortController();
      const redirectTimeoutId = setTimeout(() => redirectController.abort(), timeout);

      let redirectResponse = await fetch(currentUrl, {
        method: 'HEAD',
        headers: browserHeaders,
        signal: redirectController.signal,
        redirect: 'manual',
      });

      // Retry with GET if HEAD fails on redirect too
      if ([400, 403, 405].includes(redirectResponse.status)) {
        const getRedirectController = new AbortController();
        const getRedirectTimeoutId = setTimeout(() => getRedirectController.abort(), timeout);

        redirectResponse = await fetch(currentUrl, {
          method: 'GET',
          headers: browserHeaders,
          signal: getRedirectController.signal,
          redirect: 'manual',
        });

        clearTimeout(getRedirectTimeoutId);
      }

      response = redirectResponse;
      clearTimeout(redirectTimeoutId);
    }

    const responseTime = Date.now() - startTime;

    return {
      ...linkObj,
      status: response.status,
      statusText: response.statusText,
      responseTime,
      redirectChain: redirectChain.length > 0 ? redirectChain : null,
      finalUrl: currentUrl !== linkObj.url ? currentUrl : null,
      checked: true,
    };
  } catch (error) {
    if (error.name === 'AbortError') {
      return {
        ...linkObj,
        status: 408,
        statusText: 'Request Timeout',
        responseTime: Date.now() - startTime,
        redirectChain: null,
        checked: true,
        error: 'Timeout',
      };
    }

    return {
      ...linkObj,
      status: 0,
      statusText: error.message,
      responseTime: Date.now() - startTime,
      redirectChain: null,
      checked: true,
      error: error.message,
    };
  }
}

/**
 * Update job progress in Redis
 */
async function updateJobProgress(jobId, updates) {
  try {
    const jobData = await redisUtils.get(`linkchecker:${jobId}`);
    if (!jobData) return false;

    Object.assign(jobData, updates);
    jobData.updatedAt = Date.now();

    await redisUtils.setex(`linkchecker:${jobId}`, FREE_TIER_CONFIG.jobTTL, jobData);
    return true;
  } catch (error) {
    console.error('Error updating job progress:', error);
    return false;
  }
}

/**
 * Background job processor for link checking
 */
async function processLinkCheckerJob(jobId, normalizedUrl, mode, checkOptions) {
  try {
    // Update status to processing
    await updateJobProgress(jobId, { status: 'processing' });

    if (mode === 'single') {
      // Single page mode
      const htmlResult = await fetchHtml(normalizedUrl);
      if (!htmlResult.success) {
        await updateJobProgress(jobId, {
          status: 'failed',
          error: `Failed to fetch URL: ${htmlResult.error}`,
          completedAt: Date.now(),
        });
        return;
      }

      // Extract links
      let allLinks = extractLinks(htmlResult.html, normalizedUrl, checkOptions);

      // ALWAYS run bot protection detection and include in response for debugging
      const protection = detectBotProtection(htmlResult.html);
      let protectionWarning = null;

      // Show warning if no links found OR protection detected
      if (allLinks.length === 0 || protection.detected) {
        // Add diagnostic info
        const diagnostics = [];
        if (allLinks.length === 0) {
          diagnostics.push(`No links extracted from HTML (${htmlResult.html.length} bytes)`);
        }

        protectionWarning = {
          detected: protection.detected || allLinks.length === 0,
          type: [],
          message: allLinks.length === 0
            ? 'No links found on this page. This may indicate bot protection or JavaScript-rendered content.'
            : 'This page may be protected or require JavaScript to render content.',
          details: [...protection.details, ...diagnostics]
        };

        // Add specific protection types
        if (protection.cloudflare) protectionWarning.type.push('Cloudflare');
        if (protection.recaptcha) protectionWarning.type.push('reCAPTCHA');
        if (protection.jsRequired) protectionWarning.type.push('JavaScript-Required');
        if (protection.emptyBody) protectionWarning.type.push('Empty-Content');
        if (allLinks.length === 0 && !protection.detected) {
          protectionWarning.type.push('No-Links-Found');
        }
      }

      // Filter external only if requested
      if (checkOptions.externalOnly) {
        allLinks = allLinks.filter(link => !isSameDomain(normalizedUrl, link.url));
      }

      // Remove duplicates
      const uniqueLinks = Array.from(
        new Map(allLinks.map(link => [link.url, link])).values()
      );

      // Check all links with concurrency limit
      const limitFn = await getPLimit();
      const limit = limitFn(FREE_TIER_CONFIG.maxConcurrency);

      const checkedLinks = [];
      let checkedCount = 0;

      // Check links and update progress incrementally
      const checkPromises = uniqueLinks.map(link =>
        limit(async () => {
          const result = await checkLink(link);
          checkedLinks.push(result);
          checkedCount++;

          // Update progress every 5 links
          if (checkedCount % 5 === 0) {
            const stats = calculateStats(checkedLinks);
            await updateJobProgress(jobId, {
              progress: {
                checked: checkedCount,
                crawledPages: 1,
              },
              results: checkedLinks,
              stats,
            });
          }

          return result;
        })
      );

      await Promise.all(checkPromises);

      // Final update
      const stats = calculateStats(checkedLinks);
      const finalUpdate = {
        status: 'completed',
        progress: {
          checked: checkedLinks.length,
          crawledPages: 1,
        },
        results: checkedLinks,
        stats,
        crawledPages: [normalizedUrl],
        completedAt: Date.now(),
      };

      // Include protection warning if detected
      if (protectionWarning) {
        finalUpdate.protectionWarning = protectionWarning;
      }

      await updateJobProgress(jobId, finalUpdate);

    } else if (mode === 'crawl') {
      // Website crawl mode
      const visited = new Set();
      const toVisit = [{ url: normalizedUrl, depth: 0 }];
      const crawledPages = [];
      const allFoundLinks = new Map();
      const protectedPages = []; // Track pages with bot protection

      // Breadth-first crawl
      while (toVisit.length > 0 && crawledPages.length < FREE_TIER_CONFIG.maxPages) {
        const { url: currentUrl, depth } = toVisit.shift();

        // Skip if already visited
        if (visited.has(currentUrl)) continue;
        visited.add(currentUrl);

        // Fetch the page
        const htmlResult = await fetchHtml(currentUrl);
        if (!htmlResult.success) {
          // Still count as crawled but couldn't fetch
          crawledPages.push({ url: currentUrl, success: false, error: htmlResult.error });
          continue;
        }

        crawledPages.push({ url: currentUrl, success: true });

        // Extract links
        const pageLinks = extractLinks(htmlResult.html, currentUrl, checkOptions);

        // Detect bot protection on this page
        const protection = detectBotProtection(htmlResult.html);
        if (pageLinks.length === 0 || protection.detected) {
          protectedPages.push({
            url: currentUrl,
            linkCount: pageLinks.length,
            protection: protection
          });
        }

        // Add to all found links
        pageLinks.forEach(link => {
          if (!allFoundLinks.has(link.url)) {
            allFoundLinks.set(link.url, link);
          }
        });

        // Add same-domain links to crawl queue (if not too deep)
        if (depth < FREE_TIER_CONFIG.maxDepth) {
          pageLinks.forEach(link => {
            if (link.type === 'hyperlink' && isSameDomain(normalizedUrl, link.url) && !visited.has(link.url)) {
              toVisit.push({ url: link.url, depth: depth + 1 });
            }
          });
        }

        // Update progress after each page crawled
        await updateJobProgress(jobId, {
          progress: {
            crawledPages: crawledPages.length,
            checked: 0, // Will be updated during link checking
          },
        });
      }

      // Get unique links
      let uniqueLinks = Array.from(allFoundLinks.values());

      // Create protection warning if any pages had issues
      let protectionWarning = null;
      if (protectedPages.length > 0) {
        const allDetails = [];
        const protectionTypes = new Set();

        protectedPages.forEach(page => {
          allDetails.push(`Page: ${page.url} (${page.linkCount} links found)`);
          page.protection.details.forEach(d => allDetails.push(`  - ${d}`));

          if (page.protection.cloudflare) protectionTypes.add('Cloudflare');
          if (page.protection.recaptcha) protectionTypes.add('reCAPTCHA');
          if (page.protection.jsRequired) protectionTypes.add('JavaScript-Required');
          if (page.protection.emptyBody) protectionTypes.add('Empty-Content');
          if (page.linkCount === 0) protectionTypes.add('No-Links-Found');
        });

        protectionWarning = {
          detected: true,
          type: Array.from(protectionTypes),
          message: `${protectedPages.length} page(s) showed signs of bot protection or JavaScript rendering during crawl.`,
          details: allDetails,
          affectedPages: protectedPages.length
        };
      }

      // Filter external only if requested
      if (checkOptions.externalOnly) {
        uniqueLinks = uniqueLinks.filter(link => !isSameDomain(normalizedUrl, link.url));
      }

      // Check all links with concurrency limit and update progress
      const limitFn = await getPLimit();
      const limit = limitFn(FREE_TIER_CONFIG.maxConcurrency);

      const checkedLinks = [];
      let checkedCount = 0;

      const checkPromises = uniqueLinks.map(link =>
        limit(async () => {
          const result = await checkLink(link);
          checkedLinks.push(result);
          checkedCount++;

          // Update progress every 10 links
          if (checkedCount % 10 === 0) {
            const stats = calculateStats(checkedLinks);
            await updateJobProgress(jobId, {
              progress: {
                checked: checkedCount,
                crawledPages: crawledPages.length,
              },
              results: checkedLinks,
              stats,
            });
          }

          return result;
        })
      );

      await Promise.all(checkPromises);

      // Final update
      const stats = calculateStats(checkedLinks);
      const finalUpdate = {
        status: 'completed',
        progress: {
          checked: checkedLinks.length,
          crawledPages: crawledPages.length,
        },
        results: checkedLinks,
        stats,
        crawledPages: crawledPages.map(p => p.url),
        completedAt: Date.now(),
      };

      // Include protection warning if detected
      if (protectionWarning) {
        finalUpdate.protectionWarning = protectionWarning;
      }

      await updateJobProgress(jobId, finalUpdate);
    }

  } catch (error) {
    console.error('Link checker job error:', error);
    await updateJobProgress(jobId, {
      status: 'failed',
      error: error.message,
      completedAt: Date.now(),
    });
  }
}

/**
 * Calculate statistics from checked links
 */
function calculateStats(checkedLinks) {
  return {
    total: checkedLinks.length,
    working: checkedLinks.filter(l => l.status >= 200 && l.status < 300).length,
    broken: checkedLinks.filter(l => l.status >= 400 || l.status === 0).length,
    redirects: checkedLinks.filter(l => l.status >= 300 && l.status < 400).length,
  };
}

/**
 * POST /api/link-checker/start
 * Start a link checking job
 * No rate limiting - protected by worker token authentication
 */
router.post('/start', async (req, res) => {
  try {
    const { url, mode = 'single', options = {} } = req.body;

    if (!url) {
      return sendError(res, 'URL is required', 400);
    }

    // Validate URL
    const validation = validateUrl(url);
    if (!validation.valid) {
      return sendError(res, validation.error, 400);
    }

    // Use normalized URL
    const normalizedUrl = validation.normalizedUrl;

    // Set default options
    const checkOptions = {
      checkImages: options.checkImages || false,
      checkCssJs: options.checkCssJs || false,
      externalOnly: options.externalOnly || false,
    };

    // Validate mode
    if (!['single', 'crawl'].includes(mode)) {
      return sendError(res, 'Invalid mode. Use "single" or "crawl"', 400);
    }

    // Generate job ID
    const jobId = `job_${Date.now()}_${crypto.randomBytes(8).toString('hex')}`;

    // Create job in Redis
    const jobData = {
      jobId,
      status: 'queued',
      url: normalizedUrl,
      mode,
      options: checkOptions,
      progress: {
        checked: 0,
        crawledPages: 0,
      },
      results: [],
      createdAt: Date.now(),
      updatedAt: Date.now(),
    };

    await redisUtils.setex(`linkchecker:${jobId}`, FREE_TIER_CONFIG.jobTTL, jobData);

    // Start background processing (fire and forget)
    processLinkCheckerJob(jobId, normalizedUrl, mode, checkOptions);

    // Return immediately
    return res.json({
      success: true,
      jobId,
      status: 'queued',
      message: 'Job created successfully. Poll /api/link-checker/job/{jobId} for progress.',
    });

  } catch (error) {
    console.error('Link checker start error:', error);
    return sendError(res, 'Internal server error', 500);
  }
});

/**
 * GET /api/link-checker/job/:jobId
 * Get job status and results
 * No rate limiting - protected by worker token authentication
 */
router.get('/job/:jobId', async (req, res) => {
  try {
    const { jobId } = req.params;

    // Get job from Redis
    const jobData = await redisUtils.get(`linkchecker:${jobId}`);

    if (!jobData) {
      return res.status(404).json({
        success: false,
        error: 'Job not found or expired',
      });
    }

    // Return job data
    return res.json({
      success: true,
      ...jobData,
    });

  } catch (error) {
    console.error('Link checker job status error:', error);
    return sendError(res, 'Internal server error', 500);
  }
});

/**
 * GET /api/link-checker/info
 * Get service information
 * No rate limiting - protected by worker token authentication
 */
router.get('/info', (req, res) => {
  const info = {
    service: 'Broken Link Checker',
    version: '2.0.0',
    description: 'Check broken links on web pages with single page or full website crawling',
    features: [
      'Single page link checking',
      'Full website crawling (breadth-first)',
      'Comprehensive link type detection (16 types)',
      'Always checked: hyperlinks, favicons, canonical URLs, iframes, RSS/Atom feeds, PWA manifests',
      'Optional media: images, srcset images, video sources, audio sources (with checkImages)',
      'Optional resources: stylesheets, scripts, preload, prefetch, dns-prefetch, preconnect (with checkCssJs)',
      'External links only option',
      'Redirect chain tracking',
      'Response time metrics',
      'HTTP status code detection',
      'Concurrent link checking',
      'Background job processing with real-time progress',
    ],
    limits: {
      free_tier: {
        max_depth: FREE_TIER_CONFIG.maxDepth,
        max_pages: FREE_TIER_CONFIG.maxPages,
        max_concurrency: FREE_TIER_CONFIG.maxConcurrency,
        timeout: `${FREE_TIER_CONFIG.timeout / 1000}s`,
        max_content_size: `${FREE_TIER_CONFIG.maxContentSize / 1024 / 1024}MB`,
        job_ttl: `${FREE_TIER_CONFIG.jobTTL / 60}min`,
      },
    },
    usage: {
      start_job: {
        endpoint: 'POST /api/link-checker/start',
        body: {
          url: 'string (required) - URL to check',
          mode: 'string (optional) - "single" or "crawl" (default: "single")',
          options: {
            checkImages: 'boolean (optional) - Check image links',
            checkCssJs: 'boolean (optional) - Check CSS and JS files',
            externalOnly: 'boolean (optional) - Check only external links',
          },
        },
        response: {
          jobId: 'string - Job identifier for polling',
          status: 'string - "queued"',
        },
      },
      poll_job: {
        endpoint: 'GET /api/link-checker/job/:jobId',
        response: {
          status: 'string - "queued", "processing", "completed", or "failed"',
          progress: {
            checked: 'number - Links checked so far',
            crawledPages: 'number - Pages crawled (for crawl mode)',
          },
          results: 'array - Checked links (partial during processing, complete when done)',
          stats: 'object - Statistics (total, working, broken, redirects)',
        },
      },
    },
  };

  sendSuccess(res, 'Link checker service information', info);
});

module.exports = router;
