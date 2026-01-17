const express = require('express');
const axios = require('axios');
const dns = require('dns').promises;
const { createCustomRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError, asyncHandler } = require('../middleware/errorHandler');
const { redisUtils } = require('../config/redis');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Aggressive rate limiter for social media checker
 * 10 requests per hour per user to prevent abuse
 */
const socialMediaRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: {
    success: false,
    message: 'Too many username check requests. Please try again in 1 hour.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    return `social-media:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  },
  handler: (req, res) => {
    logger.securityLog('Social media checker rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method
    });

    res.status(429).json({
      success: false,
      message: 'Too many username check requests. Please try again in 1 hour.',
      retryAfter: 3600,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Validate username format
 */
function validateUsername(username) {
  if (!username || typeof username !== 'string') {
    return { valid: false, error: 'Username is required' };
  }

  // Clean username
  const cleanUsername = username.trim().toLowerCase();

  // Username length validation
  if (cleanUsername.length < 1 || cleanUsername.length > 30) {
    return { valid: false, error: 'Username must be between 1 and 30 characters' };
  }

  // Username format validation: alphanumeric, underscores, hyphens
  const usernameRegex = /^[a-z0-9_-]+$/;
  if (!usernameRegex.test(cleanUsername)) {
    return { valid: false, error: 'Username can only contain letters, numbers, underscores, and hyphens' };
  }

  // Check for suspicious patterns
  const suspiciousPatterns = [
    /^admin$/i,
    /^root$/i,
    /^system$/i,
    /^test$/i,
    /<script/i,
    /javascript:/i,
    /on\w+=/i
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(cleanUsername)) {
      return { valid: false, error: 'Username contains restricted patterns' };
    }
  }

  return { valid: true, cleanUsername };
}

/**
 * Platform check configurations
 */
const PLATFORMS = {
  twitter: {
    name: 'Twitter/X',
    checkUrl: (username) => `https://twitter.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  instagram: {
    name: 'Instagram',
    checkUrl: (username) => `https://www.instagram.com/${username}/`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  facebook: {
    name: 'Facebook',
    checkUrl: (username) => `https://www.facebook.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  github: {
    name: 'GitHub',
    checkUrl: (username) => `https://api.github.com/users/${username}`,
    method: 'GET',
    timeout: 3000,
    checkAvailability: (status) => status === 404,
    headers: {
      'User-Agent': 'ToolzyHub-Social-Checker/1.0'
    }
  },
  youtube: {
    name: 'YouTube',
    checkUrl: (username) => `https://www.youtube.com/@${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  tiktok: {
    name: 'TikTok',
    checkUrl: (username) => `https://www.tiktok.com/@${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  linkedin: {
    name: 'LinkedIn',
    checkUrl: (username) => `https://www.linkedin.com/company/${username}/?viewAsMember=true`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  reddit: {
    name: 'Reddit',
    checkUrl: (username) => `https://www.reddit.com/user/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  pinterest: {
    name: 'Pinterest',
    checkUrl: (username) => `https://www.pinterest.com/${username}/`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  twitch: {
    name: 'Twitch',
    checkUrl: (username) => `https://www.twitch.tv/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  snapchat: {
    name: 'Snapchat',
    checkUrl: (username) => `https://www.snapchat.com/add/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  medium: {
    name: 'Medium',
    checkUrl: (username) => `https://medium.com/@${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  devto: {
    name: 'Dev.to',
    checkUrl: (username) => `https://dev.to/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  behance: {
    name: 'Behance',
    checkUrl: (username) => `https://www.behance.net/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  dribbble: {
    name: 'Dribbble',
    checkUrl: (username) => `https://dribbble.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  telegram: {
    name: 'Telegram',
    checkUrl: (username) => `https://t.me/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  vimeo: {
    name: 'Vimeo',
    checkUrl: (username) => `https://vimeo.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  tumblr: {
    name: 'Tumblr',
    checkUrl: (username) => `https://${username}.tumblr.com/`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  slack: {
    name: 'Slack',
    checkUrl: (username) => `https://${username}.slack.com`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  foursquare: {
    name: 'Foursquare',
    checkUrl: (username) => `https://foursquare.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  lastfm: {
    name: 'Last.fm',
    checkUrl: (username) => `https://www.last.fm/user/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  flickr: {
    name: 'Flickr',
    checkUrl: (username) => `https://www.flickr.com/people/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  wordpress: {
    name: 'WordPress',
    checkUrl: (username) => `https://${username}.wordpress.com/`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  blogger: {
    name: 'Blogger',
    checkUrl: (username) => `https://${username}.blogspot.com`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  mix: {
    name: 'Mix',
    checkUrl: (username) => `https://mix.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  deviantart: {
    name: 'DeviantArt',
    checkUrl: (username) => `https://www.deviantart.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  etsy: {
    name: 'Etsy',
    checkUrl: (username) => `https://www.etsy.com/shop/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  aboutme: {
    name: 'About.me',
    checkUrl: (username) => `https://about.me/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  venmo: {
    name: 'Venmo',
    checkUrl: (username) => `https://venmo.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  cashapp: {
    name: 'Cash App',
    checkUrl: (username) => `https://cash.app/$${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  livejournal: {
    name: 'LiveJournal',
    checkUrl: (username) => `https://${username}.livejournal.com`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  disqus: {
    name: 'Disqus',
    checkUrl: (username) => `https://disqus.com/by/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  discord: {
    name: 'Discord',
    checkUrl: (username) => `https://discord.com/users/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  patreon: {
    name: 'Patreon',
    checkUrl: (username) => `https://www.patreon.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  soundcloud: {
    name: 'SoundCloud',
    checkUrl: (username) => `https://soundcloud.com/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  spotify: {
    name: 'Spotify',
    checkUrl: (username) => `https://open.spotify.com/user/${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  substack: {
    name: 'Substack',
    checkUrl: (username) => `https://${username}.substack.com`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  producthunt: {
    name: 'Product Hunt',
    checkUrl: (username) => `https://www.producthunt.com/@${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  },
  mastodon: {
    name: 'Mastodon',
    checkUrl: (username) => `https://mastodon.social/@${username}`,
    method: 'HEAD',
    timeout: 3000,
    checkAvailability: (status) => status === 404
  }
};

/**
 * Domain extensions to check
 */
const DOMAIN_EXTENSIONS = [
  'com', 'net', 'org', 'io', 'co', 'ai', 'me', 'app', 'dev', 'xyz',
  'us', 'de', 'eu', 'ru', 'jp', 'in', 'uk', 'ca', 'ee', 'do', 'cn',
  'tech', 'blog', 'store', 'shop', 'live', 'tv'
];

/**
 * Check platform availability with retry logic
 */
async function checkPlatform(platform, username, retries = 2) {
  const config = PLATFORMS[platform];
  const url = config.checkUrl(username);

  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const response = await axios({
        method: config.method,
        url: url,
        timeout: config.timeout,
        headers: config.headers || {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        },
        validateStatus: () => true, // Don't throw on any status
        maxRedirects: 5
      });

      const available = config.checkAvailability(response.status);

      return {
        platform: config.name,
        available,
        url,
        status: response.status,
        checked: true,
        error: null
      };

    } catch (error) {
      // Log error but continue
      if (attempt === retries) {
        logger.warn(`Platform check failed for ${platform}:`, {
          username,
          error: error.message,
          attempt: attempt + 1
        });

        return {
          platform: config.name,
          available: null,
          url,
          status: null,
          checked: false,
          error: error.code || 'CHECK_FAILED'
        };
      }

      // Wait before retry (exponential backoff)
      await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, attempt)));
    }
  }
}

/**
 * Check domain availability using DNS lookup
 */
async function checkDomain(domain, retries = 2) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      // Try to resolve the domain
      // If it resolves, the domain is taken
      await dns.resolve4(domain);

      return {
        extension: domain.split('.').pop(),
        domain,
        available: false,
        checked: true,
        error: null
      };

    } catch (error) {
      // ENOTFOUND means domain is available
      if (error.code === 'ENOTFOUND') {
        return {
          extension: domain.split('.').pop(),
          domain,
          available: true,
          checked: true,
          error: null
        };
      }

      // Other errors - retry or return error
      if (attempt === retries) {
        logger.warn(`Domain check failed for ${domain}:`, {
          error: error.message,
          code: error.code,
          attempt: attempt + 1
        });

        return {
          extension: domain.split('.').pop(),
          domain,
          available: null,
          checked: false,
          error: error.code || 'CHECK_FAILED'
        };
      }

      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 100 * Math.pow(2, attempt)));
    }
  }
}

/**
 * POST /api/tools/social-media-checker
 * Check username availability across social media platforms and domains
 */
router.post('/', socialMediaRateLimit, asyncHandler(async (req, res) => {
  const startTime = Date.now();

  try {
    const { username } = req.body;

    // Validate username
    const validation = validateUsername(username);
    if (!validation.valid) {
      logger.securityLog('Invalid username in social media check', {
        ip: req.ip,
        username,
        error: validation.error
      });
      return sendError(res, validation.error, 400);
    }

    const cleanUsername = validation.cleanUsername;

    // Check Redis cache (6 hour TTL)
    const cacheKey = `social-media:${cleanUsername}`;
    const cached = await redisUtils.get(cacheKey);

    if (cached) {
      logger.info('Social media check served from cache', { username: cleanUsername });
      return sendSuccess(res, 'Username availability retrieved from cache', {
        ...cached,
        cached: true,
        timestamp: new Date().toISOString()
      });
    }

    // Log check request
    logger.info('Starting social media availability check', {
      username: cleanUsername,
      ip: req.ip,
      platforms: Object.keys(PLATFORMS).length,
      domains: DOMAIN_EXTENSIONS.length
    });

    // Check all platforms in parallel
    const platformChecks = Object.keys(PLATFORMS).map(async (platform) => {
      try {
        const result = await checkPlatform(platform, cleanUsername);
        return { [platform]: result };
      } catch (error) {
        logger.error(`Error checking ${platform}:`, error);
        return {
          [platform]: {
            platform: PLATFORMS[platform].name,
            available: null,
            url: PLATFORMS[platform].checkUrl(cleanUsername),
            status: null,
            checked: false,
            error: 'CHECK_FAILED'
          }
        };
      }
    });

    // Check all domains in parallel
    const domainChecks = DOMAIN_EXTENSIONS.map(async (ext) => {
      const domain = `${cleanUsername}.${ext}`;
      try {
        const result = await checkDomain(domain);
        return { [ext]: result };
      } catch (error) {
        logger.error(`Error checking domain ${domain}:`, error);
        return {
          [ext]: {
            extension: ext,
            domain,
            available: null,
            checked: false,
            error: 'CHECK_FAILED'
          }
        };
      }
    });

    // Execute all checks in parallel
    const [platformResults, domainResults] = await Promise.all([
      Promise.all(platformChecks),
      Promise.all(domainChecks)
    ]);

    // Combine platform results
    const platforms = platformResults.reduce((acc, result) => {
      return { ...acc, ...result };
    }, {});

    // Combine domain results
    const domains = domainResults.reduce((acc, result) => {
      return { ...acc, ...result };
    }, {});

    const totalTime = Date.now() - startTime;

    // Calculate statistics
    const platformStats = {
      total: Object.keys(platforms).length,
      checked: Object.values(platforms).filter(p => p.checked).length,
      available: Object.values(platforms).filter(p => p.available === true).length,
      unavailable: Object.values(platforms).filter(p => p.available === false).length,
      failed: Object.values(platforms).filter(p => p.checked === false).length
    };

    const domainStats = {
      total: Object.keys(domains).length,
      checked: Object.values(domains).filter(d => d.checked).length,
      available: Object.values(domains).filter(d => d.available === true).length,
      unavailable: Object.values(domains).filter(d => d.available === false).length,
      failed: Object.values(domains).filter(d => d.checked === false).length
    };

    // Prepare response
    const result = {
      username: cleanUsername,
      platforms,
      domains,
      statistics: {
        platforms: platformStats,
        domains: domainStats,
        totalResponseTime: totalTime
      },
      cached: false,
      checkedAt: new Date().toISOString()
    };

    // Cache result for 6 hours (21600 seconds)
    await redisUtils.setex(cacheKey, 21600, result);

    logger.info('Social media check completed', {
      username: cleanUsername,
      platformsChecked: platformStats.checked,
      domainsChecked: domainStats.checked,
      responseTime: totalTime,
      ip: req.ip
    });

    return sendSuccess(
      res,
      'Username availability check completed',
      result,
      200
    );

  } catch (error) {
    logger.error('Social media checker error:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    return sendError(res, 'Failed to check username availability', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
}));

/**
 * GET /api/tools/social-media-checker/info
 * Get service information
 */
router.get('/info', asyncHandler(async (req, res) => {
  const info = {
    service: 'Social Media Name Checker',
    version: '2.0.0',
    description: 'Check username availability across 41 social media platforms and 27 domain extensions',
    features: [
      'Check 41 social media platforms simultaneously',
      'Check 27 high-quality domain extensions',
      'Parallel processing for fast results',
      'Retry logic for failed checks',
      'Redis caching with 6-hour TTL',
      'Aggressive rate limiting (10 requests/hour)',
      'Username validation and sanitization',
      'Detailed statistics and error reporting'
    ],
    platforms: Object.keys(PLATFORMS).map(key => ({
      id: key,
      name: PLATFORMS[key].name
    })),
    domainExtensions: DOMAIN_EXTENSIONS,
    endpoint: {
      method: 'POST',
      path: '/api/tools/social-media-checker',
      description: 'Check username availability',
      rateLimit: {
        requests: 10,
        window: '1 hour'
      },
      requestBody: {
        username: 'string (1-30 chars, alphanumeric, underscores, hyphens)'
      },
      responseFormat: {
        username: 'string',
        platforms: 'object (platform check results)',
        domains: 'object (domain check results)',
        statistics: 'object (summary statistics)',
        cached: 'boolean',
        checkedAt: 'ISO 8601 timestamp'
      }
    },
    caching: {
      enabled: true,
      ttl: '6 hours',
      backend: 'Redis'
    },
    security: {
      inputValidation: true,
      usernameFormat: 'alphanumeric, underscores, hyphens only',
      rateLimiting: '10 requests per hour per user',
      ipBasedLimiting: true,
      suspiciousPatternDetection: true
    },
    limitations: [
      'Rate limited to 10 requests per hour per user',
      'Username must be 1-30 characters',
      'Only alphanumeric characters, underscores, and hyphens allowed',
      'Platform API changes may affect accuracy',
      '3 second timeout per platform check',
      'Some platforms may block automated checks'
    ],
    usage: {
      example: {
        request: {
          method: 'POST',
          url: '/api/tools/social-media-checker',
          body: {
            username: 'johndoe'
          }
        },
        response: {
          success: true,
          message: 'Username availability check completed',
          data: {
            username: 'johndoe',
            platforms: {
              twitter: {
                platform: 'Twitter/X',
                available: false,
                url: 'https://twitter.com/johndoe',
                status: 200,
                checked: true,
                error: null
              },
              github: {
                platform: 'GitHub',
                available: true,
                url: 'https://api.github.com/users/johndoe',
                status: 404,
                checked: true,
                error: null
              }
            },
            domains: {
              com: {
                extension: 'com',
                domain: 'johndoe.com',
                available: false,
                checked: true,
                error: null
              },
              io: {
                extension: 'io',
                domain: 'johndoe.io',
                available: true,
                checked: true,
                error: null
              }
            },
            statistics: {
              platforms: {
                total: 17,
                checked: 17,
                available: 8,
                unavailable: 8,
                failed: 1
              },
              domains: {
                total: 10,
                checked: 10,
                available: 5,
                unavailable: 5,
                failed: 0
              },
              totalResponseTime: 2500
            },
            cached: false,
            checkedAt: '2025-01-15T10:30:00.000Z'
          },
          timestamp: '2025-01-15T10:30:00.000Z'
        }
      }
    }
  };

  return sendSuccess(res, 'Social Media Name Checker service information', info);
}));

module.exports = router;
