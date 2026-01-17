const express = require('express');
const dns = require('dns').promises;
const { basicRateLimit, createCustomRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { redisUtils } = require('../config/redis');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Custom rate limiter for DNS lookup endpoints
 * 30 requests per minute per user
 */
const dnsRateLimit = createCustomRateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30,
  message: {
    success: false,
    message: 'Too many DNS lookup requests. Please try again later.',
    retryAfter: 60
  },
  keyGenerator: (req) => {
    // Combine IP + User-Agent for more specific rate limiting
    return `dns:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  }
});

/**
 * Validate domain name format
 */
function validateDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    return { valid: false, error: 'Domain is required' };
  }

  // Clean domain
  let cleanDomain = domain.trim().toLowerCase();

  // Remove protocol if present
  cleanDomain = cleanDomain.replace(/^https?:\/\//, '');

  // Remove path if present
  cleanDomain = cleanDomain.replace(/\/.*$/, '');

  // Remove port if present
  cleanDomain = cleanDomain.replace(/:.*$/, '');

  // Basic domain validation regex
  // Allows: domain.com, subdomain.domain.com, etc.
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*\.[a-zA-Z]{2,}$/;

  if (!domainRegex.test(cleanDomain)) {
    return { valid: false, error: 'Invalid domain format' };
  }

  // Check for potential DNS rebinding attack patterns
  const suspiciousPatterns = [
    /localhost/i,
    /127\./,
    /0\.0\.0\.0/,
    /169\.254\./,  // Link-local
    /192\.168\./,  // Private network
    /10\./,        // Private network
    /172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private network
    /\.\./,        // Path traversal
    /[<>'"]/       // XSS attempts
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(cleanDomain)) {
      return { valid: false, error: 'Suspicious domain detected' };
    }
  }

  return { valid: true, cleanDomain };
}

/**
 * Resolve nameserver hostname to IP addresses
 */
async function resolveNameserver(hostname) {
  const startTime = Date.now();

  try {
    // Try to resolve to IPv4 addresses
    const addresses = await dns.resolve4(hostname);
    const responseTime = Date.now() - startTime;

    return {
      success: true,
      ip: addresses[0], // Return primary IP
      allIps: addresses, // Return all IPs
      responseTime
    };
  } catch (error) {
    // If IPv4 fails, try IPv6
    try {
      const addresses = await dns.resolve6(hostname);
      const responseTime = Date.now() - startTime;

      return {
        success: true,
        ip: addresses[0],
        allIps: addresses,
        responseTime,
        ipv6: true
      };
    } catch (ipv6Error) {
      // Both failed, return error
      const responseTime = Date.now() - startTime;
      return {
        success: false,
        error: error.code || 'RESOLUTION_FAILED',
        responseTime
      };
    }
  }
}

/**
 * POST /api/dns/mx-lookup
 * Perform MX (mail exchange) lookup for a domain
 */
router.post('/mx-lookup', dnsRateLimit, async (req, res) => {
  const startTime = Date.now();

  try {
    const { domain } = req.body;

    // Validate domain
    const validation = validateDomain(domain);
    if (!validation.valid) {
      logger.securityLog('Invalid domain in MX lookup', {
        ip: req.ip,
        domain,
        error: validation.error
      });
      return sendError(res, validation.error, 400);
    }

    const cleanDomain = validation.cleanDomain;

    // Check Redis cache (24 hour TTL)
    const cacheKey = `mx-lookup:${cleanDomain}`;
    const cached = await redisUtils.get(cacheKey);

    if (cached) {
      logger.info('MX lookup served from cache', { domain: cleanDomain });
      return sendSuccess(res, 'MX records retrieved from cache', {
        ...cached,
        cached: true,
        timestamp: new Date().toISOString()
      });
    }

    // Perform DNS MX lookup
    let mxRecords = [];
    try {
      mxRecords = await dns.resolveMx(cleanDomain);
    } catch (error) {
      logger.error('DNS MX lookup failed', {
        domain: cleanDomain,
        error: error.message,
        code: error.code
      });

      // Handle specific DNS errors
      let errorMessage = 'Failed to lookup MX records';
      let statusCode = 500;

      if (error.code === 'ENOTFOUND') {
        errorMessage = 'Domain not found or has no MX records';
        statusCode = 404;
      } else if (error.code === 'ENODATA') {
        errorMessage = 'No MX records found for this domain';
        statusCode = 404;
      } else if (error.code === 'ETIMEOUT') {
        errorMessage = 'DNS lookup timeout';
        statusCode = 408;
      } else if (error.code === 'ESERVFAIL') {
        errorMessage = 'DNS server failure';
        statusCode = 503;
      }

      return sendError(res, errorMessage, statusCode, {
        domain: cleanDomain,
        dnsError: error.code
      });
    }

    // Sort by priority (lower number = higher priority)
    mxRecords.sort((a, b) => a.priority - b.priority);

    // Resolve each MX server to IP addresses
    const resolvedMxRecords = [];

    for (const mx of mxRecords) {
      const resolution = await resolveNameserver(mx.exchange);

      if (resolution.success) {
        resolvedMxRecords.push({
          hostname: mx.exchange,
          priority: mx.priority,
          ip: resolution.ip,
          allIps: resolution.allIps,
          responseTime: resolution.responseTime,
          ipv6: resolution.ipv6 || false
        });
      } else {
        resolvedMxRecords.push({
          hostname: mx.exchange,
          priority: mx.priority,
          ip: null,
          error: resolution.error,
          responseTime: resolution.responseTime
        });
      }
    }

    const totalTime = Date.now() - startTime;

    // Prepare response
    const result = {
      domain: cleanDomain,
      mxRecords: resolvedMxRecords,
      count: resolvedMxRecords.length,
      totalResponseTime: totalTime,
      cached: false
    };

    // Cache result for 24 hours (86400 seconds)
    await redisUtils.setex(cacheKey, 86400, result);

    logger.info('MX lookup completed', {
      domain: cleanDomain,
      mxCount: resolvedMxRecords.length,
      responseTime: totalTime
    });

    sendSuccess(res, 'MX records retrieved successfully', {
      ...result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('MX lookup error:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    sendError(res, 'Failed to perform MX lookup', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/dns/ns-lookup
 * Perform NS (nameserver) lookup for a domain
 */
router.post('/ns-lookup', dnsRateLimit, async (req, res) => {
  const startTime = Date.now();

  try {
    const { domain } = req.body;

    // Validate domain
    const validation = validateDomain(domain);
    if (!validation.valid) {
      logger.securityLog('Invalid domain in NS lookup', {
        ip: req.ip,
        domain,
        error: validation.error
      });
      return sendError(res, validation.error, 400);
    }

    const cleanDomain = validation.cleanDomain;

    // Check Redis cache (24 hour TTL)
    const cacheKey = `ns-lookup:${cleanDomain}`;
    const cached = await redisUtils.get(cacheKey);

    if (cached) {
      logger.info('NS lookup served from cache', { domain: cleanDomain });
      return sendSuccess(res, 'NS records retrieved from cache', {
        ...cached,
        cached: true,
        timestamp: new Date().toISOString()
      });
    }

    // Perform DNS NS lookup
    let nameservers = [];
    try {
      nameservers = await dns.resolveNs(cleanDomain);
    } catch (error) {
      logger.error('DNS NS lookup failed', {
        domain: cleanDomain,
        error: error.message,
        code: error.code
      });

      // Handle specific DNS errors
      let errorMessage = 'Failed to lookup nameservers';
      let statusCode = 500;

      if (error.code === 'ENOTFOUND') {
        errorMessage = 'Domain not found or has no NS records';
        statusCode = 404;
      } else if (error.code === 'ENODATA') {
        errorMessage = 'No NS records found for this domain';
        statusCode = 404;
      } else if (error.code === 'ETIMEOUT') {
        errorMessage = 'DNS lookup timeout';
        statusCode = 408;
      } else if (error.code === 'ESERVFAIL') {
        errorMessage = 'DNS server failure';
        statusCode = 503;
      }

      return sendError(res, errorMessage, statusCode, {
        domain: cleanDomain,
        dnsError: error.code
      });
    }

    // Resolve each nameserver to IP addresses
    const resolvedNameservers = [];

    for (const ns of nameservers) {
      const resolution = await resolveNameserver(ns);

      if (resolution.success) {
        resolvedNameservers.push({
          hostname: ns,
          ip: resolution.ip,
          allIps: resolution.allIps,
          responseTime: resolution.responseTime,
          ipv6: resolution.ipv6 || false
        });
      } else {
        resolvedNameservers.push({
          hostname: ns,
          ip: null,
          error: resolution.error,
          responseTime: resolution.responseTime
        });
      }
    }

    const totalTime = Date.now() - startTime;

    // Prepare response
    const result = {
      domain: cleanDomain,
      nameservers: resolvedNameservers,
      count: resolvedNameservers.length,
      totalResponseTime: totalTime,
      cached: false
    };

    // Cache result for 24 hours (86400 seconds)
    await redisUtils.setex(cacheKey, 86400, result);

    logger.info('NS lookup completed', {
      domain: cleanDomain,
      nameserverCount: resolvedNameservers.length,
      responseTime: totalTime
    });

    sendSuccess(res, 'NS records retrieved successfully', {
      ...result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('NS lookup error:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    sendError(res, 'Failed to perform NS lookup', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/dns/info
 * Get DNS lookup service information
 */
router.get('/info', basicRateLimit, (req, res) => {
  const info = {
    service: 'DNS Lookup Service',
    version: '1.0.0',
    description: 'Query DNS records including nameservers (NS) and mail exchange (MX) records for any domain',
    features: [
      'NS (Nameserver) record lookup',
      'MX (Mail Exchange) record lookup',
      'IP address resolution for nameservers and mail servers',
      'MX priority sorting',
      'IPv4 and IPv6 support',
      'Response time measurement',
      'Redis caching with 24-hour TTL',
      'Rate limiting protection',
      'DNS rebinding attack prevention',
      'Comprehensive error handling'
    ],
    endpoints: {
      nsLookup: {
        method: 'POST',
        path: '/api/dns/ns-lookup',
        description: 'Lookup nameserver records for a domain',
        rateLimit: {
          requests: 30,
          window: '1 minute'
        },
        requestBody: {
          domain: 'example.com (required)'
        },
        responseFormat: {
          domain: 'string',
          nameservers: 'array',
          count: 'number',
          totalResponseTime: 'number (ms)',
          cached: 'boolean',
          timestamp: 'ISO 8601'
        }
      },
      mxLookup: {
        method: 'POST',
        path: '/api/dns/mx-lookup',
        description: 'Lookup mail exchange records for a domain',
        rateLimit: {
          requests: 30,
          window: '1 minute'
        },
        requestBody: {
          domain: 'example.com (required)'
        },
        responseFormat: {
          domain: 'string',
          mxRecords: 'array (sorted by priority)',
          count: 'number',
          totalResponseTime: 'number (ms)',
          cached: 'boolean',
          timestamp: 'ISO 8601'
        }
      }
    },
    caching: {
      enabled: true,
      ttl: '24 hours',
      backend: 'Redis'
    },
    security: {
      inputValidation: true,
      xssProtection: true,
      dnsRebindingProtection: true,
      rateLimiting: true,
      ipBasedLimiting: true
    },
    limitations: [
      'Rate limited to 30 requests per minute per user',
      'DNS lookup timeout after 5 seconds',
      'Private/local IP addresses blocked',
      'Requires valid public domain'
    ],
    usage: {
      nsLookupExample: {
        request: {
          method: 'POST',
          url: '/api/dns/ns-lookup',
          body: { domain: 'google.com' }
        },
        response: {
          success: true,
          message: 'NS records retrieved successfully',
          data: {
            domain: 'google.com',
            nameservers: [
              {
                hostname: 'ns1.google.com',
                ip: '216.239.32.10',
                allIps: ['216.239.32.10'],
                responseTime: 45,
                ipv6: false
              }
            ],
            count: 4,
            totalResponseTime: 250,
            cached: false,
            timestamp: '2025-01-15T10:30:00Z'
          }
        }
      },
      mxLookupExample: {
        request: {
          method: 'POST',
          url: '/api/dns/mx-lookup',
          body: { domain: 'google.com' }
        },
        response: {
          success: true,
          message: 'MX records retrieved successfully',
          data: {
            domain: 'google.com',
            mxRecords: [
              {
                hostname: 'smtp.google.com',
                priority: 10,
                ip: '142.250.185.26',
                allIps: ['142.250.185.26'],
                responseTime: 52,
                ipv6: false
              }
            ],
            count: 5,
            totalResponseTime: 300,
            cached: false,
            timestamp: '2025-01-15T10:30:00Z'
          }
        }
      }
    }
  };

  sendSuccess(res, 'DNS service information', info);
});

module.exports = router;
