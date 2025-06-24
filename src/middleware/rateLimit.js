const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const ExpressBrute = require('express-brute');
const ExpressBruteRedis = require('express-brute-redis');
const { getRedisClient } = require('../config/redis');
const logger = require('../utils/logger');

/**
 * Create Redis store for express-brute if Redis is available
 */
const createBruteStore = () => {
  try {
    const redisClient = getRedisClient();
    if (redisClient && redisClient.isOpen) {
      return new ExpressBruteRedis({
        client: redisClient,
        prefix: 'brute:'
      });
    }
  } catch (error) {
    logger.warn('Failed to create Redis brute store, using memory store:', error.message);
  }
  return undefined; // Use memory store as fallback
};

/**
 * Basic Rate Limiter
 */
const basicRateLimit = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests from this IP, please try again later.',
    retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000) / 1000)
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESSFUL_REQUESTS === 'true',
  skipFailedRequests: false,
  keyGenerator: (req) => {
    // Use IP + User-Agent for more specific rate limiting
    return `${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  },
  handler: (req, res) => {
    logger.securityLog('Rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method
    });
    
    res.status(429).json({
      success: false,
      message: 'Too many requests from this IP, please try again later.',
      retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000) / 1000)
    });
  }
});

/**
 * Strict Rate Limiter for sensitive endpoints
 */
const strictRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // limit each IP to 5 requests per windowMs
  message: {
    success: false,
    message: 'Too many requests to this endpoint, please try again later.',
    retryAfter: 900 // 15 minutes in seconds
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  skipFailedRequests: false,
  keyGenerator: (req) => {
    return `strict-${req.ip}-${req.originalUrl}`;
  },
  handler: (req, res) => {
    logger.securityLog('Strict rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method
    });
    
    res.status(429).json({
      success: false,
      message: 'Too many requests to this endpoint, please try again later.',
      retryAfter: 900
    });
  }
});

/**
 * API Key Rate Limiter (higher limits for authenticated requests)
 */
const apiKeyRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 1000, // higher limit for API key users
  message: {
    success: false,
    message: 'API rate limit exceeded, please try again later.',
    retryAfter: 900
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Use API key or user ID if available, fallback to IP
    return req.user?.id || req.apiKey || req.ip;
  },
  skip: (req) => {
    // Skip rate limiting if no API key or user authentication
    return !req.user && !req.apiKey;
  },
  handler: (req, res) => {
    logger.securityLog('API rate limit exceeded', {
      ip: req.ip,
      userId: req.user?.id,
      apiKey: req.apiKey ? 'present' : 'absent',
      url: req.originalUrl,
      method: req.method
    });
    
    res.status(429).json({
      success: false,
      message: 'API rate limit exceeded, please try again later.',
      retryAfter: 900
    });
  }
});

/**
 * Slow Down Middleware (progressive delay)
 */
const progressiveSlowDown = slowDown({
  windowMs: parseInt(process.env.SLOW_DOWN_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
  delayAfter: parseInt(process.env.SLOW_DOWN_DELAY_AFTER) || 50, // allow 50 requests per windowMs without delay
  delayMs: () => parseInt(process.env.SLOW_DOWN_DELAY_MS) || 500, // add 500ms delay per request after delayAfter
  maxDelayMs: parseInt(process.env.SLOW_DOWN_MAX_DELAY_MS) || 20000, // max delay of 20 seconds
  keyGenerator: (req) => {
    return `${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  },
  validate: {
    delayMs: false // Disable the deprecation warning
  }
});

/**
 * Lazy-loaded brute force instances
 */
let bruteForceInstance = null;
let loginBruteForceInstance = null;

/**
 * Get or create brute force protection instance
 */
const getBruteForce = () => {
  if (!bruteForceInstance) {
    bruteForceInstance = new ExpressBrute(createBruteStore(), {
      freeRetries: 5, // allow 5 attempts
      minWait: 5 * 60 * 1000, // 5 minutes
      maxWait: 60 * 60 * 1000, // 1 hour
      lifetime: 24 * 60 * 60, // 24 hours (in seconds)
      failCallback: (req, res, next, nextValidRequestDate) => {
        logger.securityLog('Brute force protection triggered', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          url: req.originalUrl,
          method: req.method,
          nextValidRequestDate
        });
        
        res.status(429).json({
          success: false,
          message: 'Too many failed attempts, please try again later.',
          retryAfter: Math.ceil((nextValidRequestDate - Date.now()) / 1000)
        });
      },
      handleStoreError: (error) => {
        logger.error('Brute force store error:', error);
        // Don't throw error, just log it and continue
      }
    });
  }
  return bruteForceInstance;
};

/**
 * Get or create login brute force protection instance
 */
const getLoginBruteForce = () => {
  if (!loginBruteForceInstance) {
    loginBruteForceInstance = new ExpressBrute(createBruteStore(), {
      freeRetries: 3, // allow 3 attempts
      minWait: 10 * 60 * 1000, // 10 minutes
      maxWait: 2 * 60 * 60 * 1000, // 2 hours
      lifetime: 24 * 60 * 60, // 24 hours (in seconds)
      failCallback: (req, res, next, nextValidRequestDate) => {
        logger.securityLog('Login brute force protection triggered', {
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          url: req.originalUrl,
          method: req.method,
          nextValidRequestDate,
          email: req.body?.email || 'unknown'
        });
        
        res.status(429).json({
          success: false,
          message: 'Too many failed login attempts, please try again later.',
          retryAfter: Math.ceil((nextValidRequestDate - Date.now()) / 1000)
        });
      },
      handleStoreError: (error) => {
        logger.error('Login brute force store error:', error);
        // Don't throw error, just log it and continue
      }
    });
  }
  return loginBruteForceInstance;
};

/**
 * Brute Force Protection Middleware (disabled for now)
 */
const bruteForce = (req, res, next) => {
  // Temporarily disabled to avoid Redis connection issues
  next();
};

/**
 * Login Brute Force Protection Middleware (disabled for now)
 */
const loginBruteForce = (req, res, next) => {
  // Temporarily disabled to avoid Redis connection issues
  next();
};

/**
 * File Upload Rate Limiter
 */
const uploadRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 50, // limit each IP to 50 uploads per hour
  message: {
    success: false,
    message: 'Too many file uploads, please try again later.',
    retryAfter: 3600
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return `upload-${req.ip}`;
  },
  handler: (req, res) => {
    logger.securityLog('Upload rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method
    });
    
    res.status(429).json({
      success: false,
      message: 'Too many file uploads, please try again later.',
      retryAfter: 3600
    });
  }
});

/**
 * Create custom rate limiter
 */
const createCustomRateLimit = (options = {}) => {
  const defaultOptions = {
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
      success: false,
      message: 'Rate limit exceeded, please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false
  };

  return rateLimit({ ...defaultOptions, ...options });
};

module.exports = {
  basicRateLimit,
  strictRateLimit,
  apiKeyRateLimit,
  progressiveSlowDown,
  bruteForce,
  loginBruteForce,
  uploadRateLimit,
  createCustomRateLimit
};
