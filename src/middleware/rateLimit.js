const rateLimit = require('express-rate-limit');
const slowDown = require('express-slow-down');
const { getRedisClient } = require('../config/redis');
const logger = require('../utils/logger');

/**
 * Custom Brute Force Protection Class
 * Secure replacement for express-brute with Redis backing
 */
class SecureBruteForce {
  constructor(options = {}) {
    this.options = {
      freeRetries: options.freeRetries || 5,
      minWait: options.minWait || 5 * 60 * 1000, // 5 minutes
      maxWait: options.maxWait || 60 * 60 * 1000, // 1 hour
      lifetime: options.lifetime || 24 * 60 * 60 * 1000, // 24 hours
      prefix: options.prefix || 'brute:',
      ...options
    };
    this.memoryStore = new Map();
  }

  /**
   * Get Redis client or fallback to memory store
   */
  getStore() {
    try {
      const redisClient = getRedisClient();
      if (redisClient && redisClient.isOpen) {
        return { type: 'redis', client: redisClient };
      }
    } catch (error) {
      logger.warn('Redis not available for brute force protection, using memory store');
    }
    return { type: 'memory', client: this.memoryStore };
  }

  /**
   * Generate key for rate limiting
   */
  generateKey(req, keyGenerator) {
    if (typeof keyGenerator === 'function') {
      return keyGenerator(req);
    }
    return `${req.ip}-${req.originalUrl}`;
  }

  /**
   * Get attempt data from store
   */
  async getAttempts(key) {
    const store = this.getStore();
    const fullKey = `${this.options.prefix}${key}`;

    try {
      if (store.type === 'redis') {
        const data = await store.client.get(fullKey);
        return data ? JSON.parse(data) : { count: 0, firstRequest: Date.now() };
      } else {
        return store.client.get(fullKey) || { count: 0, firstRequest: Date.now() };
      }
    } catch (error) {
      logger.error('Error getting attempts from store:', error);
      return { count: 0, firstRequest: Date.now() };
    }
  }

  /**
   * Set attempt data in store
   */
  async setAttempts(key, data) {
    const store = this.getStore();
    const fullKey = `${this.options.prefix}${key}`;

    try {
      if (store.type === 'redis') {
        await store.client.setEx(fullKey, Math.ceil(this.options.lifetime / 1000), JSON.stringify(data));
      } else {
        store.client.set(fullKey, data);
        // Clean up memory store periodically
        setTimeout(() => {
          if (store.client.has(fullKey)) {
            const storedData = store.client.get(fullKey);
            if (Date.now() - storedData.firstRequest > this.options.lifetime) {
              store.client.delete(fullKey);
            }
          }
        }, this.options.lifetime);
      }
    } catch (error) {
      logger.error('Error setting attempts in store:', error);
    }
  }

  /**
   * Reset attempts for a key
   */
  async resetAttempts(key) {
    const store = this.getStore();
    const fullKey = `${this.options.prefix}${key}`;

    try {
      if (store.type === 'redis') {
        await store.client.del(fullKey);
      } else {
        store.client.delete(fullKey);
      }
    } catch (error) {
      logger.error('Error resetting attempts:', error);
    }
  }

  /**
   * Calculate wait time based on attempt count
   */
  calculateWaitTime(attempts) {
    if (attempts <= this.options.freeRetries) {
      return 0;
    }

    const extraAttempts = attempts - this.options.freeRetries;
    const waitTime = Math.min(
      this.options.minWait * Math.pow(2, extraAttempts - 1),
      this.options.maxWait
    );

    return waitTime;
  }

  /**
   * Create middleware function
   */
  prevent(keyGenerator, failCallback) {
    return async (req, res, next) => {
      const key = this.generateKey(req, keyGenerator);
      
      try {
        const attempts = await this.getAttempts(key);
        const now = Date.now();
        const waitTime = this.calculateWaitTime(attempts.count);
        const nextValidRequestDate = attempts.lastRequest ? attempts.lastRequest + waitTime : now;

        // Check if we're still in the wait period
        if (waitTime > 0 && now < nextValidRequestDate) {
          const retryAfter = Math.ceil((nextValidRequestDate - now) / 1000);
          
          logger.securityLog('Brute force protection triggered', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            url: req.originalUrl,
            method: req.method,
            attempts: attempts.count,
            waitTime,
            retryAfter,
            key: key.substring(0, 20) + '...' // Log partial key for debugging
          });

          if (typeof failCallback === 'function') {
            return failCallback(req, res, next, nextValidRequestDate);
          }

          return res.status(429).json({
            success: false,
            message: 'Too many failed attempts, please try again later.',
            retryAfter
          });
        }

        // Store the middleware reset function for successful requests
        req.bruteForceReset = () => this.resetAttempts(key);
        
        // Store the middleware fail function for failed requests
        req.bruteForceIncrement = async () => {
          const newAttempts = {
            count: attempts.count + 1,
            firstRequest: attempts.firstRequest || now,
            lastRequest: now
          };
          await this.setAttempts(key, newAttempts);
        };

        next();
      } catch (error) {
        logger.error('Brute force protection error:', error);
        // Don't block requests on errors, just log and continue
        next();
      }
    };
  }
}

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
 * Create secure brute force protection instances
 */
const createBruteForceProtection = (options = {}) => {
  return new SecureBruteForce(options);
};

// Create default brute force protection instances
const generalBruteForce = createBruteForceProtection({
  freeRetries: 5,
  minWait: 5 * 60 * 1000, // 5 minutes
  maxWait: 60 * 60 * 1000, // 1 hour
  lifetime: 24 * 60 * 60 * 1000, // 24 hours
  prefix: 'brute:general:'
});

const loginBruteForce = createBruteForceProtection({
  freeRetries: 3,
  minWait: 10 * 60 * 1000, // 10 minutes
  maxWait: 2 * 60 * 60 * 1000, // 2 hours
  lifetime: 24 * 60 * 60 * 1000, // 24 hours
  prefix: 'brute:login:'
});

/**
 * Brute Force Protection Middleware
 */
const bruteForce = generalBruteForce.prevent(
  (req) => `${req.ip}-${req.originalUrl}`,
  (req, res, next, nextValidRequestDate) => {
    const retryAfter = Math.ceil((nextValidRequestDate - Date.now()) / 1000);
    res.status(429).json({
      success: false,
      message: 'Too many failed attempts, please try again later.',
      retryAfter
    });
  }
);

/**
 * Login Brute Force Protection Middleware
 */
const loginBruteForceMiddleware = loginBruteForce.prevent(
  (req) => `${req.ip}-${req.body?.email || 'unknown'}`,
  (req, res, next, nextValidRequestDate) => {
    const retryAfter = Math.ceil((nextValidRequestDate - Date.now()) / 1000);
    
    logger.securityLog('Login brute force protection triggered', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method,
      email: req.body?.email || 'unknown',
      retryAfter
    });
    
    res.status(429).json({
      success: false,
      message: 'Too many failed login attempts, please try again later.',
      retryAfter
    });
  }
);

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

/**
 * Helper middleware to reset brute force attempts on successful requests
 */
const resetBruteForceOnSuccess = (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    // Reset brute force attempts on successful responses (2xx status codes)
    if (res.statusCode >= 200 && res.statusCode < 300 && req.bruteForceReset) {
      req.bruteForceReset().catch(error => {
        logger.error('Error resetting brute force attempts:', error);
      });
    }
    
    return originalSend.call(this, data);
  };
  
  next();
};

/**
 * Helper middleware to increment brute force attempts on failed requests
 */
const incrementBruteForceOnFailure = (req, res, next) => {
  const originalSend = res.send;
  
  res.send = function(data) {
    // Increment brute force attempts on failed responses (4xx/5xx status codes)
    if (res.statusCode >= 400 && req.bruteForceIncrement) {
      req.bruteForceIncrement().catch(error => {
        logger.error('Error incrementing brute force attempts:', error);
      });
    }
    
    return originalSend.call(this, data);
  };
  
  next();
};

module.exports = {
  basicRateLimit,
  strictRateLimit,
  apiKeyRateLimit,
  progressiveSlowDown,
  bruteForce,
  loginBruteForce: loginBruteForceMiddleware,
  uploadRateLimit,
  createCustomRateLimit,
  createBruteForceProtection,
  resetBruteForceOnSuccess,
  incrementBruteForceOnFailure,
  SecureBruteForce
};
