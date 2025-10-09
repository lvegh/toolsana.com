const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const logger = require('../utils/logger');
const { redisUtils } = require('../config/redis');

/**
 * JWT Token Verification Middleware
 */
const verifyToken = async (req, res, next) => {
  try {
    // Get token from header
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') 
      ? authHeader.substring(7) 
      : null;

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Access token required'
      });
    }

    // Check if token is blacklisted (if Redis is available)
    const isBlacklisted = await redisUtils.exists(`blacklist:${token}`);
    if (isBlacklisted) {
      logger.securityLog('Blacklisted token used', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        token: token.substring(0, 20) + '...'
      });
      
      return res.status(401).json({
        success: false,
        message: 'Token has been revoked'
      });
    }

    // Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    // Add user info to request
    req.user = decoded;
    req.token = token;
    
    // Log successful authentication
    logger.info('Token verified successfully', {
      userId: decoded.id,
      email: decoded.email,
      ip: req.ip
    });

    next();
  } catch (error) {
    logger.securityLog('Token verification failed', {
      error: error.message,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl
    });

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        message: 'Token has expired'
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        message: 'Invalid token'
      });
    }

    return res.status(401).json({
      success: false,
      message: 'Token verification failed'
    });
  }
};

/**
 * API Key Verification Middleware
 */
const verifyApiKey = async (req, res, next) => {
  try {
    const apiKey = req.headers['x-api-key'];

    if (!apiKey) {
      return res.status(401).json({
        success: false,
        message: 'API key required'
      });
    }

    // Validate against single API key from environment
    const validApiKey = process.env.VALID_API_KEY;

    if (!validApiKey) {
      logger.error('No valid API key configured');
      return res.status(500).json({
        success: false,
        message: 'API key validation not configured'
      });
    }

    if (apiKey !== validApiKey) {
      logger.securityLog('Invalid API key used', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        apiKey: apiKey.substring(0, 8) + '...',
        url: req.originalUrl
      });

      return res.status(401).json({
        success: false,
        message: 'Invalid API key'
      });
    }

    // Add API key info to request
    req.apiKey = apiKey;
    req.isApiKeyAuth = true;

    logger.info('API key verified successfully', {
      apiKey: apiKey.substring(0, 8) + '...',
      ip: req.ip
    });

    next();
  } catch (error) {
    logger.error('API key verification error:', error);
    return res.status(500).json({
      success: false,
      message: 'API key verification failed'
    });
  }
};

/**
 * Optional Authentication (JWT or API Key)
 */
const optionalAuth = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  const apiKey = req.headers['x-api-key'];

  if (authHeader && authHeader.startsWith('Bearer ')) {
    return verifyToken(req, res, next);
  } else if (apiKey) {
    return verifyApiKey(req, res, next);
  } else {
    // No authentication provided, continue without user info
    next();
  }
};

/**
 * Role-based Authorization Middleware
 */
const requireRole = (roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: 'Authentication required'
      });
    }

    const userRoles = req.user.roles || [];
    const hasRequiredRole = roles.some(role => userRoles.includes(role));

    if (!hasRequiredRole) {
      logger.securityLog('Insufficient permissions', {
        userId: req.user.id,
        userRoles,
        requiredRoles: roles,
        ip: req.ip,
        url: req.originalUrl
      });

      return res.status(403).json({
        success: false,
        message: 'Insufficient permissions'
      });
    }

    next();
  };
};

/**
 * Admin Authorization Middleware
 */
const requireAdmin = requireRole(['admin']);

/**
 * User or Admin Authorization Middleware
 */
const requireUserOrAdmin = requireRole(['user', 'admin']);

/**
 * Generate JWT Token
 */
const generateToken = (payload, options = {}) => {
  const defaultOptions = {
    expiresIn: process.env.JWT_EXPIRES_IN || '24h',
    issuer: 'toolzyhub-api',
    audience: 'toolzyhub-client'
  };

  return jwt.sign(payload, process.env.JWT_SECRET, { ...defaultOptions, ...options });
};

/**
 * Generate Refresh Token
 */
const generateRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
    issuer: 'toolzyhub-api',
    audience: 'toolzyhub-client'
  });
};

/**
 * Verify Refresh Token
 */
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET);
  } catch (error) {
    throw error;
  }
};

/**
 * Hash Password
 */
const hashPassword = async (password) => {
  const saltRounds = parseInt(process.env.BCRYPT_ROUNDS) || 12;
  return await bcrypt.hash(password, saltRounds);
};

/**
 * Compare Password
 */
const comparePassword = async (password, hashedPassword) => {
  return await bcrypt.compare(password, hashedPassword);
};

/**
 * Blacklist Token (logout)
 */
const blacklistToken = async (token) => {
  try {
    // Decode token to get expiration time
    const decoded = jwt.decode(token);
    if (!decoded || !decoded.exp) {
      return false;
    }

    // Calculate TTL (time to live) for the blacklist entry
    const now = Math.floor(Date.now() / 1000);
    const ttl = decoded.exp - now;

    if (ttl > 0) {
      // Add token to blacklist with TTL
      await redisUtils.setex(`blacklist:${token}`, ttl, true);
      return true;
    }

    return false;
  } catch (error) {
    logger.error('Error blacklisting token:', error);
    return false;
  }
};

/**
 * Validation Rules for Authentication
 */
const loginValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 6 })
    .withMessage('Password must be at least 6 characters long')
];

const registerValidation = [
  body('email')
    .isEmail()
    .normalizeEmail()
    .withMessage('Valid email is required'),
  body('password')
    .isLength({ min: 8 })
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must be at least 8 characters long and contain at least one lowercase letter, one uppercase letter, one number, and one special character'),
  body('name')
    .trim()
    .isLength({ min: 2, max: 50 })
    .withMessage('Name must be between 2 and 50 characters')
];

/**
 * Validation Error Handler
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.securityLog('Validation errors', {
      errors: errors.array(),
      ip: req.ip,
      url: req.originalUrl
    });

    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array()
    });
  }
  next();
};

module.exports = {
  verifyToken,
  verifyApiKey,
  optionalAuth,
  requireRole,
  requireAdmin,
  requireUserOrAdmin,
  generateToken,
  generateRefreshToken,
  verifyRefreshToken,
  hashPassword,
  comparePassword,
  blacklistToken,
  loginValidation,
  registerValidation,
  handleValidationErrors
};
