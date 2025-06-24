const cors = require('cors');
const logger = require('../utils/logger');

/**
 * CORS Configuration
 */
const corsOptions = {
  // Origin configuration
  origin: (origin, callback) => {
    // Get allowed origins from environment variable
    const allowedOrigins = (process.env.CORS_ORIGIN || 'http://localhost:3000')
      .split(',')
      .map(origin => origin.trim());
    
    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) {
      return callback(null, true);
    }
    
    // Check if origin is allowed
    if (allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      callback(null, true);
    } else {
      logger.securityLog('CORS origin blocked', {
        origin,
        allowedOrigins,
        timestamp: new Date().toISOString()
      });
      
      callback(new Error('Not allowed by CORS'));
    }
  },
  
  // Allowed HTTP methods
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  
  // Allowed headers
  allowedHeaders: [
    'Origin',
    'X-Requested-With',
    'Content-Type',
    'Accept',
    'Authorization',
    'X-API-Key',
    'X-Request-ID',
    'Cache-Control',
    'Pragma'
  ],
  
  // Exposed headers (headers that the client can access)
  exposedHeaders: [
    'X-Total-Count',
    'X-Page-Count',
    'X-Current-Page',
    'X-Per-Page',
    'X-Request-ID',
    'X-Response-Time',
    'X-API-Version',
    'RateLimit-Limit',
    'RateLimit-Remaining',
    'RateLimit-Reset'
  ],
  
  // Allow credentials (cookies, authorization headers, etc.)
  credentials: process.env.CORS_CREDENTIALS === 'true',
  
  // Preflight cache duration (in seconds)
  maxAge: 86400, // 24 hours
  
  // Handle preflight requests
  preflightContinue: false,
  optionsSuccessStatus: 204
};

/**
 * Development CORS (more permissive)
 */
const developmentCorsOptions = {
  origin: true, // Allow all origins in development
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD'],
  allowedHeaders: '*',
  exposedHeaders: '*',
  credentials: true,
  maxAge: 86400,
  preflightContinue: false,
  optionsSuccessStatus: 204
};

/**
 * Strict CORS for production
 */
const productionCorsOptions = {
  ...corsOptions,
  origin: (origin, callback) => {
    const allowedOrigins = (process.env.CORS_ORIGIN || '')
      .split(',')
      .map(origin => origin.trim())
      .filter(origin => origin.length > 0);
    
    if (allowedOrigins.length === 0) {
      logger.error('No CORS origins configured for production');
      return callback(new Error('CORS not configured'));
    }
    
    if (!origin) {
      // In production, be more strict about requests without origin
      if (process.env.ALLOW_NO_ORIGIN === 'true') {
        return callback(null, true);
      } else {
        return callback(new Error('Origin required'));
      }
    }
    
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      logger.securityLog('CORS origin blocked in production', {
        origin,
        allowedOrigins,
        timestamp: new Date().toISOString()
      });
      
      callback(new Error('Not allowed by CORS'));
    }
  }
};

/**
 * API-specific CORS (for API endpoints)
 */
const apiCorsOptions = {
  ...corsOptions,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Request-ID'
  ]
};

/**
 * Upload-specific CORS (for file upload endpoints)
 */
const uploadCorsOptions = {
  ...corsOptions,
  methods: ['POST', 'PUT'],
  allowedHeaders: [
    'Content-Type',
    'Authorization',
    'X-API-Key',
    'X-Request-ID',
    'Content-Length'
  ]
};

/**
 * Custom CORS error handler
 */
const corsErrorHandler = (err, req, res, next) => {
  if (err.message === 'Not allowed by CORS' || err.message === 'Origin required' || err.message === 'CORS not configured') {
    logger.securityLog('CORS error', {
      error: err.message,
      origin: req.get('Origin'),
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method
    });
    
    return res.status(403).json({
      success: false,
      message: 'CORS policy violation',
      error: 'Access denied'
    });
  }
  
  next(err);
};

/**
 * Get CORS middleware based on environment
 */
const getCorsMiddleware = () => {
  const env = process.env.NODE_ENV || 'development';
  
  switch (env) {
    case 'production':
      return cors(productionCorsOptions);
    case 'development':
      return cors(developmentCorsOptions);
    case 'test':
      return cors(developmentCorsOptions);
    default:
      return cors(corsOptions);
  }
};

/**
 * Create custom CORS middleware
 */
const createCustomCors = (options = {}) => {
  const customOptions = { ...corsOptions, ...options };
  return cors(customOptions);
};

/**
 * CORS preflight handler
 */
const handlePreflight = (req, res, next) => {
  if (req.method === 'OPTIONS') {
    logger.info('CORS preflight request', {
      origin: req.get('Origin'),
      method: req.get('Access-Control-Request-Method'),
      headers: req.get('Access-Control-Request-Headers'),
      url: req.originalUrl
    });
  }
  next();
};

module.exports = {
  corsOptions,
  developmentCorsOptions,
  productionCorsOptions,
  apiCorsOptions,
  uploadCorsOptions,
  corsErrorHandler,
  getCorsMiddleware,
  createCustomCors,
  handlePreflight,
  // Export the default CORS middleware
  default: getCorsMiddleware()
};
