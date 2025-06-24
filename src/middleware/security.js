const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const xss = require('xss');
const hpp = require('hpp');
const logger = require('../utils/logger');

/**
 * XSS Protection Middleware
 */
const xssProtection = (req, res, next) => {
  // Sanitize request body
  if (req.body && typeof req.body === 'object') {
    const sanitizeObject = (obj) => {
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          if (typeof obj[key] === 'string') {
            obj[key] = xss(obj[key]);
          } else if (typeof obj[key] === 'object' && obj[key] !== null) {
            sanitizeObject(obj[key]);
          }
        }
      }
    };
    sanitizeObject(req.body);
  }

  // Sanitize query parameters
  if (req.query && typeof req.query === 'object') {
    for (const key in req.query) {
      if (req.query.hasOwnProperty(key) && typeof req.query[key] === 'string') {
        req.query[key] = xss(req.query[key]);
      }
    }
  }

  next();
};

/**
 * Security Headers Configuration
 */
const securityHeaders = helmet({
  // Content Security Policy
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:", "https:"],
      scriptSrc: ["'self'"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  
  // Cross Origin Embedder Policy
  crossOriginEmbedderPolicy: false,
  
  // DNS Prefetch Control
  dnsPrefetchControl: {
    allow: false
  },
  
  // Frame Options
  frameguard: {
    action: 'deny'
  },
  
  // Hide Powered By
  hidePoweredBy: true,
  
  // HSTS (HTTP Strict Transport Security)
  hsts: {
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true
  },
  
  // IE No Open
  ieNoOpen: true,
  
  // No Sniff
  noSniff: true,
  
  // Origin Agent Cluster
  originAgentCluster: true,
  
  // Permitted Cross Domain Policies
  permittedCrossDomainPolicies: false,
  
  // Referrer Policy
  referrerPolicy: {
    policy: "strict-origin-when-cross-origin"
  },
  
  // X-XSS-Protection
  xssFilter: true
});

/**
 * Request Size Limiter
 */
const requestSizeLimiter = (req, res, next) => {
  const maxSize = parseInt(process.env.MAX_REQUEST_SIZE) || 10 * 1024 * 1024; // 10MB default
  
  if (req.headers['content-length'] && parseInt(req.headers['content-length']) > maxSize) {
    logger.securityLog('Request size limit exceeded', {
      ip: req.ip,
      size: req.headers['content-length'],
      maxSize,
      url: req.originalUrl
    });
    
    return res.status(413).json({
      success: false,
      message: 'Request entity too large'
    });
  }
  
  next();
};

/**
 * Suspicious Activity Detection
 */
const suspiciousActivityDetection = (req, res, next) => {
  const suspiciousPatterns = [
    /(\<|\%3C)script(.|\n)*?(\>|\%3E)/i,
    /(\<|\%3C)iframe(.|\n)*?(\>|\%3E)/i,
    /(\<|\%3C)object(.|\n)*?(\>|\%3E)/i,
    /(\<|\%3C)embed(.|\n)*?(\>|\%3E)/i,
    /javascript:/i,
    /vbscript:/i,
    /onload=/i,
    /onerror=/i,
    /onclick=/i,
    /union.*select/i,
    /select.*from/i,
    /insert.*into/i,
    /delete.*from/i,
    /drop.*table/i,
    /exec.*\(/i,
    /\.\.\/\.\.\//,
    /etc\/passwd/i,
    /cmd\.exe/i,
    /powershell/i
  ];

  const checkForSuspiciousContent = (obj, path = '') => {
    if (typeof obj === 'string') {
      for (const pattern of suspiciousPatterns) {
        if (pattern.test(obj)) {
          logger.securityLog('Suspicious content detected', {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            url: req.originalUrl,
            method: req.method,
            path,
            content: obj.substring(0, 200),
            pattern: pattern.toString()
          });
          
          return true;
        }
      }
    } else if (typeof obj === 'object' && obj !== null) {
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          if (checkForSuspiciousContent(obj[key], `${path}.${key}`)) {
            return true;
          }
        }
      }
    }
    return false;
  };

  // Check URL
  if (checkForSuspiciousContent(req.originalUrl, 'url')) {
    return res.status(400).json({
      success: false,
      message: 'Invalid request'
    });
  }

  // Check query parameters
  if (checkForSuspiciousContent(req.query, 'query')) {
    return res.status(400).json({
      success: false,
      message: 'Invalid request parameters'
    });
  }

  // Check request body
  if (checkForSuspiciousContent(req.body, 'body')) {
    return res.status(400).json({
      success: false,
      message: 'Invalid request data'
    });
  }

  next();
};

/**
 * IP Whitelist/Blacklist Middleware
 */
const ipFilter = (req, res, next) => {
  const clientIP = req.ip;
  
  // IP Blacklist
  const blacklistedIPs = (process.env.IP_BLACKLIST || '').split(',').filter(ip => ip.trim());
  if (blacklistedIPs.includes(clientIP)) {
    logger.securityLog('Blacklisted IP access attempt', {
      ip: clientIP,
      url: req.originalUrl,
      userAgent: req.get('User-Agent')
    });
    
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  // IP Whitelist (if configured)
  const whitelistedIPs = (process.env.IP_WHITELIST || '').split(',').filter(ip => ip.trim());
  if (whitelistedIPs.length > 0 && !whitelistedIPs.includes(clientIP)) {
    logger.securityLog('Non-whitelisted IP access attempt', {
      ip: clientIP,
      url: req.originalUrl,
      userAgent: req.get('User-Agent')
    });
    
    return res.status(403).json({
      success: false,
      message: 'Access denied'
    });
  }

  next();
};

/**
 * Security Response Headers
 */
const securityResponseHeaders = (req, res, next) => {
  // Remove server information
  res.removeHeader('X-Powered-By');
  res.removeHeader('Server');
  
  // Add custom security headers
  res.setHeader('X-API-Version', process.env.API_VERSION || 'v1');
  res.setHeader('X-Request-ID', req.id || 'unknown');
  
  next();
};

/**
 * Combined Security Middleware
 */
const securityMiddleware = [
  // Helmet security headers
  securityHeaders,
  
  // Request size limiter
  requestSizeLimiter,
  
  // IP filtering
  ipFilter,
  
  // MongoDB injection protection
  mongoSanitize({
    replaceWith: '_'
  }),
  
  // XSS protection
  xssProtection,
  
  // HTTP Parameter Pollution protection
  hpp({
    whitelist: ['tags', 'categories'] // Allow arrays for these parameters
  }),
  
  // Suspicious activity detection
  suspiciousActivityDetection,
  
  // Security response headers
  securityResponseHeaders
];

module.exports = securityMiddleware;
