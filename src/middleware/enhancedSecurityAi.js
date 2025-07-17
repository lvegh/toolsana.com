const logger = require('../utils/logger');
const ipBanManager = require('../utils/ipBanManager');
const securityNotifier = require('../utils/securityNotifier');

/**
 * ONNX-Compatible Enhanced Security Middleware
 * Combines token validation, IP banning, and security notifications
 * WITHOUT modifying the request object to maintain ONNX compatibility
 */
class EnhancedSecurityAi {
  constructor() {
    this.apiSecretToken = process.env.API_SECRET_TOKEN;
    this.isDevelopment = process.env.NODE_ENV === 'development';
    
    // In-memory store for security context (ONNX-safe)
    this.securityContexts = new Map();
    
    if (!this.apiSecretToken && !this.isDevelopment) {
      logger.error('API_SECRET_TOKEN not configured - enhanced security disabled');
    }
    
    if (this.isDevelopment) {
      logger.info('Development mode detected - API token validation disabled');
    }

    // Clean up old security contexts periodically (prevent memory leaks)
    setInterval(() => this.cleanupOldContexts(), 60000); // Clean every minute
  }

  /**
   * Generate a unique request ID for security context tracking
   */
  generateRequestId(req) {
    const ip = req.ip || req.connection.remoteAddress;
    const timestamp = Date.now();
    const userAgent = req.get('User-Agent') || 'Unknown';
    return `${ip}-${timestamp}-${Buffer.from(userAgent).toString('base64').slice(0, 8)}`;
  }

  /**
   * Store security context without modifying request object
   */
  setSecurityContext(requestId, context) {
    this.securityContexts.set(requestId, {
      ...context,
      createdAt: Date.now()
    });
  }

  /**
   * Retrieve security context
   */
  getSecurityContext(requestId) {
    return this.securityContexts.get(requestId);
  }

  /**
   * Clean up old security contexts to prevent memory leaks
   */
  cleanupOldContexts() {
    const now = Date.now();
    const maxAge = 300000; // 5 minutes

    for (const [requestId, context] of this.securityContexts.entries()) {
      if (now - context.createdAt > maxAge) {
        this.securityContexts.delete(requestId);
      }
    }
  }

  /**
   * Main enhanced security middleware (ONNX-compatible)
   */
  middleware() {
    return async (req, res, next) => {
      const startTime = Date.now();
      const ip = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';
      const endpoint = req.originalUrl;
      const requestId = this.generateRequestId(req);

      try {
        // Step 1: Check if IP is banned (always check, even in development)
        const banData = await ipBanManager.isBanned(ip);
        if (banData) {
          const timeRemaining = ipBanManager.formatBanTimeRemaining(banData);
          
          logger.warn('Banned IP attempted access', {
            ip,
            endpoint,
            userAgent,
            bannedAt: banData.bannedAt,
            timeRemaining,
            reason: banData.reason
          });

          return res.status(429).json({
            success: false,
            message: 'IP address is banned',
            error: 'TOO_MANY_REQUESTS',
            banInfo: {
              reason: banData.reason,
              bannedAt: banData.bannedAt,
              expiresAt: banData.expiresAt,
              timeRemaining: timeRemaining
            }
          });
        }

        // Step 2: Skip token validation in development
        if (this.isDevelopment) {
          // Store security info in context map (ONNX-safe)
          this.setSecurityContext(requestId, {
            ip,
            authMethod: 'development',
            authenticated: true,
            authenticatedAt: new Date().toISOString(),
            processingTime: Date.now() - startTime,
            developmentMode: true
          });

          logger.info('Development mode - skipping token validation', {
            ip,
            endpoint,
            userAgent,
            processingTime: Date.now() - startTime,
            requestId
          });

          // Add request ID to response headers for tracking (optional)
          res.set('X-Security-Request-ID', requestId);
          return next();
        }

        // Step 3: Validate API token (production/non-development only)
        const authHeader = req.headers.authorization;
        const apiKeyHeader = req.headers['x-api-key'];
        
        let token = null;
        let authMethod = null;

        // Extract token from Authorization header (Bearer token)
        if (authHeader && authHeader.startsWith('Bearer ')) {
          token = authHeader.substring(7);
          authMethod = 'bearer';
        }
        // Extract token from X-API-Key header
        else if (apiKeyHeader) {
          token = apiKeyHeader;
          authMethod = 'api-key';
        }

        // Check if token is provided
        if (!token) {
          await this.handleFailedAttempt(ip, 'No authentication token provided', {
            endpoint,
            userAgent,
            authMethod: 'none'
          });

          return res.status(401).json({
            success: false,
            message: 'Authentication required',
            error: 'MISSING_TOKEN',
            details: 'Provide token via Authorization header (Bearer token) or X-API-Key header'
          });
        }

        // Validate token
        if (!this.apiSecretToken) {
          logger.error('API_SECRET_TOKEN not configured', { ip, endpoint });
          return res.status(500).json({
            success: false,
            message: 'Server configuration error',
            error: 'CONFIGURATION_ERROR'
          });
        }

        // Check if token is valid
        if (token !== this.apiSecretToken) {
          await this.handleFailedAttempt(ip, 'Invalid authentication token', {
            endpoint,
            userAgent,
            authMethod,
            tokenLength: token.length,
            tokenPrefix: token.substring(0, 8) + '...'
          });

          return res.status(401).json({
            success: false,
            message: 'Invalid authentication token',
            error: 'INVALID_TOKEN'
          });
        }

        // Step 4: Token is valid - clear any failed attempts and proceed
        await ipBanManager.clearFailedAttempts(ip);

        // Store security info in context map (ONNX-safe)
        this.setSecurityContext(requestId, {
          ip,
          authMethod,
          authenticated: true,
          authenticatedAt: new Date().toISOString(),
          processingTime: Date.now() - startTime
        });

        // Log successful authentication
        logger.info('Request authenticated successfully', {
          ip,
          endpoint,
          authMethod,
          userAgent,
          processingTime: Date.now() - startTime,
          requestId
        });

        // Add request ID to response headers for tracking (optional)
        res.set('X-Security-Request-ID', requestId);
        next();

      } catch (error) {
        logger.error('Enhanced security middleware error', {
          error: error.message,
          stack: error.stack,
          ip,
          endpoint,
          userAgent,
          requestId
        });

        return res.status(500).json({
          success: false,
          message: 'Security validation error',
          error: 'SECURITY_ERROR'
        });
      }
    };
  }

  /**
   * Handle failed authentication attempt
   */
  async handleFailedAttempt(ip, reason, requestInfo = {}) {
    try {
      // Skip failed attempt tracking in development
      if (this.isDevelopment) {
        logger.info('Development mode - skipping failed attempt tracking', {
          ip,
          reason,
          requestInfo
        });
        return 1;
      }

      // Increment failed attempts counter
      const failedAttempts = await ipBanManager.incrementFailedAttempts(ip, requestInfo);

      // Check if IP should be banned
      const shouldBan = await ipBanManager.shouldBanIP(ip);

      if (shouldBan) {
        // Ban the IP
        const banData = await ipBanManager.banIP(ip, 'Too many failed authentication attempts', {
          ...requestInfo,
          failedAttempts
        });

        if (banData) {
          // Send security notification email
          try {
            await securityNotifier.sendIPBanAlert(banData);
          } catch (emailError) {
            logger.error('Failed to send security notification email', {
              error: emailError.message,
              ip,
              banData
            });
          }

          logger.error('IP banned due to failed authentication attempts', {
            ip,
            failedAttempts,
            reason,
            bannedAt: banData.bannedAt,
            expiresAt: banData.expiresAt,
            requestInfo
          });
        }
      } else {
        logger.warn('Failed authentication attempt', {
          ip,
          reason,
          failedAttempts,
          maxAttempts: ipBanManager.maxFailedAttempts,
          requestInfo
        });
      }

      return failedAttempts;
    } catch (error) {
      logger.error('Error handling failed attempt', {
        error: error.message,
        ip,
        reason
      });
      return 1;
    }
  }

  /**
   * Create rate-limited version of enhanced security
   * Combines with existing rate limiting
   */
  withRateLimit(rateLimitMiddleware) {
    const securityMiddleware = this.middleware();
    
    return (req, res, next) => {
      // First apply rate limiting
      rateLimitMiddleware(req, res, (rateLimitError) => {
        if (rateLimitError) {
          return next(rateLimitError);
        }
        
        // Then apply enhanced security
        securityMiddleware(req, res, next);
      });
    };
  }

  /**
   * Create optional security middleware (for endpoints that don't require auth)
   * ONNX-compatible version
   */
  optional() {
    return async (req, res, next) => {
      const ip = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';
      const endpoint = req.originalUrl;
      const requestId = this.generateRequestId(req);

      try {
        // Check if IP is banned (even for optional auth)
        const banData = await ipBanManager.isBanned(ip);
        if (banData) {
          const timeRemaining = ipBanManager.formatBanTimeRemaining(banData);
          
          logger.warn('Banned IP attempted access to optional auth endpoint', {
            ip,
            endpoint,
            userAgent,
            bannedAt: banData.bannedAt,
            timeRemaining
          });

          return res.status(429).json({
            success: false,
            message: 'IP address is banned',
            error: 'TOO_MANY_REQUESTS',
            banInfo: {
              reason: banData.reason,
              bannedAt: banData.bannedAt,
              expiresAt: banData.expiresAt,
              timeRemaining: timeRemaining
            }
          });
        }

        // Skip token validation in development
        if (this.isDevelopment) {
          this.setSecurityContext(requestId, {
            ip,
            authenticated: true,
            authMethod: 'development',
            authenticatedAt: new Date().toISOString(),
            developmentMode: true
          });
          
          logger.info('Development mode - optional auth skipped', {
            ip,
            endpoint,
            userAgent,
            requestId
          });
          
          res.set('X-Security-Request-ID', requestId);
          return next();
        }

        // Check for token but don't require it (production)
        const authHeader = req.headers.authorization;
        const apiKeyHeader = req.headers['x-api-key'];
        
        let token = null;
        let authMethod = null;

        if (authHeader && authHeader.startsWith('Bearer ')) {
          token = authHeader.substring(7);
          authMethod = 'bearer';
        } else if (apiKeyHeader) {
          token = apiKeyHeader;
          authMethod = 'api-key';
        }

        // If token provided, validate it
        if (token) {
          if (token === this.apiSecretToken) {
            this.setSecurityContext(requestId, {
              ip,
              authMethod,
              authenticated: true,
              authenticatedAt: new Date().toISOString()
            });
            
            logger.info('Optional auth - token validated', {
              ip,
              endpoint,
              authMethod,
              requestId
            });
          } else {
            // Invalid token provided - log but don't block
            logger.warn('Optional auth - invalid token provided', {
              ip,
              endpoint,
              authMethod,
              tokenLength: token.length,
              requestId
            });
            
            this.setSecurityContext(requestId, {
              ip,
              authenticated: false,
              reason: 'invalid_token'
            });
          }
        } else {
          // No token provided - that's okay for optional auth
          this.setSecurityContext(requestId, {
            ip,
            authenticated: false,
            reason: 'no_token'
          });
        }

        res.set('X-Security-Request-ID', requestId);
        next();

      } catch (error) {
        logger.error('Optional security middleware error', {
          error: error.message,
          ip,
          endpoint,
          requestId
        });

        // For optional auth, continue even if there's an error
        this.setSecurityContext(requestId, {
          ip,
          authenticated: false,
          reason: 'security_error'
        });
        
        res.set('X-Security-Request-ID', requestId);
        next();
      }
    };
  }

  /**
   * Utility method to get security context for a request
   * Use this in your route handlers if you need access to security info
   */
  getRequestSecurity(requestId) {
    return this.getSecurityContext(requestId);
  }

  /**
   * Get security statistics
   */
  async getSecurityStats() {
    try {
      const banStats = await ipBanManager.getBanStats();
      
      return {
        security: {
          developmentMode: this.isDevelopment,
          tokenProtection: this.isDevelopment ? false : !!this.apiSecretToken,
          maxFailedAttempts: ipBanManager.maxFailedAttempts,
          banDurationHours: ipBanManager.banDurationHours,
          securityEmail: process.env.SECURITY_EMAIL,
          onnxCompatible: true,
          activeSecurityContexts: this.securityContexts.size
        },
        bans: banStats,
        timestamp: new Date().toISOString()
      };
    } catch (error) {
      logger.error('Error getting security statistics', { error: error.message });
      return {
        error: 'Failed to retrieve security statistics',
        timestamp: new Date().toISOString()
      };
    }
  }
}

// Export singleton instance
const enhancedSecurityAi = new EnhancedSecurityAi();

module.exports = {
  enhancedSecurityAi: enhancedSecurityAi.middleware(),
  enhancedSecurityWithRateLimitAi: (rateLimitMiddleware) => enhancedSecurityAi.withRateLimit(rateLimitMiddleware),
  optionalSecurityAi: enhancedSecurityAi.optional(),
  getSecurityStatsAi: () => enhancedSecurityAi.getSecurityStats(),
  // New ONNX-compatible utility
  getRequestSecurityAi: (requestId) => enhancedSecurityAi.getRequestSecurity(requestId),
  securityInstance: enhancedSecurityAi // Export instance for advanced usage
};