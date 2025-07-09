const logger = require('../utils/logger');
const ipBanManager = require('../utils/ipBanManager');
const securityNotifier = require('../utils/securityNotifier');

/**
 * Enhanced Security Middleware
 * Combines token validation, IP banning, and security notifications
 */
class EnhancedSecurity {
  constructor() {
    this.apiSecretToken = process.env.API_SECRET_TOKEN;
    
    if (!this.apiSecretToken) {
      logger.error('API_SECRET_TOKEN not configured - enhanced security disabled');
    }
  }

  /**
   * Main enhanced security middleware
   */
  middleware() {
    return async (req, res, next) => {
      const startTime = Date.now();
      const ip = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';
      const endpoint = req.originalUrl;

      try {
        // Step 1: Check if IP is banned
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

        // Step 2: Validate API token
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

        // Step 3: Token is valid - clear any failed attempts and proceed
        await ipBanManager.clearFailedAttempts(ip);

        // Add security info to request object
        req.security = {
          ip,
          authMethod,
          authenticatedAt: new Date().toISOString(),
          processingTime: Date.now() - startTime
        };

        // Log successful authentication
        logger.info('Request authenticated successfully', {
          ip,
          endpoint,
          authMethod,
          userAgent,
          processingTime: Date.now() - startTime
        });

        next();

      } catch (error) {
        logger.error('Enhanced security middleware error', {
          error: error.message,
          stack: error.stack,
          ip,
          endpoint,
          userAgent
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
   */
  optional() {
    return async (req, res, next) => {
      const ip = req.ip || req.connection.remoteAddress;
      const userAgent = req.get('User-Agent') || 'Unknown';
      const endpoint = req.originalUrl;

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

        // Check for token but don't require it
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
            req.security = {
              ip,
              authMethod,
              authenticated: true,
              authenticatedAt: new Date().toISOString()
            };
            
            logger.info('Optional auth - token validated', {
              ip,
              endpoint,
              authMethod
            });
          } else {
            // Invalid token provided - log but don't block
            logger.warn('Optional auth - invalid token provided', {
              ip,
              endpoint,
              authMethod,
              tokenLength: token.length
            });
            
            req.security = {
              ip,
              authenticated: false,
              reason: 'invalid_token'
            };
          }
        } else {
          // No token provided - that's okay for optional auth
          req.security = {
            ip,
            authenticated: false,
            reason: 'no_token'
          };
        }

        next();

      } catch (error) {
        logger.error('Optional security middleware error', {
          error: error.message,
          ip,
          endpoint
        });

        // For optional auth, continue even if there's an error
        req.security = {
          ip,
          authenticated: false,
          reason: 'security_error'
        };
        
        next();
      }
    };
  }

  /**
   * Get security statistics
   */
  async getSecurityStats() {
    try {
      const banStats = await ipBanManager.getBanStats();
      
      return {
        security: {
          tokenProtection: !!this.apiSecretToken,
          maxFailedAttempts: ipBanManager.maxFailedAttempts,
          banDurationHours: ipBanManager.banDurationHours,
          securityEmail: process.env.SECURITY_EMAIL
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
const enhancedSecurity = new EnhancedSecurity();

module.exports = {
  enhancedSecurity: enhancedSecurity.middleware(),
  enhancedSecurityWithRateLimit: (rateLimitMiddleware) => enhancedSecurity.withRateLimit(rateLimitMiddleware),
  optionalSecurity: enhancedSecurity.optional(),
  getSecurityStats: () => enhancedSecurity.getSecurityStats()
};
