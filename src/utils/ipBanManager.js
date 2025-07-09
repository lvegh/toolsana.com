const logger = require('./logger');
const { redisUtils } = require('../config/redis');

/**
 * IP Ban Manager
 * Handles IP banning, tracking failed attempts, and ban management
 */
class IPBanManager {
  constructor() {
    this.maxFailedAttempts = parseInt(process.env.MAX_FAILED_ATTEMPTS) || 5;
    this.banDurationHours = parseInt(process.env.BAN_DURATION_HOURS) || 24;
    this.banDurationSeconds = this.banDurationHours * 60 * 60; // Convert to seconds
  }

  /**
   * Get Redis key for failed attempts counter
   */
  getFailedAttemptsKey(ip) {
    return `failed_attempts:${ip}`;
  }

  /**
   * Get Redis key for IP ban
   */
  getBanKey(ip) {
    return `banned_ip:${ip}`;
  }

  /**
   * Check if an IP is currently banned
   */
  async isBanned(ip) {
    try {
      if (!global.redisClient) {
        logger.warn('Redis not available, IP ban check skipped', { ip });
        return false;
      }

      const banData = await redisUtils.get(this.getBanKey(ip));
      if (banData) {
        const ban = JSON.parse(banData);
        logger.info('IP ban check - banned IP detected', {
          ip,
          bannedAt: ban.bannedAt,
          expiresAt: ban.expiresAt,
          reason: ban.reason
        });
        return ban;
      }

      return false;
    } catch (error) {
      logger.error('Error checking IP ban status', {
        error: error.message,
        ip
      });
      return false;
    }
  }

  /**
   * Get current failed attempts count for an IP
   */
  async getFailedAttempts(ip) {
    try {
      if (!global.redisClient) {
        return 0;
      }

      const count = await redisUtils.get(this.getFailedAttemptsKey(ip));
      return parseInt(count) || 0;
    } catch (error) {
      logger.error('Error getting failed attempts count', {
        error: error.message,
        ip
      });
      return 0;
    }
  }

  /**
   * Increment failed attempts counter for an IP
   */
  async incrementFailedAttempts(ip, requestInfo = {}) {
    try {
      if (!global.redisClient) {
        logger.warn('Redis not available, failed attempts tracking skipped', { ip });
        return 1;
      }

      const key = this.getFailedAttemptsKey(ip);
      const currentCount = await this.getFailedAttempts(ip);
      const newCount = currentCount + 1;

      // Set with 1 hour expiration (attempts reset after 1 hour of no activity)
      await redisUtils.setex(key, 3600, newCount.toString());

      // Log the failed attempt
      logger.warn('Failed authentication attempt recorded', {
        ip,
        attemptCount: newCount,
        maxAttempts: this.maxFailedAttempts,
        userAgent: requestInfo.userAgent,
        endpoint: requestInfo.endpoint,
        timestamp: new Date().toISOString()
      });

      return newCount;
    } catch (error) {
      logger.error('Error incrementing failed attempts', {
        error: error.message,
        ip
      });
      return 1;
    }
  }

  /**
   * Ban an IP address
   */
  async banIP(ip, reason = 'Too many failed authentication attempts', requestInfo = {}) {
    try {
      if (!global.redisClient) {
        logger.error('Redis not available, cannot ban IP', { ip });
        return false;
      }

      const now = new Date();
      const expiresAt = new Date(now.getTime() + (this.banDurationSeconds * 1000));

      const banData = {
        ip,
        reason,
        bannedAt: now.toISOString(),
        expiresAt: expiresAt.toISOString(),
        banDurationHours: this.banDurationHours,
        requestInfo: {
          userAgent: requestInfo.userAgent,
          endpoint: requestInfo.endpoint,
          failedAttempts: requestInfo.failedAttempts
        }
      };

      // Store ban with TTL
      await redisUtils.setex(
        this.getBanKey(ip),
        this.banDurationSeconds,
        JSON.stringify(banData)
      );

      // Clear failed attempts counter
      await redisUtils.del(this.getFailedAttemptsKey(ip));

      logger.error('IP address banned', {
        ip,
        reason,
        bannedAt: banData.bannedAt,
        expiresAt: banData.expiresAt,
        banDurationHours: this.banDurationHours,
        userAgent: requestInfo.userAgent,
        endpoint: requestInfo.endpoint,
        failedAttempts: requestInfo.failedAttempts
      });

      return banData;
    } catch (error) {
      logger.error('Error banning IP address', {
        error: error.message,
        ip,
        reason
      });
      return false;
    }
  }

  /**
   * Manually unban an IP address
   */
  async unbanIP(ip) {
    try {
      if (!global.redisClient) {
        logger.warn('Redis not available, cannot unban IP', { ip });
        return false;
      }

      await redisUtils.del(this.getBanKey(ip));
      await redisUtils.del(this.getFailedAttemptsKey(ip));

      logger.info('IP address manually unbanned', { ip });
      return true;
    } catch (error) {
      logger.error('Error unbanning IP address', {
        error: error.message,
        ip
      });
      return false;
    }
  }

  /**
   * Clear failed attempts for an IP (on successful authentication)
   */
  async clearFailedAttempts(ip) {
    try {
      if (!global.redisClient) {
        return true;
      }

      await redisUtils.del(this.getFailedAttemptsKey(ip));
      logger.info('Failed attempts cleared for IP', { ip });
      return true;
    } catch (error) {
      logger.error('Error clearing failed attempts', {
        error: error.message,
        ip
      });
      return false;
    }
  }

  /**
   * Get ban statistics
   */
  async getBanStats() {
    try {
      if (!global.redisClient) {
        return {
          totalBannedIPs: 0,
          recentBans: []
        };
      }

      // Get all banned IPs
      const banKeys = await redisUtils.keys('banned_ip:*');
      const bannedIPs = [];

      for (const key of banKeys) {
        try {
          const banData = await redisUtils.get(key);
          if (banData) {
            bannedIPs.push(JSON.parse(banData));
          }
        } catch (parseError) {
          logger.warn('Error parsing ban data', { key, error: parseError.message });
        }
      }

      return {
        totalBannedIPs: bannedIPs.length,
        recentBans: bannedIPs.sort((a, b) => new Date(b.bannedAt) - new Date(a.bannedAt)).slice(0, 10)
      };
    } catch (error) {
      logger.error('Error getting ban statistics', { error: error.message });
      return {
        totalBannedIPs: 0,
        recentBans: []
      };
    }
  }

  /**
   * Check if IP should be banned after failed attempt
   */
  async shouldBanIP(ip) {
    const failedAttempts = await this.getFailedAttempts(ip);
    return failedAttempts >= this.maxFailedAttempts;
  }

  /**
   * Get time until ban expires
   */
  getBanTimeRemaining(banData) {
    if (!banData || !banData.expiresAt) {
      return 0;
    }

    const now = new Date();
    const expiresAt = new Date(banData.expiresAt);
    const remainingMs = expiresAt.getTime() - now.getTime();

    return Math.max(0, Math.ceil(remainingMs / 1000)); // Return seconds
  }

  /**
   * Format ban time remaining for human reading
   */
  formatBanTimeRemaining(banData) {
    const seconds = this.getBanTimeRemaining(banData);
    
    if (seconds <= 0) {
      return 'Expired';
    }

    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const remainingSeconds = seconds % 60;

    if (hours > 0) {
      return `${hours}h ${minutes}m ${remainingSeconds}s`;
    } else if (minutes > 0) {
      return `${minutes}m ${remainingSeconds}s`;
    } else {
      return `${remainingSeconds}s`;
    }
  }
}

// Export singleton instance
module.exports = new IPBanManager();
