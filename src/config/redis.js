const redis = require('redis');
const logger = require('../utils/logger');

let redisClient = null;

/**
 * Connect to Redis
 */
const connectRedis = async () => {
    
  try {
    const redisConfig = {
      socket: {
        host: process.env.REDIS_HOST || 'localhost',
        port: parseInt(process.env.REDIS_PORT) || 6379,
        connectTimeout: 10000,
        commandTimeout: 5000,
        keepAlive: 30000
      },
      database: parseInt(process.env.REDIS_DB) || 0
    };

    // Add password if provided
    if (process.env.REDIS_PASSWORD) {
      redisConfig.password = process.env.REDIS_PASSWORD;
    }

    // Create Redis client
    redisClient = redis.createClient(redisConfig);

    // Event listeners
    redisClient.on('connect', () => {
      logger.info('Redis client connected');
    });

    redisClient.on('ready', () => {
      logger.info('Redis client ready');
    });

    redisClient.on('error', (error) => {
      logger.error('Redis client error:', error);
    });

    redisClient.on('end', () => {
      logger.info('Redis client disconnected');
    });

    redisClient.on('reconnecting', () => {
      logger.info('Redis client reconnecting...');
    });

    // Connect to Redis
    await redisClient.connect();

    // Test connection
    await redisClient.ping();
    logger.info('Redis connection established successfully');

    // Store client globally for access in other modules
    global.redisClient = redisClient;

    return redisClient;
  } catch (error) {
    logger.error('Failed to connect to Redis:', error);
    throw error;
  }
};

/**
 * Get Redis client instance
 */
const getRedisClient = () => {
  if (!redisClient || !redisClient.isOpen) {
    logger.warn('Redis client not available');
    return null;
  }
  return redisClient;
};

/**
 * Close Redis connection
 */
const closeRedis = async () => {
  if (redisClient && redisClient.isOpen) {
    try {
      await redisClient.quit();
      logger.info('Redis connection closed');
    } catch (error) {
      logger.error('Error closing Redis connection:', error);
    }
  }
};

/**
 * Redis utility functions
 */
const redisUtils = {
  /**
   * Set key with expiration
   */
  setex: async (key, seconds, value) => {
    const client = getRedisClient();
    if (!client) return false;
    
    try {
      await client.setEx(key, seconds, JSON.stringify(value));
      return true;
    } catch (error) {
      logger.error(`Redis SETEX error for key ${key}:`, error);
      return false;
    }
  },

  /**
   * Get key value
   */
  get: async (key) => {
    const client = getRedisClient();
    if (!client) return null;
    
    try {
      const value = await client.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error(`Redis GET error for key ${key}:`, error);
      return null;
    }
  },

  /**
   * Delete key
   */
  del: async (key) => {
    const client = getRedisClient();
    if (!client) return false;
    
    try {
      await client.del(key);
      return true;
    } catch (error) {
      logger.error(`Redis DEL error for key ${key}:`, error);
      return false;
    }
  },

  /**
   * Check if key exists
   */
  exists: async (key) => {
    const client = getRedisClient();
    if (!client) return false;
    
    try {
      const result = await client.exists(key);
      return result === 1;
    } catch (error) {
      logger.error(`Redis EXISTS error for key ${key}:`, error);
      return false;
    }
  },

  /**
   * Increment key value
   */
  incr: async (key) => {
    const client = getRedisClient();
    if (!client) return null;
    
    try {
      return await client.incr(key);
    } catch (error) {
      logger.error(`Redis INCR error for key ${key}:`, error);
      return null;
    }
  },

  /**
   * Set key expiration
   */
  expire: async (key, seconds) => {
    const client = getRedisClient();
    if (!client) return false;
    
    try {
      await client.expire(key, seconds);
      return true;
    } catch (error) {
      logger.error(`Redis EXPIRE error for key ${key}:`, error);
      return false;
    }
  },

  /**
   * Get keys by pattern
   */
  keys: async (pattern) => {
    const client = getRedisClient();
    if (!client) return [];
    
    try {
      return await client.keys(pattern);
    } catch (error) {
      logger.error(`Redis KEYS error for pattern ${pattern}:`, error);
      return [];
    }
  },

  /**
   * Flush all keys (use with caution)
   */
  flushall: async () => {
    const client = getRedisClient();
    if (!client) return false;
    
    try {
      await client.flushAll();
      logger.warn('Redis FLUSHALL executed - all keys deleted');
      return true;
    } catch (error) {
      logger.error('Redis FLUSHALL error:', error);
      return false;
    }
  }
};

module.exports = {
  connectRedis,
  getRedisClient,
  closeRedis,
  redisUtils
};
