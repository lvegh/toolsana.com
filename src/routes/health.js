const express = require('express');
const os = require('os');
const { getRedisClient } = require('../config/redis');
const { getDirectorySize, formatFileSize } = require('../utils/fileSystem');
const logger = require('../utils/logger');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { basicRateLimit } = require('../middleware/rateLimit');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');

const router = express.Router();

/**
 * Basic Health Check
 */
router.get('/health', enhancedSecurityWithRateLimit(basicRateLimit), (req, res) => {
  const healthCheck = {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: process.env.NODE_ENV || 'development',
    version: process.env.npm_package_version || '1.0.0',
    node_version: process.version
  };

  sendSuccess(res, 'Server is healthy', healthCheck);
});

/**
 * Detailed Health Check
 */
router.get('/health/detailed', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const startTime = Date.now();
    
    // System Information
    const systemInfo = {
      platform: os.platform(),
      arch: os.arch(),
      hostname: os.hostname(),
      uptime: os.uptime(),
      loadavg: os.loadavg(),
      totalmem: formatFileSize(os.totalmem()),
      freemem: formatFileSize(os.freemem()),
      cpus: os.cpus().length
    };

    // Process Information
    const processInfo = {
      pid: process.pid,
      uptime: process.uptime(),
      memory: {
        rss: formatFileSize(process.memoryUsage().rss),
        heapTotal: formatFileSize(process.memoryUsage().heapTotal),
        heapUsed: formatFileSize(process.memoryUsage().heapUsed),
        external: formatFileSize(process.memoryUsage().external)
      },
      cpu: process.cpuUsage()
    };

    // Redis Health Check
    let redisStatus = 'disconnected';
    let redisInfo = null;
    try {
      const redisClient = getRedisClient();
      if (redisClient && redisClient.isOpen) {
        await redisClient.ping();
        redisStatus = 'connected';
        redisInfo = {
          status: 'connected',
          ready: redisClient.isReady
        };
      }
    } catch (error) {
      redisStatus = 'error';
      redisInfo = { error: error.message };
    }

    // File System Health Check
    let uploadsSize = 0;
    try {
      uploadsSize = await getDirectorySize('./uploads');
    } catch (error) {
      logger.warn('Could not get uploads directory size:', error.message);
    }

    // Response Time
    const responseTime = Date.now() - startTime;

    const healthCheck = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      responseTime: `${responseTime}ms`,
      environment: process.env.NODE_ENV || 'development',
      version: process.env.npm_package_version || '1.0.0',
      system: systemInfo,
      process: processInfo,
      services: {
        redis: {
          status: redisStatus,
          ...redisInfo
        }
      },
      storage: {
        uploads: {
          size: formatFileSize(uploadsSize)
        }
      }
    };

    sendSuccess(res, 'Detailed health check completed', healthCheck);
  } catch (error) {
    logger.error('Health check error:', error);
    sendError(res, 'Health check failed', 500);
  }
});

/**
 * Readiness Check (for Kubernetes/Docker)
 */
router.get('/ready', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const checks = [];
    let allReady = true;

    // Check Redis connection (if configured)
    if (process.env.REDIS_HOST) {
      try {
        const redisClient = getRedisClient();
        if (redisClient && redisClient.isOpen) {
          await redisClient.ping();
          checks.push({ service: 'redis', status: 'ready' });
        } else {
          checks.push({ service: 'redis', status: 'not ready' });
          allReady = false;
        }
      } catch (error) {
        checks.push({ service: 'redis', status: 'error', error: error.message });
        allReady = false;
      }
    }

    // Check file system
    try {
      const fs = require('fs');
      fs.accessSync('./uploads', fs.constants.W_OK);
      checks.push({ service: 'filesystem', status: 'ready' });
    } catch (error) {
      checks.push({ service: 'filesystem', status: 'not ready', error: error.message });
      allReady = false;
    }

    const readinessCheck = {
      ready: allReady,
      timestamp: new Date().toISOString(),
      checks
    };

    if (allReady) {
      sendSuccess(res, 'Service is ready', readinessCheck);
    } else {
      sendError(res, 'Service is not ready', 503, readinessCheck);
    }
  } catch (error) {
    logger.error('Readiness check error:', error);
    sendError(res, 'Readiness check failed', 500);
  }
});

/**
 * Liveness Check (for Kubernetes/Docker)
 */
router.get('/live', enhancedSecurityWithRateLimit(basicRateLimit), (req, res) => {
  const livenessCheck = {
    alive: true,
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage()
  };

  sendSuccess(res, 'Service is alive', livenessCheck);
});

/**
 * Metrics Endpoint
 */
router.get('/metrics', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const metrics = {
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      memory: {
        usage: process.memoryUsage(),
        system: {
          total: os.totalmem(),
          free: os.freemem(),
          used: os.totalmem() - os.freemem()
        }
      },
      cpu: {
        usage: process.cpuUsage(),
        loadavg: os.loadavg(),
        cores: os.cpus().length
      },
      system: {
        platform: os.platform(),
        arch: os.arch(),
        hostname: os.hostname(),
        uptime: os.uptime()
      }
    };

    // Add Redis metrics if available
    try {
      const redisClient = getRedisClient();
      if (redisClient && redisClient.isOpen) {
        metrics.redis = {
          connected: true,
          ready: redisClient.isReady
        };
      } else {
        metrics.redis = { connected: false };
      }
    } catch (error) {
      metrics.redis = { connected: false, error: error.message };
    }

    sendSuccess(res, 'Metrics retrieved', metrics);
  } catch (error) {
    logger.error('Metrics error:', error);
    sendError(res, 'Failed to retrieve metrics', 500);
  }
});

/**
 * Version Information
 */
router.get('/version', enhancedSecurityWithRateLimit(basicRateLimit), (req, res) => {
  const versionInfo = {
    name: 'toolzyhub-api',
    version: process.env.npm_package_version || '1.0.0',
    node_version: process.version,
    environment: process.env.NODE_ENV || 'development',
    api_version: process.env.API_VERSION || 'v1',
    build_date: process.env.BUILD_DATE || new Date().toISOString(),
    git_commit: process.env.GIT_COMMIT || 'unknown'
  };

  sendSuccess(res, 'Version information', versionInfo);
});

/**
 * Status Summary
 */
router.get('/status', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const status = {
      service: 'toolzyhub-api',
      status: 'operational',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      version: process.env.npm_package_version || '1.0.0',
      environment: process.env.NODE_ENV || 'development'
    };

    // Check critical services
    const services = {};

    // Redis status
    try {
      const redisClient = getRedisClient();
      if (redisClient && redisClient.isOpen) {
        await redisClient.ping();
        services.redis = 'operational';
      } else {
        services.redis = 'unavailable';
      }
    } catch (error) {
      services.redis = 'error';
    }

    // File system status
    try {
      const fs = require('fs');
      fs.accessSync('./uploads', fs.constants.W_OK);
      services.filesystem = 'operational';
    } catch (error) {
      services.filesystem = 'error';
    }

    status.services = services;

    // Determine overall status
    const serviceStatuses = Object.values(services);
    if (serviceStatuses.includes('error')) {
      status.status = 'degraded';
    } else if (serviceStatuses.includes('unavailable')) {
      status.status = 'partial';
    }

    sendSuccess(res, 'Status retrieved', status);
  } catch (error) {
    logger.error('Status check error:', error);
    sendError(res, 'Status check failed', 500);
  }
});

module.exports = router;
