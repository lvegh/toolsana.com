const express = require('express');
const dotenv = require('dotenv');
const path = require('path');

// Load environment variables
dotenv.config();

// Import core modules
const logger = require('./utils/logger');
const { connectRedis } = require('./config/redis');
const { sendSuccess, sendError } = require('./middleware/errorHandler');
const { createUploadsDir } = require('./utils/fileSystem');

// Initialize Express app
const app = express();

// Get configuration from environment
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';

// Trust proxy (important for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// Body parsing middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression middleware
const compression = require('compression');
app.use(compression());

// Static files middleware for uploads
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Request logging middleware
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.originalUrl}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });
  next();
});

// Basic test route
app.get('/test', (req, res) => {
  sendSuccess(res, 'Server is working!', {
    timestamp: new Date().toISOString(),
    redis: global.redisClient ? 'connected' : 'not connected',
    environment: NODE_ENV
  });
});

// Health check route
app.get('/health', (req, res) => {
  sendSuccess(res, 'Server is healthy', {
    status: 'OK',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV,
    redis: global.redisClient ? 'connected' : 'not connected'
  });
});

// Import and use routes
try {
  const healthRoutes = require('./routes/health');
  const apiRoutes = require('./routes');
  
  // Health check routes
  app.use(healthRoutes);
  
  // API routes
  const API_PREFIX = process.env.API_PREFIX || '/api';
  app.use(API_PREFIX, apiRoutes);
  
  logger.info('Routes loaded successfully');
} catch (error) {
  logger.error('Error loading routes:', error);
}

// 404 handler
app.use('*', (req, res) => {
  sendError(res, 'Route not found', 404, { path: req.originalUrl });
});

// Basic error handler
app.use((err, req, res, next) => {
  logger.error('Server error:', err);
  
  if (res.headersSent) {
    return next(err);
  }
  
  sendError(res, 'Internal server error', 500);
});

// Graceful shutdown handler
const gracefulShutdown = (server) => (signal) => {
  logger.info(`Received ${signal}. Starting graceful shutdown...`);

  server.close(() => {
    logger.info('HTTP server closed.');

    // Close Redis connection if exists
    if (global.redisClient) {
      global.redisClient.quit(() => {
        logger.info('Redis connection closed.');
        process.exit(0);
      });
    } else {
      process.exit(0);
    }
  });

  // Force close after 30 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30000);
};

// Initialize server
const startServer = async () => {
  try {
    logger.info('Starting server initialization...');

    // Create uploads directory if it doesn't exist
    await createUploadsDir();
    logger.info('Uploads directory ready');

    // Connect to Redis (optional)
    if (process.env.REDIS_HOST) {
      try {
        logger.info('Attempting Redis connection...');
        await connectRedis();
        logger.info('Redis connected successfully');
      } catch (error) {
        logger.warn('Redis connection failed, continuing without Redis', { error: error.message });
      }
    } else {
      logger.info('Redis not configured, skipping connection');
    }

    // Start HTTP server
    const server = app.listen(PORT, HOST, () => {
      logger.info(`🚀 Server running on ${HOST}:${PORT}`, {
        environment: NODE_ENV,
        pid: process.pid,
        timestamp: new Date().toISOString()
      });
    });

    // Set server timeout
    server.timeout = 30000;

    // Handle graceful shutdown
    process.on('SIGTERM', gracefulShutdown(server));
    process.on('SIGINT', gracefulShutdown(server));

    // Handle uncaught exceptions
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      gracefulShutdown(server)('UNCAUGHT_EXCEPTION');
    });

    // Handle unhandled promise rejections
    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
      gracefulShutdown(server)('UNHANDLED_REJECTION');
    });

    return server;

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

console.log('=== TOOLZYHUB API SERVER ===');
console.log('Environment variables:', {
  NODE_ENV: NODE_ENV,
  PORT: PORT,
  HOST: HOST,
  REDIS_HOST: process.env.REDIS_HOST || 'not configured',
  REDIS_PORT: process.env.REDIS_PORT || 'not configured',
  API_PREFIX: process.env.API_PREFIX || '/api'
});
console.log('============================');

// Start the server
startServer();

module.exports = app;
