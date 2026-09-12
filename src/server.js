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
const securityMiddleware = require('./middleware/security');
const { getCorsMiddleware, corsErrorHandler } = require('./middleware/cors');
const { createEdgeProxyGuard } = require('./middleware/edgeProxy');
const { checkBinaries } = require('./services/pngOptimizer');

// Initialize Express app
const app = express();

// Get configuration from environment
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';

// Trust proxy (important for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// Security headers and CORS. These are mounted before body parsing and routing
// so that every response — including 404s, 413s, and error responses — carries
// them. `securityMiddleware` is the header/limit layer only; see the note in
// middleware/security.js for what is deliberately left out and why.
app.use(securityMiddleware);
app.use(getCorsMiddleware());

// Reject requests that did not come through the Cloudflare Worker, and mark the
// client IP as trustworthy on the ones that did. Mounted before the routes so a
// direct hit is turned away before it reaches any handler.
app.use(createEdgeProxyGuard());

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
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
  const { webhookReceiver } = require('./routes/webhook');

  // Health check routes
  app.use(healthRoutes);

  // Webhook receiver route (not under /api prefix)
  app.all('/webhook/:id', webhookReceiver);

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

// Turn CORS rejections into a clean 403 before the generic handler logs them
// as unexpected server errors.
app.use(corsErrorHandler);

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

/**
 * Refuse to start in a misconfigured production state.
 *
 * These are conditions where the process would come up looking healthy while
 * silently serving unauthenticated traffic, which is worse than not starting.
 */
const assertProductionConfig = () => {
  if (NODE_ENV !== 'production') return;

  const problems = [];

  if (!process.env.API_SECRET_TOKEN) {
    problems.push('API_SECRET_TOKEN is not set - every protected endpoint would reject or be open');
  }
  if (process.env.DISABLE_API_AUTH === 'true') {
    problems.push('DISABLE_API_AUTH=true is set in production');
  }
  if (process.env.TURNSTILE_DISABLED === 'true' && process.env.ALLOW_DIRECT_ORIGIN !== 'true') {
    problems.push('TURNSTILE_DISABLED=true is set in production - the contact form would be an open mail relay. Only allowed together with ALLOW_DIRECT_ORIGIN=true (emergency no-Cloudflare mode).');
  }
  if (!process.env.TURNSTILE_SECRET_KEY && process.env.TURNSTILE_DISABLED !== 'true') {
    problems.push('TURNSTILE_SECRET_KEY is not set - the contact form would fail closed for real users');
  }
  if (!process.env.CORS_ORIGIN) {
    problems.push('CORS_ORIGIN is not set - production CORS rejects everything');
  }
  // The Worker builds its own header set for forwarded requests and never
  // forwards the browser's Origin header, so production CORS (which checks
  // Origin) would reject every one of those requests unless this is set.
  if (process.env.ALLOW_NO_ORIGIN !== 'true' && process.env.ALLOW_DIRECT_ORIGIN !== 'true') {
    problems.push('ALLOW_NO_ORIGIN is not set - requests forwarded by the Worker carry no Origin header and production CORS would reject every one of them');
  }
  // Not required when the operator has explicitly declared there is no edge in
  // front (VPS-only deployment, or a migration away from Cloudflare).
  if (!process.env.EDGE_SECRET && process.env.ALLOW_DIRECT_ORIGIN !== 'true') {
    problems.push(
      'EDGE_SECRET is not set - the origin would accept direct requests, letting callers bypass the Worker ' +
      'and forge X-Forwarded-For. If this deployment genuinely has no edge in front, set ALLOW_DIRECT_ORIGIN=true.'
    );
  }

  // Warning, not a hard failure: binding to all interfaces is correct inside a
  // container (the host port mapping needs it) but wrong on a bare VM, where it
  // publishes the API on the public IP and lets callers bypass nginx, Cloudflare
  // and the Worker by hitting <vm-ip>:<port> directly. Only the operator knows
  // which topology this is, so surface it rather than refuse to start.
  if (HOST === '0.0.0.0' && !process.env.EDGE_SECRET) {
    logger.warn(
      `Listening on 0.0.0.0:${PORT} in production with no EDGE_SECRET. If this host is not ` +
      'inside a container behind a reverse proxy, the API is reachable directly on the public ' +
      'IP, bypassing the edge. Bind to 127.0.0.1 and let nginx proxy to it, or set EDGE_SECRET.'
    );
  }

  if (problems.length) {
    logger.error('Refusing to start: production configuration is unsafe', { problems });
    problems.forEach((p) => console.error(`  ✗ ${p}`));
    process.exit(1);
  }
};

// Initialize server
const startServer = async () => {
  try {
    logger.info('Starting server initialization...');

    assertProductionConfig();

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

    // Probe the external PNG compressors. Missing binaries are not fatal: the
    // PNG route degrades to returning the upload untouched / the Sharp fallback.
    try {
      const pngBinaries = await checkBinaries();
      if (!pngBinaries.pngquant || !pngBinaries.optipng) {
        logger.warn('PNG compression will fall back to Sharp \u2014 install with: apt install pngquant optipng', pngBinaries);
      } else {
        logger.info('PNG compression binaries available', pngBinaries);
      }
    } catch (error) {
      logger.warn('PNG compression binary check failed', { error: error.message });
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
