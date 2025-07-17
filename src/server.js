// src/server-stripped.js - Stripped to standalone level for debugging
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');
const { createUploadsDir } = require('./utils/fileSystem');
const { connectRedis } = require('./config/redis');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();

// Get configuration from environment
const PORT = process.env.PORT || 3001;
const HOST = process.env.HOST || '0.0.0.0';
const NODE_ENV = process.env.NODE_ENV || 'development';

// Trust proxy (important for rate limiting behind reverse proxy)
app.set('trust proxy', 1);

// ===== MINIMAL MIDDLEWARE (SAME AS STANDALONE) =====

// Body parsing middleware - BASIC ONLY
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Compression middleware
const compression = require('compression');
app.use(compression());

// Basic CORS - SIMPLE VERSION
app.use(cors());

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${req.method} ${req.originalUrl}`, {
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    timestamp: new Date().toISOString()
  });
  next();
});

// Static files middleware for uploads
const path = require('path');
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Basic test route (same as standalone)
app.get('/test', (req, res) => {
  res.json({
    success: true,
    message: 'Server is working!',
    data: {
      timestamp: new Date().toISOString(),
      environment: NODE_ENV
    }
  });
});

// Health check route (same as standalone)
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    environment: NODE_ENV
  });
});

// ===== STEP 1: ADD AI ROUTES ONLY =====
// Import ONLY the AI routes first to test if they work
try {
  const aiRoutes = require('./routes/ai-standalone'); // We'll create this
  app.use('/api/ai', aiRoutes);

  console.log('✅ AI routes loaded successfully');
} catch (error) {
  console.error('❌ Error loading AI routes:', error);
}

try {
  // Test hash routes first (they don't use complex middleware)
  const hashRoutes = require('./routes/hash');
  app.use('/api/hash', hashRoutes);
  console.log('✅ Hash routes loaded');
} catch (error) {
  console.error('❌ Error loading hash routes:', error);
}

// 404 handler - SIMPLE
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    message: 'Route not found',
    path: req.originalUrl
  });
});

// Error handler - SIMPLE
app.use((err, req, res, next) => {
  console.error('Server error:', err);

  if (res.headersSent) {
    return next(err);
  }

  res.status(500).json({
    success: false,
    message: 'Internal server error'
  });
});

// Initialize server - SIMPLE
const startServer = async () => {
  try {
    console.log('Starting STRIPPED server...');

    // Create uploads directory if it doesn't exist
    await createUploadsDir();
    console.log('Uploads directory ready');

    // Connect to Redis (optional)
    if (process.env.REDIS_HOST) {
      try {
        console.log('Attempting Redis connection...');
        await connectRedis();
        console.log('Redis connected successfully');
      } catch (error) {
        console.warn('Redis connection failed, continuing without Redis', { error: error.message });
      }
    } else {
      console.log('Redis not configured, skipping connection');
    }

    // Start HTTP server
    const server = app.listen(PORT, HOST, () => {
      console.log(`🚀 STRIPPED Server running on ${HOST}:${PORT}`);
      console.log(`Environment: ${NODE_ENV}`);
      console.log(`PID: ${process.pid}`);
      console.log('Middleware: MINIMAL (standalone level)');
    });

    // Set server timeout
    server.timeout = 30000;

    return server;

  } catch (error) {
    console.error('Failed to start server:', error);
    process.exit(1);
  }
};

console.log('=== TOOLZYHUB STRIPPED SERVER (DEBUG) ===');
console.log('Purpose: Find what causes ONNX crashes');
console.log('Level: Standalone equivalent');
console.log('AI Routes: Enabled');
console.log('Other Routes: Commented out');
console.log('Middleware: Minimal only');
console.log('=======================================');

// Start the server
startServer();

module.exports = app;