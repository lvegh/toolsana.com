// src/server-stripped.js - Stripped to standalone level for debugging
const express = require('express');
const dotenv = require('dotenv');
const cors = require('cors');

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

// ===== STEP 2: UNCOMMENT TO TEST OTHER ROUTES GRADUALLY =====
/*
// Add other routes one by one to find the culprit
try {
  // Test compress routes first
  const compressRoutes = require('./routes/compress');
  app.use('/api/compress', compressRoutes);
  console.log('✅ Compress routes loaded');
} catch (error) {
  console.error('❌ Error loading compress routes:', error);
}

try {
  // Test convert routes
  const convertRoutes = require('./routes/convert');
  app.use('/api/convert', convertRoutes);
  console.log('✅ Convert routes loaded');
} catch (error) {
  console.error('❌ Error loading convert routes:', error);
}

try {
  // Test hash routes
  const hashRoutes = require('./routes/hash');
  app.use('/api/hash', hashRoutes);
  console.log('✅ Hash routes loaded');
} catch (error) {
  console.error('❌ Error loading hash routes:', error);
}

try {
  // Test format routes
  const formatRoutes = require('./routes/format');
  app.use('/api/format', formatRoutes);
  console.log('✅ Format routes loaded');
} catch (error) {
  console.error('❌ Error loading format routes:', error);
}

try {
  // Test contact routes
  const contactRoutes = require('./routes/contact');
  app.use('/api/contact', contactRoutes);
  console.log('✅ Contact routes loaded');
} catch (error) {
  console.error('❌ Error loading contact routes:', error);
}

try {
  // Test subscribe routes
  const subscribeRoutes = require('./routes/subscribe');
  app.use('/api/subscribe', subscribeRoutes);
  console.log('✅ Subscribe routes loaded');
} catch (error) {
  console.error('❌ Error loading subscribe routes:', error);
}

try {
  // Test health routes
  const healthRoutes = require('./routes/health');
  app.use('/health', healthRoutes);
  console.log('✅ Health routes loaded');
} catch (error) {
  console.error('❌ Error loading health routes:', error);
}
*/

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