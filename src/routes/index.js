const express = require('express');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess } = require('../middleware/errorHandler');

const router = express.Router();

/**
 * API Root Endpoint
 */
router.get('/', basicRateLimit, (req, res) => {
  const apiInfo = {
    name: 'ToolzyHub API',
    version: process.env.API_VERSION || 'v1',
    description: 'Secure Node.js API server for ToolzyHub with token protection and rate limiting',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    endpoints: {
      health: '/health',
      version: '/version',
      status: '/status',
      metrics: '/metrics',
      compress: '/api/compress',
      convert: '/api/convert',
      format: '/api/format',
      hash: '/api/hash',
      ai: '/api/ai',
      ssl: '/api/ssl',
      fetch: '/api/fetch',
      canonical: '/api/canonical',
      cors: '/api/cors',
      contact: '/api/contact',
      subscribe: '/api/subscribe',
      ogImage: '/api/og-image',
      httpHeaders: '/api/http-headers',
      webhooks: '/api/webhooks',
      htmlValidator: '/api/html-validator'
      // Add more endpoints as they are created
      // auth: '/api/v1/auth',
      // upload: '/api/v1/upload',
      // tools: '/api/v1/tools'
    },
    documentation: {
      swagger: '/api/docs', // Future implementation
      postman: '/api/postman' // Future implementation
    },
    support: {
      email: 'info@toolzyhub.app',
      github: 'https://github.com/toolzyhub/api'
    }
  };

  sendSuccess(res, 'Welcome to ToolzyHub API', apiInfo);
});

/**
 * API Information Endpoint
 */
router.get('/info', basicRateLimit, (req, res) => {
  const info = {
    api: {
      name: 'ToolzyHub API',
      version: process.env.API_VERSION || 'v1',
      description: 'Secure Node.js API server for ToolzyHub',
      author: 'ToolzyHub Team',
      license: 'MIT'
    },
    server: {
      environment: process.env.NODE_ENV || 'development',
      node_version: process.version,
      uptime: process.uptime(),
      memory_usage: process.memoryUsage(),
      platform: process.platform,
      arch: process.arch
    },
    features: {
      authentication: {
        jwt: true,
        api_keys: true,
        refresh_tokens: true
      },
      security: {
        rate_limiting: true,
        cors: true,
        helmet: true,
        xss_protection: true,
        sql_injection_protection: true,
        brute_force_protection: true
      },
      file_handling: {
        image_processing: true,
        ai_background_removal: true,
        file_uploads: true,
        sharp_integration: true
      },
      ai_capabilities: {
        background_removal: true,
        device_capability_detection: true,
        intelligent_processing: true,
        client_server_fallback: true
      },
      monitoring: {
        health_checks: true,
        metrics: true,
        logging: true
      },
      caching: {
        redis: process.env.REDIS_HOST ? true : false
      }
    },
    limits: {
      max_file_size: process.env.MAX_FILE_SIZE || '10MB',
      max_ai_file_size: '20MB',
      rate_limit: {
        window: process.env.RATE_LIMIT_WINDOW_MS || '15 minutes',
        max_requests: process.env.RATE_LIMIT_MAX_REQUESTS || 100
      }
    }
  };

  sendSuccess(res, 'API information retrieved', info);
});

/**
 * API Documentation Endpoint (placeholder)
 */
router.get('/docs', basicRateLimit, (req, res) => {
  const docs = {
    message: 'API Documentation',
    swagger_ui: '/api/docs/swagger', // Future implementation
    openapi_spec: '/api/docs/openapi.json', // Future implementation
    postman_collection: '/api/docs/postman.json', // Future implementation
    endpoints: {
      authentication: {
        login: 'POST /api/v1/auth/login',
        register: 'POST /api/v1/auth/register',
        refresh: 'POST /api/v1/auth/refresh',
        logout: 'POST /api/v1/auth/logout'
      },
      file_operations: {
        upload: 'POST /api/v1/upload',
        process_image: 'POST /api/v1/upload/process',
        delete: 'DELETE /api/v1/upload/:id'
      },
      ai_processing: {
        remove_background: 'POST /api/ai/remove-background',
        check_device_capability: 'POST /api/ai/check-device-capability',
        ai_info: 'GET /api/ai/info'
      },
      image_compression: {
        compress_jpg: 'POST /api/compress/jpg',
        compress_png: 'POST /api/compress/png',
        compress_webp: 'POST /api/compress/webp',
        batch_compress: 'POST /api/compress/batch',
        compression_info: 'GET /api/compress/info'
      },
      image_conversion: {
        jpg_to_png: 'POST /api/convert/jpg-to-png',
        png_to_jpg: 'POST /api/convert/png-to-jpg',
        png_to_webp: 'POST /api/convert/png-to-webp',
        png_to_avif: 'POST /api/convert/png-to-avif',
        jpg_to_webp: 'POST /api/convert/jpg-to-webp',
        jpg_to_avif: 'POST /api/convert/jpg-to-avif',
        webp_to_avif: 'POST /api/convert/webp_to_avif',
        webp_to_jpg: 'POST /api/convert/webp_to_jpg',
        webp_to_png: 'POST /api/convert/webp_to_png',
        avif_to_png: 'POST /api/convert/avif_to_png',
        avif_to_jpg: 'POST /api/convert/avif_to_jpg',
        avif_to_webp: 'POST /api/convert/avif_to_webp',
        image_to_base64: 'POST /api/convert/image-to-base64',
        base64_to_image: 'POST /api/convert/base64-to-image',
        conversion_info: 'GET /api/convert/info'
      },
      health_monitoring: {
        health: 'GET /health',
        detailed_health: 'GET /health/detailed',
        readiness: 'GET /ready',
        liveness: 'GET /live',
        metrics: 'GET /metrics',
        status: 'GET /status',
        version: 'GET /version'
      }
    },
    authentication: {
      type: 'Bearer Token or API Key',
      header: 'Authorization: Bearer <token> or X-API-Key: <api_key>',
      token_expiry: process.env.JWT_EXPIRES_IN || '24h'
    },
    error_handling: {
      format: {
        success: false,
        message: 'Error description',
        timestamp: 'ISO 8601 timestamp',
        errors: 'Array of detailed errors (optional)'
      },
      status_codes: {
        200: 'Success',
        201: 'Created',
        400: 'Bad Request',
        401: 'Unauthorized',
        403: 'Forbidden',
        404: 'Not Found',
        413: 'Payload Too Large',
        429: 'Too Many Requests',
        500: 'Internal Server Error'
      }
    }
  };

  sendSuccess(res, 'API documentation', docs);
});

// Import and use route modules as they are created2
const aiRoutes = require('./ai');
const compressRoutes = require('./compress');
const convertRoutes = require('./convert');
const hashRoutes = require('./hash');
const formatRoutes = require('./format');
const contactRoutes = require('./contact');
const subscribeRoutes = require('./subscribe');
const healthRoutes = require('./health');
const sslRoutes = require('./ssl');
const fetchRoutes = require('./fetch');
const canonicalRoutes = require('./canonical');
const corsRoutes = require('./cors');
const ogImageRoutes = require('./ogImageRoutes');
const httpHeadersRoutes = require('./httpHeaders');
const { router: webhookRoutes } = require('./webhook');
const htmlValidatorRoutes = require('./htmlValidator');

// Register routes
router.use('/webhooks', webhookRoutes);
router.use('/ai', aiRoutes);
router.use('/compress', compressRoutes);
router.use('/convert', convertRoutes);
router.use('/format', formatRoutes);
router.use('/contact', contactRoutes);
router.use('/hash', hashRoutes);
router.use('/health', healthRoutes);
router.use('/ssl', sslRoutes);
router.use('/fetch', fetchRoutes);
router.use('/canonical', canonicalRoutes);
router.use('/cors', corsRoutes);
router.use('/subscribe', subscribeRoutes);
router.use('/og-image', ogImageRoutes);
router.use('/og', ogImageRoutes); // Also handle /api/og/* routes
router.use('/http-headers', httpHeadersRoutes);
router.use('/html-validator', htmlValidatorRoutes);

// Example for future routes:
// const authRoutes = require('./auth');
// const uploadRoutes = require('./upload');
// const toolsRoutes = require('./tools');

// router.use('/auth', authRoutes);
// router.use('/upload', uploadRoutes);
// router.use('/tools', toolsRoutes);

module.exports = router;