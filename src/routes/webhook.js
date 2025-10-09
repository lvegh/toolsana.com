const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { redisUtils } = require('../config/redis');
const { verifyApiKey } = require('../middleware/auth');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();

// Constants
const WEBHOOK_TTL = 60 * 60; // 1 hour in seconds
const MAX_REQUESTS_PER_WEBHOOK = 100;
const MAX_REQUEST_SIZE = 1024 * 1024; // 1MB

/**
 * Helper: Generate webhook metadata key
 */
const getMetadataKey = (id) => `webhook:${id}:metadata`;

/**
 * Helper: Generate webhook requests key
 */
const getRequestsKey = (id) => `webhook:${id}:requests`;

/**
 * Helper: Validate webhook ID format
 */
const isValidWebhookId = (id) => {
  return /^[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}$/i.test(id);
};

/**
 * Helper: Check if webhook exists and is not expired
 */
const getWebhookMetadata = async (id) => {
  try {
    const metadata = await redisUtils.get(getMetadataKey(id));

    if (!metadata) {
      return null;
    }

    // Check if expired
    if (Date.now() > metadata.expiresAt) {
      // Clean up expired webhook
      await redisUtils.del(getMetadataKey(id));
      await redisUtils.del(getRequestsKey(id));
      return null;
    }

    return metadata;
  } catch (error) {
    logger.error('Error getting webhook metadata:', error);
    return null;
  }
};

/**
 * POST /api/webhooks/create
 * Create a new webhook endpoint
 */
router.post('/create', verifyApiKey, async (req, res) => {
  try {
    // Generate unique webhook ID
    const webhookId = uuidv4();
    const now = Date.now();
    const expiresAt = now + (WEBHOOK_TTL * 1000);

    // Create webhook metadata
    const metadata = {
      id: webhookId,
      createdAt: now,
      expiresAt: expiresAt
    };

    // Store metadata in Redis with TTL
    const stored = await redisUtils.setex(
      getMetadataKey(webhookId),
      WEBHOOK_TTL,
      metadata
    );

    if (!stored) {
      logger.error('Failed to store webhook metadata in Redis');
      return sendError(res, 'Failed to create webhook. Please try again.', 500);
    }

    // Initialize empty requests array
    await redisUtils.setex(
      getRequestsKey(webhookId),
      WEBHOOK_TTL,
      []
    );

    // Construct webhook URL
    const baseUrl = process.env.API_BASE_URL || `http://localhost:${process.env.PORT || 3001}`;
    const webhookUrl = `${baseUrl}/webhook/${webhookId}`;

    logger.info('Webhook created', {
      webhookId,
      expiresAt: new Date(expiresAt).toISOString(),
      ip: req.ip
    });

    sendSuccess(res, 'Webhook created successfully', {
      id: webhookId,
      url: webhookUrl,
      expiresAt: expiresAt
    }, 201);

  } catch (error) {
    logger.error('Error creating webhook:', error);
    sendError(res, 'Internal server error', 500);
  }
});

/**
 * GET /api/webhooks/:id/requests
 * Get all requests received by a webhook
 */
router.get('/:id/requests', verifyApiKey, async (req, res) => {
  try {
    const webhookId = req.params.id;

    // Validate webhook ID format
    if (!isValidWebhookId(webhookId)) {
      return sendError(res, 'Invalid webhook ID format', 400);
    }

    // Check if webhook exists
    const metadata = await getWebhookMetadata(webhookId);
    if (!metadata) {
      return sendError(res, 'Webhook not found or expired', 404);
    }

    // Get requests from Redis
    const requests = await redisUtils.get(getRequestsKey(webhookId)) || [];

    sendSuccess(res, 'Requests retrieved successfully', {
      webhookId: webhookId,
      expiresAt: metadata.expiresAt,
      requestCount: requests.length,
      requests: requests
    });

  } catch (error) {
    logger.error('Error getting webhook requests:', error);
    sendError(res, 'Internal server error', 500);
  }
});

/**
 * DELETE /api/webhooks/:id/requests
 * Clear all requests for a webhook
 */
router.delete('/:id/requests', verifyApiKey, async (req, res) => {
  try {
    const webhookId = req.params.id;

    // Validate webhook ID format
    if (!isValidWebhookId(webhookId)) {
      return sendError(res, 'Invalid webhook ID format', 400);
    }

    // Check if webhook exists
    const metadata = await getWebhookMetadata(webhookId);
    if (!metadata) {
      return sendError(res, 'Webhook not found or expired', 404);
    }

    // Clear requests (reset to empty array with same TTL)
    const remainingTTL = Math.ceil((metadata.expiresAt - Date.now()) / 1000);
    await redisUtils.setex(
      getRequestsKey(webhookId),
      Math.max(remainingTTL, 1), // At least 1 second
      []
    );

    logger.info('Webhook requests cleared', { webhookId, ip: req.ip });

    sendSuccess(res, 'Requests cleared successfully', {
      webhookId: webhookId
    });

  } catch (error) {
    logger.error('Error clearing webhook requests:', error);
    sendError(res, 'Internal server error', 500);
  }
});

/**
 * ALL /webhook/:id
 * Universal webhook receiver - accepts any HTTP method
 * Note: This route is registered directly on the app, not under /api prefix
 */
const webhookReceiver = async (req, res) => {
  try {
    const webhookId = req.params.id;

    // Validate webhook ID format
    if (!isValidWebhookId(webhookId)) {
      return res.status(400).json({
        success: false,
        message: 'Invalid webhook ID format'
      });
    }

    // Check if webhook exists
    const metadata = await getWebhookMetadata(webhookId);
    if (!metadata) {
      return res.status(404).json({
        success: false,
        message: 'Webhook not found or expired'
      });
    }

    // Get existing requests
    const requests = await redisUtils.get(getRequestsKey(webhookId)) || [];

    // Check max requests limit
    if (requests.length >= MAX_REQUESTS_PER_WEBHOOK) {
      logger.warn('Webhook request limit reached', { webhookId });
      return res.status(429).json({
        success: false,
        message: 'Webhook request limit reached'
      });
    }

    // Prepare request data
    let body = null;
    let bodySize = 0;

    // Capture request body
    if (req.body && Object.keys(req.body).length > 0) {
      body = JSON.stringify(req.body);
      bodySize = Buffer.byteLength(body, 'utf8');
    } else if (req.rawBody) {
      body = req.rawBody.toString();
      bodySize = req.rawBody.length;
    }

    // Check request size
    if (bodySize > MAX_REQUEST_SIZE) {
      logger.warn('Webhook request too large', { webhookId, size: bodySize });
      return res.status(413).json({
        success: false,
        message: 'Request body too large'
      });
    }

    // Create request record
    const requestRecord = {
      id: uuidv4(),
      method: req.method,
      headers: req.headers,
      body: body,
      queryParams: req.query || {},
      contentType: req.get('content-type') || 'unknown',
      timestamp: Date.now(),
      ip: req.ip || req.connection.remoteAddress
    };

    // Add request to array
    requests.push(requestRecord);

    // Store updated requests with remaining TTL
    const remainingTTL = Math.ceil((metadata.expiresAt - Date.now()) / 1000);
    await redisUtils.setex(
      getRequestsKey(webhookId),
      Math.max(remainingTTL, 1),
      requests
    );

    logger.info('Webhook request received', {
      webhookId,
      method: req.method,
      contentType: requestRecord.contentType,
      bodySize: bodySize,
      requestCount: requests.length
    });

    // Send success response
    res.status(200).json({
      success: true,
      message: 'Webhook received successfully',
      requestId: requestRecord.id,
      timestamp: requestRecord.timestamp
    });

  } catch (error) {
    logger.error('Error processing webhook request:', error);
    res.status(500).json({
      success: false,
      message: 'Internal server error'
    });
  }
};

// Export router and webhook receiver
module.exports = {
  router,
  webhookReceiver
};
