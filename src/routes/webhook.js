const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { redisUtils, getRedisClient } = require('../config/redis');
// These used to use verifyApiKey, which checks VALID_API_KEY — a second secret
// that happened to hold the same value as API_SECRET_TOKEN. The Worker only
// ever sends API_SECRET_TOKEN (as x-api-key), so the two were coupled by
// accident and rotating either would have silently broken webhooks.
// enhancedSecurity accepts the token from x-api-key or Authorization: Bearer,
// so the Worker needs no change, and every route now uses one mechanism.
const { enhancedSecurity } = require('../middleware/enhancedSecurity');
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
 * Helper: legacy requests key. Before the list-based log below, every
 * delivery re-wrote one JSON array stored under this key (read-append-write,
 * so concurrent deliveries overwrote each other). It is still read so a
 * webhook created before the deploy keeps its history until it expires (1 h),
 * but nothing writes to it any more.
 */
const getRequestsKey = (id) => `webhook:${id}:requests`;

/**
 * Helper: Redis LIST holding one JSON-encoded record per delivery. Appended
 * atomically by APPEND_SCRIPT, so simultaneous deliveries are all kept.
 */
const getLogKey = (id) => `webhook:${id}:log`;

/**
 * Atomic append with the per-webhook cap. Check-then-push has to happen in one
 * step, otherwise two deliveries racing at 99 would both pass the check.
 *   KEYS[1] = log list
 *   ARGV[1] = record JSON, ARGV[2] = max records, ARGV[3] = expiry (unix ms)
 * Returns the new length, or -1 when the cap is reached.
 */
const APPEND_SCRIPT = `
if redis.call('LLEN', KEYS[1]) >= tonumber(ARGV[2]) then
  return -1
end
local n = redis.call('RPUSH', KEYS[1], ARGV[1])
redis.call('PEXPIREAT', KEYS[1], ARGV[3])
return n
`;

/**
 * Read every stored delivery for a webhook, oldest first.
 */
const readRequests = async (id) => {
  const client = getRedisClient();
  if (!client) return [];

  const legacy = (await redisUtils.get(getRequestsKey(id))) || [];
  let entries = [];
  try {
    entries = await client.lRange(getLogKey(id), 0, -1);
  } catch (error) {
    logger.error('Redis LRANGE error for webhook log:', error);
    entries = [];
  }

  const records = [];
  for (const entry of entries) {
    try {
      records.push(JSON.parse(entry));
    } catch {
      // A corrupt entry must not hide the rest of the history.
    }
  }
  return [...(Array.isArray(legacy) ? legacy : []), ...records];
};

/**
 * Decode the raw request body without losing information.
 *
 * The receiver stores exactly what the sender delivered: `body` is the UTF-8
 * text when the bytes are valid UTF-8 (so an HMAC over it matches the
 * sender's), otherwise `body` is null and `bodyBase64` carries the bytes.
 * `bodyJsonValid` tells the viewer whether the text parses as JSON; the parsed
 * view is built client-side from the raw text rather than stored twice.
 */
const describeBody = (buffer) => {
  if (!buffer || buffer.length === 0) {
    return { body: null, bodyBase64: null, bodyEncoding: null, bodySize: 0, bodyJsonValid: false };
  }

  let text = null;
  try {
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer);
  } catch {
    text = null;
  }

  if (text === null) {
    return {
      body: null,
      bodyBase64: buffer.toString('base64'),
      bodyEncoding: 'base64',
      bodySize: buffer.length,
      bodyJsonValid: false,
    };
  }

  let bodyJsonValid = false;
  try {
    JSON.parse(text);
    bodyJsonValid = true;
  } catch {
    bodyJsonValid = false;
  }

  return { body: text, bodyBase64: null, bodyEncoding: 'utf8', bodySize: buffer.length, bodyJsonValid };
};

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
      await redisUtils.del(getLogKey(id));
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
router.post('/create', enhancedSecurity, async (req, res) => {
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

    // No request log to initialise: the list is created by the first
    // delivery (see APPEND_SCRIPT), with its expiry pinned to expiresAt.

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
router.get('/:id/requests', enhancedSecurity, async (req, res) => {
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
    const requests = await readRequests(webhookId);

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
router.delete('/:id/requests', enhancedSecurity, async (req, res) => {
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

    // Clear requests (both the list log and any pre-deploy legacy array)
    await redisUtils.del(getLogKey(webhookId));
    await redisUtils.del(getRequestsKey(webhookId));

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
 * Raw body parser for the webhook receiver.
 *
 * Mounted on /webhook/:id only; server.js skips the global JSON/urlencoded
 * parsers for that path so this sees the untouched stream. Every content type
 * (and a missing Content-Type) is read as bytes, so text/plain, XML,
 * multipart and malformed JSON are all recorded exactly as sent.
 * Over-limit and undecodable bodies get a webhook-style JSON error.
 */
const rawParser = express.raw({ type: () => true, limit: MAX_REQUEST_SIZE });

const webhookRawBody = (req, res, next) => {
  rawParser(req, res, (err) => {
    if (!err) return next();

    if (err.type === 'entity.too.large') {
      logger.warn('Webhook request too large', { webhookId: req.params.id, length: err.length });
      return res.status(413).json({
        success: false,
        message: 'Request body too large (max 1 MB)'
      });
    }
    if (err.type === 'encoding.unsupported') {
      return res.status(415).json({
        success: false,
        message: 'Unsupported Content-Encoding'
      });
    }
    logger.warn('Webhook body could not be read', { webhookId: req.params.id, type: err.type });
    return res.status(400).json({
      success: false,
      message: 'Request body could not be read'
    });
  });
};

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

    const client = getRedisClient();
    if (!client) {
      return res.status(503).json({
        success: false,
        message: 'Webhook storage unavailable'
      });
    }

    // Raw bytes from webhookRawBody; body-parser leaves `{}` when there is no body.
    const rawBuffer = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
    const bodyInfo = describeBody(rawBuffer);

    // Defensive: the raw parser already enforces this limit.
    if (bodyInfo.bodySize > MAX_REQUEST_SIZE) {
      logger.warn('Webhook request too large', { webhookId, size: bodyInfo.bodySize });
      return res.status(413).json({
        success: false,
        message: 'Request body too large (max 1 MB)'
      });
    }

    // Create request record
    const requestRecord = {
      id: uuidv4(),
      method: req.method,
      headers: req.headers,
      ...bodyInfo,
      queryParams: req.query || {},
      contentType: req.get('content-type') || 'unknown',
      timestamp: Date.now(),
      // /webhook/ is exempt from the edge guard (third-party senders hit the
      // origin directly), so this is req.ip as derived from X-Forwarded-For
      // under `trust proxy` = 1. The viewer labels it accordingly.
      ip: req.ip || req.socket?.remoteAddress,
      ipSource: 'x-forwarded-for'
    };

    // Atomic capped append; expiry pinned to the webhook's own expiry.
    const newLength = await client.eval(APPEND_SCRIPT, {
      keys: [getLogKey(webhookId)],
      arguments: [
        JSON.stringify(requestRecord),
        String(MAX_REQUESTS_PER_WEBHOOK),
        String(Math.max(metadata.expiresAt, Date.now() + 1000))
      ]
    });

    if (Number(newLength) < 0) {
      logger.warn('Webhook request limit reached', { webhookId });
      return res.status(429).json({
        success: false,
        message: 'Webhook request limit reached'
      });
    }

    logger.info('Webhook request received', {
      webhookId,
      method: req.method,
      contentType: requestRecord.contentType,
      bodySize: bodyInfo.bodySize,
      requestCount: Number(newLength)
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
  webhookReceiver,
  webhookRawBody,
  // exported for tests
  describeBody,
  APPEND_SCRIPT
};
