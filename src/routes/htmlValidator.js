/**
 * HTML Validator Route using W3C HTML Validator
 * Validates HTML content against W3C standards
 */

const express = require('express');
const router = express.Router();
const { w3cHtmlValidator } = require('w3c-html-validator');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { basicRateLimit } = require('../middleware/rateLimit');

/**
 * POST /api/html-validator
 * Validates HTML content using W3C validator
 *
 * Request body:
 * {
 *   "html": "<!DOCTYPE html>..."
 * }
 *
 * Response:
 * {
 *   "success": true,
 *   "validates": true/false,
 *   "messages": [...],
 *   "errorCount": 0,
 *   "warningCount": 0,
 *   "infoCount": 0
 * }
 */
router.post('/', basicRateLimit, async (req, res) => {
  try {
    const { html } = req.body;

    // Validate input
    if (!html || typeof html !== 'string') {
      return sendError(res, 'HTML content is required', 400);
    }

    // Check HTML length (max 5MB)
    const MAX_HTML_LENGTH = 5 * 1024 * 1024;
    if (html.length > MAX_HTML_LENGTH) {
      return sendError(res, `HTML content exceeds maximum length of 5MB`, 400);
    }

    // Validate HTML using W3C validator
    const options = {
      html: html,
      output: 'json'
    };

    const result = await w3cHtmlValidator.validate(options);

    // Process validation results
    const messages = result.messages || [];

    // Count message types
    const errorCount = messages.filter(msg => msg.type === 'error').length;
    const warningCount = messages.filter(msg => msg.type === 'warning' || msg.type === 'info' && msg.subType === 'warning').length;
    const infoCount = messages.filter(msg => msg.type === 'info' && msg.subType !== 'warning').length;

    // Format messages for frontend
    const formattedMessages = messages.map(msg => ({
      type: msg.type === 'error' ? 'error' : (msg.type === 'info' && msg.subType === 'warning') ? 'warning' : 'info',
      message: msg.message,
      line: msg.lastLine || msg.firstLine,
      column: msg.lastColumn || msg.firstColumn,
      extract: msg.extract,
      hiliteStart: msg.hiliteStart,
      hiliteLength: msg.hiliteLength
    }));

    return sendSuccess(res, {
      validates: result.validates || errorCount === 0,
      messages: formattedMessages,
      errorCount,
      warningCount,
      infoCount,
      totalIssues: messages.length
    });

  } catch (error) {
    console.error('HTML validation error:', error);

    // Handle W3C validator errors
    if (error.message && error.message.includes('W3C')) {
      return sendError(res, 'W3C validator service is temporarily unavailable. Please try again later.', 503);
    }

    return sendError(res, 'Failed to validate HTML', 500);
  }
});

module.exports = router;
