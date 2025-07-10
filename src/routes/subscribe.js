const express = require('express');
const { basicRateLimit } = require('../middleware/rateLimit');
const { optionalSecurity, enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Validate email format
 */
const isValidEmail = (email) => {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
};

/**
 * POST /api/subscribe
 * Subscribe user to newsletter via Brevo API
 */
router.post('/', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { email } = req.body;

    // Validate email
    if (!email || typeof email !== 'string') {
      return sendError(res, 'Email is required', 400);
    }

    const trimmedEmail = email.trim();

    if (!isValidEmail(trimmedEmail)) {
      return sendError(res, 'Valid email is required', 400);
    }

    // Check if email is too long (reasonable limit)
    if (trimmedEmail.length > 254) {
      return sendError(res, 'Email is too long', 400);
    }

    // Check for Brevo API key
    const brevoApiKey = process.env.BREVO_API_KEY;
    if (!brevoApiKey) {
      logger.error('BREVO_API_KEY environment variable is not set');
      return sendError(res, 'Newsletter service is not configured', 500);
    }

    logger.info('Processing newsletter subscription', {
      email: trimmedEmail,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    const startTime = Date.now();

    // Make request to Brevo API
    const response = await fetch('https://api.brevo.com/v3/contacts', {
      method: 'POST',
      headers: {
        'api-key': brevoApiKey,
        'Content-Type': 'application/json',
        'accept': 'application/json',
      },
      body: JSON.stringify({
        email: trimmedEmail,
        attributes: {
          SIGNUP_SOURCE: 'blog_sidebar'
        },
        listIds: [4],
        updateEnabled: true
      }),
    });

    const endTime = Date.now();
    const processingTime = endTime - startTime;

    if (response.ok) {
      logger.info('Newsletter subscription successful', {
        email: trimmedEmail,
        processingTime: `${processingTime}ms`,
        ip: req.ip
      });

      return sendSuccess(res, 'Successfully subscribed! Thank you for joining our newsletter.', {
        email: trimmedEmail,
        processingTime: processingTime,
        timestamp: new Date().toISOString()
      });
    } else {
      // Handle Brevo API errors
      let errorData;
      try {
        errorData = await response.json();
      } catch (parseError) {
        logger.error('Failed to parse Brevo API error response', {
          error: parseError.message,
          status: response.status,
          statusText: response.statusText
        });
        return sendError(res, 'Subscription failed. Please try again.', 400);
      }

      logger.warn('Brevo API error response', {
        email: trimmedEmail,
        status: response.status,
        errorCode: errorData.code,
        errorMessage: errorData.message,
        processingTime: `${processingTime}ms`,
        ip: req.ip
      });

      // Handle duplicate email (already subscribed)
      if (errorData.code === 'duplicate_parameter') {
        return sendSuccess(res, 'You\'re already subscribed! Thank you for your interest.', {
          email: trimmedEmail,
          alreadySubscribed: true,
          processingTime: processingTime,
          timestamp: new Date().toISOString()
        });
      }

      // Handle other Brevo API errors
      const errorMessage = errorData.message || 'Subscription failed. Please try again.';
      return sendError(res, errorMessage, 400, {
        brevoError: {
          code: errorData.code,
          message: errorData.message
        }
      });
    }

  } catch (error) {
    logger.error('Newsletter subscription error:', {
      error: error.message,
      stack: error.stack,
      email: req.body?.email,
      ip: req.ip,
      userAgent: req.get('User-Agent')
    });

    // Handle network errors
    if (error.name === 'TypeError' && error.message.includes('fetch')) {
      return sendError(res, 'Network error. Please try again.', 500);
    }

    // Handle timeout errors
    if (error.name === 'AbortError' || error.message.includes('timeout')) {
      return sendError(res, 'Request timeout. Please try again.', 500);
    }

    return sendError(res, 'Network error. Please try again.', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/subscribe/info
 * Get subscription service information
 */
router.get('/info', basicRateLimit, (req, res) => {
  const info = {
    service: 'Newsletter Subscription API',
    version: '1.0.0',
    endpoints: {
      subscribe: 'POST /api/subscribe',
      info: 'GET /api/subscribe/info'
    },
    requirements: {
      email: {
        type: 'string',
        format: 'Valid email address',
        maxLength: 254,
        required: true
      }
    },
    features: {
      emailValidation: true,
      duplicateHandling: true,
      rateLimiting: true,
      logging: true,
      brevoIntegration: true
    },
    usage: {
      subscribe: {
        method: 'POST',
        endpoint: '/api/subscribe',
        contentType: 'application/json',
        body: {
          email: 'user@example.com'
        },
        responses: {
          200: {
            success: true,
            message: 'Successfully subscribed! Thank you for joining our newsletter.',
            data: {
              email: 'user@example.com',
              processingTime: 1250,
              timestamp: '2025-01-01T00:00:00.000Z'
            }
          },
          400: {
            success: false,
            message: 'Valid email is required'
          },
          500: {
            success: false,
            message: 'Network error. Please try again.'
          }
        }
      }
    }
  };

  sendSuccess(res, 'Subscription service information', info);
});

module.exports = router;