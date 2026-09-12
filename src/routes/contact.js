const express = require('express');
const nodemailer = require('nodemailer');
const { basicRateLimit } = require('../middleware/rateLimit');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { verifyTurnstileToken, TOKEN_FIELD } = require('../utils/turnstile');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Escape the five HTML-significant characters.
 *
 * Escaping happens here, at the point the value is interpolated into markup —
 * not on the way in. Sanitising the request body would corrupt the data for
 * every other consumer (and this API's whole job is handling arbitrary text);
 * escaping at render time fixes the injection without touching what the user
 * actually typed.
 */
function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

/**
 * Create nodemailer transporter
 */
function createTransporter() {
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = process.env.SMTP_PORT;
  const smtpUser = process.env.SMTP_USER;
  const smtpPass = process.env.SMTP_PASS;

  // Log environment variables for debugging (without exposing sensitive data)
  logger.info('SMTP Configuration Check:', {
    host: !!smtpHost,
    port: !!smtpPort,
    user: !!smtpUser,
    pass: !!smtpPass,
    hostValue: smtpHost ? smtpHost.substring(0, 10) + '...' : 'undefined'
  });

  if (!smtpHost || !smtpPort || !smtpUser || !smtpPass) {
    throw new Error('SMTP configuration is incomplete');
  }

  try {
    return nodemailer.createTransport({  // ✅ Fixed: createTransport (not createTransporter)
      host: smtpHost,
      port: parseInt(smtpPort),
      secure: false, // true for 465, false for other ports
      auth: {
        user: smtpUser,
        pass: smtpPass,
      },
    });
  } catch (error) {
    logger.error('Failed to create nodemailer transport:', error);
    throw error;
  }
}

/**
 * POST /api/contact/send-email
 * Send contact form email
 */
router.post('/send-email', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { name, email, subject, message } = req.body;

    // Verify the captcha BEFORE any other work. The client has always sent this
    // token; until now nothing checked it, which made this endpoint a free
    // relay through our SMTP account. Tokens are single-use at Cloudflare, so
    // this also blocks replay of a previously-solved challenge.
    const captcha = await verifyTurnstileToken(req.body[TOKEN_FIELD]);
    if (!captcha.success) {
      logger.securityLog('Contact form captcha verification failed', {
        reason: captcha.reason,
        codes: captcha.codes,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
      });

      // A missing/rejected token is the caller's problem (400); a
      // misconfigured or unreachable verifier is ours (503). Don't report an
      // infrastructure fault as user error.
      const isServerSide =
        captcha.reason === 'not_configured' || captcha.reason === 'verification_unavailable';

      return sendError(
        res,
        isServerSide
          ? 'Captcha verification is temporarily unavailable. Please try again shortly.'
          : 'Captcha verification failed. Please complete the challenge and try again.',
        isServerSide ? 503 : 400
      );
    }

    // Validate required fields
    if (!name || !email || !subject || !message) {
      return sendError(res, 'All fields are required', 400);
    }

    // Validate field types
    if (typeof name !== 'string' || typeof email !== 'string' || 
        typeof subject !== 'string' || typeof message !== 'string') {
      return sendError(res, 'All fields must be strings', 400);
    }

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return sendError(res, 'Invalid email format', 400);
    }

    // Validate field lengths
    if (name.length > 100) {
      return sendError(res, 'Name must be less than 100 characters', 400);
    }

    if (subject.length > 200) {
      return sendError(res, 'Subject must be less than 200 characters', 400);
    }

    if (message.length > 5000) {
      return sendError(res, 'Message must be less than 5000 characters', 400);
    }

    logger.info('Processing contact form submission', {
      name: name.substring(0, 20) + (name.length > 20 ? '...' : ''),
      email: email,
      subject: subject.substring(0, 50) + (subject.length > 50 ? '...' : ''),
      messageLength: message.length
    });

    const startTime = Date.now();

    // Create email transporter
    const transporter = createTransporter();

    // Email configuration
    const emailFrom = process.env.EMAIL_FROM;
    const emailTo = process.env.EMAIL_TO;

    // Log email configuration for debugging
    logger.info('Email Configuration Check:', {
      from: !!emailFrom,
      to: !!emailTo,
      fromValue: emailFrom ? emailFrom.substring(0, 10) + '...' : 'undefined',
      toValue: emailTo ? emailTo.substring(0, 10) + '...' : 'undefined'
    });

    if (!emailFrom || !emailTo) {
      throw new Error('Email configuration is incomplete');
    }

    // Escape every user-controlled field before it enters the HTML body.
    // These values are attacker-controlled and land in a mail client we read;
    // unescaped, a submitter could inject arbitrary markup and links into an
    // email that appears to come from our own contact form.
    const safeName = escapeHtml(name);
    const safeEmail = escapeHtml(email);
    const safeSubject = escapeHtml(subject);
    // Escape first, THEN convert newlines to <br> — doing it the other way
    // round would escape the <br> tags we just inserted.
    const safeMessage = escapeHtml(message).replace(/\r?\n/g, '<br>');

    // Email content
    const mailOptions = {
      from: emailFrom,
      to: emailTo,
      // Strip CR/LF from the subject: nodemailer guards against header
      // injection, but a subject spanning lines is malformed regardless.
      subject: `Contact Form: ${subject.replace(/[\r\n]+/g, ' ')}`,
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px;">
            New Contact Form Submission
          </h2>

          <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0;">
            <p><strong>Name:</strong> ${safeName}</p>
            <p><strong>Email:</strong> ${safeEmail}</p>
            <p><strong>Subject:</strong> ${safeSubject}</p>
          </div>

          <div style="background-color: #ffffff; padding: 20px; border: 1px solid #dee2e6; border-radius: 5px;">
            <h3 style="color: #495057; margin-top: 0;">Message:</h3>
            <p style="line-height: 1.6; color: #6c757d;">${safeMessage}</p>
          </div>

          <div style="margin-top: 20px; padding: 15px; background-color: #e9ecef; border-radius: 5px; font-size: 12px; color: #6c757d;">
            <p>This email was sent from the ToolzyHub contact form.</p>
            <p>Submitted at: ${new Date().toLocaleString()}</p>
          </div>
        </div>
      `,
      text: `
        New Contact Form Submission
        
        Name: ${name}
        Email: ${email}
        Subject: ${subject}
        
        Message:
        ${message}
        
        Submitted at: ${new Date().toLocaleString()}
      `,
    };

    // Send email
    logger.info('Attempting to send email...');
    await transporter.sendMail(mailOptions);

    const endTime = Date.now();
    const processingTime = endTime - startTime;

    logger.info('Contact form email sent successfully', {
      to: emailTo,
      from: emailFrom,
      subject: `Contact Form: ${subject}`,
      processingTime: `${processingTime}ms`
    });

    return sendSuccess(res, 'Email sent successfully', {
      processingTime: processingTime,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('Contact form email sending error:', {
      error: error.message,
      stack: error.stack,
      requestData: {
        hasName: !!req.body?.name,
        hasEmail: !!req.body?.email,
        hasSubject: !!req.body?.subject,
        hasMessage: !!req.body?.message
      }
    });

    if (error.message.includes('SMTP configuration is incomplete')) {
      return sendError(res, 'Email service configuration error', 500);
    }

    if (error.message.includes('Email configuration is incomplete')) {
      return sendError(res, 'Email service configuration error', 500);
    }

    if (error.message.includes('Invalid login')) {
      return sendError(res, 'Email service authentication error', 500);
    }

    if (error.message.includes('Connection timeout')) {
      return sendError(res, 'Email service connection timeout', 500);
    }

    return sendError(res, 'Failed to send email', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/contact/info
 * Get contact service information
 */
router.get('/info', enhancedSecurityWithRateLimit(basicRateLimit), (req, res) => {
  const info = {
    service: 'Contact Form Email API',
    version: '1.0.0',
    endpoints: {
      send_email: 'POST /api/contact/send-email',
      info: 'GET /api/contact/info'
    },
    limits: {
      name: {
        maxLength: 100,
        required: true
      },
      email: {
        format: 'Valid email address',
        required: true
      },
      subject: {
        maxLength: 200,
        required: true
      },
      message: {
        maxLength: 5000,
        required: true
      }
    },
    features: {
      htmlEmail: true,
      plainTextEmail: true,
      inputValidation: true,
      rateLimiting: true,
      logging: true
    },
    usage: {
      send_email: {
        method: 'POST',
        endpoint: '/api/contact/send-email',
        contentType: 'application/json',
        body: {
          name: 'Sender name (required, max 100 chars)',
          email: 'Sender email (required, valid format)',
          subject: 'Email subject (required, max 200 chars)',
          message: 'Email message (required, max 5000 chars)'
        },
        response: {
          success: true,
          message: 'Email sent successfully',
          data: {
            processingTime: 'Time taken in milliseconds',
            timestamp: 'ISO timestamp of when email was sent'
          }
        }
      }
    }
  };

  sendSuccess(res, 'Contact service information', info);
});

module.exports = router;