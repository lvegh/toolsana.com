const express = require('express');
const multer = require('multer');
const { body, validationResult } = require('express-validator');
const { createCustomRateLimit } = require('../middleware/rateLimit');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');
const ocrService = require('../services/ocrService');
const xss = require('xss');

const router = express.Router();

/**
 * OCR Rate Limiter
 * OCR is computationally expensive, so we use strict rate limiting
 * 20 requests per hour per user
 */
const ocrRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 requests per hour
  message: {
    success: false,
    message: 'OCR rate limit exceeded. Maximum 20 requests per hour allowed.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    // Use IP + User-Agent for rate limiting
    return `ocr-${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  },
  handler: (req, res) => {
    logger.securityLog('OCR rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method
    });

    res.status(429).json({
      success: false,
      message: 'OCR rate limit exceeded. Maximum 20 requests per hour allowed.',
      retryAfter: 3600,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * Configure multer for file uploads
 * Support images and PDFs up to 10MB
 */
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
    files: 1 // Single file only
  },
  fileFilter: (req, file, cb) => {
    // Allowed MIME types
    const allowedMimeTypes = [
      'image/jpeg',
      'image/jpg',
      'image/png',
      'image/webp',
      'image/tiff',
      'image/gif',
      'image/bmp',
      'application/pdf'
    ];

    if (allowedMimeTypes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid file type. Allowed types: ${allowedMimeTypes.join(', ')}`), false);
    }
  }
});

/**
 * XSS Protection Middleware
 * Sanitize language parameter
 */
const sanitizeLanguageParam = (req, res, next) => {
  if (req.body.language) {
    req.body.language = xss(req.body.language);
  }
  next();
};

/**
 * Validation Rules for OCR Request
 */
const ocrValidationRules = [
  body('language')
    .optional()
    .trim()
    .matches(/^[a-z]{3}(\+[a-z]{3})*$/)
    .withMessage('Invalid language code format. Use ISO 639-3 codes (e.g., "eng", "eng+fra")'),

  body('bypassCache')
    .optional()
    .isBoolean()
    .withMessage('bypassCache must be a boolean'),

  body('threshold')
    .optional()
    .isBoolean()
    .withMessage('threshold must be a boolean'),

  body('thresholdValue')
    .optional()
    .isInt({ min: 0, max: 255 })
    .withMessage('thresholdValue must be between 0 and 255'),

  body('denoise')
    .optional()
    .isBoolean()
    .withMessage('denoise must be a boolean'),

  body('maxDimension')
    .optional()
    .isInt({ min: 500, max: 5000 })
    .withMessage('maxDimension must be between 500 and 5000')
];

/**
 * Handle validation errors
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.securityLog('OCR validation errors', {
      errors: errors.array(),
      ip: req.ip,
      url: req.originalUrl
    });

    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: errors.array().map(err => ({
        field: err.param,
        message: err.msg,
        value: err.value
      })),
      timestamp: new Date().toISOString()
    });
  }
  next();
};

/**
 * POST /api/ocr/image-to-text
 * Extract text from images using OCR
 */
router.post(
  '/image-to-text',
  enhancedSecurityWithRateLimit(ocrRateLimit),
  upload.single('image'),
  sanitizeLanguageParam,
  ocrValidationRules,
  handleValidationErrors,
  async (req, res) => {
    const startTime = Date.now();

    try {
      // Check if file was uploaded
      if (!req.file) {
        return sendError(res, 'No image file provided', 400);
      }

      const { buffer, originalname, mimetype, size } = req.file;

      logger.info('OCR request received', {
        originalName: originalname,
        mimetype,
        size,
        ip: req.ip,
        language: req.body.language || 'eng'
      });

      // Validate image
      try {
        await ocrService.validateImage(buffer);
      } catch (validationError) {
        logger.warn('Image validation failed', {
          error: validationError.message,
          originalName: originalname
        });
        return sendError(res, validationError.message, 400);
      }

      // Extract OCR options from request
      const ocrOptions = {
        language: req.body.language || 'eng',
        bypassCache: req.body.bypassCache === 'true' || req.body.bypassCache === true,
        preprocessing: {
          threshold: req.body.threshold !== 'false' && req.body.threshold !== false,
          thresholdValue: parseInt(req.body.thresholdValue) || 128,
          denoise: req.body.denoise !== 'false' && req.body.denoise !== false,
          maxDimension: parseInt(req.body.maxDimension) || 3000
        }
      };

      logger.info('Starting OCR processing', {
        originalName: originalname,
        language: ocrOptions.language,
        bypassCache: ocrOptions.bypassCache,
        preprocessing: ocrOptions.preprocessing
      });

      // Perform OCR
      const result = await ocrService.performOCR(buffer, ocrOptions);

      // Calculate total processing time
      const totalProcessingTime = Date.now() - startTime;

      logger.info('OCR processing completed successfully', {
        originalName: originalname,
        language: result.language,
        confidence: result.confidence,
        textLength: result.text.length,
        blockCount: result.blocks.length,
        processingTime: totalProcessingTime,
        cached: result.cached
      });

      // Prepare response
      const response = {
        text: result.text,
        confidence: result.confidence,
        language: result.language,
        processingTime: totalProcessingTime,
        cached: result.cached,
        metadata: {
          originalName: originalname,
          fileSize: size,
          mimeType: mimetype,
          blockCount: result.blocks.length,
          lineCount: result.lines.length,
          wordCount: result.words.length
        },
        blocks: result.blocks,
        lines: result.lines,
        words: result.words
      };

      // Set cache headers
      res.set({
        'X-Processing-Time': totalProcessingTime.toString(),
        'X-Cached': result.cached.toString(),
        'X-OCR-Language': result.language,
        'X-OCR-Confidence': result.confidence.toString(),
        'X-Text-Length': result.text.length.toString(),
        'X-Block-Count': result.blocks.length.toString()
      });

      return sendSuccess(res, 'Text extracted successfully', response);

    } catch (error) {
      logger.error('OCR processing error', {
        error: error.message,
        stack: error.stack,
        originalName: req.file?.originalname,
        fileSize: req.file?.size,
        ip: req.ip
      });

      // Handle specific errors
      if (error.message.includes('validation failed')) {
        return sendError(res, error.message, 400);
      }

      if (error.message.includes('preprocessing failed')) {
        return sendError(res, 'Failed to preprocess image', 500, {
          details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
      }

      if (error.message.includes('OCR processing failed')) {
        return sendError(res, 'Failed to extract text from image', 500, {
          details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
      }

      // Generic error
      return sendError(res, 'Failed to process image', 500, {
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

/**
 * POST /api/ocr/validate
 * Validate image file before OCR processing
 */
router.post(
  '/validate',
  enhancedSecurityWithRateLimit(ocrRateLimit),
  upload.single('image'),
  async (req, res) => {
    try {
      // Check if file was uploaded
      if (!req.file) {
        return sendError(res, 'No image file provided', 400);
      }

      const { buffer, originalname, mimetype, size } = req.file;

      logger.info('Image validation request received', {
        originalName: originalname,
        mimetype,
        size,
        ip: req.ip
      });

      // Validate image
      const validationResult = await ocrService.validateImage(buffer);

      logger.info('Image validation successful', {
        originalName: originalname,
        validation: validationResult
      });

      return sendSuccess(res, 'Image is valid for OCR processing', {
        valid: true,
        ...validationResult,
        originalName: originalname
      });

    } catch (error) {
      logger.warn('Image validation failed', {
        error: error.message,
        originalName: req.file?.originalname,
        fileSize: req.file?.size,
        ip: req.ip
      });

      return sendError(res, error.message, 400);
    }
  }
);

/**
 * GET /api/ocr/info
 * Get OCR service information
 */
router.get('/info', enhancedSecurityWithRateLimit(ocrRateLimit), (req, res) => {
  try {
    const info = ocrService.getInfo();

    logger.info('OCR info requested', {
      ip: req.ip
    });

    return sendSuccess(res, 'OCR service information', {
      ...info,
      endpoints: {
        imageToText: 'POST /api/ocr/image-to-text',
        validate: 'POST /api/ocr/validate',
        info: 'GET /api/ocr/info'
      },
      rateLimit: {
        requests: 20,
        window: '1 hour'
      },
      usage: {
        imageToText: {
          method: 'POST',
          endpoint: '/api/ocr/image-to-text',
          contentType: 'multipart/form-data',
          fields: {
            image: 'Image file (required) - JPEG, PNG, WebP, TIFF, GIF, BMP, or PDF',
            language: 'Language code (optional, default: "eng") - ISO 639-3 codes',
            bypassCache: 'Bypass cache (optional, default: false)',
            threshold: 'Apply threshold (optional, default: true)',
            thresholdValue: 'Threshold value 0-255 (optional, default: 128)',
            denoise: 'Apply denoising (optional, default: true)',
            maxDimension: 'Max dimension 500-5000 (optional, default: 3000)'
          },
          response: 'JSON with extracted text, confidence, blocks, lines, and words'
        },
        validate: {
          method: 'POST',
          endpoint: '/api/ocr/validate',
          contentType: 'multipart/form-data',
          fields: {
            image: 'Image file (required) - JPEG, PNG, WebP, TIFF, GIF, BMP, or PDF'
          },
          response: 'JSON with validation result'
        }
      }
    });

  } catch (error) {
    logger.error('Error retrieving OCR info', {
      error: error.message,
      ip: req.ip
    });

    return sendError(res, 'Failed to retrieve OCR service information', 500);
  }
});

/**
 * GET /api/ocr/languages
 * Get list of supported languages
 */
router.get('/languages', enhancedSecurityWithRateLimit(ocrRateLimit), (req, res) => {
  try {
    const info = ocrService.getInfo();

    logger.info('OCR languages requested', {
      ip: req.ip
    });

    // Language name mapping
    const languageNames = {
      eng: 'English',
      fra: 'French',
      deu: 'German',
      spa: 'Spanish',
      ita: 'Italian',
      por: 'Portuguese',
      rus: 'Russian',
      ara: 'Arabic',
      zho: 'Chinese',
      jpn: 'Japanese',
      kor: 'Korean',
      hin: 'Hindi',
      ben: 'Bengali',
      tur: 'Turkish',
      vie: 'Vietnamese',
      tha: 'Thai',
      nld: 'Dutch',
      pol: 'Polish',
      swe: 'Swedish',
      nor: 'Norwegian',
      dan: 'Danish',
      fin: 'Finnish',
      ces: 'Czech',
      ron: 'Romanian',
      hun: 'Hungarian'
    };

    const languages = info.supportedLanguages.map(code => ({
      code,
      name: languageNames[code] || code.toUpperCase()
    }));

    return sendSuccess(res, 'Supported languages retrieved', {
      languages,
      count: languages.length,
      multiLanguageSupport: true,
      example: 'eng+fra for English and French'
    });

  } catch (error) {
    logger.error('Error retrieving OCR languages', {
      error: error.message,
      ip: req.ip
    });

    return sendError(res, 'Failed to retrieve supported languages', 500);
  }
});

module.exports = router;
