const express = require('express');
const multer = require('multer');
const { basicRateLimit } = require('../middleware/rateLimit');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const { sendError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');
const pdfOptimizer = require('../services/pdfOptimizer');

const router = express.Router();

// PDFs run larger than the images this API usually handles — a scanned
// document of a few dozen pages routinely passes 10 MB — so the limit is
// raised accordingly while still bounding memory per request.
const MAX_PDF_BYTES = 25 * 1024 * 1024;

const uploadPdf = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_PDF_BYTES,
  },
  fileFilter: (req, file, cb) => {
    if (file.mimetype === 'application/pdf') {
      cb(null, true);
    } else {
      cb(new Error('File must be a PDF'), false);
    }
  }
});

// Preset names map to the JPEG quality and downsample cap applied to the
// images embedded in the document.
const PRESETS = {
  low: { quality: 85, maxImageWidth: 2400 },
  medium: { quality: 70, maxImageWidth: 1600 },
  high: { quality: 50, maxImageWidth: 1000 },
};

/**
 * POST /api/pdf/compress
 * Compress a PDF by re-encoding the raster images it embeds.
 */
router.post('/compress', enhancedSecurityWithRateLimit(basicRateLimit), uploadPdf.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const level = (req.body.level || 'medium').toLowerCase();
    if (!PRESETS[level]) {
      return sendError(res, `Level must be one of: ${Object.keys(PRESETS).join(', ')}`, 400);
    }

    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const { quality, maxImageWidth } = PRESETS[level];

    logger.info('Starting PDF compression', {
      originalName: req.file.originalname,
      originalSize: req.file.size,
      level,
      quality,
      maxImageWidth
    });

    const { buffer, stats } = await pdfOptimizer.compress(req.file.buffer, {
      quality,
      maxImageWidth
    });

    logger.info('PDF compression completed', {
      originalName: req.file.originalname,
      ...stats,
      level
    });

    const filename = `${originalName}_compressed.pdf`;

    res.set({
      'Content-Type': 'application/pdf',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': stats.compressedSize.toString(),
      'X-Original-Size': stats.originalSize.toString(),
      'X-Compressed-Size': stats.compressedSize.toString(),
      'X-Compression-Ratio': stats.compressionRatio.toString(),
      'X-Page-Count': stats.pageCount.toString(),
      'X-Images-Found': stats.imagesFound.toString(),
      'X-Images-Recompressed': stats.imagesRecompressed.toString(),
      'X-Images-Skipped': stats.imagesSkipped.toString(),
      'X-Compression-Level': level,
      'X-Original-Filename': req.file.originalname,
      // The frontend reads the X-* stats to explain the result, so they must
      // survive the cross-origin hop.
      'Access-Control-Expose-Headers': [
        'X-Original-Size',
        'X-Compressed-Size',
        'X-Compression-Ratio',
        'X-Page-Count',
        'X-Images-Found',
        'X-Images-Recompressed',
        'X-Images-Skipped',
        'X-Compression-Level',
        'X-Original-Filename'
      ].join(', ')
    });

    return res.send(buffer);

  } catch (error) {
    logger.error('PDF compression error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (/encrypt/i.test(error.message)) {
      return sendError(res, 'This PDF is password-protected. Remove the protection before compressing it.', 400);
    }
    if (/Failed to parse|Expected instance of PDFDict|No PDF header/i.test(error.message)) {
      return sendError(res, 'This file is not a valid PDF, or it is corrupted.', 400);
    }
    if (error.message.includes('File must be a PDF')) {
      return sendError(res, 'File must be a PDF', 400);
    }

    return sendError(res, 'Failed to compress PDF', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/pdf/info
 * Describes the compression presets and limits.
 */
router.get('/info', basicRateLimit, (req, res) => {
  res.json({
    success: true,
    data: {
      endpoint: '/api/pdf/compress',
      method: 'POST',
      field: 'file',
      maxFileSize: `${MAX_PDF_BYTES / (1024 * 1024)}MB`,
      levels: Object.entries(PRESETS).map(([name, preset]) => ({
        name,
        jpegQuality: preset.quality,
        maxImageWidth: preset.maxImageWidth
      })),
      notes: [
        'Compression re-encodes the JPEG images embedded in the PDF.',
        'Text and vector content are never rasterised, so the text layer is preserved.',
        'PDFs containing no raster images will not shrink meaningfully.'
      ]
    }
  });
});

module.exports = router;
