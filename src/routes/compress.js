const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const { basicRateLimit } = require('../middleware/rateLimit');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');
const pngOptimizer = require('../services/pngOptimizer');

const router = express.Router();

// Configure multer for file uploads (JPG/JPEG)
const uploadJpg = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Check if file is JPG/JPEG
    if (file.mimetype === 'image/jpeg' || file.mimetype === 'image/jpg') {
      cb(null, true);
    } else {
      cb(new Error('File must be a JPG/JPEG image'), false);
    }
  }
});

// Configure multer for file uploads (PNG)
const uploadPng = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Check if file is PNG
    if (file.mimetype === 'image/png') {
      cb(null, true);
    } else {
      cb(new Error('File must be a PNG image'), false);
    }
  }
});

// Configure multer for file uploads (WebP)
const uploadWebp = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Check if file is WebP
    if (file.mimetype === 'image/webp') {
      cb(null, true);
    } else {
      cb(new Error('File must be a WebP image'), false);
    }
  }
});

/**
 * POST /api/compress/jpg
 * Compress JPG/JPEG images
 */
router.post('/jpg', enhancedSecurityWithRateLimit(basicRateLimit), uploadJpg.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    // Get quality parameter (default to 75)
    const quality = parseInt(req.body.quality) || 75;

    // Validate quality range
    if (quality < 1 || quality > 100) {
      return sendError(res, 'Quality must be between 1 and 100', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalSize = originalBuffer.length;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');

    logger.info('Starting JPG compression', {
      originalName: req.file.originalname,
      originalSize,
      quality,
      mimetype: req.file.mimetype
    });

    // Compress JPG with Sharp
    const compressedBuffer = await sharp(originalBuffer)
      .rotate() // Auto-rotate based on EXIF orientation
      .jpeg({
        quality,
        chromaSubsampling: '4:2:0',
        mozjpeg: true, // Use mozjpeg encoder for better compression
        trellisQuantisation: true, // Better compression through trellis optimization
        overshootDeringing: true, // Reduces compression artifacts
        optimizeScans: true, // Optimizes progressive JPEG scans
      })
      .toBuffer();

    // Calculate compression statistics
    const compressedSize = compressedBuffer.length;
    const compressionRatio = (
      ((originalSize - compressedSize) / originalSize) * 100
    ).toFixed(1);

    // Generate filename
    const filename = `${originalName}_compressed.jpg`;

    logger.info('JPG compression completed', {
      originalName: req.file.originalname,
      originalSize,
      compressedSize,
      compressionRatio: `${compressionRatio}%`,
      quality
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/jpeg',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': compressedSize.toString(),
      'X-Original-Size': originalSize.toString(),
      'X-Compressed-Size': compressedSize.toString(),
      'X-Compression-Ratio': compressionRatio,
      'X-Quality': quality.toString(),
      'X-Original-Filename': req.file.originalname
    });

    // Send the compressed image
    res.send(compressedBuffer);

  } catch (error) {
    logger.error('JPG compression error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (error.message.includes('File must be a JPG/JPEG image')) {
      return sendError(res, 'File must be a JPG/JPEG image', 400);
    }

    return sendError(res, 'Failed to compress image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/compress/png
 * Compress PNG images with intelligent optimization
 */
router.post('/png', enhancedSecurityWithRateLimit(basicRateLimit), uploadPng.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalSize = originalBuffer.length;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');

    logger.info('Starting intelligent PNG compression', {
      originalName: req.file.originalname,
      originalSize,
      mimetype: req.file.mimetype
    });

    // Use intelligent PNG optimization
    const compressionResult = await pngOptimizer.compress(originalBuffer);

    // Generate filename
    const filename = `${originalName}_compressed.png`;

    logger.info('Intelligent PNG compression completed', {
      originalName: req.file.originalname,
      originalSize,
      compressedSize: compressionResult.compressedSize,
      compressionRatio: `${compressionResult.compressionRatio}%`,
      strategy: compressionResult.strategy
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/png',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': compressionResult.compressedSize.toString(),
      'X-Original-Size': originalSize.toString(),
      'X-Compressed-Size': compressionResult.compressedSize.toString(),
      'X-Compression-Ratio': compressionResult.compressionRatio,
      'X-Compression-Strategy': compressionResult.strategy,
      'X-Original-Filename': req.file.originalname
    });

    // Send the compressed image
    res.send(compressionResult.buffer);

  } catch (error) {
    logger.error('Intelligent PNG compression error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (error.message.includes('File must be a PNG image')) {
      return sendError(res, 'File must be a PNG image', 400);
    }

    return sendError(res, 'Failed to compress image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/compress/webp
 * Compress WebP images
 */
router.post('/webp', enhancedSecurityWithRateLimit(basicRateLimit), uploadWebp.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    // Get quality parameter (default to 80)
    const quality = parseInt(req.body.quality) || 80;

    // Validate quality range (0-100 for WebP)
    if (quality < 0 || quality > 100) {
      return sendError(res, 'Quality must be between 0 and 100', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalSize = originalBuffer.length;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');

    logger.info('Starting WebP compression', {
      originalName: req.file.originalname,
      originalSize,
      quality,
      mimetype: req.file.mimetype
    });

    // Compress WebP with Sharp
    const compressedBuffer = await sharp(originalBuffer)
      .webp({
        quality, // 0-100, where 100 is maximum quality
        effort: 6, // 0-6, where 6 is maximum effort (slower but better compression)
        lossless: false
      })
      .toBuffer();

    // Calculate compression statistics
    const compressedSize = compressedBuffer.length;
    const compressionRatio = (
      ((originalSize - compressedSize) / originalSize) * 100
    ).toFixed(1);

    // Generate filename
    const filename = `${originalName}_compressed.webp`;

    logger.info('WebP compression completed', {
      originalName: req.file.originalname,
      originalSize,
      compressedSize,
      compressionRatio: `${compressionRatio}%`,
      quality
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/webp',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': compressedSize.toString(),
      'X-Original-Size': originalSize.toString(),
      'X-Compressed-Size': compressedSize.toString(),
      'X-Compression-Ratio': compressionRatio,
      'X-Quality': quality.toString(),
      'X-Original-Filename': req.file.originalname
    });

    // Send the compressed image
    res.send(compressedBuffer);

  } catch (error) {
    logger.error('WebP compression error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (error.message.includes('File must be a WebP image')) {
      return sendError(res, 'File must be a WebP image', 400);
    }

    return sendError(res, 'Failed to compress image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/compress/batch
 * Compress multiple JPG/JPEG images
 */
router.post('/batch', enhancedSecurityWithRateLimit(basicRateLimit), uploadJpg.array('files', 5), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return sendError(res, 'No files provided', 400);
    }

    const quality = parseInt(req.body.quality) || 75;

    if (quality < 1 || quality > 100) {
      return sendError(res, 'Quality must be between 1 and 100', 400);
    }

    const results = [];
    const errors = [];

    logger.info('Starting batch JPG compression', {
      fileCount: req.files.length,
      quality
    });

    // Process each file
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];
      
      try {
        const originalBuffer = file.buffer;
        const originalSize = originalBuffer.length;
        const originalName = file.originalname.replace(/\.[^/.]+$/, '');

        // Compress the image
        const compressedBuffer = await sharp(originalBuffer)
          .rotate()
          .jpeg({
            quality,
            chromaSubsampling: '4:2:0',
            mozjpeg: true,
            trellisQuantisation: true, // Better compression through trellis optimization
            overshootDeringing: true, // Reduces compression artifacts
            optimizeScans: true, // Optimizes progressive JPEG scans
          })
          .toBuffer();

        const compressedSize = compressedBuffer.length;
        const compressionRatio = (
          ((originalSize - compressedSize) / originalSize) * 100
        ).toFixed(1);

        results.push({
          originalName: file.originalname,
          compressedName: `${originalName}_compressed.jpg`,
          originalSize,
          compressedSize,
          compressionRatio: `${compressionRatio}%`,
          compressedData: compressedBuffer.toString('base64')
        });

      } catch (error) {
        errors.push({
          filename: file.originalname,
          error: error.message
        });
      }
    }

    logger.info('Batch JPG compression completed', {
      totalFiles: req.files.length,
      successful: results.length,
      failed: errors.length,
      quality
    });

    return sendSuccess(res, 'Batch compression completed', {
      results,
      errors,
      summary: {
        totalFiles: req.files.length,
        successful: results.length,
        failed: errors.length,
        quality
      }
    });

  } catch (error) {
    logger.error('Batch JPG compression error:', {
      error: error.message,
      stack: error.stack,
      fileCount: req.files?.length
    });

    return sendError(res, 'Failed to process batch compression', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/compress/info
 * Get compression service information
 */
router.get('/info', enhancedSecurityWithRateLimit(basicRateLimit), (req, res) => {
  const info = {
    service: 'Image Compression API',
    version: '1.0.0',
    supportedFormats: ['image/jpeg', 'image/jpg', 'image/png'],
    endpoints: {
      jpg_single: 'POST /api/compress/jpg',
      png_single: 'POST /api/compress/png',
      batch: 'POST /api/compress/batch',
      info: 'GET /api/compress/info'
    },
    limits: {
      maxFileSize: '10MB',
      maxBatchFiles: 5,
      jpgQualityRange: '1-100',
      pngCompressionRange: '0-9'
    },
    features: {
      autoRotation: true,
      mozjpegEncoder: true,
      chromaSubsampling: '4:2:0',
      pngOptimization: true,
      adaptiveFiltering: true,
      compressionStats: true,
      batchProcessing: true
    },
    usage: {
      jpg_compression: {
        method: 'POST',
        endpoint: '/api/compress/jpg',
        contentType: 'multipart/form-data',
        fields: {
          file: 'JPG/JPEG image file (required)',
          quality: 'Compression quality 1-100 (optional, default: 75)'
        },
        response: 'Compressed image file with compression headers'
      },
      png_compression: {
        method: 'POST',
        endpoint: '/api/compress/png',
        contentType: 'multipart/form-data',
        fields: {
          file: 'PNG image file (required)',
          compressionLevel: 'Compression level 0-9 (optional, default: 6)'
        },
        response: 'Compressed image file with compression headers'
      },
      batch: {
        method: 'POST',
        endpoint: '/api/compress/batch',
        contentType: 'multipart/form-data',
        fields: {
          files: 'Array of JPG/JPEG image files (required, max 5)',
          quality: 'Compression quality 1-100 (optional, default: 75)'
        },
        response: 'JSON with compressed images as base64 and statistics'
      }
    }
  };

  sendSuccess(res, 'Compression service information', info);
});

module.exports = router;
