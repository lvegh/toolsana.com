const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs').promises;
const { createCustomRateLimit } = require('../middleware/rateLimit');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const { sendSuccess, sendError, asyncHandler } = require('../middleware/errorHandler');
const logger = require('../utils/logger');
const { deleteFile, fileExists } = require('../utils/fileSystem');

const router = express.Router();

// Configure multer for image uploads
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Check if file is an image
    const allowedMimes = [
      'image/jpeg',
      'image/jpg',
      'image/png',
      'image/gif',
      'image/webp',
      'image/bmp',
      'image/tiff'
    ];

    if (allowedMimes.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Only images are allowed.'), false);
    }
  }
});

// Custom rate limit for reverse image search - 10 uploads per hour
const reverseImageSearchRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: {
    success: false,
    message: 'Too many image uploads. Please try again in an hour.'
  },
  keyGenerator: (req) => {
    return `reverse-image-search-${req.ip}`;
  },
  handler: (req, res) => {
    logger.securityLog('Reverse image search rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl
    });

    res.status(429).json({
      success: false,
      message: 'Too many image uploads. Please try again in an hour.',
      retryAfter: 3600
    });
  }
});

/**
 * Generate search URLs for all reverse image search engines
 * @param {string} imageUrl - Public URL of the uploaded image
 * @returns {object} Search URLs for each engine
 */
const generateSearchUrls = (imageUrl) => {
  const encodedUrl = encodeURIComponent(imageUrl);

  return {
    google: `https://www.google.com/searchbyimage?image_url=${encodedUrl}`,
    bing: `https://www.bing.com/images/search?view=detailv2&iss=sbi&form=SBIIDP&sbisrc=UrlPaste&q=imgurl:${encodedUrl}`,
    tineye: `https://tineye.com/search?url=${encodedUrl}`,
    yandex: `https://yandex.com/images/search?rpt=imageview&url=${encodedUrl}`
  };
};

/**
 * Optimize and process image
 * @param {Buffer} buffer - Image buffer
 * @param {string} mimetype - Original mimetype
 * @returns {object} Processed image data
 */
const processImage = async (buffer, mimetype) => {
  try {
    const image = sharp(buffer);
    const metadata = await image.metadata();

    // Resize if image is too large (max 2000px on longest side)
    let processedImage = image;
    const maxDimension = 2000;

    if (metadata.width > maxDimension || metadata.height > maxDimension) {
      processedImage = processedImage.resize(maxDimension, maxDimension, {
        fit: 'inside',
        withoutEnlargement: true
      });
    }

    // Convert to JPEG for optimal size/quality balance
    const processedBuffer = await processedImage
      .jpeg({
        quality: 85,
        mozjpeg: true
      })
      .toBuffer();

    return {
      buffer: processedBuffer,
      format: 'jpeg',
      originalSize: buffer.length,
      newSize: processedBuffer.length,
      width: metadata.width,
      height: metadata.height
    };
  } catch (error) {
    logger.error('Image processing error:', {
      error: error.message,
      mimetype
    });
    throw new Error('Failed to process image');
  }
};

/**
 * Basic virus/malware scan using file size and magic bytes
 * @param {Buffer} buffer - File buffer
 * @returns {boolean} True if file appears safe
 */
const basicSecurityScan = (buffer) => {
  // Check for suspicious file patterns
  const header = buffer.slice(0, 8).toString('hex');

  // Valid image file signatures
  const validSignatures = [
    'ffd8ff',      // JPEG
    '89504e47',    // PNG
    '47494638',    // GIF
    '52494646',    // WEBP/RIFF
    '424d',        // BMP
    '49492a00',    // TIFF (little-endian)
    '4d4d002a'     // TIFF (big-endian)
  ];

  // Check if header matches any valid signature
  const isValidImage = validSignatures.some(sig =>
    header.toLowerCase().startsWith(sig.toLowerCase())
  );

  if (!isValidImage) {
    logger.securityLog('Invalid image file signature detected', {
      header: header.substring(0, 20)
    });
    return false;
  }

  // Additional checks can be added here
  // - Scan for embedded scripts
  // - Check EXIF data for anomalies
  // - Validate image structure

  return true;
};

/**
 * POST /api/tools/reverse-image-search
 * Upload image and get reverse image search URLs
 */
router.post(
  '/',
  enhancedSecurityWithRateLimit(reverseImageSearchRateLimit),
  upload.single('image'),
  asyncHandler(async (req, res) => {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No image file provided', 400);
    }

    const startTime = Date.now();
    const originalBuffer = req.file.buffer;
    const originalSize = originalBuffer.length;
    const originalName = req.file.originalname;
    const mimetype = req.file.mimetype;

    logger.info('Reverse image search request received', {
      originalName,
      originalSize,
      mimetype,
      ip: req.ip
    });

    // Security scan
    if (!basicSecurityScan(originalBuffer)) {
      logger.securityLog('Suspicious file upload detected', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        originalName,
        mimetype
      });
      return sendError(res, 'File failed security validation', 400);
    }

    // Process and optimize image
    let processedImage;
    try {
      processedImage = await processImage(originalBuffer, mimetype);
    } catch (error) {
      logger.error('Image processing failed:', {
        error: error.message,
        originalName,
        mimetype
      });
      return sendError(res, 'Failed to process image', 500);
    }

    // Generate unique filename
    const uniqueId = uuidv4();
    const filename = `${uniqueId}.jpg`;
    const uploadsDir = path.join(__dirname, '../../uploads/reverse-search');

    // Create directory if it doesn't exist
    try {
      await fs.mkdir(uploadsDir, { recursive: true });
    } catch (error) {
      logger.error('Failed to create uploads directory:', error);
      return sendError(res, 'Server configuration error', 500);
    }

    // Save file
    const filePath = path.join(uploadsDir, filename);
    try {
      await fs.writeFile(filePath, processedImage.buffer);
    } catch (error) {
      logger.error('Failed to save file:', {
        error: error.message,
        filePath
      });
      return sendError(res, 'Failed to save image', 500);
    }

    // Generate public URL (adjust based on your deployment)
    const baseUrl = process.env.API_URL || `http://${req.get('host')}`;
    const imageUrl = `${baseUrl}/uploads/reverse-search/${filename}`;

    // Generate search URLs
    const searchUrls = generateSearchUrls(imageUrl);

    // Calculate expiration time (24 hours from now)
    const expiresAt = new Date(Date.now() + 24 * 60 * 60 * 1000);

    // Store metadata for cleanup (in production, use Redis or database)
    const metadata = {
      filename,
      filePath,
      uploadedAt: new Date(),
      expiresAt,
      ip: req.ip,
      originalName
    };

    // In production, store this in Redis with TTL
    // For now, we'll rely on the cleanup job
    try {
      const metadataPath = path.join(uploadsDir, `${uniqueId}.json`);
      await fs.writeFile(metadataPath, JSON.stringify(metadata, null, 2));
    } catch (error) {
      logger.warn('Failed to save metadata:', error);
      // Non-critical, continue
    }

    const processingTime = Date.now() - startTime;

    logger.info('Reverse image search completed', {
      filename,
      originalSize,
      newSize: processedImage.newSize,
      compressionRatio: ((1 - processedImage.newSize / originalSize) * 100).toFixed(1) + '%',
      processingTime: processingTime + 'ms',
      expiresAt
    });

    // Send response
    return sendSuccess(res, 'Image uploaded successfully', {
      imageUrl,
      searchUrls,
      expiresAt: expiresAt.toISOString(),
      optimized: {
        originalSize,
        newSize: processedImage.newSize,
        format: processedImage.format,
        compressionRatio: ((1 - processedImage.newSize / originalSize) * 100).toFixed(1) + '%',
        dimensions: {
          width: processedImage.width,
          height: processedImage.height
        }
      },
      expiresIn: '24 hours',
      processingTime: processingTime + 'ms'
    });
  })
);

/**
 * GET /api/tools/reverse-image-search/info
 * Get service information
 */
router.get('/info', asyncHandler(async (req, res) => {
  const info = {
    service: 'Reverse Image Search API',
    version: '1.0.0',
    description: 'Upload images and get reverse image search URLs for multiple search engines',
    supportedEngines: ['Google', 'Bing', 'TinEye', 'Yandex'],
    supportedFormats: ['JPEG', 'PNG', 'GIF', 'WebP', 'BMP', 'TIFF'],
    limits: {
      maxFileSize: '10MB',
      maxUploadsPerHour: 10,
      imageRetention: '24 hours'
    },
    features: {
      autoOptimization: true,
      autoResize: true,
      securityScanning: true,
      compressionEnabled: true,
      multipleSearchEngines: true
    },
    usage: {
      endpoint: 'POST /api/tools/reverse-image-search',
      method: 'POST',
      contentType: 'multipart/form-data',
      fields: {
        image: 'Image file (required)'
      },
      response: {
        imageUrl: 'Public URL of the uploaded image',
        searchUrls: 'Object containing search URLs for each engine',
        expiresAt: 'ISO timestamp when the image will be deleted',
        optimized: 'Image optimization details'
      }
    },
    rateLimit: {
      window: '1 hour',
      maxRequests: 10
    }
  };

  return sendSuccess(res, 'Service information retrieved', info);
}));

/**
 * DELETE /api/tools/reverse-image-search/:filename
 * Manually delete an uploaded image
 */
router.delete('/:filename', asyncHandler(async (req, res) => {
  const { filename } = req.params;

  // Validate filename format (UUID.jpg)
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.jpg$/i.test(filename)) {
    return sendError(res, 'Invalid filename format', 400);
  }

  const uploadsDir = path.join(__dirname, '../../uploads/reverse-search');
  const filePath = path.join(uploadsDir, filename);
  const metadataPath = path.join(uploadsDir, filename.replace('.jpg', '.json'));

  // Check if file exists
  if (!await fileExists(filePath)) {
    return sendError(res, 'File not found', 404);
  }

  // Delete image file
  try {
    await deleteFile(filePath);

    // Also delete metadata if exists
    if (await fileExists(metadataPath)) {
      await deleteFile(metadataPath);
    }

    logger.info('Image deleted manually', {
      filename,
      ip: req.ip
    });

    return sendSuccess(res, 'Image deleted successfully', { filename });
  } catch (error) {
    logger.error('Failed to delete image:', {
      error: error.message,
      filename
    });
    return sendError(res, 'Failed to delete image', 500);
  }
}));

module.exports = router;
