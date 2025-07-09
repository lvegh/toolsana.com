const express = require('express');
const multer = require('multer');
const sharp = require('sharp');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const logger = require('../utils/logger');
const Potrace = require('potrace');

const router = express.Router();

// Configure multer for JPG/JPEG file uploads
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

// Configure multer for PNG file uploads
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

// Configure multer for WebP file uploads
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

// Configure multer for AVIF file uploads
const uploadAvif = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Check if file is AVIF
    if (file.mimetype === 'image/avif') {
      cb(null, true);
    } else {
      cb(new Error('File must be an AVIF image'), false);
    }
  }
});

// Add this to your convert.js file

// Configure multer for SVG file uploads
const uploadSvg = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Check if file is SVG
    if (file.mimetype === 'image/svg+xml' || file.mimetype === 'text/xml' || file.originalname.toLowerCase().endsWith('.svg')) {
      cb(null, true);
    } else {
      cb(new Error('File must be an SVG image'), false);
    }
  }
});

// Configure multer for any image file uploads
const uploadAnyImage = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10MB limit
  },
  fileFilter: (req, file, cb) => {
    // Check if file is an image
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('File must be an image'), false);
    }
  }
});

/**
 * POST /api/convert/image-to-base64
 * Convert any image to Base64 string
 */
router.post('/image-to-base64', basicRateLimit, uploadAnyImage.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const includeDataUrl = req.body.includeDataUrl === 'true';
    const copyFormat = req.body.copyFormat || 'dataurl'; // 'dataurl', 'base64only', 'css', 'html', 'json'

    logger.info('Starting Image to Base64 conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      includeDataUrl,
      copyFormat
    });

    // Get image metadata
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('Image metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      hasAlpha: metadata.hasAlpha,
      colorspace: metadata.space
    });

    // Convert buffer to base64
    const base64String = originalBuffer.toString('base64');
    const mimeType = req.file.mimetype;
    const dataUrl = `data:${mimeType};base64,${base64String}`;

    // Generate different formats based on request
    let output = '';
    let contentType = 'text/plain';
    let filename = `${originalName}_base64.txt`;

    switch (copyFormat) {
      case 'dataurl':
        output = dataUrl;
        filename = `${originalName}_dataurl.txt`;
        break;
      
      case 'base64only':
        output = base64String;
        filename = `${originalName}_base64.txt`;
        break;
      
      case 'css':
        output = `background-image: url('${dataUrl}');`;
        filename = `${originalName}_css.css`;
        contentType = 'text/css';
        break;
      
      case 'html':
        output = `<img src="${dataUrl}" alt="${originalName}" />`;
        filename = `${originalName}_html.html`;
        contentType = 'text/html';
        break;
      
      case 'json':
        output = JSON.stringify({
          filename: req.file.originalname,
          mimeType: mimeType,
          size: originalBuffer.length,
          width: metadata.width,
          height: metadata.height,
          base64: base64String,
          dataUrl: dataUrl
        }, null, 2);
        filename = `${originalName}_data.json`;
        contentType = 'application/json';
        break;
      
      default:
        output = dataUrl;
        break;
    }

    logger.info('Image to Base64 conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      base64Length: base64String.length,
      outputLength: output.length,
      format: copyFormat,
      mimeType,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': contentType,
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': Buffer.byteLength(output, 'utf8').toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Base64-Length': base64String.length.toString(),
      'X-Output-Format': copyFormat,
      'X-Mime-Type': mimeType,
      'X-Image-Width': (metadata.width || 'unknown').toString(),
      'X-Image-Height': (metadata.height || 'unknown').toString(),
      'X-Image-Channels': (metadata.channels || 'unknown').toString()
    });

    // Send the base64 output
    res.send(output);

  } catch (error) {
    logger.error('Image to Base64 conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      copyFormat: req.body?.copyFormat
    });

    if (error.message.includes('File must be an image')) {
      return sendError(res, 'File must be an image', 400);
    }

    if (error.message.includes('Input buffer contains unsupported image format')) {
      return sendError(res, 'Unsupported image format', 400);
    }

    return sendError(res, 'Failed to convert image to Base64', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/base64-to-image
 * Convert Base64 string to image
 */
router.post('/base64-to-image', basicRateLimit, async (req, res) => {
  try {
    const { base64Data, filename, outputFormat } = req.body;

    if (!base64Data) {
      return sendError(res, 'No Base64 data provided', 400);
    }

    logger.info('Starting Base64 to Image conversion', {
      base64Length: base64Data.length,
      filename: filename || 'converted',
      outputFormat: outputFormat || 'auto'
    });

    let base64String = base64Data;
    let detectedMimeType = null;

    // Handle data URL format
    if (base64Data.startsWith('data:')) {
      const dataUrlMatch = base64Data.match(/^data:([^;]+);base64,(.+)$/);
      if (dataUrlMatch) {
        detectedMimeType = dataUrlMatch[1];
        base64String = dataUrlMatch[2];
        logger.info('Detected data URL format', { mimeType: detectedMimeType });
      } else {
        return sendError(res, 'Invalid data URL format', 400);
      }
    }

    // Convert base64 to buffer
    let imageBuffer;
    try {
      imageBuffer = Buffer.from(base64String, 'base64');
    } catch (bufferError) {
      return sendError(res, 'Invalid Base64 string', 400);
    }

    if (imageBuffer.length === 0) {
      return sendError(res, 'Empty Base64 data', 400);
    }

    // Get image metadata to validate and determine format
    let metadata;
    try {
      metadata = await sharp(imageBuffer).metadata();
    } catch (sharpError) {
      return sendError(res, 'Invalid image data in Base64 string', 400);
    }

    logger.info('Decoded image metadata', {
      width: metadata.width,
      height: metadata.height,
      format: metadata.format,
      hasAlpha: metadata.hasAlpha,
      colorspace: metadata.space,
      size: imageBuffer.length
    });

    // Determine output format
    let targetFormat = outputFormat || metadata.format || 'png';
    let outputMimeType = `image/${targetFormat}`;
    let outputBuffer = imageBuffer;

    // Convert if different format requested
    if (outputFormat && outputFormat !== metadata.format) {
      try {
        let sharpInstance = sharp(imageBuffer);
        
        switch (outputFormat.toLowerCase()) {
          case 'png':
            outputBuffer = await sharpInstance.png().toBuffer();
            outputMimeType = 'image/png';
            break;
          case 'jpg':
          case 'jpeg':
            outputBuffer = await sharpInstance.jpeg({ quality: 90 }).toBuffer();
            outputMimeType = 'image/jpeg';
            targetFormat = 'jpg';
            break;
          case 'webp':
            outputBuffer = await sharpInstance.webp({ quality: 90 }).toBuffer();
            outputMimeType = 'image/webp';
            break;
          case 'avif':
            outputBuffer = await sharpInstance.avif({ quality: 90 }).toBuffer();
            outputMimeType = 'image/avif';
            break;
          default:
            // Keep original format
            outputBuffer = imageBuffer;
            outputMimeType = detectedMimeType || `image/${metadata.format}`;
            targetFormat = metadata.format;
        }
      } catch (conversionError) {
        logger.error('Format conversion error:', conversionError);
        // Fall back to original format
        outputBuffer = imageBuffer;
        outputMimeType = detectedMimeType || `image/${metadata.format}`;
        targetFormat = metadata.format;
      }
    } else {
      outputMimeType = detectedMimeType || `image/${metadata.format}`;
    }

    // Generate filename
    const outputFilename = filename 
      ? `${filename.replace(/\.[^/.]+$/, '')}.${targetFormat}`
      : `converted_image.${targetFormat}`;

    logger.info('Base64 to Image conversion completed', {
      inputBase64Length: base64Data.length,
      outputSize: outputBuffer.length,
      outputFormat: targetFormat,
      outputMimeType,
      filename: outputFilename,
      originalFormat: metadata.format,
      converted: outputFormat && outputFormat !== metadata.format
    });

    // Set response headers
    res.set({
      'Content-Type': outputMimeType,
      'Content-Disposition': `attachment; filename="${outputFilename}"`,
      'Content-Length': outputBuffer.length.toString(),
      'X-Original-Format': metadata.format,
      'X-Output-Format': targetFormat,
      'X-Image-Width': (metadata.width || 'unknown').toString(),
      'X-Image-Height': (metadata.height || 'unknown').toString(),
      'X-Original-Base64-Length': base64Data.length.toString(),
      'X-Converted': (outputFormat && outputFormat !== metadata.format) ? 'true' : 'false'
    });

    // Send the converted image
    res.send(outputBuffer);

  } catch (error) {
    logger.error('Base64 to Image conversion error:', {
      error: error.message,
      stack: error.stack,
      base64Length: req.body?.base64Data?.length,
      filename: req.body?.filename,
      outputFormat: req.body?.outputFormat
    });

    return sendError(res, 'Failed to convert Base64 to image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/png-to-svg
 * Convert PNG images to SVG using JavaScript Potrace (Railway-compatible)
 */
router.post('/png-to-svg', basicRateLimit, uploadPng.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const threshold = parseInt(req.body.threshold) || 128;
    const turdSize = parseInt(req.body.turdSize) || 2;
    const alphaMax = parseFloat(req.body.alphaMax) || 1.0;
    const optCurve = req.body.optCurve !== 'false';
    const optTolerance = parseFloat(req.body.optTolerance) || 0.2;
    const turnPolicy = req.body.turnPolicy || 'minority';
    const color = req.body.color || 'auto';

    // Validate parameters
    if (threshold < 0 || threshold > 255) {
      return sendError(res, 'Threshold must be between 0 and 255', 400);
    }

    if (turdSize < 0 || turdSize > 100) {
      return sendError(res, 'Turd size must be between 0 and 100', 400);
    }

    if (alphaMax < 0 || alphaMax > 1.3) {
      return sendError(res, 'Alpha max must be between 0 and 1.3', 400);
    }

    if (optTolerance < 0 || optTolerance > 1) {
      return sendError(res, 'Optimization tolerance must be between 0 and 1', 400);
    }

    const validTurnPolicies = ['black', 'white', 'left', 'right', 'minority', 'majority'];
    if (!validTurnPolicies.includes(turnPolicy)) {
      return sendError(res, 'Invalid turn policy', 400);
    }

    logger.info('Starting PNG to SVG conversion (JavaScript Potrace)', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      threshold,
      turdSize,
      alphaMax,
      optCurve,
      optTolerance,
      turnPolicy,
      color
    });

    // Get PNG metadata
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('PNG metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      hasAlpha: metadata.hasAlpha,
      colorspace: metadata.space
    });

    // Configure potrace options for JavaScript implementation
    const potraceOptions = {
      threshold: threshold,
      turdSize: turdSize,
      alphaMax: alphaMax,
      optCurve: optCurve,
      optTolerance: optTolerance,
      turnPolicy: turnPolicy
    };

    // Add color if specified (not 'auto')
    if (color !== 'auto') {
      potraceOptions.color = color;
    }

    logger.info('JavaScript Potrace options', potraceOptions);

    // Use JavaScript Potrace to trace the image
    const svgString = await new Promise((resolve, reject) => {
      Potrace.trace(originalBuffer, potraceOptions, (err, svg) => {
        if (err) {
          reject(err);
        } else {
          resolve(svg);
        }
      });
    });

    // Verify the SVG was generated
    if (!svgString || svgString.length === 0) {
      throw new Error('Vectorization resulted in empty SVG');
    }

    // Additional validation - check if SVG is valid
    if (!svgString.includes('<svg') || !svgString.includes('</svg>')) {
      throw new Error('Generated SVG is invalid or corrupted');
    }

    // Convert string to buffer for consistent handling
    const svgBuffer = Buffer.from(svgString, 'utf8');

    // Generate filename
    const filename = `${originalName}.svg`;

    const compressionRatio = ((originalBuffer.length - svgBuffer.length) / originalBuffer.length * 100).toFixed(2);

    logger.info('PNG to SVG conversion completed (JavaScript Potrace)', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: svgBuffer.length,
      compressionRatio: compressionRatio + '%',
      svgLength: svgString.length,
      threshold,
      turdSize,
      alphaMax,
      optCurve,
      optTolerance,
      turnPolicy,
      color,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/svg+xml',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': svgBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': svgBuffer.length.toString(),
      'X-Compression-Ratio': compressionRatio + '%',
      'X-Threshold': threshold.toString(),
      'X-Turd-Size': turdSize.toString(),
      'X-Alpha-Max': alphaMax.toString(),
      'X-Opt-Curve': optCurve.toString(),
      'X-Opt-Tolerance': optTolerance.toString(),
      'X-Turn-Policy': turnPolicy,
      'X-Color': color,
      'X-Original-Width': (metadata.width || 'unknown').toString(),
      'X-Original-Height': (metadata.height || 'unknown').toString(),
      'X-Original-Channels': (metadata.channels || 'unknown').toString(),
      'X-Engine': 'potrace-js'
    });

    // Send the converted SVG
    res.send(svgBuffer);

  } catch (error) {
    logger.error('PNG to SVG conversion error (JavaScript Potrace):', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      threshold: req.body?.threshold,
      turdSize: req.body?.turdSize,
      alphaMax: req.body?.alphaMax,
      optCurve: req.body?.optCurve,
      optTolerance: req.body?.optTolerance,
      turnPolicy: req.body?.turnPolicy,
      color: req.body?.color
    });

    if (error.message.includes('File must be a PNG image')) {
      return sendError(res, 'File must be a PNG image', 400);
    }

    if (error.message.includes('Vectorization resulted in empty SVG')) {
      return sendError(res, 'Vectorization failed. The image may be too complex or contain no traceable content.', 500);
    }

    if (error.message.includes('Generated SVG is invalid')) {
      return sendError(res, 'SVG generation failed - resulting file is corrupted', 500);
    }

    if (error.message.includes('ENOENT') || error.message.includes('no such file')) {
      return sendError(res, 'Image file could not be processed. Please ensure the file is a valid PNG.', 400);
    }

    return sendError(res, 'Failed to convert PNG to SVG', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/jpg-to-svg
 * Convert JPG/JPEG images to SVG using JavaScript Potrace (Railway-compatible)
 */
router.post('/jpg-to-svg', basicRateLimit, uploadJpg.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const threshold = parseInt(req.body.threshold) || 128;
    const turdSize = parseInt(req.body.turdSize) || 2;
    const alphaMax = parseFloat(req.body.alphaMax) || 1.0;
    const optCurve = req.body.optCurve !== 'false';
    const optTolerance = parseFloat(req.body.optTolerance) || 0.2;
    const turnPolicy = req.body.turnPolicy || 'minority';
    const color = req.body.color || 'auto';

    // Same validation as PNG to SVG...
    if (threshold < 0 || threshold > 255) {
      return sendError(res, 'Threshold must be between 0 and 255', 400);
    }

    if (turdSize < 0 || turdSize > 100) {
      return sendError(res, 'Turd size must be between 0 and 100', 400);
    }

    if (alphaMax < 0 || alphaMax > 1.3) {
      return sendError(res, 'Alpha max must be between 0 and 1.3', 400);
    }

    if (optTolerance < 0 || optTolerance > 1) {
      return sendError(res, 'Optimization tolerance must be between 0 and 1', 400);
    }

    const validTurnPolicies = ['black', 'white', 'left', 'right', 'minority', 'majority'];
    if (!validTurnPolicies.includes(turnPolicy)) {
      return sendError(res, 'Invalid turn policy', 400);
    }

    logger.info('Starting JPG to SVG conversion (JavaScript Potrace)', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      threshold,
      turdSize,
      alphaMax,
      optCurve,
      optTolerance,
      turnPolicy,
      color
    });

    // Get JPG metadata
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('JPG metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      colorspace: metadata.space
    });

    // Configure potrace options for JavaScript implementation
    const potraceOptions = {
      threshold: threshold,
      turdSize: turdSize,
      alphaMax: alphaMax,
      optCurve: optCurve,
      optTolerance: optTolerance,
      turnPolicy: turnPolicy
    };

    // Add color if specified (not 'auto')
    if (color !== 'auto') {
      potraceOptions.color = color;
    }

    logger.info('JavaScript Potrace options', potraceOptions);

    // Use JavaScript Potrace to trace the JPG image
    const svgString = await new Promise((resolve, reject) => {
      Potrace.trace(originalBuffer, potraceOptions, (err, svg) => {
        if (err) {
          reject(err);
        } else {
          resolve(svg);
        }
      });
    });

    // Verify the SVG was generated
    if (!svgString || svgString.length === 0) {
      throw new Error('Vectorization resulted in empty SVG');
    }

    // Additional validation - check if SVG is valid
    if (!svgString.includes('<svg') || !svgString.includes('</svg>')) {
      throw new Error('Generated SVG is invalid or corrupted');
    }

    // Convert string to buffer for consistent handling
    const svgBuffer = Buffer.from(svgString, 'utf8');

    // Generate filename
    const filename = `${originalName}.svg`;

    const compressionRatio = ((originalBuffer.length - svgBuffer.length) / originalBuffer.length * 100).toFixed(2);

    logger.info('JPG to SVG conversion completed (JavaScript Potrace)', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: svgBuffer.length,
      compressionRatio: compressionRatio + '%',
      svgLength: svgString.length,
      threshold,
      turdSize,
      alphaMax,
      optCurve,
      optTolerance,
      turnPolicy,
      color,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/svg+xml',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': svgBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': svgBuffer.length.toString(),
      'X-Compression-Ratio': compressionRatio + '%',
      'X-Threshold': threshold.toString(),
      'X-Turd-Size': turdSize.toString(),
      'X-Alpha-Max': alphaMax.toString(),
      'X-Opt-Curve': optCurve.toString(),
      'X-Opt-Tolerance': optTolerance.toString(),
      'X-Turn-Policy': turnPolicy,
      'X-Color': color,
      'X-Original-Width': (metadata.width || 'unknown').toString(),
      'X-Original-Height': (metadata.height || 'unknown').toString(),
      'X-Original-Format': 'JPEG',
      'X-Engine': 'potrace-js'
    });

    // Send the converted SVG
    res.send(svgBuffer);

  } catch (error) {
    logger.error('JPG to SVG conversion error (JavaScript Potrace):', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      threshold: req.body?.threshold,
      turdSize: req.body?.turdSize,
      alphaMax: req.body?.alphaMax,
      optCurve: req.body?.optCurve,
      optTolerance: req.body?.optTolerance,
      turnPolicy: req.body?.turnPolicy,
      color: req.body?.color
    });

    if (error.message.includes('File must be a JPG/JPEG image')) {
      return sendError(res, 'File must be a JPG/JPEG image', 400);
    }

    if (error.message.includes('Vectorization resulted in empty SVG')) {
      return sendError(res, 'Vectorization failed. The image may be too complex or contain no traceable content.', 500);
    }

    if (error.message.includes('Generated SVG is invalid')) {
      return sendError(res, 'SVG generation failed - resulting file is corrupted', 500);
    }

    if (error.message.includes('ENOENT') || error.message.includes('no such file')) {
      return sendError(res, 'Image file could not be processed. Please ensure the file is a valid JPG.', 400);
    }

    return sendError(res, 'Failed to convert JPG to SVG', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/svg-to-jpg
 * Convert SVG images to JPG/JPEG
 */
router.post('/svg-to-jpg', basicRateLimit, uploadSvg.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const quality = parseInt(req.body.quality) || 90;
    const backgroundColor = req.body.backgroundColor || '#ffffff';
    const width = parseInt(req.body.width) || null;
    const height = parseInt(req.body.height) || null;
    const density = parseInt(req.body.density) || 72;

    // Validate quality parameter
    if (quality < 10 || quality > 100) {
      return sendError(res, 'Quality must be between 10 and 100', 400);
    }

    // Validate background color format
    if (!/^#[0-9A-F]{6}$/i.test(backgroundColor)) {
      return sendError(res, 'Background color must be a valid hex color (e.g., #ffffff)', 400);
    }

    // Validate dimensions
    if (width && (width < 1 || width > 8000)) {
      return sendError(res, 'Width must be between 1 and 8000 pixels', 400);
    }

    if (height && (height < 1 || height > 8000)) {
      return sendError(res, 'Height must be between 1 and 8000 pixels', 400);
    }

    // Validate density
    if (density < 72 || density > 300) {
      return sendError(res, 'Density must be between 72 and 300 DPI', 400);
    }

    logger.info('Starting SVG to JPG conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      quality,
      backgroundColor,
      width: width || 'auto',
      height: height || 'auto',
      density
    });

    // Configure JPEG options
    const jpegOptions = {
      quality: quality,
      progressive: true,
      mozjpeg: true // Use mozjpeg encoder for better compression
    };

    // Convert hex color to RGB values for background
    const rgb = {
      r: parseInt(backgroundColor.slice(1, 3), 16),
      g: parseInt(backgroundColor.slice(3, 5), 16),
      b: parseInt(backgroundColor.slice(5, 7), 16)
    };

    // Convert SVG to JPG with Sharp
    let sharpInstance = sharp(originalBuffer, {
      density: density // Set DPI for rasterization
    });

    // Get SVG metadata to understand dimensions
    const metadata = await sharpInstance.metadata();

    logger.info('SVG metadata', {
      width: metadata.width,
      height: metadata.height,
      format: metadata.format,
      density: metadata.density,
      hasAlpha: metadata.hasAlpha
    });

    // Apply resizing if specified
    if (width || height) {
      sharpInstance = sharpInstance.resize(width, height, {
        fit: 'inside', // Maintain aspect ratio
        withoutEnlargement: false // Allow enlargement
      });
    }

    // Convert to JPG with background color (SVG transparency handling)
    const jpegBuffer = await sharpInstance
      .flatten({ background: rgb }) // Handle transparency with background color
      .jpeg(jpegOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!jpegBuffer || jpegBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(jpegBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        size: jpegBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.jpg`;

    const compressionRatio = ((originalBuffer.length - jpegBuffer.length) / originalBuffer.length * 100).toFixed(2);

    logger.info('SVG to JPG conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: jpegBuffer.length,
      compressionRatio: compressionRatio + '%',
      quality,
      backgroundColor,
      finalWidth: width || metadata.width,
      finalHeight: height || metadata.height,
      density,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/jpeg',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': jpegBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': jpegBuffer.length.toString(),
      'X-Compression-Ratio': compressionRatio + '%',
      'X-Quality': quality.toString(),
      'X-Background-Color': backgroundColor,
      'X-Width': (width || metadata.width || 'auto').toString(),
      'X-Height': (height || metadata.height || 'auto').toString(),
      'X-Density': density.toString(),
      'X-Original-Format': 'SVG'
    });

    // Send the converted image
    res.send(jpegBuffer);

  } catch (error) {
    logger.error('SVG to JPG conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      quality: req.body?.quality,
      backgroundColor: req.body?.backgroundColor,
      width: req.body?.width,
      height: req.body?.height,
      density: req.body?.density
    });

    if (error.message.includes('File must be an SVG image')) {
      return sendError(res, 'File must be an SVG image', 400);
    }

    if (error.message.includes('Input buffer contains unsupported image format')) {
      return sendError(res, 'Invalid SVG file format or corrupted file', 400);
    }

    if (error.message.includes('jpeg') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'JPEG encoding failed. The SVG file may be corrupted or contain unsupported elements.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert SVG to JPG', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/svg-to-png  
 * Convert SVG images to PNG
 */
router.post('/svg-to-png', basicRateLimit, uploadSvg.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const compressionLevel = parseInt(req.body.compressionLevel) || 6;
    const width = parseInt(req.body.width) || null;
    const height = parseInt(req.body.height) || null;
    const density = parseInt(req.body.density) || 72;

    // Validate compression level parameter
    if (compressionLevel < 0 || compressionLevel > 9) {
      return sendError(res, 'Compression level must be between 0 and 9', 400);
    }

    // Validate dimensions
    if (width && (width < 1 || width > 8000)) {
      return sendError(res, 'Width must be between 1 and 8000 pixels', 400);
    }

    if (height && (height < 1 || height > 8000)) {
      return sendError(res, 'Height must be between 1 and 8000 pixels', 400);
    }

    // Validate density
    if (density < 72 || density > 300) {
      return sendError(res, 'Density must be between 72 and 300 DPI', 400);
    }

    logger.info('Starting SVG to PNG conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      compressionLevel,
      width: width || 'auto',
      height: height || 'auto',
      density
    });

    // Configure PNG options
    const pngOptions = {
      compressionLevel: compressionLevel,
      adaptiveFiltering: true,
      force: true // Force PNG output
    };

    // Convert SVG to PNG with Sharp
    let sharpInstance = sharp(originalBuffer, {
      density: density // Set DPI for rasterization
    });

    // Get SVG metadata to understand dimensions
    const metadata = await sharpInstance.metadata();

    logger.info('SVG metadata', {
      width: metadata.width,
      height: metadata.height,
      format: metadata.format,
      density: metadata.density,
      hasAlpha: metadata.hasAlpha
    });

    // Apply resizing if specified
    if (width || height) {
      sharpInstance = sharpInstance.resize(width, height, {
        fit: 'inside', // Maintain aspect ratio
        withoutEnlargement: false // Allow enlargement
      });
    }

    // Convert to PNG (preserves transparency)
    const pngBuffer = await sharpInstance
      .png(pngOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!pngBuffer || pngBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(pngBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        hasAlpha: convertedMetadata.hasAlpha,
        size: pngBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.png`;

    const sizeChange = ((pngBuffer.length - originalBuffer.length) / originalBuffer.length * 100).toFixed(2);
    const sizeChangeType = pngBuffer.length > originalBuffer.length ? 'increase' : 'decrease';

    logger.info('SVG to PNG conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: pngBuffer.length,
      sizeChange: `${Math.abs(parseFloat(sizeChange))}% ${sizeChangeType}`,
      compressionLevel,
      finalWidth: width || metadata.width,
      finalHeight: height || metadata.height,
      density,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/png',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': pngBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': pngBuffer.length.toString(),
      'X-Size-Change': `${sizeChange}%`,
      'X-Size-Change-Type': sizeChangeType,
      'X-Compression-Level': compressionLevel.toString(),
      'X-Width': (width || metadata.width || 'auto').toString(),
      'X-Height': (height || metadata.height || 'auto').toString(),
      'X-Density': density.toString(),
      'X-Original-Format': 'SVG'
    });

    // Send the converted image
    res.send(pngBuffer);

  } catch (error) {
    logger.error('SVG to PNG conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      compressionLevel: req.body?.compressionLevel,
      width: req.body?.width,
      height: req.body?.height,
      density: req.body?.density
    });

    if (error.message.includes('File must be an SVG image')) {
      return sendError(res, 'File must be an SVG image', 400);
    }

    if (error.message.includes('Input buffer contains unsupported image format')) {
      return sendError(res, 'Invalid SVG file format or corrupted file', 400);
    }

    if (error.message.includes('png') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'PNG encoding failed. The SVG file may be corrupted or contain unsupported elements.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert SVG to PNG', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/avif-to-png
 * Convert AVIF images to PNG
 */
router.post('/avif-to-png', basicRateLimit, uploadAvif.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const compressionLevel = parseInt(req.body.compressionLevel) || 6;

    // Validate compression level parameter
    if (compressionLevel < 0 || compressionLevel > 9) {
      return sendError(res, 'Compression level must be between 0 and 9', 400);
    }

    logger.info('Starting AVIF to PNG conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      compressionLevel
    });

    // Get image metadata for better conversion handling
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('Image metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      colorspace: metadata.space,
      hasAlpha: metadata.hasAlpha,
      hasProfile: !!metadata.icc
    });

    // Configure PNG options
    const pngOptions = {
      compressionLevel: compressionLevel,
      adaptiveFiltering: true,
      force: true // Force PNG output even if input is already PNG
    };

    // Convert AVIF to PNG with Sharp
    let sharpInstance = sharp(originalBuffer)
      .rotate(); // Auto-rotate based on EXIF orientation

    // Ensure proper color space handling while preserving transparency
    if (metadata.space && metadata.space !== 'srgb') {
      sharpInstance = sharpInstance.toColorspace('srgb');
    }

    const pngBuffer = await sharpInstance
      .png(pngOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!pngBuffer || pngBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(pngBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        hasAlpha: convertedMetadata.hasAlpha,
        size: pngBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.png`;

    const sizeChange = ((pngBuffer.length - originalBuffer.length) / originalBuffer.length * 100).toFixed(2);
    const sizeChangeType = pngBuffer.length > originalBuffer.length ? 'increase' : 'decrease';

    logger.info('AVIF to PNG conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: pngBuffer.length,
      sizeChange: `${Math.abs(parseFloat(sizeChange))}% ${sizeChangeType}`,
      compressionLevel,
      preservedTransparency: metadata.hasAlpha,
      colorspace: metadata.space,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/png',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': pngBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': pngBuffer.length.toString(),
      'X-Size-Change': `${sizeChange}%`,
      'X-Size-Change-Type': sizeChangeType,
      'X-Compression-Level': compressionLevel.toString(),
      'X-Preserved-Transparency': metadata.hasAlpha ? 'true' : 'false',
      'X-Original-Colorspace': metadata.space || 'unknown'
    });

    // Send the converted image
    res.send(pngBuffer);

  } catch (error) {
    logger.error('AVIF to PNG conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      compressionLevel: req.body?.compressionLevel
    });

    if (error.message.includes('File must be an AVIF image')) {
      return sendError(res, 'File must be an AVIF image', 400);
    }

    if (error.message.includes('png') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'PNG encoding failed. The image cannot be converted.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/avif-to-jpg
 * Convert AVIF images to JPG/JPEG
 */
router.post('/avif-to-jpg', basicRateLimit, uploadAvif.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const quality = parseInt(req.body.quality) || 90;
    const backgroundColor = req.body.backgroundColor || '#ffffff';

    // Validate quality parameter
    if (quality < 10 || quality > 100) {
      return sendError(res, 'Quality must be between 10 and 100', 400);
    }

    // Validate background color format
    if (!/^#[0-9A-F]{6}$/i.test(backgroundColor)) {
      return sendError(res, 'Background color must be a valid hex color (e.g., #ffffff)', 400);
    }

    logger.info('Starting AVIF to JPG conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      quality,
      backgroundColor
    });

    // Get image metadata for better conversion handling
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('Image metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      colorspace: metadata.space,
      hasAlpha: metadata.hasAlpha,
      hasProfile: !!metadata.icc
    });

    // Configure JPEG options
    const jpegOptions = {
      quality: quality,
      progressive: true,
      mozjpeg: true // Use mozjpeg encoder for better compression
    };

    // Convert AVIF to JPG with Sharp
    let sharpInstance = sharp(originalBuffer)
      .rotate(); // Auto-rotate based on EXIF orientation

    // Handle transparency by flattening with background color
    if (metadata.hasAlpha) {
      const rgb = {
        r: parseInt(backgroundColor.slice(1, 3), 16),
        g: parseInt(backgroundColor.slice(3, 5), 16),
        b: parseInt(backgroundColor.slice(5, 7), 16)
      };
      sharpInstance = sharpInstance.flatten({ background: rgb });
    }

    // Ensure proper color space handling
    if (metadata.space && metadata.space !== 'srgb') {
      sharpInstance = sharpInstance.toColorspace('srgb');
    }

    const jpegBuffer = await sharpInstance
      .jpeg(jpegOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!jpegBuffer || jpegBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(jpegBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        size: jpegBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.jpg`;

    const compressionRatio = ((originalBuffer.length - jpegBuffer.length) / originalBuffer.length * 100).toFixed(2);

    logger.info('AVIF to JPG conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: jpegBuffer.length,
      compressionRatio: compressionRatio + '%',
      quality,
      backgroundColor,
      hadTransparency: metadata.hasAlpha,
      colorspace: metadata.space,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/jpeg',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': jpegBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': jpegBuffer.length.toString(),
      'X-Compression-Ratio': compressionRatio + '%',
      'X-Quality': quality.toString(),
      'X-Background-Color': backgroundColor,
      'X-Had-Transparency': metadata.hasAlpha ? 'true' : 'false',
      'X-Original-Colorspace': metadata.space || 'unknown'
    });

    // Send the converted image
    res.send(jpegBuffer);

  } catch (error) {
    logger.error('AVIF to JPG conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      quality: req.body?.quality,
      backgroundColor: req.body?.backgroundColor
    });

    if (error.message.includes('File must be an AVIF image')) {
      return sendError(res, 'File must be an AVIF image', 400);
    }

    if (error.message.includes('jpeg') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'JPEG encoding failed. The image cannot be converted.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/avif-to-webp
 * Convert AVIF images to WebP
 */
router.post('/avif-to-webp', basicRateLimit, uploadAvif.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const quality = parseInt(req.body.quality) || 80;
    const lossless = req.body.lossless === 'true';
    const effort = parseInt(req.body.effort) || 4;

    // Validate quality parameter (only for lossy compression)
    if (!lossless && (quality < 1 || quality > 100)) {
      return sendError(res, 'Quality must be between 1 and 100', 400);
    }

    // Validate effort parameter
    if (effort < 0 || effort > 6) {
      return sendError(res, 'Effort must be between 0 and 6', 400);
    }

    logger.info('Starting AVIF to WebP conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      quality: lossless ? 'lossless' : quality,
      lossless,
      effort
    });

    // Get image metadata for better conversion handling
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('Image metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      colorspace: metadata.space,
      hasAlpha: metadata.hasAlpha,
      hasProfile: !!metadata.icc
    });

    // Configure WebP options
    const webpOptions = {
      quality: lossless ? 100 : quality,
      lossless: lossless,
      effort: effort,
      smartSubsample: !lossless // Use smart subsampling for lossy compression
    };

    // Convert AVIF to WebP with Sharp
    let sharpInstance = sharp(originalBuffer)
      .rotate(); // Auto-rotate based on EXIF orientation

    // Ensure proper color space handling while preserving transparency
    if (metadata.space && metadata.space !== 'srgb') {
      sharpInstance = sharpInstance.toColorspace('srgb');
    }

    const webpBuffer = await sharpInstance
      .webp(webpOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!webpBuffer || webpBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(webpBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        hasAlpha: convertedMetadata.hasAlpha,
        size: webpBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.webp`;

    const compressionRatio = ((originalBuffer.length - webpBuffer.length) / originalBuffer.length * 100).toFixed(2);

    logger.info('AVIF to WebP conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: webpBuffer.length,
      compressionRatio: compressionRatio + '%',
      quality: lossless ? 'lossless' : quality,
      lossless,
      effort,
      preservedTransparency: metadata.hasAlpha,
      colorspace: metadata.space,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/webp',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': webpBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': webpBuffer.length.toString(),
      'X-Compression-Ratio': compressionRatio + '%',
      'X-Quality': lossless ? 'lossless' : quality.toString(),
      'X-Lossless': lossless ? 'true' : 'false',
      'X-Effort': effort.toString(),
      'X-Preserved-Transparency': metadata.hasAlpha ? 'true' : 'false',
      'X-Original-Colorspace': metadata.space || 'unknown'
    });

    // Send the converted image
    res.send(webpBuffer);

  } catch (error) {
    logger.error('AVIF to WebP conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      quality: req.body?.quality,
      lossless: req.body?.lossless,
      effort: req.body?.effort
    });

    if (error.message.includes('File must be an AVIF image')) {
      return sendError(res, 'File must be an AVIF image', 400);
    }

    if (error.message.includes('webp') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'WebP encoding failed. The image cannot be converted.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/jpg-to-png
 * Convert JPG/JPEG images to PNG
 */
router.post('/jpg-to-png', basicRateLimit, uploadJpg.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');

    logger.info('Starting JPG to PNG conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype
    });

    // Convert JPG to PNG with Sharp
    const pngBuffer = await sharp(originalBuffer)
      .rotate() // Auto-rotate based on EXIF orientation
      .png() // Convert to PNG format
      .toBuffer();

    // Generate filename
    const filename = `${originalName}.png`;

    logger.info('JPG to PNG conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: pngBuffer.length,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/png',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': pngBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': pngBuffer.length.toString()
    });

    // Send the converted image
    res.send(pngBuffer);

  } catch (error) {
    logger.error('JPG to PNG conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (error.message.includes('File must be a JPG/JPEG image')) {
      return sendError(res, 'File must be a JPG/JPEG image', 400);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/png-to-avif
 * Convert PNG images to AVIF
 */
router.post('/png-to-avif', basicRateLimit, uploadPng.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const quality = parseInt(req.body.quality) || 80;
    const compressionType = req.body.compressionType || 'lossy';

    // Validate compression type
    if (!['lossy', 'lossless'].includes(compressionType)) {
      return sendError(res, 'Compression type must be either "lossy" or "lossless"', 400);
    }

    // Validate quality parameter for lossy compression
    if (compressionType === 'lossy' && (quality < 10 || quality > 100)) {
      return sendError(res, 'Quality must be between 10 and 100 for lossy compression', 400);
    }

    logger.info('Starting PNG to AVIF conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      compressionType,
      quality: compressionType === 'lossy' ? quality : 'N/A (lossless)'
    });

    // Get image metadata to check for transparency
    const metadata = await sharp(originalBuffer).metadata();
    const hasAlpha = metadata.channels === 4 || metadata.hasAlpha;

    logger.info('Image metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      hasAlpha: hasAlpha,
      format: metadata.format,
      colorspace: metadata.space
    });

    // Configure AVIF options based on compression type and image characteristics
    const avifOptions = {
      effort: 4, // Encoding effort (0-9, higher = better compression but slower)
    };

    if (compressionType === 'lossless') {
      // Lossless AVIF configuration
      avifOptions.lossless = true;
      // Do NOT use chroma subsampling with lossless - it causes issues
      // Remove any quality settings for lossless
    } else {
      // Lossy AVIF configuration
      avifOptions.quality = quality;

      // Only use chroma subsampling for lossy compression
      if (!hasAlpha) {
        avifOptions.chromaSubsampling = '4:2:0';
      } else {
        // For images with transparency, use 4:4:4 to preserve quality
        avifOptions.chromaSubsampling = '4:4:4';
      }
    }

    // Convert PNG to AVIF with Sharp
    let sharpInstance = sharp(originalBuffer)
      .rotate(); // Auto-rotate based on EXIF orientation

    // Ensure proper color space handling
    if (metadata.space && metadata.space !== 'srgb') {
      sharpInstance = sharpInstance.toColorspace('srgb');
    }

    const avifBuffer = await sharpInstance
      .avif(avifOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!avifBuffer || avifBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(avifBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        size: avifBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.avif`;

    const compressionRatio = ((originalBuffer.length - avifBuffer.length) / originalBuffer.length * 100).toFixed(2);

    logger.info('PNG to AVIF conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: avifBuffer.length,
      compressionRatio: compressionRatio + '%',
      compressionType,
      quality: compressionType === 'lossy' ? quality : 'N/A (lossless)',
      hasAlpha: hasAlpha,
      chromaSubsampling: compressionType === 'lossless' ? 'none (lossless)' : avifOptions.chromaSubsampling,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/avif',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': avifBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': avifBuffer.length.toString(),
      'X-Compression-Ratio': compressionRatio + '%',
      'X-Compression-Type': compressionType,
      'X-Quality': compressionType === 'lossy' ? quality.toString() : 'lossless',
      'X-Has-Alpha': hasAlpha.toString(),
      'X-Chroma-Subsampling': compressionType === 'lossless' ? 'none' : (avifOptions.chromaSubsampling || 'none')
    });

    // Send the converted image
    res.send(avifBuffer);

  } catch (error) {
    logger.error('PNG to AVIF conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      compressionType: req.body?.compressionType,
      quality: req.body?.quality
    });

    if (error.message.includes('File must be a PNG image')) {
      return sendError(res, 'File must be a PNG image', 400);
    }

    if (error.message.includes('avif') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'AVIF encoding failed. Your system may not support AVIF conversion or the image cannot be converted.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/jpg-to-avif
 * Convert JPG/JPEG images to AVIF
 */
router.post('/jpg-to-avif', basicRateLimit, uploadJpg.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const quality = parseInt(req.body.quality) || 80;

    // Validate quality parameter
    if (quality < 10 || quality > 100) {
      return sendError(res, 'Quality must be between 10 and 100', 400);
    }

    logger.info('Starting JPG to AVIF conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      quality
    });

    // Get image metadata for better conversion handling
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('Image metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      colorspace: metadata.space,
      hasProfile: !!metadata.icc
    });

    // Configure AVIF options
    const avifOptions = {
      quality: quality,
      effort: 4, // Encoding effort (0-9, higher = better compression but slower)
      chromaSubsampling: '4:2:0' // Good for JPG since it doesn't have transparency
    };

    // Convert JPG to AVIF with Sharp
    let sharpInstance = sharp(originalBuffer)
      .rotate(); // Auto-rotate based on EXIF orientation

    // Ensure proper color space handling
    if (metadata.space && metadata.space !== 'srgb') {
      sharpInstance = sharpInstance.toColorspace('srgb');
    }

    const avifBuffer = await sharpInstance
      .avif(avifOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!avifBuffer || avifBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(avifBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        size: avifBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.avif`;

    const compressionRatio = ((originalBuffer.length - avifBuffer.length) / originalBuffer.length * 100).toFixed(2);

    logger.info('JPG to AVIF conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: avifBuffer.length,
      compressionRatio: compressionRatio + '%',
      quality,
      colorspace: metadata.space,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/avif',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': avifBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': avifBuffer.length.toString(),
      'X-Compression-Ratio': compressionRatio + '%',
      'X-Quality': quality.toString(),
      'X-Original-Colorspace': metadata.space || 'unknown',
      'X-Chroma-Subsampling': '4:2:0'
    });

    // Send the converted image
    res.send(avifBuffer);

  } catch (error) {
    logger.error('JPG to AVIF conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      quality: req.body?.quality
    });

    if (error.message.includes('File must be a JPG/JPEG image')) {
      return sendError(res, 'File must be a JPG/JPEG image', 400);
    }

    if (error.message.includes('avif') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'AVIF encoding failed. Your system may not support AVIF conversion or the image cannot be converted.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/webp-to-jpg
 * Convert WebP images to JPG/JPEG
 */
router.post('/webp-to-jpg', basicRateLimit, uploadWebp.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const quality = parseInt(req.body.quality) || 90;
    const backgroundColor = req.body.backgroundColor || '#ffffff';

    // Validate quality parameter
    if (quality < 10 || quality > 100) {
      return sendError(res, 'Quality must be between 10 and 100', 400);
    }

    // Validate background color format
    if (!/^#[0-9A-F]{6}$/i.test(backgroundColor)) {
      return sendError(res, 'Background color must be a valid hex color (e.g., #ffffff)', 400);
    }

    logger.info('Starting WebP to JPG conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      quality,
      backgroundColor
    });

    // Get image metadata for better conversion handling
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('Image metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      colorspace: metadata.space,
      hasAlpha: metadata.hasAlpha,
      hasProfile: !!metadata.icc
    });

    // Configure JPEG options
    const jpegOptions = {
      quality: quality,
      progressive: true,
      mozjpeg: true // Use mozjpeg encoder for better compression
    };

    // Convert WebP to JPG with Sharp
    let sharpInstance = sharp(originalBuffer)
      .rotate(); // Auto-rotate based on EXIF orientation

    // Handle transparency by flattening with background color
    if (metadata.hasAlpha) {
      const rgb = {
        r: parseInt(backgroundColor.slice(1, 3), 16),
        g: parseInt(backgroundColor.slice(3, 5), 16),
        b: parseInt(backgroundColor.slice(5, 7), 16)
      };
      sharpInstance = sharpInstance.flatten({ background: rgb });
    }

    // Ensure proper color space handling
    if (metadata.space && metadata.space !== 'srgb') {
      sharpInstance = sharpInstance.toColorspace('srgb');
    }

    const jpegBuffer = await sharpInstance
      .jpeg(jpegOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!jpegBuffer || jpegBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(jpegBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        size: jpegBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.jpg`;

    const compressionRatio = ((originalBuffer.length - jpegBuffer.length) / originalBuffer.length * 100).toFixed(2);

    logger.info('WebP to JPG conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: jpegBuffer.length,
      compressionRatio: compressionRatio + '%',
      quality,
      backgroundColor,
      hadTransparency: metadata.hasAlpha,
      colorspace: metadata.space,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/jpeg',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': jpegBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': jpegBuffer.length.toString(),
      'X-Compression-Ratio': compressionRatio + '%',
      'X-Quality': quality.toString(),
      'X-Background-Color': backgroundColor,
      'X-Had-Transparency': metadata.hasAlpha ? 'true' : 'false',
      'X-Original-Colorspace': metadata.space || 'unknown'
    });

    // Send the converted image
    res.send(jpegBuffer);

  } catch (error) {
    logger.error('WebP to JPG conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      quality: req.body?.quality,
      backgroundColor: req.body?.backgroundColor
    });

    if (error.message.includes('File must be a WebP image')) {
      return sendError(res, 'File must be a WebP image', 400);
    }

    if (error.message.includes('jpeg') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'JPEG encoding failed. The image cannot be converted.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/webp-to-png
 * Convert WebP images to PNG
 */
router.post('/webp-to-png', basicRateLimit, uploadWebp.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const compressionLevel = parseInt(req.body.compressionLevel) || 6;

    // Validate compression level parameter
    if (compressionLevel < 0 || compressionLevel > 9) {
      return sendError(res, 'Compression level must be between 0 and 9', 400);
    }

    logger.info('Starting WebP to PNG conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      compressionLevel
    });

    // Get image metadata for better conversion handling
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('Image metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      colorspace: metadata.space,
      hasAlpha: metadata.hasAlpha,
      hasProfile: !!metadata.icc
    });

    // Configure PNG options
    const pngOptions = {
      compressionLevel: compressionLevel,
      adaptiveFiltering: true,
      force: true // Force PNG output even if input is already PNG
    };

    // Convert WebP to PNG with Sharp
    let sharpInstance = sharp(originalBuffer)
      .rotate(); // Auto-rotate based on EXIF orientation

    // Ensure proper color space handling while preserving transparency
    if (metadata.space && metadata.space !== 'srgb') {
      sharpInstance = sharpInstance.toColorspace('srgb');
    }

    const pngBuffer = await sharpInstance
      .png(pngOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!pngBuffer || pngBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(pngBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        hasAlpha: convertedMetadata.hasAlpha,
        size: pngBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.png`;

    const sizeChange = ((pngBuffer.length - originalBuffer.length) / originalBuffer.length * 100).toFixed(2);
    const sizeChangeType = pngBuffer.length > originalBuffer.length ? 'increase' : 'decrease';

    logger.info('WebP to PNG conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: pngBuffer.length,
      sizeChange: `${Math.abs(parseFloat(sizeChange))}% ${sizeChangeType}`,
      compressionLevel,
      preservedTransparency: metadata.hasAlpha,
      colorspace: metadata.space,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/png',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': pngBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': pngBuffer.length.toString(),
      'X-Size-Change': `${sizeChange}%`,
      'X-Size-Change-Type': sizeChangeType,
      'X-Compression-Level': compressionLevel.toString(),
      'X-Preserved-Transparency': metadata.hasAlpha ? 'true' : 'false',
      'X-Original-Colorspace': metadata.space || 'unknown'
    });

    // Send the converted image
    res.send(pngBuffer);

  } catch (error) {
    logger.error('WebP to PNG conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      compressionLevel: req.body?.compressionLevel
    });

    if (error.message.includes('File must be a WebP image')) {
      return sendError(res, 'File must be a WebP image', 400);
    }

    if (error.message.includes('png') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'PNG encoding failed. The image cannot be converted.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/webp-to-avif
 * Convert WebP images to AVIF
 */
router.post('/webp-to-avif', enhancedSecurityWithRateLimit(basicRateLimit), uploadWebp.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
    const quality = parseInt(req.body.quality) || 50;
    const speed = parseInt(req.body.speed) || 6;

    // Validate quality parameter
    if (quality < 1 || quality > 100) {
      return sendError(res, 'Quality must be between 1 and 100', 400);
    }

    // Validate speed parameter
    if (speed < 0 || speed > 10) {
      return sendError(res, 'Speed must be between 0 and 10', 400);
    }

    logger.info('Starting WebP to AVIF conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype,
      quality,
      speed
    });

    // Get image metadata for better conversion handling
    const metadata = await sharp(originalBuffer).metadata();

    logger.info('Image metadata', {
      width: metadata.width,
      height: metadata.height,
      channels: metadata.channels,
      format: metadata.format,
      colorspace: metadata.space,
      hasAlpha: metadata.hasAlpha,
      hasProfile: !!metadata.icc
    });

    // Configure AVIF options
    const avifOptions = {
      quality: quality,
      effort: speed, // Encoding effort (0-10, higher = better compression but slower)
      chromaSubsampling: metadata.hasAlpha ? '4:4:4' : '4:2:0', // Better subsampling for images with transparency
      lossless: false // Use lossy compression for better file size
    };

    // Convert WebP to AVIF with Sharp
    let sharpInstance = sharp(originalBuffer)
      .rotate(); // Auto-rotate based on EXIF orientation

    // Ensure proper color space handling while preserving transparency
    if (metadata.space && metadata.space !== 'srgb') {
      sharpInstance = sharpInstance.toColorspace('srgb');
    }

    const avifBuffer = await sharpInstance
      .avif(avifOptions)
      .toBuffer();

    // Verify the converted buffer is valid
    if (!avifBuffer || avifBuffer.length === 0) {
      throw new Error('Conversion resulted in empty buffer');
    }

    // Additional validation - try to read the converted image
    try {
      const convertedMetadata = await sharp(avifBuffer).metadata();
      logger.info('Converted image metadata', {
        width: convertedMetadata.width,
        height: convertedMetadata.height,
        format: convertedMetadata.format,
        hasAlpha: convertedMetadata.hasAlpha,
        size: avifBuffer.length
      });
    } catch (validationError) {
      logger.error('Converted image validation failed', { error: validationError.message });
      throw new Error('Converted image is invalid or corrupted');
    }

    // Generate filename
    const filename = `${originalName}.avif`;

    const compressionRatio = ((originalBuffer.length - avifBuffer.length) / originalBuffer.length * 100).toFixed(2);

    logger.info('WebP to AVIF conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: avifBuffer.length,
      compressionRatio: compressionRatio + '%',
      quality,
      speed,
      preservedTransparency: metadata.hasAlpha,
      colorspace: metadata.space,
      chromaSubsampling: avifOptions.chromaSubsampling,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/avif',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': avifBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': avifBuffer.length.toString(),
      'X-Compression-Ratio': compressionRatio + '%',
      'X-Quality': quality.toString(),
      'X-Speed': speed.toString(),
      'X-Preserved-Transparency': metadata.hasAlpha ? 'true' : 'false',
      'X-Original-Colorspace': metadata.space || 'unknown',
      'X-Chroma-Subsampling': avifOptions.chromaSubsampling
    });

    // Send the converted image
    res.send(avifBuffer);

  } catch (error) {
    logger.error('WebP to AVIF conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size,
      quality: req.body?.quality,
      speed: req.body?.speed
    });

    if (error.message.includes('File must be a WebP image')) {
      return sendError(res, 'File must be a WebP image', 400);
    }

    if (error.message.includes('avif') || error.message.includes('Conversion resulted in empty buffer')) {
      return sendError(res, 'AVIF encoding failed. Your system may not support AVIF conversion or the image cannot be converted.', 500);
    }

    if (error.message.includes('Converted image is invalid')) {
      return sendError(res, 'Image conversion failed - resulting file is corrupted', 500);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/png-to-jpg
 * Convert PNG images to JPG/JPEG
 */
router.post('/png-to-jpg', enhancedSecurityWithRateLimit(basicRateLimit), uploadPng.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    // Get quality parameter (default to 90)
    const quality = parseInt(req.body.quality) || 90;
    const backgroundColor = req.body.backgroundColor || '#ffffff';

    // Validate quality range
    if (quality < 1 || quality > 100) {
      return sendError(res, 'Quality must be between 1 and 100', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');

    logger.info('Starting PNG to JPG conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      quality,
      backgroundColor,
      mimetype: req.file.mimetype
    });

    // Convert hex color to RGB values
    const hexToRgb = (hex) => {
      const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
      return result ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16)
      } : { r: 255, g: 255, b: 255 };
    };

    const bgColor = hexToRgb(backgroundColor);

    // Convert PNG to JPG with Sharp
    const jpgBuffer = await sharp(originalBuffer)
      .rotate() // Auto-rotate based on EXIF orientation
      .flatten({ background: bgColor }) // Handle transparency with background color
      .jpeg({ quality }) // Convert to JPEG with specified quality
      .toBuffer();

    // Generate filename
    const filename = `${originalName}.jpg`;

    logger.info('PNG to JPG conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: jpgBuffer.length,
      quality,
      backgroundColor,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/jpeg',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': jpgBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': jpgBuffer.length.toString(),
      'X-Quality': quality.toString(),
      'X-Background-Color': backgroundColor
    });

    // Send the converted image
    res.send(jpgBuffer);

  } catch (error) {
    logger.error('PNG to JPG conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (error.message.includes('File must be a PNG image')) {
      return sendError(res, 'File must be a PNG image', 400);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/png-to-webp
 * Convert PNG images to WebP
 */
router.post('/png-to-webp', basicRateLimit, uploadPng.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    // Get quality parameter (default to 80)
    const quality = parseInt(req.body.quality) || 80;
    const lossless = req.body.lossless === 'true' || req.body.lossless === true;

    // Validate quality range (only applies to lossy compression)
    if (!lossless && (quality < 1 || quality > 100)) {
      return sendError(res, 'Quality must be between 1 and 100', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');

    logger.info('Starting PNG to WebP conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      quality,
      lossless,
      mimetype: req.file.mimetype
    });

    // Convert PNG to WebP with Sharp
    const webpOptions = lossless ? { lossless: true } : { quality };
    const webpBuffer = await sharp(originalBuffer)
      .rotate() // Auto-rotate based on EXIF orientation
      .webp(webpOptions) // Convert to WebP with specified options
      .toBuffer();

    // Generate filename
    const filename = `${originalName}.webp`;

    logger.info('PNG to WebP conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: webpBuffer.length,
      quality: lossless ? 'lossless' : quality,
      lossless,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/webp',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': webpBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': webpBuffer.length.toString(),
      'X-Quality': lossless ? 'lossless' : quality.toString(),
      'X-Lossless': lossless.toString()
    });

    // Send the converted image
    res.send(webpBuffer);

  } catch (error) {
    logger.error('PNG to WebP conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (error.message.includes('File must be a PNG image')) {
      return sendError(res, 'File must be a PNG image', 400);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/jpg-to-png-batch
 * Convert multiple JPG/JPEG images to PNG
 */
router.post('/jpg-to-png-batch', basicRateLimit, uploadJpg.array('files', 5), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return sendError(res, 'No files provided', 400);
    }

    const results = [];
    const errors = [];

    logger.info('Starting batch JPG to PNG conversion', {
      fileCount: req.files.length
    });

    // Process each file
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];

      try {
        const originalBuffer = file.buffer;
        const originalName = file.originalname.replace(/\.[^/.]+$/, '');

        // Convert JPG to PNG with Sharp
        const pngBuffer = await sharp(originalBuffer)
          .rotate()
          .png()
          .toBuffer();

        results.push({
          originalName: file.originalname,
          convertedName: `${originalName}.png`,
          originalSize: originalBuffer.length,
          convertedSize: pngBuffer.length,
          convertedData: pngBuffer.toString('base64')
        });

      } catch (error) {
        errors.push({
          filename: file.originalname,
          error: error.message
        });
      }
    }

    logger.info('Batch JPG to PNG conversion completed', {
      totalFiles: req.files.length,
      successful: results.length,
      failed: errors.length
    });

    return sendSuccess(res, 'Batch conversion completed', {
      results,
      errors,
      summary: {
        totalFiles: req.files.length,
        successful: results.length,
        failed: errors.length
      }
    });

  } catch (error) {
    logger.error('Batch JPG to PNG conversion error:', {
      error: error.message,
      stack: error.stack,
      fileCount: req.files?.length
    });

    return sendError(res, 'Failed to process batch conversion', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/jpg-to-webp
 * Convert JPG/JPEG images to WebP
 */
router.post('/jpg-to-webp', basicRateLimit, uploadJpg.single('file'), async (req, res) => {
  try {
    // Check if file was uploaded
    if (!req.file) {
      return sendError(res, 'No file provided', 400);
    }

    const originalBuffer = req.file.buffer;
    const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');

    logger.info('Starting JPG to WebP conversion', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      mimetype: req.file.mimetype
    });

    // Convert JPG to WebP with Sharp
    const webpBuffer = await sharp(originalBuffer)
      .rotate() // Auto-rotate based on EXIF orientation
      .webp({ quality: 80 }) // Convert to WebP format with quality setting
      .toBuffer();

    // Generate filename
    const filename = `${originalName}.webp`;

    logger.info('JPG to WebP conversion completed', {
      originalName: req.file.originalname,
      originalSize: originalBuffer.length,
      convertedSize: webpBuffer.length,
      filename
    });

    // Set response headers
    res.set({
      'Content-Type': 'image/webp',
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Content-Length': webpBuffer.length.toString(),
      'X-Original-Filename': req.file.originalname,
      'X-Original-Size': originalBuffer.length.toString(),
      'X-Converted-Size': webpBuffer.length.toString()
    });

    // Send the converted image
    res.send(webpBuffer);

  } catch (error) {
    logger.error('JPG to WebP conversion error:', {
      error: error.message,
      stack: error.stack,
      originalName: req.file?.originalname,
      fileSize: req.file?.size
    });

    if (error.message.includes('File must be a JPG/JPEG image')) {
      return sendError(res, 'File must be a JPG/JPEG image', 400);
    }

    return sendError(res, 'Failed to convert image', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/convert/png-to-jpg-batch
 * Convert multiple PNG images to JPG/JPEG
 */
router.post('/png-to-jpg-batch', basicRateLimit, uploadPng.array('files', 5), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return sendError(res, 'No files provided', 400);
    }

    const quality = parseInt(req.body.quality) || 90;
    const backgroundColor = req.body.backgroundColor || '#ffffff';

    if (quality < 1 || quality > 100) {
      return sendError(res, 'Quality must be between 1 and 100', 400);
    }

    const results = [];
    const errors = [];

    logger.info('Starting batch PNG to JPG conversion', {
      fileCount: req.files.length,
      quality,
      backgroundColor
    });

    // Convert hex color to RGB values
    const hexToRgb = (hex) => {
      const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
      return result ? {
        r: parseInt(result[1], 16),
        g: parseInt(result[2], 16),
        b: parseInt(result[3], 16)
      } : { r: 255, g: 255, b: 255 };
    };

    const bgColor = hexToRgb(backgroundColor);

    // Process each file
    for (let i = 0; i < req.files.length; i++) {
      const file = req.files[i];

      try {
        const originalBuffer = file.buffer;
        const originalName = file.originalname.replace(/\.[^/.]+$/, '');

        // Convert PNG to JPG with Sharp
        const jpgBuffer = await sharp(originalBuffer)
          .rotate()
          .flatten({ background: bgColor })
          .jpeg({ quality })
          .toBuffer();

        results.push({
          originalName: file.originalname,
          convertedName: `${originalName}.jpg`,
          originalSize: originalBuffer.length,
          convertedSize: jpgBuffer.length,
          quality,
          backgroundColor,
          convertedData: jpgBuffer.toString('base64')
        });

      } catch (error) {
        errors.push({
          filename: file.originalname,
          error: error.message
        });
      }
    }

    logger.info('Batch PNG to JPG conversion completed', {
      totalFiles: req.files.length,
      successful: results.length,
      failed: errors.length,
      quality,
      backgroundColor
    });

    return sendSuccess(res, 'Batch conversion completed', {
      results,
      errors,
      summary: {
        totalFiles: req.files.length,
        successful: results.length,
        failed: errors.length,
        quality,
        backgroundColor
      }
    });

  } catch (error) {
    logger.error('Batch PNG to JPG conversion error:', {
      error: error.message,
      stack: error.stack,
      fileCount: req.files?.length
    });

    return sendError(res, 'Failed to process batch conversion', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/convert/info
 * Get conversion service information
 */
router.get('/info', basicRateLimit, (req, res) => {
  const info = {
    service: 'Image Conversion API',
    version: '1.0.0',
    supportedConversions: [
      'JPG/JPEG to PNG',
      'PNG to JPG/JPEG'
    ],
    endpoints: {
      jpg_to_png: 'POST /api/convert/jpg-to-png',
      png_to_jpg: 'POST /api/convert/png-to-jpg',
      jpg_to_png_batch: 'POST /api/convert/jpg-to-png-batch',
      png_to_jpg_batch: 'POST /api/convert/png-to-jpg-batch',
      info: 'GET /api/convert/info'
    },
    limits: {
      maxFileSize: '10MB',
      maxBatchFiles: 5,
      jpgQualityRange: '1-100'
    },
    features: {
      autoRotation: true,
      transparencyHandling: true,
      customBackgroundColor: true,
      qualityControl: true
    },
    usage: {
      jpg_to_png: {
        method: 'POST',
        endpoint: '/api/convert/jpg-to-png',
        contentType: 'multipart/form-data',
        fields: {
          file: 'JPG/JPEG image file (required)'
        },
        response: 'PNG image file'
      },
      png_to_jpg: {
        method: 'POST',
        endpoint: '/api/convert/png-to-jpg',
        contentType: 'multipart/form-data',
        fields: {
          file: 'PNG image file (required)',
          quality: 'JPEG quality 1-100 (optional, default: 90)',
          backgroundColor: 'Background color for transparency (optional, default: #ffffff)'
        },
        response: 'JPEG image file'
      }
    }
  };

  sendSuccess(res, 'Conversion service information', info);
});

module.exports = router;
