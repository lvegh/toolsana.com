const sharp = require('sharp');
const Tesseract = require('tesseract.js');
const crypto = require('crypto');
const logger = require('../utils/logger');
const { redisUtils } = require('../config/redis');

/**
 * OCR Service
 * Provides image-to-text extraction with preprocessing and caching
 */
class OCRService {
  constructor() {
    this.supportedLanguages = [
      'eng', // English
      'fra', // French
      'deu', // German
      'spa', // Spanish
      'ita', // Italian
      'por', // Portuguese
      'rus', // Russian
      'ara', // Arabic
      'zho', // Chinese
      'jpn', // Japanese
      'kor', // Korean
      'hin', // Hindi
      'ben', // Bengali
      'tur', // Turkish
      'vie', // Vietnamese
      'tha', // Thai
      'nld', // Dutch
      'pol', // Polish
      'swe', // Swedish
      'nor', // Norwegian
      'dan', // Danish
      'fin', // Finnish
      'ces', // Czech
      'ron', // Romanian
      'hun', // Hungarian
    ];

    // Cache settings
    this.cacheTTL = 7 * 24 * 60 * 60; // 7 days in seconds
    this.cachePrefix = 'ocr:';

    // Tesseract worker pool
    this.workerPool = null;
    this.maxWorkers = 2;
  }

  /**
   * Validate language code
   */
  validateLanguage(language) {
    if (!language) return 'eng'; // Default to English

    // Handle multiple languages (e.g., "eng+fra")
    const languages = language.split('+');
    const validLanguages = languages.filter(lang =>
      this.supportedLanguages.includes(lang.trim())
    );

    if (validLanguages.length === 0) {
      logger.warn(`Invalid language code: ${language}, defaulting to 'eng'`);
      return 'eng';
    }

    return validLanguages.join('+');
  }

  /**
   * Calculate hash of image buffer for caching
   */
  calculateImageHash(buffer, language) {
    const hash = crypto.createHash('sha256');
    hash.update(buffer);
    hash.update(language);
    return hash.digest('hex');
  }

  /**
   * Get cached OCR result
   */
  async getCachedResult(imageHash) {
    try {
      const cacheKey = `${this.cachePrefix}${imageHash}`;
      const cachedData = await redisUtils.get(cacheKey);

      if (cachedData) {
        logger.info('OCR result retrieved from cache', { imageHash });
        return cachedData;
      }

      return null;
    } catch (error) {
      logger.error('Error retrieving cached OCR result', {
        error: error.message,
        imageHash
      });
      return null;
    }
  }

  /**
   * Cache OCR result
   */
  async cacheResult(imageHash, result) {
    try {
      const cacheKey = `${this.cachePrefix}${imageHash}`;
      await redisUtils.setex(cacheKey, this.cacheTTL, result);
      logger.info('OCR result cached', { imageHash, ttl: this.cacheTTL });
      return true;
    } catch (error) {
      logger.error('Error caching OCR result', {
        error: error.message,
        imageHash
      });
      return false;
    }
  }

  /**
   * Preprocess image for better OCR accuracy
   */
  async preprocessImage(buffer, options = {}) {
    try {
      const startTime = Date.now();

      logger.info('Starting image preprocessing for OCR', {
        originalSize: buffer.length,
        options
      });

      let image = sharp(buffer);

      // Get image metadata
      const metadata = await image.metadata();
      logger.info('Image metadata', {
        width: metadata.width,
        height: metadata.height,
        format: metadata.format,
        channels: metadata.channels,
        hasAlpha: metadata.hasAlpha
      });

      // Convert to grayscale for better OCR accuracy
      image = image.greyscale();

      // Resize if image is too large (max 3000px on longest side)
      const maxDimension = options.maxDimension || 3000;
      if (metadata.width > maxDimension || metadata.height > maxDimension) {
        logger.info('Resizing large image', {
          original: { width: metadata.width, height: metadata.height },
          maxDimension
        });

        image = image.resize(maxDimension, maxDimension, {
          fit: 'inside',
          withoutEnlargement: true
        });
      }

      // Enhance contrast using histogram equalization
      image = image.normalize();

      // Apply sharpening to improve edge detection
      image = image.sharpen({
        sigma: options.sharpenSigma || 1.0,
        m1: options.sharpenM1 || 1.0,
        m2: options.sharpenM2 || 0.5,
        x1: options.sharpenX1 || 2,
        y2: options.sharpenY2 || 10,
        y3: options.sharpenY3 || 20
      });

      // Apply threshold if requested (for better text detection)
      if (options.threshold !== false) {
        const thresholdValue = options.thresholdValue || 128;
        image = image.threshold(thresholdValue);
      }

      // Remove noise with median filter
      if (options.denoise !== false) {
        image = image.median(options.medianSize || 3);
      }

      // Convert to PNG for Tesseract
      const processedBuffer = await image.png().toBuffer();

      const processingTime = Date.now() - startTime;
      logger.info('Image preprocessing completed', {
        processingTime,
        processedSize: processedBuffer.length,
        sizeReduction: ((buffer.length - processedBuffer.length) / buffer.length * 100).toFixed(2) + '%'
      });

      return processedBuffer;

    } catch (error) {
      logger.error('Image preprocessing failed', {
        error: error.message,
        stack: error.stack
      });
      throw new Error(`Image preprocessing failed: ${error.message}`);
    }
  }

  /**
   * Perform OCR on image buffer
   */
  async performOCR(buffer, options = {}) {
    const startTime = Date.now();
    const language = this.validateLanguage(options.language);
    const imageHash = this.calculateImageHash(buffer, language);

    try {
      // Check cache first
      const cachedResult = await this.getCachedResult(imageHash);
      if (cachedResult && !options.bypassCache) {
        return {
          ...cachedResult,
          cached: true,
          processingTime: Date.now() - startTime
        };
      }

      logger.info('Starting OCR processing', {
        language,
        imageSize: buffer.length,
        imageHash: imageHash.substring(0, 16) + '...'
      });

      // Preprocess image
      const preprocessedBuffer = await this.preprocessImage(buffer, options.preprocessing || {});

      // Perform OCR with Tesseract.js
      const result = await Tesseract.recognize(
        preprocessedBuffer,
        language,
        {
          logger: (info) => {
            if (info.status === 'recognizing text') {
              logger.info('OCR progress', {
                status: info.status,
                progress: (info.progress * 100).toFixed(2) + '%'
              });
            }
          }
        }
      );

      // Extract and format results
      const ocrData = this.formatOCRResult(result.data, language);
      const processingTime = Date.now() - startTime;

      const response = {
        ...ocrData,
        language,
        processingTime,
        imageHash: imageHash.substring(0, 16) + '...',
        cached: false
      };

      // Cache the result (without processingTime and imageHash)
      const cacheableData = {
        text: ocrData.text,
        confidence: ocrData.confidence,
        blocks: ocrData.blocks,
        lines: ocrData.lines,
        words: ocrData.words,
        symbols: ocrData.symbols
      };
      await this.cacheResult(imageHash, cacheableData);

      logger.info('OCR processing completed', {
        language,
        confidence: ocrData.confidence,
        textLength: ocrData.text.length,
        blockCount: ocrData.blocks.length,
        processingTime
      });

      return response;

    } catch (error) {
      logger.error('OCR processing failed', {
        error: error.message,
        stack: error.stack,
        language,
        imageHash: imageHash.substring(0, 16) + '...'
      });
      throw new Error(`OCR processing failed: ${error.message}`);
    }
  }

  /**
   * Format OCR result for API response
   */
  formatOCRResult(tesseractData, language) {
    try {
      // Extract text
      const text = tesseractData.text || '';

      // Calculate overall confidence
      const confidence = tesseractData.confidence || 0;

      // Format blocks with bounding boxes
      const blocks = (tesseractData.blocks || []).map(block => ({
        text: block.text,
        confidence: block.confidence,
        bbox: {
          x: block.bbox.x0,
          y: block.bbox.y0,
          width: block.bbox.x1 - block.bbox.x0,
          height: block.bbox.y1 - block.bbox.y0
        }
      }));

      // Format lines with bounding boxes
      const lines = (tesseractData.lines || []).map(line => ({
        text: line.text,
        confidence: line.confidence,
        bbox: {
          x: line.bbox.x0,
          y: line.bbox.y0,
          width: line.bbox.x1 - line.bbox.x0,
          height: line.bbox.y1 - line.bbox.y0
        },
        baseline: line.baseline
      }));

      // Format words with bounding boxes
      const words = (tesseractData.words || []).map(word => ({
        text: word.text,
        confidence: word.confidence,
        bbox: {
          x: word.bbox.x0,
          y: word.bbox.y0,
          width: word.bbox.x1 - word.bbox.x0,
          height: word.bbox.y1 - word.bbox.y0
        },
        isNumeric: word.is_numeric,
        isBold: word.is_bold,
        isItalic: word.is_italic
      }));

      // Format symbols (characters)
      const symbols = (tesseractData.symbols || []).map(symbol => ({
        text: symbol.text,
        confidence: symbol.confidence,
        bbox: {
          x: symbol.bbox.x0,
          y: symbol.bbox.y0,
          width: symbol.bbox.x1 - symbol.bbox.x0,
          height: symbol.bbox.y1 - symbol.bbox.y0
        }
      }));

      return {
        text,
        confidence: parseFloat(confidence.toFixed(2)),
        blocks,
        lines,
        words,
        symbols
      };

    } catch (error) {
      logger.error('Error formatting OCR result', {
        error: error.message
      });
      return {
        text: '',
        confidence: 0,
        blocks: [],
        lines: [],
        words: [],
        symbols: []
      };
    }
  }

  /**
   * Validate image format and size
   */
  async validateImage(buffer, maxSize = 10 * 1024 * 1024) {
    try {
      // Check file size
      if (buffer.length > maxSize) {
        throw new Error(`Image size exceeds maximum allowed size of ${maxSize / 1024 / 1024}MB`);
      }

      // Validate image format using Sharp
      const metadata = await sharp(buffer).metadata();

      const supportedFormats = ['jpeg', 'jpg', 'png', 'webp', 'tiff', 'gif', 'bmp', 'pdf'];
      if (!supportedFormats.includes(metadata.format)) {
        throw new Error(`Unsupported image format: ${metadata.format}. Supported formats: ${supportedFormats.join(', ')}`);
      }

      logger.info('Image validation passed', {
        format: metadata.format,
        width: metadata.width,
        height: metadata.height,
        size: buffer.length
      });

      return {
        valid: true,
        format: metadata.format,
        width: metadata.width,
        height: metadata.height,
        size: buffer.length
      };

    } catch (error) {
      logger.error('Image validation failed', {
        error: error.message
      });
      throw new Error(`Image validation failed: ${error.message}`);
    }
  }

  /**
   * Get service information
   */
  getInfo() {
    return {
      service: 'OCR (Optical Character Recognition) Service',
      version: '1.0.0',
      provider: 'Tesseract.js',
      supportedLanguages: this.supportedLanguages,
      features: {
        preprocessing: true,
        caching: true,
        multiLanguage: true,
        blockDetection: true,
        lineDetection: true,
        wordDetection: true,
        confidenceScores: true
      },
      limits: {
        maxFileSize: '10MB',
        maxDimension: 3000,
        cacheTTL: `${this.cacheTTL / 86400} days`
      },
      preprocessing: {
        grayscale: true,
        contrast: true,
        sharpening: true,
        thresholding: true,
        denoising: true,
        resizing: true
      }
    };
  }
}

// Export singleton instance
module.exports = new OCRService();
