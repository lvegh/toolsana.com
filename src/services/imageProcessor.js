const sharp = require('sharp');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const logger = require('../utils/logger');
const { fileExists, deleteFile, generateUniqueFilename } = require('../utils/fileSystem');

/**
 * Image Processing Service
 * Handles image operations that can't run on Cloudflare Pages edge runtime
 */
class ImageProcessor {
  constructor() {
    this.supportedFormats = ['jpeg', 'jpg', 'png', 'webp', 'gif', 'tiff', 'avif'];
    this.maxWidth = parseInt(process.env.IMAGE_MAX_WIDTH) || 1920;
    this.maxHeight = parseInt(process.env.IMAGE_MAX_HEIGHT) || 1080;
    this.defaultQuality = parseInt(process.env.IMAGE_QUALITY) || 80;
  }

  /**
   * Validate image file
   */
  async validateImage(filePath) {
    try {
      if (!await fileExists(filePath)) {
        throw new Error('Image file not found');
      }

      const metadata = await sharp(filePath).metadata();
      
      if (!metadata.format || !this.supportedFormats.includes(metadata.format)) {
        throw new Error(`Unsupported image format: ${metadata.format}`);
      }

      return {
        valid: true,
        metadata: {
          format: metadata.format,
          width: metadata.width,
          height: metadata.height,
          channels: metadata.channels,
          density: metadata.density,
          hasAlpha: metadata.hasAlpha,
          size: metadata.size
        }
      };
    } catch (error) {
      logger.error('Image validation error:', error);
      return {
        valid: false,
        error: error.message
      };
    }
  }

  /**
   * Resize image
   */
  async resizeImage(inputPath, outputPath, options = {}) {
    try {
      const {
        width,
        height,
        fit = 'cover', // cover, contain, fill, inside, outside
        position = 'center',
        background = { r: 255, g: 255, b: 255, alpha: 1 },
        withoutEnlargement = true
      } = options;

      let pipeline = sharp(inputPath);

      if (width || height) {
        pipeline = pipeline.resize({
          width: width ? Math.min(width, this.maxWidth) : undefined,
          height: height ? Math.min(height, this.maxHeight) : undefined,
          fit,
          position,
          background,
          withoutEnlargement
        });
      }

      await pipeline.toFile(outputPath);

      logger.info('Image resized successfully', {
        inputPath,
        outputPath,
        options
      });

      return {
        success: true,
        outputPath,
        metadata: await sharp(outputPath).metadata()
      };
    } catch (error) {
      logger.error('Image resize error:', error);
      throw new Error(`Failed to resize image: ${error.message}`);
    }
  }

  /**
   * Convert image format
   */
  async convertFormat(inputPath, outputPath, format, options = {}) {
    try {
      const { quality = this.defaultQuality } = options;
      
      let pipeline = sharp(inputPath);

      switch (format.toLowerCase()) {
        case 'jpeg':
        case 'jpg':
          pipeline = pipeline.jpeg({ quality, progressive: true });
          break;
        case 'png':
          pipeline = pipeline.png({ 
            quality, 
            compressionLevel: 9,
            progressive: true 
          });
          break;
        case 'webp':
          pipeline = pipeline.webp({ 
            quality,
            effort: 6 
          });
          break;
        case 'avif':
          pipeline = pipeline.avif({ 
            quality,
            effort: 4 
          });
          break;
        default:
          throw new Error(`Unsupported output format: ${format}`);
      }

      await pipeline.toFile(outputPath);

      logger.info('Image format converted successfully', {
        inputPath,
        outputPath,
        format,
        quality
      });

      return {
        success: true,
        outputPath,
        format,
        metadata: await sharp(outputPath).metadata()
      };
    } catch (error) {
      logger.error('Image format conversion error:', error);
      throw new Error(`Failed to convert image format: ${error.message}`);
    }
  }

  /**
   * Optimize image (reduce file size while maintaining quality)
   */
  async optimizeImage(inputPath, outputPath, options = {}) {
    try {
      const {
        quality = this.defaultQuality,
        progressive = true,
        mozjpeg = true
      } = options;

      const metadata = await sharp(inputPath).metadata();
      let pipeline = sharp(inputPath);

      // Apply format-specific optimizations
      switch (metadata.format) {
        case 'jpeg':
          pipeline = pipeline.jpeg({
            quality,
            progressive,
            mozjpeg
          });
          break;
        case 'png':
          pipeline = pipeline.png({
            quality,
            compressionLevel: 9,
            progressive
          });
          break;
        case 'webp':
          pipeline = pipeline.webp({
            quality,
            effort: 6
          });
          break;
        default:
          // Keep original format with basic optimization
          break;
      }

      await pipeline.toFile(outputPath);

      const originalStats = await sharp(inputPath).stats();
      const optimizedStats = await sharp(outputPath).stats();

      logger.info('Image optimized successfully', {
        inputPath,
        outputPath,
        originalSize: originalStats.size,
        optimizedSize: optimizedStats.size,
        compressionRatio: ((originalStats.size - optimizedStats.size) / originalStats.size * 100).toFixed(2) + '%'
      });

      return {
        success: true,
        outputPath,
        optimization: {
          originalSize: originalStats.size,
          optimizedSize: optimizedStats.size,
          compressionRatio: ((originalStats.size - optimizedStats.size) / originalStats.size * 100).toFixed(2) + '%'
        },
        metadata: await sharp(outputPath).metadata()
      };
    } catch (error) {
      logger.error('Image optimization error:', error);
      throw new Error(`Failed to optimize image: ${error.message}`);
    }
  }

  /**
   * Generate thumbnails
   */
  async generateThumbnails(inputPath, outputDir, sizes = []) {
    try {
      const defaultSizes = [
        { name: 'small', width: 150, height: 150 },
        { name: 'medium', width: 300, height: 300 },
        { name: 'large', width: 600, height: 600 }
      ];

      const thumbnailSizes = sizes.length > 0 ? sizes : defaultSizes;
      const results = [];

      const inputFilename = path.basename(inputPath, path.extname(inputPath));
      const inputExtension = path.extname(inputPath);

      for (const size of thumbnailSizes) {
        const outputFilename = `${inputFilename}_${size.name}${inputExtension}`;
        const outputPath = path.join(outputDir, outputFilename);

        const result = await this.resizeImage(inputPath, outputPath, {
          width: size.width,
          height: size.height,
          fit: 'cover'
        });

        results.push({
          name: size.name,
          ...result
        });
      }

      logger.info('Thumbnails generated successfully', {
        inputPath,
        outputDir,
        count: results.length
      });

      return {
        success: true,
        thumbnails: results
      };
    } catch (error) {
      logger.error('Thumbnail generation error:', error);
      throw new Error(`Failed to generate thumbnails: ${error.message}`);
    }
  }

  /**
   * Apply image filters/effects
   */
  async applyFilters(inputPath, outputPath, filters = {}) {
    try {
      let pipeline = sharp(inputPath);

      // Apply various filters
      if (filters.blur && filters.blur > 0) {
        pipeline = pipeline.blur(Math.min(filters.blur, 100));
      }

      if (filters.sharpen) {
        pipeline = pipeline.sharpen({
          sigma: filters.sharpen.sigma || 1,
          flat: filters.sharpen.flat || 1,
          jagged: filters.sharpen.jagged || 2
        });
      }

      if (filters.brightness && filters.brightness !== 1) {
        pipeline = pipeline.modulate({
          brightness: Math.max(0.1, Math.min(3, filters.brightness))
        });
      }

      if (filters.saturation && filters.saturation !== 1) {
        pipeline = pipeline.modulate({
          saturation: Math.max(0, Math.min(3, filters.saturation))
        });
      }

      if (filters.hue && filters.hue !== 0) {
        pipeline = pipeline.modulate({
          hue: filters.hue
        });
      }

      if (filters.grayscale) {
        pipeline = pipeline.grayscale();
      }

      if (filters.negate) {
        pipeline = pipeline.negate();
      }

      if (filters.gamma && filters.gamma !== 1) {
        pipeline = pipeline.gamma(Math.max(0.1, Math.min(3, filters.gamma)));
      }

      await pipeline.toFile(outputPath);

      logger.info('Image filters applied successfully', {
        inputPath,
        outputPath,
        filters
      });

      return {
        success: true,
        outputPath,
        filters,
        metadata: await sharp(outputPath).metadata()
      };
    } catch (error) {
      logger.error('Image filter application error:', error);
      throw new Error(`Failed to apply image filters: ${error.message}`);
    }
  }

  /**
   * Extract image metadata
   */
  async getMetadata(imagePath) {
    try {
      const metadata = await sharp(imagePath).metadata();
      const stats = await sharp(imagePath).stats();

      return {
        success: true,
        metadata: {
          format: metadata.format,
          width: metadata.width,
          height: metadata.height,
          channels: metadata.channels,
          depth: metadata.depth,
          density: metadata.density,
          chromaSubsampling: metadata.chromaSubsampling,
          isProgressive: metadata.isProgressive,
          hasProfile: metadata.hasProfile,
          hasAlpha: metadata.hasAlpha,
          orientation: metadata.orientation,
          exif: metadata.exif,
          icc: metadata.icc,
          iptc: metadata.iptc,
          xmp: metadata.xmp,
          tifftagPhotoshop: metadata.tifftagPhotoshop,
          size: metadata.size,
          stats: {
            channels: stats.channels,
            isOpaque: stats.isOpaque,
            min: stats.min,
            max: stats.max,
            sum: stats.sum,
            squaresSum: stats.squaresSum,
            mean: stats.mean,
            stdev: stats.stdev,
            minX: stats.minX,
            minY: stats.minY,
            maxX: stats.maxX,
            maxY: stats.maxY
          }
        }
      };
    } catch (error) {
      logger.error('Metadata extraction error:', error);
      throw new Error(`Failed to extract image metadata: ${error.message}`);
    }
  }

  /**
   * Process image with multiple operations
   */
  async processImage(inputPath, operations = []) {
    try {
      const processId = uuidv4();
      const results = [];
      let currentPath = inputPath;

      logger.info('Starting image processing', {
        processId,
        inputPath,
        operations: operations.length
      });

      for (let i = 0; i < operations.length; i++) {
        const operation = operations[i];
        const outputPath = path.join(
          path.dirname(inputPath),
          `${processId}_step_${i + 1}_${path.basename(inputPath)}`
        );

        let result;

        switch (operation.type) {
          case 'resize':
            result = await this.resizeImage(currentPath, outputPath, operation.options);
            break;
          case 'convert':
            result = await this.convertFormat(currentPath, outputPath, operation.format, operation.options);
            break;
          case 'optimize':
            result = await this.optimizeImage(currentPath, outputPath, operation.options);
            break;
          case 'filter':
            result = await this.applyFilters(currentPath, outputPath, operation.filters);
            break;
          default:
            throw new Error(`Unknown operation type: ${operation.type}`);
        }

        results.push({
          step: i + 1,
          operation: operation.type,
          ...result
        });

        // Clean up intermediate files (except the first input)
        if (currentPath !== inputPath) {
          await deleteFile(currentPath);
        }

        currentPath = outputPath;
      }

      logger.info('Image processing completed', {
        processId,
        steps: results.length,
        finalOutput: currentPath
      });

      return {
        success: true,
        processId,
        finalOutput: currentPath,
        steps: results
      };
    } catch (error) {
      logger.error('Image processing error:', error);
      throw new Error(`Failed to process image: ${error.message}`);
    }
  }
}

module.exports = new ImageProcessor();
