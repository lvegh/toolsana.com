const sharp = require('sharp');
const logger = require('../utils/logger');

// Dynamic imports for ES modules (will be loaded async)
let imagemin, imageminPngquant, imageminOptipng, imageminAdvpng;

async function loadImageminModules() {
  if (!imagemin) {
    const imageminModule = await import('imagemin');
    imagemin = imageminModule.default; // Get the default export
    imageminPngquant = await import('imagemin-pngquant');
    imageminOptipng = await import('imagemin-optipng');
    imageminAdvpng = await import('imagemin-advpng');
  }
}

// Helper to process buffer with imagemin plugins using the buffer API
async function processWithImagemin(buffer, plugins) {
  await loadImageminModules();

  // Node.js Buffer IS a Uint8Array subclass, so we can pass it directly
  // imagemin.buffer() accepts both Buffer and Uint8Array
  const result = await imagemin.buffer(buffer, { plugins });

  // Ensure result is a Node.js Buffer (convert if it's a Uint8Array)
  return Buffer.isBuffer(result) ? result : Buffer.from(result);
}

class PngOptimizer {
  constructor() {
    this.compressionStrategies = {
      aggressive: {
        quality: [0.3, 0.5],
        speed: 1,
        strip: true,
        dithering: 1
      },
      balanced: {
        quality: [0.5, 0.7],
        speed: 3,
        strip: true,
        dithering: 0.75
      },
      quality: {
        quality: [0.7, 0.9],
        speed: 5,
        strip: true,
        dithering: 0.5
      }
    };
  }

  async analyzeImage(buffer) {
    try {
      const metadata = await sharp(buffer).metadata();
      const stats = await sharp(buffer).stats();

      const analysis = {
        width: metadata.width,
        height: metadata.height,
        channels: metadata.channels,
        hasAlpha: metadata.hasAlpha,
        isAnimated: metadata.pages && metadata.pages > 1,
        colorSpace: metadata.space,
        density: metadata.density,
        size: buffer.length,
        uniqueColors: this.estimateUniqueColors(stats),
        complexity: this.calculateComplexity(metadata, stats)
      };

      logger.info('PNG image analyzed', analysis);
      return analysis;
    } catch (error) {
      logger.error('Failed to analyze PNG image', { error: error.message });
      throw error;
    }
  }

  estimateUniqueColors(stats) {
    if (!stats.channels || stats.channels.length === 0) return 0;

    const rgbChannels = stats.channels.slice(0, 3);
    const averageColors = rgbChannels.reduce((acc, channel) => {
      const uniqueValues = channel.max - channel.min;
      return acc + uniqueValues;
    }, 0) / 3;

    return Math.min(Math.round(averageColors * 100), 16777216);
  }

  calculateComplexity(metadata, stats) {
    let complexity = 0;

    if (metadata.hasAlpha) complexity += 20;
    if (metadata.width * metadata.height > 1000000) complexity += 20;

    if (stats.channels && stats.channels.length > 0) {
      const avgStdDev = stats.channels.reduce((acc, ch) => acc + (ch.stdev || 0), 0) / stats.channels.length;
      complexity += Math.min(avgStdDev / 2, 30);
    }

    const estimatedColors = this.estimateUniqueColors(stats);
    if (estimatedColors > 10000) complexity += 20;
    else if (estimatedColors > 1000) complexity += 10;

    return Math.min(complexity, 100);
  }

  async stripMetadata(buffer) {
    try {
      const stripped = await sharp(buffer)
        .withMetadata(false)
        .toBuffer();

      const reduction = buffer.length - stripped.length;
      if (reduction > 0) {
        logger.info('Metadata stripped', { bytesRemoved: reduction });
      }

      return stripped;
    } catch (error) {
      logger.warn('Failed to strip metadata', { error: error.message });
      return buffer;
    }
  }

  // Determine image type based on analysis
  determineImageType(analysis) {
    const { complexity, uniqueColors, hasAlpha, width, height } = analysis;
    const pixelCount = width * height;

    // Simple graphics/icons/logos (flat colors, minimal complexity)
    if (uniqueColors < 256 && complexity < 30) {
      return 'simple-graphics';
    }

    // Logos/graphics with gradients (small size, moderate colors)
    // This catches logos with anti-aliasing or gradients before they're classified as photos
    if (pixelCount < 350000 && uniqueColors < 25000 && complexity < 75) {
      return 'simple-graphics';
    }

    // Complex photos with gradients (high complexity OR high color count + large size)
    // Photos with high complexity
    if (complexity > 60 && pixelCount > 400000) {
      return 'complex-photo';
    }

    // Photos with very high color count
    if (uniqueColors > 30000) {
      return 'complex-photo';
    }

    // Medium-large images with moderate color count (likely photos)
    if (pixelCount > 400000 && uniqueColors > 15000) {
      return 'complex-photo';
    }

    // Default balanced
    return 'balanced';
  }

  async compress(buffer, options = {}) {
    const startTime = Date.now();
    const originalSize = buffer.length;

    try {
      await loadImageminModules();

      // First strip metadata
      let currentBuffer = await this.stripMetadata(buffer);

      // Analyze the image
      const analysis = await this.analyzeImage(currentBuffer);

      // Determine image type based on analysis
      const imageType = this.determineImageType(analysis);
      logger.info('Detected image type', { imageType });

      let strategyName = '';

      // Apply strategy based on image type
      if (imageType === 'simple-graphics') {
        // Simple graphics, icons, logos - use BALANCED for quality
        strategyName = 'Simple Graphics (Pngquant Balanced)';
        logger.info('Using balanced pngquant for simple graphics/logos');

        try {
          const pngquantBuffer = await processWithImagemin(currentBuffer, [
            imageminPngquant.default({
              quality: [0.5, 0.8],
              speed: 3,
              strip: true,
              dithering: 0.5
            })
          ]);

          if (pngquantBuffer.length < currentBuffer.length) {
            const reduction = ((currentBuffer.length - pngquantBuffer.length) / currentBuffer.length * 100).toFixed(1);
            logger.info('Pngquant reduced size', { reduction: `${reduction}%` });
            currentBuffer = pngquantBuffer;
          }
        } catch (err) {
          logger.warn('Pngquant failed, using fallback', { error: err.message });
        }

        // Polish with OptiPNG
        try {
          const optipngBuffer = await processWithImagemin(currentBuffer, [
            imageminOptipng.default({
              optimizationLevel: 7
            })
          ]);

          if (optipngBuffer.length < currentBuffer.length) {
            logger.info('OptiPNG polished the result');
            currentBuffer = optipngBuffer;
          }
        } catch (err) {
          logger.warn('OptiPNG failed', { error: err.message });
        }

      } else if (imageType === 'complex-photo') {
        // Complex photos with gradients - use AGGRESSIVE pngquant only (fast)
        strategyName = 'Complex Photo (Pngquant Aggressive 0.15-0.45)';
        logger.info('Using aggressive pngquant for complex photos');

        try {
          const pngquantBuffer = await processWithImagemin(currentBuffer, [
            imageminPngquant.default({
              quality: [0.15, 0.45],
              speed: 1,
              strip: true,
              dithering: 1,
              posterize: 1
            })
          ]);

          if (pngquantBuffer.length < currentBuffer.length) {
            const reduction = ((currentBuffer.length - pngquantBuffer.length) / currentBuffer.length * 100).toFixed(1);
            logger.info('Pngquant reduced size', { reduction: `${reduction}%` });
            currentBuffer = pngquantBuffer;
          }
        } catch (err) {
          logger.warn('Pngquant failed', { error: err.message });
        }

      } else {
        // Balanced approach for everything else
        strategyName = 'Balanced (Auto-detect)';
        logger.info('Using balanced approach');

        try {
          const pngquantBuffer = await processWithImagemin(currentBuffer, [
            imageminPngquant.default({
              quality: [0.5, 0.7],
              speed: 2,
              strip: true,
              dithering: 1,
              posterize: 1
            })
          ]);

          if (pngquantBuffer.length < currentBuffer.length) {
            const reduction = ((currentBuffer.length - pngquantBuffer.length) / currentBuffer.length * 100).toFixed(1);
            logger.info('Pngquant reduced size', { reduction: `${reduction}%` });
            currentBuffer = pngquantBuffer;
          }
        } catch (err) {
          logger.warn('Pngquant failed', { error: err.message });
        }

        try {
          const optipngBuffer = await processWithImagemin(currentBuffer, [
            imageminOptipng.default({
              optimizationLevel: 7
            })
          ]);

          if (optipngBuffer.length < currentBuffer.length) {
            logger.info('OptiPNG reduced size');
            currentBuffer = optipngBuffer;
          }
        } catch (err) {
          logger.warn('OptiPNG failed', { error: err.message });
        }
      }

      const finalSize = currentBuffer.length;
      const compressionRatio = ((originalSize - finalSize) / originalSize * 100).toFixed(1);
      const processingTime = Date.now() - startTime;

      logger.info('PNG compression completed', {
        originalSize,
        finalSize,
        compressionRatio: `${compressionRatio}%`,
        strategy: strategyName,
        processingTime: `${processingTime}ms`
      });

      return {
        buffer: currentBuffer,
        originalSize,
        compressedSize: finalSize,
        compressionRatio,
        strategy: strategyName,
        imageType,
        analysis
      };

    } catch (error) {
      logger.error('PNG compression failed, using Sharp fallback', {
        error: error.message,
        stack: error.stack
      });

      // Fallback to Sharp with maximum compression
      const fallbackBuffer = await sharp(buffer)
        .png({
          compressionLevel: 9,
          adaptiveFiltering: true,
          palette: true,
          quality: 60,
          effort: 10,
          colors: 256
        })
        .toBuffer();

      return {
        buffer: fallbackBuffer,
        originalSize,
        compressedSize: fallbackBuffer.length,
        compressionRatio: ((originalSize - fallbackBuffer.length) / originalSize * 100).toFixed(1),
        strategy: 'fallback-sharp',
        analysis: null
      };
    }
  }
}

module.exports = new PngOptimizer();
