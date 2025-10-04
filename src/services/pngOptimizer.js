const sharp = require('sharp');
const imagemin = require('imagemin');
const imageminPngquant = require('imagemin-pngquant');
const imageminOptipng = require('imagemin-optipng');
const imageminAdvpng = require('imagemin-advpng');
const logger = require('../utils/logger');

class PngOptimizer {
  constructor() {
    // Keep your existing strategies but improve them
    this.compressionStrategies = {
      gradient: {
        // For smooth gradients - preserve quality to avoid banding
        quality: [0.85, 0.95],
        speed: 1,
        strip: true,
        dithering: 0,
        posterize: 0
      },
      aggressive: {
        // For detailed photos/complex images
        quality: [0.65, 0.85],
        speed: 1,
        strip: true,
        dithering: 1,
        posterize: 0
      },
      ultraAggressive: {
        // Maximum compression for acceptable quality loss
        quality: [0.50, 0.75],
        speed: 1,
        strip: true,
        dithering: 1,
        posterize: 0
      },
      balanced: {
        quality: [0.70, 0.85],
        speed: 3,
        strip: true,
        dithering: 0.5,
        posterize: 0
      }
    };
  }

  async analyzeImage(buffer) {
    try {
      const metadata = await sharp(buffer).metadata();
      const stats = await sharp(buffer).stats();

      // Detect gradients by analyzing standard deviation
      const hasGradients = stats.channels.some(channel => channel.stdev < 40);

      // Calculate complexity
      const avgStdDev = stats.channels.reduce((acc, ch) => acc + (ch.stdev || 0), 0) / stats.channels.length;

      const analysis = {
        width: metadata.width,
        height: metadata.height,
        channels: metadata.channels,
        hasAlpha: metadata.hasAlpha,
        isAnimated: metadata.pages && metadata.pages > 1,
        colorSpace: metadata.space,
        density: metadata.density,
        size: buffer.length,
        hasGradients,
        avgStdDev,
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

  selectCompressionStrategy(analysis) {
    // CRITICAL: Detect gradients first
    if (analysis.hasGradients) {
      logger.info('Gradient image detected, using gradient-safe strategy', {
        avgStdDev: analysis.avgStdDev
      });
      return 'gradient';
    }

    if (analysis.size < 10000) {
      logger.info('Small image detected, using balanced strategy');
      return 'balanced';
    }

    if (analysis.complexity < 30 || analysis.uniqueColors < 256) {
      logger.info('Simple image detected, using ultra-aggressive strategy', {
        complexity: analysis.complexity,
        uniqueColors: analysis.uniqueColors
      });
      return 'ultraAggressive';
    }

    if (analysis.complexity > 70 || analysis.hasAlpha) {
      logger.info('Complex image detected, using aggressive strategy', {
        complexity: analysis.complexity,
        hasAlpha: analysis.hasAlpha
      });
      return 'aggressive';
    }

    logger.info('Standard image detected, using aggressive strategy');
    return 'aggressive';
  }

  async stripMetadata(buffer) {
    try {
      const stripped = await sharp(buffer)
        .withMetadata(false)
        .toBuffer();

      const reduction = buffer.length - stripped.length;
      if (reduction > 0) {
        logger.info('Metadata stripped', {
          bytesRemoved: reduction
        });
      }

      return stripped;
    } catch (error) {
      logger.warn('Failed to strip metadata', { error: error.message });
      return buffer;
    }
  }

  async compress(buffer, options = {}) {
    const startTime = Date.now();
    const originalSize = buffer.length;

    try {
      logger.info('Starting compression', { originalSize });

      // Strip metadata first
      let currentBuffer = await this.stripMetadata(buffer);
      logger.info('After metadata strip', { size: currentBuffer.length });

      // Analyze the image
      const analysis = await this.analyzeImage(currentBuffer);

      logger.info('Image analysis complete', {
        hasGradients: analysis.hasGradients,
        complexity: analysis.complexity,
        avgStdDev: analysis.avgStdDev
      });

      let bestBuffer = currentBuffer;
      let bestSize = currentBuffer.length;
      let bestStrategy = 'original';

      // For gradients - preserve quality
      if (analysis.hasGradients) {
        logger.info('Gradient detected - using quality-preserving compression');

        const gradientBuffer = await imagemin.buffer(currentBuffer, {
          plugins: [
            imageminPngquant({
              quality: [0.90, 0.98],
              speed: 1,
              strip: true,
              dithering: 0
            })
          ]
        }).catch(err => {
          logger.error('Gradient pngquant failed:', err.message);
          return currentBuffer;
        });

        logger.info('After gradient pngquant', { size: gradientBuffer.length });

        let optimized = await imagemin.buffer(gradientBuffer, {
          plugins: [imageminOptipng({ optimizationLevel: 2 })]
        }).catch(() => gradientBuffer);

        logger.info('After OptiPNG', { size: optimized.length });

        optimized = await imagemin.buffer(optimized, {
          plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 20 })]
        }).catch(() => optimized);

        logger.info('After AdvPNG', { size: optimized.length });

        return {
          buffer: optimized,
          originalSize,
          compressedSize: optimized.length,
          compressionRatio: ((originalSize - optimized.length) / originalSize * 100).toFixed(1),
          strategy: 'gradient-safe',
          analysis
        };
      }

      // For detailed images - AGGRESSIVE compression
      logger.info('Detailed image - applying AGGRESSIVE compression');

      // Test 1: Quality 50-70 (TinyPNG range)
      logger.info('TEST 1: quality [0.50, 0.70]');
      let test1 = await imagemin.buffer(currentBuffer, {
        plugins: [
          imageminPngquant({
            quality: [0.50, 0.70],
            speed: 1,
            strip: true,
            dithering: 1.0
          })
        ]
      }).catch(err => {
        logger.error('Test 1 failed:', err.message);
        return currentBuffer;
      });
      logger.info('Test 1 result:', {
        size: test1.length,
        ratio: ((originalSize - test1.length) / originalSize * 100).toFixed(1) + '%'
      });

      // Test 2: Quality 45-65 (More aggressive)
      logger.info('TEST 2: quality [0.45, 0.65]');
      let test2 = await imagemin.buffer(currentBuffer, {
        plugins: [
          imageminPngquant({
            quality: [0.45, 0.65],
            speed: 1,
            strip: true,
            dithering: 1.0
          })
        ]
      }).catch(err => {
        logger.error('Test 2 failed:', err.message);
        return currentBuffer;
      });
      logger.info('Test 2 result:', {
        size: test2.length,
        ratio: ((originalSize - test2.length) / originalSize * 100).toFixed(1) + '%'
      });

      // Test 3: Quality 40-60 (Very aggressive)
      logger.info('TEST 3: quality [0.40, 0.60]');
      let test3 = await imagemin.buffer(currentBuffer, {
        plugins: [
          imageminPngquant({
            quality: [0.40, 0.60],
            speed: 1,
            strip: true,
            dithering: 1.0
          })
        ]
      }).catch(err => {
        logger.error('Test 3 failed:', err.message);
        return currentBuffer;
      });
      logger.info('Test 3 result:', {
        size: test3.length,
        ratio: ((originalSize - test3.length) / originalSize * 100).toFixed(1) + '%'
      });

      // Pick the best test result
      let compressed = test1;
      let testUsed = 'test1-[0.50,0.70]';

      if (test2.length < compressed.length) {
        compressed = test2;
        testUsed = 'test2-[0.45,0.65]';
      }

      if (test3.length < compressed.length) {
        compressed = test3;
        testUsed = 'test3-[0.40,0.60]';
      }

      logger.info('Best pngquant result:', {
        test: testUsed,
        size: compressed.length,
        ratio: ((originalSize - compressed.length) / originalSize * 100).toFixed(1) + '%'
      });

      // Now optimize with OptiPNG
      logger.info('Applying OptiPNG...');
      compressed = await imagemin.buffer(compressed, {
        plugins: [imageminOptipng({ optimizationLevel: 2 })]
      }).catch(err => {
        logger.warn('OptiPNG failed:', err.message);
        return compressed;
      });

      logger.info('After OptiPNG:', {
        size: compressed.length,
        ratio: ((originalSize - compressed.length) / originalSize * 100).toFixed(1) + '%'
      });

      // Finally optimize with AdvPNG
      logger.info('Applying AdvPNG...');
      compressed = await imagemin.buffer(compressed, {
        plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 20 })]
      }).catch(err => {
        logger.warn('AdvPNG failed:', err.message);
        return compressed;
      });

      logger.info('After AdvPNG:', {
        size: compressed.length,
        ratio: ((originalSize - compressed.length) / originalSize * 100).toFixed(1) + '%'
      });

      const finalSize = compressed.length;
      const compressionRatio = ((originalSize - finalSize) / originalSize * 100).toFixed(1);
      const processingTime = Date.now() - startTime;

      logger.info('=== FINAL RESULT ===', {
        originalSize: (originalSize / 1024).toFixed(2) + ' KB',
        finalSize: (finalSize / 1024).toFixed(2) + ' KB',
        compressionRatio: `${compressionRatio}%`,
        processingTime: `${processingTime}ms`,
        tinypngTarget: '78% (475 KB)'
      });

      return {
        buffer: compressed,
        originalSize,
        compressedSize: finalSize,
        compressionRatio,
        strategy: testUsed,
        analysis
      };

    } catch (error) {
      logger.error('PNG compression failed completely', {
        error: error.message,
        stack: error.stack
      });

      // Fallback
      const fallbackBuffer = await sharp(buffer)
        .png({
          compressionLevel: 9,
          adaptiveFiltering: true,
          palette: true,
          quality: 60,
          effort: 10,
          colors: 128
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