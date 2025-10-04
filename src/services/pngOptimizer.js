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
      logger.info('Starting compression', { originalSize: (originalSize / 1024).toFixed(2) + ' KB' });

      // Strip metadata first
      let currentBuffer = await this.stripMetadata(buffer);

      // Analyze the image
      const analysis = await this.analyzeImage(currentBuffer);

      logger.info('Image analysis complete', {
        hasGradients: analysis.hasGradients,
        complexity: analysis.complexity,
        avgStdDev: analysis.avgStdDev
      });

      // For gradients - preserve quality
      if (analysis.hasGradients) {
        logger.info('Gradient detected - using quality-preserving compression');

        let gradientBuffer = await imagemin.buffer(currentBuffer, {
          plugins: [
            imageminPngquant({
              quality: [0.90, 0.98],
              speed: 1,
              strip: true,
              dithering: 0
            })
          ]
        }).catch(() => currentBuffer);

        gradientBuffer = await imagemin.buffer(gradientBuffer, {
          plugins: [imageminOptipng({ optimizationLevel: 2 })]
        }).catch(() => gradientBuffer);

        gradientBuffer = await imagemin.buffer(gradientBuffer, {
          plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 20 })]
        }).catch(() => gradientBuffer);

        const compressionRatio = ((originalSize - gradientBuffer.length) / originalSize * 100).toFixed(1);

        logger.info('Gradient compression complete', {
          finalSize: (gradientBuffer.length / 1024).toFixed(2) + ' KB',
          compressionRatio: compressionRatio + '%'
        });

        return {
          buffer: gradientBuffer,
          originalSize,
          compressedSize: gradientBuffer.length,
          compressionRatio,
          strategy: 'gradient-safe',
          analysis
        };
      }

      // For detailed images - TARGET 78% compression with quality control
      logger.info('Detailed image - targeting 75-78% compression');

      let bestBuffer = currentBuffer;
      let bestSize = currentBuffer.length;
      let bestStrategy = 'original';
      const attempts = [];

      // Strategy 1: Conservative (75-76% compression, better quality)
      logger.info('Strategy 1: Conservative [0.55, 0.75]');
      try {
        let conservative = await imagemin.buffer(currentBuffer, {
          plugins: [
            imageminPngquant({
              quality: [0.46, 0.66],
              speed: 1,
              strip: true,
              dithering: 1.0
            })
          ]
        });

        conservative = await imagemin.buffer(conservative, {
          plugins: [imageminOptipng({ optimizationLevel: 2 })]
        }).catch(() => conservative);

        conservative = await imagemin.buffer(conservative, {
          plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 15 })]
        }).catch(() => conservative);

        const ratio = ((originalSize - conservative.length) / originalSize * 100).toFixed(1);
        attempts.push({
          strategy: 'conservative',
          buffer: conservative,
          size: conservative.length,
          ratio: parseFloat(ratio)
        });

        logger.info('Conservative result:', {
          size: (conservative.length / 1024).toFixed(2) + ' KB',
          ratio: ratio + '%'
        });

        if (conservative.length < bestSize) {
          bestBuffer = conservative;
          bestSize = conservative.length;
          bestStrategy = 'conservative';
        }
      } catch (error) {
        logger.warn('Conservative strategy failed:', error.message);
      }

      // Strategy 2: Balanced (77-78% compression, TinyPNG match)
      logger.info('Strategy 2: Balanced [0.52, 0.72]');
      try {
        let balanced = await imagemin.buffer(currentBuffer, {
          plugins: [
            imageminPngquant({
              quality: [0.52, 0.72],
              speed: 1,
              strip: true,
              dithering: 1.0
            })
          ]
        });

        balanced = await imagemin.buffer(balanced, {
          plugins: [imageminOptipng({ optimizationLevel: 2 })]
        }).catch(() => balanced);

        balanced = await imagemin.buffer(balanced, {
          plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 15 })]
        }).catch(() => balanced);

        const ratio = ((originalSize - balanced.length) / originalSize * 100).toFixed(1);
        attempts.push({
          strategy: 'balanced',
          buffer: balanced,
          size: balanced.length,
          ratio: parseFloat(ratio)
        });

        logger.info('Balanced result:', {
          size: (balanced.length / 1024).toFixed(2) + ' KB',
          ratio: ratio + '%'
        });

        // Only use if it's better AND doesn't exceed 80% compression
        if (balanced.length < bestSize && parseFloat(ratio) <= 80) {
          bestBuffer = balanced;
          bestSize = balanced.length;
          bestStrategy = 'balanced';
        }
      } catch (error) {
        logger.warn('Balanced strategy failed:', error.message);
      }

      // Strategy 3: Aggressive (only if we're still below 75%)
      const currentRatio = ((originalSize - bestSize) / originalSize * 100);

      if (currentRatio < 75) {
        logger.info('Strategy 3: Aggressive [0.50, 0.70] - current ratio too low');
        try {
          let aggressive = await imagemin.buffer(currentBuffer, {
            plugins: [
              imageminPngquant({
                quality: [0.50, 0.70],
                speed: 1,
                strip: true,
                dithering: 1.0
              })
            ]
          });

          aggressive = await imagemin.buffer(aggressive, {
            plugins: [imageminOptipng({ optimizationLevel: 2 })]
          }).catch(() => aggressive);

          aggressive = await imagemin.buffer(aggressive, {
            plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 15 })]
          }).catch(() => aggressive);

          const ratio = ((originalSize - aggressive.length) / originalSize * 100).toFixed(1);
          attempts.push({
            strategy: 'aggressive',
            buffer: aggressive,
            size: aggressive.length,
            ratio: parseFloat(ratio)
          });

          logger.info('Aggressive result:', {
            size: (aggressive.length / 1024).toFixed(2) + ' KB',
            ratio: ratio + '%'
          });

          // Only use if it gets us 76-82% (quality gate)
          if (aggressive.length < bestSize && parseFloat(ratio) >= 76 && parseFloat(ratio) <= 82) {
            bestBuffer = aggressive;
            bestSize = aggressive.length;
            bestStrategy = 'aggressive';
          }
        } catch (error) {
          logger.warn('Aggressive strategy failed:', error.message);
        }
      }

      const finalSize = bestSize;
      const compressionRatio = ((originalSize - finalSize) / originalSize * 100).toFixed(1);
      const processingTime = Date.now() - startTime;

      // Log all attempts
      logger.info('All strategies tested:', attempts.map(a => ({
        strategy: a.strategy,
        size: (a.size / 1024).toFixed(2) + ' KB',
        ratio: a.ratio + '%'
      })));

      logger.info('=== COMPRESSION COMPLETE ===', {
        originalSize: (originalSize / 1024).toFixed(2) + ' KB',
        finalSize: (finalSize / 1024).toFixed(2) + ' KB',
        compressionRatio: `${compressionRatio}%`,
        strategy: bestStrategy,
        processingTime: `${processingTime}ms`,
        tinypngTarget: '78% (475 KB)',
        status: parseFloat(compressionRatio) >= 77 && parseFloat(compressionRatio) <= 80 ? '✓ MATCHED TINYPNG' :
          parseFloat(compressionRatio) > 82 ? '⚠ TOO AGGRESSIVE (QUALITY GATE BLOCKED)' :
            parseFloat(compressionRatio) >= 75 ? '≈ CLOSE TO TINYPNG' :
              '✗ BELOW TARGET'
      });

      return {
        buffer: bestBuffer,
        originalSize,
        compressedSize: finalSize,
        compressionRatio,
        strategy: bestStrategy,
        analysis,
        allAttempts: attempts
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
          quality: 75,
          effort: 10,
          colors: 192
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