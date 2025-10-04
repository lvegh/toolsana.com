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
      // Strip metadata first
      let currentBuffer = await this.stripMetadata(buffer);

      // Analyze the image
      const analysis = await this.analyzeImage(currentBuffer);

      logger.info('Image analysis complete', {
        hasGradients: analysis.hasGradients,
        complexity: analysis.complexity,
        avgStdDev: analysis.avgStdDev,
        size: analysis.size
      });

      let bestBuffer = currentBuffer;
      let bestSize = currentBuffer.length;
      let bestStrategy = 'original';
      const attempts = [];

      // Strategy 1: For gradients - preserve quality to prevent banding
      if (analysis.hasGradients) {
        logger.info('Gradient detected - using quality-preserving compression');

        const gradientBuffer = await imagemin.buffer(currentBuffer, {
          plugins: [
            imageminPngquant({
              quality: [0.90, 0.98],
              speed: 1,
              strip: true,
              dithering: 0,
              posterize: 0
            })
          ]
        }).catch(() => currentBuffer);

        // Lossless optimization
        let optimized = await imagemin.buffer(gradientBuffer, {
          plugins: [imageminOptipng({ optimizationLevel: 2 })]
        }).catch(() => gradientBuffer);

        optimized = await imagemin.buffer(optimized, {
          plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 20 })]
        }).catch(() => optimized);

        attempts.push({ strategy: 'gradient-safe', size: optimized.length, buffer: optimized });

        bestBuffer = optimized;
        bestSize = optimized.length;
        bestStrategy = 'gradient-safe';

        logger.info('Gradient compression complete', {
          size: optimized.length,
          ratio: ((originalSize - optimized.length) / originalSize * 100).toFixed(1) + '%'
        });
      }

      // Strategy 2: For detailed images - TinyPNG-calibrated compression
      if (!analysis.hasGradients) {
        logger.info('Detailed image - applying TinyPNG-calibrated compression');

        // Primary strategy: Match TinyPNG's quality sweet spot
        try {
          // Step 1: Aggressive pngquant (this is the key)
          let primaryBuffer = await imagemin.buffer(currentBuffer, {
            plugins: [
              imageminPngquant({
                quality: [0.50, 0.70], // TinyPNG sweet spot
                speed: 1,
                strip: true,
                dithering: 1.0, // Full dithering maintains perceived quality
                posterize: 0
              })
            ]
          });

          // Step 2: OptiPNG pass
          primaryBuffer = await imagemin.buffer(primaryBuffer, {
            plugins: [imageminOptipng({ optimizationLevel: 2 })]
          }).catch(() => primaryBuffer);

          // Step 3: AdvPNG pass
          primaryBuffer = await imagemin.buffer(primaryBuffer, {
            plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 18 })]
          }).catch(() => primaryBuffer);

          const ratio = ((originalSize - primaryBuffer.length) / originalSize * 100).toFixed(1);

          attempts.push({
            strategy: 'tinypng-calibrated',
            size: primaryBuffer.length,
            buffer: primaryBuffer,
            ratio: parseFloat(ratio)
          });

          logger.info(`tinypng-calibrated: ${(primaryBuffer.length / 1024).toFixed(2)} KB (${ratio}%)`);

          if (primaryBuffer.length < bestSize) {
            bestBuffer = primaryBuffer;
            bestSize = primaryBuffer.length;
            bestStrategy = 'tinypng-calibrated';
          }
        } catch (error) {
          logger.warn('Primary strategy failed:', error.message);
        }

        // Fallback strategy: If primary didn't work well
        const currentRatio = ((originalSize - bestSize) / originalSize * 100);

        if (currentRatio < 75) {
          logger.info('Primary strategy insufficient, trying fallback (current: ' + currentRatio.toFixed(1) + '%)');

          try {
            // Slightly more aggressive
            let fallbackBuffer = await imagemin.buffer(currentBuffer, {
              plugins: [
                imageminPngquant({
                  quality: [0.45, 0.65],
                  speed: 1,
                  strip: true,
                  dithering: 1.0,
                  posterize: 0
                })
              ]
            });

            fallbackBuffer = await imagemin.buffer(fallbackBuffer, {
              plugins: [imageminOptipng({ optimizationLevel: 2 })]
            }).catch(() => fallbackBuffer);

            fallbackBuffer = await imagemin.buffer(fallbackBuffer, {
              plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 20 })]
            }).catch(() => fallbackBuffer);

            const ratio = ((originalSize - fallbackBuffer.length) / originalSize * 100).toFixed(1);

            attempts.push({
              strategy: 'aggressive-fallback',
              size: fallbackBuffer.length,
              buffer: fallbackBuffer,
              ratio: parseFloat(ratio)
            });

            logger.info(`aggressive-fallback: ${(fallbackBuffer.length / 1024).toFixed(2)} KB (${ratio}%)`);

            // Use if it gets us to 76-82% range
            if (fallbackBuffer.length < bestSize && parseFloat(ratio) <= 82 && parseFloat(ratio) >= 76) {
              bestBuffer = fallbackBuffer;
              bestSize = fallbackBuffer.length;
              bestStrategy = 'aggressive-fallback';
            }
          } catch (error) {
            logger.warn('Fallback strategy failed:', error.message);
          }
        }

        // Additional strategy: Color quantization (only if still below 75%)
        const finalRatio = ((originalSize - bestSize) / originalSize * 100);

        if (finalRatio < 75 && originalSize > 100000) {
          logger.info('Trying color quantization boost (current: ' + finalRatio.toFixed(1) + '%)');

          try {
            let quantBuffer = await sharp(buffer)
              .png({
                palette: true,
                quality: 85,
                colors: 192,
                dither: 1.0,
                compressionLevel: 9,
                adaptiveFiltering: true,
                effort: 10
              })
              .toBuffer();

            quantBuffer = await imagemin.buffer(quantBuffer, {
              plugins: [
                imageminPngquant({
                  quality: [0.75, 0.85],
                  speed: 1,
                  strip: true,
                  dithering: 0.5
                })
              ]
            }).catch(() => quantBuffer);

            quantBuffer = await imagemin.buffer(quantBuffer, {
              plugins: [imageminOptipng({ optimizationLevel: 2 })]
            }).catch(() => quantBuffer);

            quantBuffer = await imagemin.buffer(quantBuffer, {
              plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 18 })]
            }).catch(() => quantBuffer);

            const ratio = ((originalSize - quantBuffer.length) / originalSize * 100).toFixed(1);

            attempts.push({
              strategy: 'quantized-boost',
              size: quantBuffer.length,
              buffer: quantBuffer,
              ratio: parseFloat(ratio)
            });

            logger.info(`quantized-boost: ${(quantBuffer.length / 1024).toFixed(2)} KB (${ratio}%)`);

            if (quantBuffer.length < bestSize) {
              bestBuffer = quantBuffer;
              bestSize = quantBuffer.length;
              bestStrategy = 'quantized-boost';
            }
          } catch (error) {
            logger.warn('Quantization boost failed:', error.message);
          }
        }
      }

      const finalSize = bestSize;
      const compressionRatio = ((originalSize - finalSize) / originalSize * 100).toFixed(1);
      const processingTime = Date.now() - startTime;

      logger.info('PNG compression completed', {
        originalSize: (originalSize / 1024).toFixed(2) + ' KB',
        finalSize: (finalSize / 1024).toFixed(2) + ' KB',
        compressionRatio: `${compressionRatio}%`,
        strategy: bestStrategy,
        processingTime: `${processingTime}ms`,
        tinypngTarget: '78% (475 KB)',
        status: parseFloat(compressionRatio) >= 78 ? '✓ MATCHED OR BEAT TINYPNG' :
          parseFloat(compressionRatio) >= 75 ? '≈ CLOSE TO TINYPNG' :
            '✗ BELOW TARGET'
      });

      return {
        buffer: bestBuffer,
        originalSize,
        compressedSize: finalSize,
        compressionRatio,
        strategy: bestStrategy,
        analysis
      };

    } catch (error) {
      logger.error('PNG compression failed', {
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