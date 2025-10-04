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

        // Lossless optimization only
        let optimized = await imagemin.buffer(gradientBuffer, {
          plugins: [imageminOptipng({ optimizationLevel: 2 })]
        }).catch(() => gradientBuffer);

        optimized = await imagemin.buffer(optimized, {
          plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 20 })]
        }).catch(() => optimized);

        attempts.push({ strategy: 'gradient-safe', size: optimized.length, buffer: optimized });

        if (optimized.length < bestSize) {
          bestBuffer = optimized;
          bestSize = optimized.length;
          bestStrategy = 'gradient-safe';
        }
      }

      // Strategy 2: TinyPNG-matched quality levels (for detailed images)
      if (!analysis.hasGradients) {
        logger.info('Applying TinyPNG-matched compression strategies');

        // These quality levels match TinyPNG's sweet spot
        // Start with higher quality and only go lower if needed
        const qualityLevels = [
          { quality: [0.65, 0.80], dither: 1.0, name: 'tinypng-match-80' },
          { quality: [0.60, 0.75], dither: 1.0, name: 'tinypng-match-75' },
          { quality: [0.55, 0.70], dither: 1.0, name: 'tinypng-match-70' }
        ];

        for (const level of qualityLevels) {
          try {
            let testBuffer = await imagemin.buffer(currentBuffer, {
              plugins: [
                imageminPngquant({
                  quality: level.quality,
                  speed: 1,
                  strip: true,
                  dithering: level.dither,
                  posterize: 0
                })
              ]
            });

            // Optimize further
            testBuffer = await imagemin.buffer(testBuffer, {
              plugins: [imageminOptipng({ optimizationLevel: 2 })]
            }).catch(() => testBuffer);

            testBuffer = await imagemin.buffer(testBuffer, {
              plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 15 })]
            }).catch(() => testBuffer);

            const ratio = ((originalSize - testBuffer.length) / originalSize * 100).toFixed(1);

            attempts.push({
              strategy: level.name,
              size: testBuffer.length,
              buffer: testBuffer,
              ratio: parseFloat(ratio)
            });

            logger.info(`${level.name}: ${testBuffer.length} bytes (${ratio}%)`);

            if (testBuffer.length < bestSize) {
              bestBuffer = testBuffer;
              bestSize = testBuffer.length;
              bestStrategy = level.name;
            }
          } catch (error) {
            logger.warn(`Failed ${level.name}:`, error.message);
          }
        }
      }

      // Strategy 3: Smart color quantization (only if quality levels didn't hit target)
      const currentRatio = ((originalSize - bestSize) / originalSize * 100);

      if (!analysis.hasGradients && currentRatio < 75 && originalSize > 100000) {
        logger.info('Applying smart color quantization (current: ' + currentRatio.toFixed(1) + '%)');

        // Only try conservative quantization levels
        const colorCounts = [256, 192, 128];

        for (const colors of colorCounts) {
          try {
            let quantBuffer = await sharp(buffer)
              .png({
                palette: true,
                quality: 90,
                colors: colors,
                dither: 1.0,
                compressionLevel: 9,
                adaptiveFiltering: true,
                effort: 10
              })
              .toBuffer();

            // Light optimization pass
            quantBuffer = await imagemin.buffer(quantBuffer, {
              plugins: [
                imageminPngquant({
                  quality: [0.85, 0.95], // High quality to preserve the quantization
                  speed: 1,
                  strip: true,
                  dithering: 0.3
                })
              ]
            }).catch(() => quantBuffer);

            quantBuffer = await imagemin.buffer(quantBuffer, {
              plugins: [imageminOptipng({ optimizationLevel: 2 })]
            }).catch(() => quantBuffer);

            quantBuffer = await imagemin.buffer(quantBuffer, {
              plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 15 })]
            }).catch(() => quantBuffer);

            const ratio = ((originalSize - quantBuffer.length) / originalSize * 100).toFixed(1);

            attempts.push({
              strategy: `quantized-${colors}`,
              size: quantBuffer.length,
              buffer: quantBuffer,
              ratio: parseFloat(ratio)
            });

            logger.info(`quantized-${colors}: ${quantBuffer.length} bytes (${ratio}%)`);

            // Only use if it's better AND maintains reasonable quality (above 75%)
            if (quantBuffer.length < bestSize && parseFloat(ratio) <= 80) {
              bestBuffer = quantBuffer;
              bestSize = quantBuffer.length;
              bestStrategy = `quantized-${colors}`;
            }
          } catch (error) {
            logger.warn(`Quantization ${colors} colors failed:`, error.message);
          }
        }
      }

      // Strategy 4: Final optimization pass (if still below target)
      const finalRatio = ((originalSize - bestSize) / originalSize * 100);

      if (!analysis.hasGradients && finalRatio < 76 && finalRatio > 70) {
        logger.info('Applying final optimization pass to reach target (current: ' + finalRatio.toFixed(1) + '%)');

        try {
          // Slightly more aggressive, but still reasonable
          let finalBuffer = await imagemin.buffer(buffer, {
            plugins: [
              imageminPngquant({
                quality: [0.58, 0.72], // Sweet spot between quality and compression
                speed: 1,
                strip: true,
                dithering: 1.0,
                posterize: 0
              })
            ]
          });

          // Double optimization pass
          finalBuffer = await imagemin.buffer(finalBuffer, {
            plugins: [imageminOptipng({ optimizationLevel: 2 })]
          }).catch(() => finalBuffer);

          finalBuffer = await imagemin.buffer(finalBuffer, {
            plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 20 })]
          }).catch(() => finalBuffer);

          const ratio = ((originalSize - finalBuffer.length) / originalSize * 100).toFixed(1);

          attempts.push({
            strategy: 'final-optimization',
            size: finalBuffer.length,
            buffer: finalBuffer,
            ratio: parseFloat(ratio)
          });

          logger.info(`final-optimization: ${finalBuffer.length} bytes (${ratio}%)`);

          // Only use if it gets us closer to 78% without going too far
          if (finalBuffer.length < bestSize && parseFloat(ratio) <= 82) {
            bestBuffer = finalBuffer;
            bestSize = finalBuffer.length;
            bestStrategy = 'final-optimization';
          }
        } catch (error) {
          logger.warn('Final optimization failed:', error.message);
        }
      }

      const finalSize = bestSize;
      const compressionRatio = ((originalSize - finalSize) / originalSize * 100).toFixed(1);
      const processingTime = Date.now() - startTime;

      // Log all attempts sorted by best ratio
      const sortedAttempts = attempts
        .map(a => ({
          strategy: a.strategy,
          size: a.size,
          sizeKB: (a.size / 1024).toFixed(2) + ' KB',
          ratio: ((originalSize - a.size) / originalSize * 100).toFixed(1) + '%'
        }))
        .sort((a, b) => parseFloat(b.ratio) - parseFloat(a.ratio));

      logger.info('All compression attempts (sorted by ratio):', sortedAttempts);

      logger.info('PNG compression completed', {
        originalSize: (originalSize / 1024).toFixed(2) + ' KB',
        finalSize: (finalSize / 1024).toFixed(2) + ' KB',
        compressionRatio: `${compressionRatio}%`,
        strategy: bestStrategy,
        processingTime: `${processingTime}ms`,
        tinypngTarget: '78% (475 KB)',
        status: parseFloat(compressionRatio) >= 78 ? '✓ BEAT TINYPNG' : parseFloat(compressionRatio) >= 75 ? '≈ CLOSE TO TINYPNG' : '✗ BELOW TARGET'
      });

      return {
        buffer: bestBuffer,
        originalSize,
        compressedSize: finalSize,
        compressionRatio,
        strategy: bestStrategy,
        analysis,
        allAttempts: sortedAttempts
      };

    } catch (error) {
      logger.error('PNG compression failed completely', {
        error: error.message,
        stack: error.stack
      });

      // Fallback with balanced settings
      const fallbackBuffer = await sharp(buffer)
        .png({
          compressionLevel: 9,
          adaptiveFiltering: true,
          palette: true,
          quality: 80,
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