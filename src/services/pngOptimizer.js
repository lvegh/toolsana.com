const sharp = require('sharp');
const imagemin = require('imagemin');
const imageminPngquant = require('imagemin-pngquant');
const imageminOptipng = require('imagemin-optipng');
const imageminAdvpng = require('imagemin-advpng');
const logger = require('../utils/logger');

class PngOptimizer {
  constructor() {
    this.compressionStrategies = {
      photo: {
        quality: [0.70, 0.85],
        speed: 4,
        strip: true,
        dithering: 1.0,
        posterize: 0 // No posterization for photos
      },
      graphic: {
        quality: [0.40, 0.65],
        speed: 3,
        strip: true,
        dithering: 0.5,
        posterize: 3
      },
      screenshot: {
        quality: [0.55, 0.75],
        speed: 3,
        strip: true,
        dithering: 0.6,
        posterize: 4
      },
      simple: {
        quality: [0.35, 0.60],
        speed: 2,
        strip: true,
        dithering: 0.4,
        posterize: 3
      }
    };
  }

  async analyzeImage(buffer) {
    try {
      const metadata = await sharp(buffer).metadata();
      const stats = await sharp(buffer).stats();

      // Get histogram for accurate color counting
      const histogram = stats.channels.map(ch => ch.histogram || []);
      const actualColors = this.countActualColors(histogram);

      // Detect edges to determine if photo or graphic
      const edgeDetection = await this.detectEdges(buffer, metadata);

      // Calculate gradient complexity
      const gradientComplexity = this.calculateGradientComplexity(stats);

      const analysis = {
        width: metadata.width,
        height: metadata.height,
        channels: metadata.channels,
        hasAlpha: metadata.hasAlpha,
        isAnimated: metadata.pages && metadata.pages > 1,
        colorSpace: metadata.space,
        density: metadata.density,
        size: buffer.length,
        actualColors: actualColors,
        estimatedColors: this.estimateUniqueColors(stats),
        edgePercentage: edgeDetection.edgePercentage,
        isPhoto: edgeDetection.isPhoto,
        gradientComplexity: gradientComplexity,
        complexity: this.calculateComplexity(metadata, stats, edgeDetection, gradientComplexity)
      };

      logger.info('PNG image analyzed', analysis);
      return analysis;
    } catch (error) {
      logger.error('Failed to analyze PNG image', { error: error.message });
      throw error;
    }
  }

  countActualColors(histogram) {
    if (!histogram || histogram.length === 0) return 0;

    // Count non-zero bins in histogram
    let totalColors = 0;
    histogram.forEach(channelHist => {
      if (channelHist && Array.isArray(channelHist)) {
        totalColors += channelHist.filter(count => count > 0).length;
      }
    });

    return Math.floor(totalColors / histogram.length);
  }

  async detectEdges(buffer, metadata) {
    try {
      // Use a simpler approach: analyze statistics instead of edge detection
      // This avoids the complexity and potential issues with convolution
      const stats = await sharp(buffer).stats();

      // Calculate color variance - photos have high variance, graphics have low
      const channelVariances = stats.channels.map(ch => ch.stdev || 0);
      const avgVariance = channelVariances.reduce((a, b) => a + b, 0) / channelVariances.length;

      // Calculate if image has few distinct values (indicator of graphics)
      const isLowVariance = avgVariance < 40;

      // Estimate edge percentage based on standard deviation
      // High std dev in localized areas = edges
      const edgePercentage = Math.min((avgVariance / 128) * 100, 100);

      // Photos have smooth gradients (high variance but distributed)
      // Graphics have sharp edges (localized high values)
      const isPhoto = avgVariance > 30 && !isLowVariance;

      return { edgePercentage, isPhoto };
    } catch (error) {
      logger.warn('Edge detection failed, using fallback', { error: error.message });
      return { edgePercentage: 10, isPhoto: true }; // Default to photo for safety
    }
  }

  calculateGradientComplexity(stats) {
    if (!stats.channels || stats.channels.length === 0) return 0;

    // Calculate average standard deviation across channels
    const avgStdDev = stats.channels.reduce((acc, ch) => acc + (ch.stdev || 0), 0) / stats.channels.length;

    // Higher std dev = more gradients/complexity
    // Normalize to 0-100 scale
    return Math.min((avgStdDev / 128) * 100, 100);
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

  calculateComplexity(metadata, stats, edgeDetection, gradientComplexity) {
    let complexity = 0;

    // Alpha channel adds complexity
    if (metadata.hasAlpha) complexity += 15;

    // Large images
    if (metadata.width * metadata.height > 1000000) complexity += 15;

    // Gradient complexity from standard deviation
    complexity += Math.min(gradientComplexity * 0.3, 30);

    // Edge complexity
    if (edgeDetection) {
      complexity += Math.min(edgeDetection.edgePercentage * 0.5, 20);
    }

    // Color complexity
    const estimatedColors = this.estimateUniqueColors(stats);
    if (estimatedColors > 10000) complexity += 20;
    else if (estimatedColors > 1000) complexity += 10;

    return Math.min(complexity, 100);
  }

  selectCompressionStrategy(analysis) {
    // Photo detection - prioritize quality for natural images
    if (analysis.isPhoto && analysis.gradientComplexity > 40) {
      logger.info('Photo detected - using photo strategy', {
        isPhoto: analysis.isPhoto,
        gradientComplexity: analysis.gradientComplexity,
        edgePercentage: analysis.edgePercentage
      });
      return 'photo';
    }

    // Simple graphics - can be compressed aggressively
    if (analysis.actualColors < 256 && analysis.edgePercentage > 20) {
      logger.info('Simple graphic detected - using simple strategy', {
        actualColors: analysis.actualColors,
        edgePercentage: analysis.edgePercentage
      });
      return 'simple';
    }

    // Screenshot/UI detection - medium compression
    if (analysis.edgePercentage > 25 && analysis.actualColors < 5000) {
      logger.info('Screenshot/UI detected - using screenshot strategy', {
        edgePercentage: analysis.edgePercentage,
        actualColors: analysis.actualColors
      });
      return 'screenshot';
    }

    // Complex graphics/illustrations
    logger.info('Complex graphic detected - using graphic strategy', {
      complexity: analysis.complexity
    });
    return 'graphic';
  }

  async optimizeWithPngquant(buffer, strategy) {
    try {
      const options = this.compressionStrategies[strategy];

      logger.info('Starting pngquant optimization', {
        strategy,
        quality: options.quality,
        speed: options.speed,
        posterize: options.posterize
      });

      // Try primary quality settings
      let optimized = await imagemin.buffer(buffer, {
        plugins: [
          imageminPngquant({
            quality: options.quality,
            speed: options.speed,
            strip: options.strip,
            dithering: options.dithering,
            posterize: options.posterize || 0
          })
        ]
      }).catch(() => null);

      // If failed or no improvement, try fallback quality
      if (!optimized || optimized.length >= buffer.length) {
        const fallbackQuality = [
          Math.max(options.quality[0] - 0.1, 0.3),
          Math.max(options.quality[1] - 0.1, 0.6)
        ];

        logger.info('Trying fallback quality settings', { fallbackQuality });

        optimized = await imagemin.buffer(buffer, {
          plugins: [
            imageminPngquant({
              quality: fallbackQuality,
              speed: options.speed,
              strip: options.strip,
              dithering: options.dithering,
              posterize: options.posterize || 0
            })
          ]
        }).catch(() => buffer);
      }

      const finalBuffer = optimized && optimized.length < buffer.length ? optimized : buffer;
      const reduction = ((buffer.length - finalBuffer.length) / buffer.length * 100).toFixed(1);

      logger.info('Pngquant optimization complete', {
        originalSize: buffer.length,
        optimizedSize: finalBuffer.length,
        reduction: `${reduction}%`
      });

      return finalBuffer;
    } catch (error) {
      logger.warn('Pngquant optimization failed, returning original', {
        error: error.message
      });
      return buffer;
    }
  }

  async optimizeWithOptipng(buffer) {
    try {
      logger.info('Starting OptiPNG optimization');

      const optimized = await imagemin.buffer(buffer, {
        plugins: [
          imageminOptipng({
            optimizationLevel: 3
          })
        ]
      });

      const reduction = ((buffer.length - optimized.length) / buffer.length * 100).toFixed(1);
      logger.info('OptiPNG optimization complete', {
        originalSize: buffer.length,
        optimizedSize: optimized.length,
        reduction: `${reduction}%`
      });

      return optimized;
    } catch (error) {
      logger.warn('OptiPNG optimization failed, returning input', {
        error: error.message
      });
      return buffer;
    }
  }

  async optimizeWithAdvpng(buffer) {
    try {
      logger.info('Starting AdvPNG optimization');

      const optimized = await imagemin.buffer(buffer, {
        plugins: [
          imageminAdvpng({
            optimizationLevel: 4
          })
        ]
      });

      const reduction = ((buffer.length - optimized.length) / buffer.length * 100).toFixed(1);
      logger.info('AdvPNG optimization complete', {
        originalSize: buffer.length,
        optimizedSize: optimized.length,
        reduction: `${reduction}%`
      });

      return optimized;
    } catch (error) {
      logger.warn('AdvPNG optimization failed, returning input', {
        error: error.message
      });
      return buffer;
    }
  }

  async optimizeWithSharp(buffer) {
    try {
      logger.info('Starting Sharp optimization (fallback)');

      const optimized = await sharp(buffer)
        .png({
          compressionLevel: 9,
          adaptiveFiltering: true,
          palette: true,
          quality: 90,
          effort: 10
        })
        .toBuffer();

      const reduction = ((buffer.length - optimized.length) / buffer.length * 100).toFixed(1);
      logger.info('Sharp optimization complete', {
        originalSize: buffer.length,
        optimizedSize: optimized.length,
        reduction: `${reduction}%`
      });

      return optimized;
    } catch (error) {
      logger.error('Sharp optimization failed', {
        error: error.message
      });
      throw error;
    }
  }

  async stripMetadata(buffer) {
    try {
      const stripped = await sharp(buffer)
        .withMetadata(false)
        .png() // Ensure output is PNG
        .toBuffer();

      // Only use stripped version if it's actually smaller
      if (stripped.length < buffer.length) {
        const reduction = buffer.length - stripped.length;
        logger.info('Metadata stripped', {
          bytesRemoved: reduction
        });
        return stripped;
      }

      return buffer;
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

      // Track the best result
      let bestBuffer = currentBuffer;
      let bestSize = currentBuffer.length;

      // Analyze the image (this doesn't modify the buffer)
      const analysis = await this.analyzeImage(currentBuffer);

      // Select optimal strategy based on image type
      const strategy = this.selectCompressionStrategy(analysis);

      // Apply pngquant with adaptive settings
      const pngquantBuffer = await this.optimizeWithPngquant(currentBuffer, strategy);

      if (pngquantBuffer && pngquantBuffer.length < bestSize) {
        bestBuffer = pngquantBuffer;
        bestSize = pngquantBuffer.length;
        const reduction = ((originalSize - bestSize) / originalSize * 100).toFixed(1);
        logger.info('Pngquant achieved reduction', { reduction: `${reduction}%` });
      }

      // Only apply OptiPNG if it's likely to help (non-photos)
      if (!analysis.isPhoto || analysis.edgePercentage > 10) {
        const optipngBuffer = await this.optimizeWithOptipng(bestBuffer);

        // Only keep if reduction is at least 1%
        if (optipngBuffer && optipngBuffer.length < bestSize * 0.99) {
          bestBuffer = optipngBuffer;
          bestSize = optipngBuffer.length;
          logger.info('OptiPNG provided additional reduction');
        } else {
          logger.info('OptiPNG skipped - minimal benefit');
        }
      }

      // Only apply AdvPNG for graphics with sharp edges
      if (analysis.edgePercentage > 20) {
        const advpngBuffer = await this.optimizeWithAdvpng(bestBuffer);

        // Only keep if reduction is at least 1%
        if (advpngBuffer && advpngBuffer.length < bestSize * 0.99) {
          bestBuffer = advpngBuffer;
          bestSize = advpngBuffer.length;
          logger.info('AdvPNG provided additional reduction');
        } else {
          logger.info('AdvPNG skipped - minimal benefit');
        }
      }

      // SAFETY CHECK: Never return a buffer larger than the original
      if (bestSize > originalSize) {
        logger.warn('Compressed size larger than original, returning original buffer');
        bestBuffer = buffer;
        bestSize = originalSize;
      }

      const compressionRatio = ((originalSize - bestSize) / originalSize * 100).toFixed(1);
      const processingTime = Date.now() - startTime;

      logger.info('PNG compression completed', {
        originalSize,
        finalSize: bestSize,
        compressionRatio: `${compressionRatio}%`,
        strategy,
        processingTime: `${processingTime}ms`,
        imageType: analysis.isPhoto ? 'photo' : 'graphic'
      });

      return {
        buffer: bestBuffer,
        originalSize,
        compressedSize: bestSize,
        compressionRatio,
        strategy,
        analysis
      };

    } catch (error) {
      logger.error('PNG compression failed, returning original buffer', {
        error: error.message,
        stack: error.stack
      });

      // Return original buffer if everything fails
      return {
        buffer: buffer,
        originalSize,
        compressedSize: originalSize,
        compressionRatio: '0.0',
        strategy: 'failed-original-returned',
        analysis: null
      };
    }
  }
}

module.exports = new PngOptimizer();