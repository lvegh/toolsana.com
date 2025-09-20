const sharp = require('sharp');
const imagemin = require('imagemin');
const imageminPngquant = require('imagemin-pngquant');
const imageminOptipng = require('imagemin-optipng');
const imageminAdvpng = require('imagemin-advpng');
const logger = require('../utils/logger');

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

  selectCompressionStrategy(analysis) {
    if (analysis.size < 10000) {
      logger.info('Small image detected, using quality strategy');
      return 'quality';
    }
    
    if (analysis.complexity < 30 || analysis.uniqueColors < 256) {
      logger.info('Simple image detected, using aggressive strategy', {
        complexity: analysis.complexity,
        uniqueColors: analysis.uniqueColors
      });
      return 'aggressive';
    }
    
    if (analysis.complexity > 70 || analysis.hasAlpha) {
      logger.info('Complex image detected, using quality strategy', {
        complexity: analysis.complexity,
        hasAlpha: analysis.hasAlpha
      });
      return 'quality';
    }
    
    logger.info('Standard image detected, using balanced strategy');
    return 'balanced';
  }

  async optimizeWithPngquant(buffer, strategy) {
    try {
      const options = this.compressionStrategies[strategy];
      
      logger.info('Starting pngquant optimization', {
        strategy,
        quality: options.quality,
        speed: options.speed
      });

      const optimized = await imagemin.buffer(buffer, {
        plugins: [
          imageminPngquant({
            quality: options.quality,
            speed: options.speed,
            strip: options.strip,
            dithering: options.dithering
          })
        ]
      });

      const reduction = ((buffer.length - optimized.length) / buffer.length * 100).toFixed(1);
      logger.info('Pngquant optimization complete', {
        originalSize: buffer.length,
        optimizedSize: optimized.length,
        reduction: `${reduction}%`
      });

      return optimized;
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
      const strippedBuffer = await this.stripMetadata(buffer);
      
      const analysis = await this.analyzeImage(strippedBuffer);
      
      const strategy = options.strategy || this.selectCompressionStrategy(analysis);
      
      let compressedBuffer = strippedBuffer;
      
      if (analysis.uniqueColors <= 256 && !analysis.hasAlpha) {
        logger.info('Image suitable for palette-based compression');
        compressedBuffer = await this.optimizeWithSharp(strippedBuffer);
      } else {
        compressedBuffer = await this.optimizeWithPngquant(strippedBuffer, strategy);
      }
      
      if (strategy !== 'aggressive') {
        const optipngBuffer = await this.optimizeWithOptipng(compressedBuffer);
        if (optipngBuffer.length < compressedBuffer.length) {
          compressedBuffer = optipngBuffer;
        }
      }
      
      const advpngBuffer = await this.optimizeWithAdvpng(compressedBuffer);
      if (advpngBuffer.length < compressedBuffer.length) {
        compressedBuffer = advpngBuffer;
      }
      
      if (compressedBuffer.length >= originalSize * 0.95) {
        logger.info('Minimal compression achieved, trying aggressive strategy');
        const aggressiveBuffer = await this.optimizeWithPngquant(strippedBuffer, 'aggressive');
        if (aggressiveBuffer.length < compressedBuffer.length) {
          compressedBuffer = aggressiveBuffer;
        }
      }
      
      const finalSize = compressedBuffer.length;
      const compressionRatio = ((originalSize - finalSize) / originalSize * 100).toFixed(1);
      const processingTime = Date.now() - startTime;
      
      logger.info('PNG compression completed', {
        originalSize,
        finalSize,
        compressionRatio: `${compressionRatio}%`,
        strategy,
        processingTime: `${processingTime}ms`,
        uniqueColors: analysis.uniqueColors,
        complexity: analysis.complexity
      });
      
      return {
        buffer: compressedBuffer,
        originalSize,
        compressedSize: finalSize,
        compressionRatio,
        strategy,
        analysis
      };
      
    } catch (error) {
      logger.error('PNG compression failed', {
        error: error.message,
        stack: error.stack
      });
      
      const fallbackBuffer = await this.optimizeWithSharp(buffer);
      return {
        buffer: fallbackBuffer,
        originalSize,
        compressedSize: fallbackBuffer.length,
        compressionRatio: ((originalSize - fallbackBuffer.length) / originalSize * 100).toFixed(1),
        strategy: 'fallback',
        analysis: null
      };
    }
  }
}

module.exports = new PngOptimizer();