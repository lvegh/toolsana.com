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
      
      // Select appropriate strategy
      const strategyName = this.selectCompressionStrategy(analysis);
      const strategy = this.compressionStrategies[strategyName];
      
      logger.info('Selected compression strategy', { 
        strategy: strategyName,
        settings: strategy
      });
      
      // Step 1: pngquant (lossy compression)
      logger.info('Step 1: Applying pngquant compression');
      const pngquantBuffer = await imagemin.buffer(currentBuffer, {
        plugins: [
          imageminPngquant({
            quality: strategy.quality,
            speed: strategy.speed,
            strip: strategy.strip,
            dithering: strategy.dithering,
            posterize: strategy.posterize
          })
        ]
      }).catch(err => {
        logger.warn('Pngquant failed', { error: err.message });
        return currentBuffer;
      });
      
      if (pngquantBuffer.length < currentBuffer.length) {
        const reduction = ((currentBuffer.length - pngquantBuffer.length) / currentBuffer.length * 100).toFixed(1);
        logger.info('Pngquant reduced size', {
          before: currentBuffer.length,
          after: pngquantBuffer.length,
          reduction: `${reduction}%`
        });
        currentBuffer = pngquantBuffer;
      }
      
      // Step 2: OptiPNG (lossless optimization)
      // Use level 2 for best compression (higher isn't always better)
      logger.info('Step 2: Applying OptiPNG optimization');
      const optipngBuffer = await imagemin.buffer(currentBuffer, {
        plugins: [
          imageminOptipng({
            optimizationLevel: 2
          })
        ]
      }).catch(err => {
        logger.warn('OptiPNG failed', { error: err.message });
        return currentBuffer;
      });
      
      if (optipngBuffer.length < currentBuffer.length) {
        const reduction = ((currentBuffer.length - optipngBuffer.length) / currentBuffer.length * 100).toFixed(1);
        logger.info('OptiPNG reduced size', {
          before: currentBuffer.length,
          after: optipngBuffer.length,
          reduction: `${reduction}%`
        });
        currentBuffer = optipngBuffer;
      }
      
      // Step 3: AdvPNG (final lossless optimization)
      logger.info('Step 3: Applying AdvPNG optimization');
      const advpngBuffer = await imagemin.buffer(currentBuffer, {
        plugins: [
          imageminAdvpng({
            optimizationLevel: 4,
            iterations: 15 // More iterations for better compression
          })
        ]
      }).catch(err => {
        logger.warn('AdvPNG failed', { error: err.message });
        return currentBuffer;
      });
      
      if (advpngBuffer.length < currentBuffer.length) {
        const reduction = ((currentBuffer.length - advpngBuffer.length) / currentBuffer.length * 100).toFixed(1);
        logger.info('AdvPNG reduced size', {
          before: currentBuffer.length,
          after: advpngBuffer.length,
          reduction: `${reduction}%`
        });
        currentBuffer = advpngBuffer;
      }
      
      // Step 4: If still not enough compression, try more aggressive settings
      // But ONLY for non-gradient images
      const currentRatio = ((originalSize - currentBuffer.length) / originalSize * 100);
      
      if (!analysis.hasGradients && currentRatio < 70 && originalSize > 50000) {
        logger.info('Step 4: Trying ultra-aggressive compression (ratio: ' + currentRatio.toFixed(1) + '%)');
        
        const ultraBuffer = await imagemin.buffer(buffer, {
          plugins: [
            imageminPngquant({
              quality: [0.40, 0.65],
              speed: 1,
              strip: true,
              dithering: 1,
              posterize: 0
            })
          ]
        }).catch(() => currentBuffer);
        
        // Chain through optimizers again
        let ultraOptimized = ultraBuffer;
        
        ultraOptimized = await imagemin.buffer(ultraOptimized, {
          plugins: [imageminOptipng({ optimizationLevel: 2 })]
        }).catch(() => ultraOptimized);
        
        ultraOptimized = await imagemin.buffer(ultraOptimized, {
          plugins: [imageminAdvpng({ optimizationLevel: 4, iterations: 15 })]
        }).catch(() => ultraOptimized);
        
        if (ultraOptimized.length < currentBuffer.length) {
          const improvement = ((currentBuffer.length - ultraOptimized.length) / currentBuffer.length * 100).toFixed(1);
          logger.info('Ultra-aggressive compression improved results', {
            improvement: `${improvement}%`,
            finalRatio: ((originalSize - ultraOptimized.length) / originalSize * 100).toFixed(1) + '%'
          });
          currentBuffer = ultraOptimized;
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
        analysis
      };
      
    } catch (error) {
      logger.error('PNG compression failed, using Sharp fallback', {
        error: error.message,
        stack: error.stack
      });
      
      // Fallback to Sharp
      const fallbackBuffer = await sharp(buffer)
        .png({
          compressionLevel: 9,
          adaptiveFiltering: true,
          palette: true,
          quality: 80,
          effort: 10
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