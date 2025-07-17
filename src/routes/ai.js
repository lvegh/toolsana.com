const express = require('express');
const multer = require('multer');
const sharp = require('sharp'); // Add this dependency
const { removeBackground } = require('@imgly/background-removal-node');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { enhancedSecurityWithRateLimitAi } = require('../middleware/enhancedSecurityAi');

const router = express.Router();

// Global process error handlers with detailed logging
process.on('uncaughtException', (error) => {
    console.error('🔥 UNCAUGHT EXCEPTION in AI module:', {
        message: error.message,
        name: error.name,
        stack: error.stack,
        code: error.code,
        timestamp: new Date().toISOString()
    });
    // Don't exit, just log for debugging
});

process.on('unhandledRejection', (reason, promise) => {
    console.error('🔥 UNHANDLED REJECTION in AI module:', {
        reason: reason,
        promise: promise,
        timestamp: new Date().toISOString()
    });
});

// Image processing configuration optimized for medium model only
const IMAGE_CONFIG = {
    // Maximum dimensions - if image is smaller, use small model; if larger, resize for medium
    resizeThreshold: {
        width: 1024,   // Images under this size won't be resized
        height: 1024   // Images under this size won't be resized
    },
    maxDimensions: {
        width: 1280,   // Maximum size for medium model processing
        height: 1280   // Maximum size for medium model processing
    },
    
    // Quality settings for preprocessing
    preprocessQuality: 85, // Slightly reduced for better compression
    // Maximum file size after preprocessing (in bytes)
    maxProcessedSize: 12 * 1024 * 1024, // 12MB (reduced from 15MB)
    // Supported formats
    supportedFormats: ['jpeg', 'jpg', 'png', 'webp']
};

// Configure multer for file uploads with disk storage
const uploadImage = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 20 * 1024 * 1024, // 20MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['image/png', 'image/jpeg', 'image/webp'];
        if (!allowedTypes.includes(file.mimetype)) {
            return cb(new Error('Only PNG, JPEG, and WebP files are allowed.'));
        }
        cb(null, true);
    }
});

/**
 * Intelligent image processing: small model for smaller images, resize only when needed
 */
async function optimizeImageForProcessing(buffer, originalFilename = 'image') {
    try {
        const startTime = Date.now();
        
        // Get image metadata
        const metadata = await sharp(buffer).metadata();
        const { width, height, format, size } = metadata;
        
        console.log(`📊 Original image: ${width}x${height}, ${format}, ${(size / 1024 / 1024).toFixed(2)}MB`);
        
        // Determine processing strategy based on image size
        const isSmallImage = width <= IMAGE_CONFIG.resizeThreshold.width && 
                            height <= IMAGE_CONFIG.resizeThreshold.height;
        
        const needsResize = width > IMAGE_CONFIG.maxDimensions.width || 
                           height > IMAGE_CONFIG.maxDimensions.height;
        
        // Strategy 1: Small images - use as-is with small model
        if (isSmallImage && !needsResize && size <= IMAGE_CONFIG.maxProcessedSize) {
            console.log(`✅ Small image detected (${width}x${height}) - using original size with small model`);
            return {
                buffer,
                optimized: false,
                originalDimensions: { width, height },
                finalDimensions: { width, height },
                compressionRatio: 0,
                processingTime: Date.now() - startTime,
                recommendedModel: 'small',
                strategy: 'small_original'
            };
        }
        
        // Strategy 2: Medium images - use as-is with medium model  
        if (!needsResize && size <= IMAGE_CONFIG.maxProcessedSize) {
            console.log(`✅ Medium image detected (${width}x${height}) - using original size with medium model`);
            return {
                buffer,
                optimized: false,
                originalDimensions: { width, height },
                finalDimensions: { width, height },
                compressionRatio: 0,
                processingTime: Date.now() - startTime,
                recommendedModel: 'medium',
                strategy: 'medium_original'
            };
        }
        
        // Strategy 3: Large images - resize for medium model
        let newWidth = width;
        let newHeight = height;
        
        if (needsResize) {
            const aspectRatio = width / height;
            
            // Scale down proportionally - find the limiting dimension
            const scaleByWidth = IMAGE_CONFIG.maxDimensions.width / width;
            const scaleByHeight = IMAGE_CONFIG.maxDimensions.height / height;
            
            // Use the smaller scale factor to ensure both dimensions fit
            const scaleFactor = Math.min(scaleByWidth, scaleByHeight, 1); // Never scale up
            
            newWidth = Math.round(width * scaleFactor);
            newHeight = Math.round(height * scaleFactor);
            
            // Ensure aspect ratio is exactly preserved (handle rounding errors)
            const newAspectRatio = newWidth / newHeight;
            if (Math.abs(newAspectRatio - aspectRatio) > 0.001) {
                // Adjust based on which dimension was the limiting factor
                if (scaleByWidth < scaleByHeight) {
                    // Width was limiting, recalculate height
                    newHeight = Math.round(newWidth / aspectRatio);
                } else {
                    // Height was limiting, recalculate width
                    newWidth = Math.round(newHeight * aspectRatio);
                }
            }
        }
        
        console.log(`🔄 Large image detected - resizing: ${width}x${height} → ${newWidth}x${newHeight} for medium model`);
        console.log(`📐 Aspect ratio: ${(width/height).toFixed(3)} → ${(newWidth/newHeight).toFixed(3)}`);
        
        // Process the image
        let sharpInstance = sharp(buffer);
        
        // Resize with high-quality scaling
        if (needsResize) {
            sharpInstance = sharpInstance.resize(newWidth, newHeight, {
                kernel: sharp.kernel.lanczos3, // High-quality scaling
                withoutEnlargement: true,      // Never scale up
                fastShrinkOnLoad: true         // Optimize loading for large images
            });
        }
        
        // Convert to optimal format for AI processing (PNG for transparency support)
        const optimizedBuffer = await sharpInstance
            .png({
                quality: IMAGE_CONFIG.preprocessQuality,
                compressionLevel: 6,
                adaptiveFiltering: true,
                palette: false // Ensure full color depth
            })
            .toBuffer();
        
        const compressionRatio = ((size - optimizedBuffer.length) / size * 100);
        const processingTime = Date.now() - startTime;
        
        console.log(`✅ Image resized: ${(optimizedBuffer.length / 1024 / 1024).toFixed(2)}MB (${compressionRatio.toFixed(1)}% reduction) in ${processingTime}ms`);
        
        // Verify aspect ratio preservation
        const originalAspectRatio = width / height;
        const finalAspectRatio = newWidth / newHeight;
        const aspectRatioDiff = Math.abs(originalAspectRatio - finalAspectRatio);
        
        if (aspectRatioDiff > 0.001) {
            console.warn(`⚠️ Aspect ratio deviation detected: ${aspectRatioDiff.toFixed(6)}`);
        }
        
        return {
            buffer: optimizedBuffer,
            optimized: true,
            originalDimensions: { width, height },
            finalDimensions: { width: newWidth, height: newHeight },
            compressionRatio,
            processingTime,
            aspectRatioPreserved: aspectRatioDiff < 0.001,
            recommendedModel: 'medium',
            strategy: 'large_resized'
        };
        
    } catch (error) {
        console.error('❌ Error optimizing image:', error);
        throw new Error(`Image optimization failed: ${error.message}`);
    }
}

/**
 * Memory usage monitoring
 */
function logMemoryUsage(stage) {
    const usage = process.memoryUsage();
    console.log(`🧠 Memory ${stage}:`, {
        rss: `${Math.round(usage.rss / 1024 / 1024)}MB`,
        heapUsed: `${Math.round(usage.heapUsed / 1024 / 1024)}MB`,
        heapTotal: `${Math.round(usage.heapTotal / 1024 / 1024)}MB`,
        external: `${Math.round(usage.external / 1024 / 1024)}MB`
    });
}

// Processing state
let processingStartTime = null;

router.post('/remove-background', enhancedSecurityWithRateLimitAi(basicRateLimit), uploadImage.single('file'), async (req, res) => {
    let originalBuffer = null;
    let optimizedBuffer = null;
    let processedBuffer = null;
    let inputForProcessing = null;

    try {
        // Check if file was uploaded
        if (!req.file) {
            console.log('❌ No file provided in request');
            return res.status(400).json({
                success: false,
                message: 'No file provided'
            });
        }

        // Set processing state
        processingStartTime = Date.now();
        logMemoryUsage('before processing');

        // Extract request parameters
        originalBuffer = req.file.buffer;
        const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
        const model = req.body.model || 'medium';
        const outputFormat = req.body.outputFormat || 'png';
        const outputQuality = parseFloat(req.body.outputQuality) || 1.0;
        const skipOptimization = req.body.skipOptimization === 'true';

        console.log(`🚀 Starting background removal: ${req.file.originalname} (${(originalBuffer.length / 1024 / 1024).toFixed(2)}MB) with ${model} model`);

        // Step 1: Analyze and optimize image (auto-detect model size)
        let optimizationResult;
        if (!skipOptimization) {
            try {
                optimizationResult = await optimizeImageForProcessing(originalBuffer, req.file.originalname);
                optimizedBuffer = optimizationResult.buffer;
                
                // Use the recommended model from optimization analysis
                const recommendedModel = optimizationResult.recommendedModel || 'medium';
                if (recommendedModel !== model) {
                    console.log(`💡 Recommending ${recommendedModel} model instead of ${model} based on image size`);
                    // Update model for AI processing
                    model = recommendedModel;
                }
                
                logMemoryUsage('after optimization');
            } catch (optimizationError) {
                console.warn('⚠️ Image optimization failed, using original:', optimizationError.message);
                optimizedBuffer = originalBuffer;
                optimizationResult = {
                    optimized: false,
                    originalDimensions: { width: 'unknown', height: 'unknown' },
                    finalDimensions: { width: 'unknown', height: 'unknown' },
                    compressionRatio: 0,
                    processingTime: 0,
                    aspectRatioPreserved: true,
                    recommendedModel: 'medium',
                    strategy: 'fallback'
                };
            }
        } else {
            console.log('⏭️ Skipping image optimization (skipOptimization=true)');
            optimizedBuffer = originalBuffer;
            optimizationResult = {
                optimized: false,
                originalDimensions: { width: 'unknown', height: 'unknown' },
                finalDimensions: { width: 'unknown', height: 'unknown' },
                compressionRatio: 0,
                processingTime: 0,
                aspectRatioPreserved: true,
                recommendedModel: model,
                strategy: 'skipped'
            };
        }

        // Step 2: Create Blob for AI processing
        const { Blob } = require('buffer');
        inputForProcessing = new Blob([optimizedBuffer], { type: 'image/png' });

        // Step 3: Configure IMG.LY background removal
        const config = {
            debug: false, // Disable debug for better performance
            proxyToWorker: false, // Disable worker threads
            model: model,
            output: {
                format: outputFormat === 'jpg' ? 'image/jpeg' : `image/${outputFormat}`,
                quality: outputQuality
            }
        };

        // Step 4: Process the image with AI
        const aiStartTime = Date.now();
        
        try {
            console.log(`🤖 Starting AI background removal with ${model} model...`);
            
            const result = removeBackground(inputForProcessing, config);

            // Convert result to buffer
            if (result instanceof Blob) {
                const arrayBuffer = await result.arrayBuffer();
                processedBuffer = Buffer.from(arrayBuffer);
            } else if (Buffer.isBuffer(result)) {
                processedBuffer = result;
            } else if (result instanceof ArrayBuffer) {
                processedBuffer = Buffer.from(result);
            } else if (result instanceof Uint8Array) {
                processedBuffer = Buffer.from(result);
            } else if (result && typeof result.arrayBuffer === 'function') {
                const arrayBuffer = await result.arrayBuffer();
                processedBuffer = Buffer.from(arrayBuffer);
            } else {
                processedBuffer = Buffer.from(result);
            }

        } catch (aiError) {
            console.error('❌ AI processing failed:', aiError.message);
            return res.status(500).json({
                success: false,
                message: 'AI background removal failed',
                error: aiError.message,
                model: model,
                optimized: optimizationResult.optimized
            });
        }

        const aiProcessingTime = Date.now() - aiStartTime;
        const totalProcessingTime = Date.now() - processingStartTime;

        logMemoryUsage('after AI processing');

        // Validate processed buffer
        if (!processedBuffer || processedBuffer.length === 0) {
            return res.status(500).json({
                success: false,
                message: 'AI processing failed to generate output'
            });
        }

        // Generate filename
        const filename = `${originalName}_no_bg.${outputFormat}`;
        const finalCompressionRatio = ((originalBuffer.length - processedBuffer.length) / originalBuffer.length * 100).toFixed(2);

        console.log(`✅ Background removal completed successfully in ${totalProcessingTime}ms`);

        // Set response headers with optimization info
        res.set({
            'Content-Type': outputFormat === 'jpg' ? 'image/jpeg' : `image/${outputFormat}`,
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length': processedBuffer.length.toString(),
            'X-Original-Filename': req.file.originalname,
            'X-Original-Size': originalBuffer.length.toString(),
            'X-Processed-Size': processedBuffer.length.toString(),
            'X-Compression-Ratio': finalCompressionRatio + '%',
            'X-Processing-Time': totalProcessingTime.toString(),
            'X-AI-Processing-Time': aiProcessingTime.toString(),
            'X-AI-Model': model,
            'X-Engine': 'imgly-background-removal-node',
            'X-Image-Optimized': optimizationResult.optimized.toString(),
            'X-Original-Dimensions': `${optimizationResult.originalDimensions.width}x${optimizationResult.originalDimensions.height}`,
            'X-Final-Dimensions': `${optimizationResult.finalDimensions.width}x${optimizationResult.finalDimensions.height}`,
            'X-Optimization-Time': optimizationResult.processingTime.toString(),
            'X-Processing-Strategy': optimizationResult.strategy || 'unknown',
            'X-Recommended-Model': optimizationResult.recommendedModel || model
        });

        // Send the processed image
        res.send(processedBuffer);

    } catch (error) {
        console.error('❌ Unexpected error in background removal:', error);
        return res.status(500).json({
            success: false,
            message: 'Failed to process image',
            error: error.message
        });
    } finally {
        // Always clean up state and memory
        processingStartTime = null;

        // Clear all large variables explicitly
        originalBuffer = null;
        optimizedBuffer = null;
        processedBuffer = null;
        inputForProcessing = null;

        logMemoryUsage('after cleanup');

        // Force multiple garbage collection cycles
        if (global.gc) {
            global.gc(); // First pass
            setTimeout(() => {
                global.gc(); // Second pass
                console.log('🗑️  Completed aggressive garbage collection');
            }, 100);
        }
    }
});

// Health check endpoint with memory optimization info
router.get('/health', (req, res) => {
    const memUsage = process.memoryUsage();
    res.json({
        status: 'ok',
        processingTime: processingStartTime ? Date.now() - processingStartTime : null,
        memory: {
            rss: Math.round(memUsage.rss / 1024 / 1024) + 'MB',
            heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
            heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB',
            external: Math.round(memUsage.external / 1024 / 1024) + 'MB'
        },
        uptime: process.uptime(),
        imageOptimization: {
            enabled: true,
            resizeThreshold: IMAGE_CONFIG.resizeThreshold,
            maxDimensions: IMAGE_CONFIG.maxDimensions,
            maxProcessedSize: `${IMAGE_CONFIG.maxProcessedSize / 1024 / 1024}MB`,
            strategy: 'auto-detect model based on image size'
        }
    });
});

/**
 * API information endpoint
 */
router.get('/info', basicRateLimit, (req, res) => {
    const info = {
        service: 'AI Background Removal API',
        version: '1.1.0',
        engine: '@imgly/background-removal-node',
        supportedModels: ['small', 'medium', 'large'],
        supportedFormats: {
            input: ['jpg', 'jpeg', 'png', 'webp'],
            output: ['png', 'jpg', 'jpeg', 'webp']
        },
        endpoints: {
            remove_background: 'POST /api/ai/remove-background',
            health: 'GET /api/ai/health',
            info: 'GET /api/ai/info'
        },
        limits: {
            maxFileSize: '20MB',
            supportedImageTypes: ['image/jpeg', 'image/png', 'image/webp'],
            outputQualityRange: '0.1-1.0',
            concurrentProcessing: false
        },
        optimization: {
            automaticImageResizing: true,
            maxDimensions: IMAGE_CONFIG.maxDimensions,
            memoryOptimization: true,
            skipOptimizationParameter: 'skipOptimization=true'
        },
        features: {
            aiBackgroundRemoval: true,
            multipleModelSizes: true,
            outputFormatControl: true,
            qualityControl: true,
            performanceOptimization: true,
            healthMonitoring: true,
            memoryManagement: true,
            intelligentImageResizing: true,
            serverSideProcessingOnly: true
        }
    };

    sendSuccess(res, 'AI service information', info);
});

module.exports = router;