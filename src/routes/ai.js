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

// Image processing configuration - focus on when NOT to resize
const IMAGE_CONFIG = {
    // Only resize if image is significantly larger than these thresholds
    resizeThreshold: {
        width: 1400,   // Only resize if width > 1400px
        height: 1400   // Only resize if height > 1400px
    },
    maxDimensions: {
        width: 1280,   // Target size when resizing is needed
        height: 1280   // Target size when resizing is needed
    },
    
    // Quality settings for preprocessing (only used when resizing)
    preprocessQuality: 85,
    // Maximum file size after preprocessing (in bytes) - be more lenient
    maxProcessedSize: 15 * 1024 * 1024, // 15MB
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
 * Conservative image processing: only resize when absolutely necessary
 */
async function optimizeImageForProcessing(buffer, originalFilename = 'image') {
    try {
        const startTime = Date.now();
        
        // Get image metadata
        const metadata = await sharp(buffer).metadata();
        const { width, height, format, size } = metadata;
        
        console.log(`📊 Original image: ${width}x${height}, ${format}, ${(size / 1024 / 1024).toFixed(2)}MB`);
        
        // Only resize if image is significantly larger than our thresholds
        const needsResize = width > IMAGE_CONFIG.resizeThreshold.width || 
                           height > IMAGE_CONFIG.resizeThreshold.height;
        
        // Check if file size is reasonable
        const sizeOk = size <= IMAGE_CONFIG.maxProcessedSize;
        
        // Strategy: Don't resize unless absolutely necessary
        if (!needsResize && sizeOk) {
            console.log(`✅ Image size acceptable (${width}x${height}) - using original without resizing`);
            return {
                buffer,
                optimized: false,
                originalDimensions: { width, height },
                finalDimensions: { width, height },
                compressionRatio: 0,
                processingTime: Date.now() - startTime,
                recommendedModel: 'medium', // Use medium for most images
                strategy: 'no_resize_needed'
            };
        }
        
        // Only resize if the image is truly too large
        if (!needsResize && !sizeOk) {
            console.log(`⚠️ Image file size too large (${(size / 1024 / 1024).toFixed(2)}MB) but dimensions OK - using original anyway`);
            return {
                buffer,
                optimized: false,
                originalDimensions: { width, height },
                finalDimensions: { width, height },
                compressionRatio: 0,
                processingTime: Date.now() - startTime,
                recommendedModel: 'medium',
                strategy: 'size_warning_but_no_resize'
            };
        }
        
        // Only resize images that are significantly larger than 1400px
        console.log(`🔄 Image is large (${width}x${height}) - resizing to prevent memory issues`);
        
        let newWidth = width;
        let newHeight = height;
        
        const aspectRatio = width / height;
        
        // Scale down proportionally
        const scaleByWidth = IMAGE_CONFIG.maxDimensions.width / width;
        const scaleByHeight = IMAGE_CONFIG.maxDimensions.height / height;
        
        // Use the smaller scale factor to ensure both dimensions fit
        const scaleFactor = Math.min(scaleByWidth, scaleByHeight, 1); // Never scale up
        
        newWidth = Math.round(width * scaleFactor);
        newHeight = Math.round(height * scaleFactor);
        
        // Ensure aspect ratio is exactly preserved
        const newAspectRatio = newWidth / newHeight;
        if (Math.abs(newAspectRatio - aspectRatio) > 0.001) {
            if (scaleByWidth < scaleByHeight) {
                newHeight = Math.round(newWidth / aspectRatio);
            } else {
                newWidth = Math.round(newHeight * aspectRatio);
            }
        }
        
        console.log(`📐 Resizing: ${width}x${height} → ${newWidth}x${newHeight} (${(aspectRatio).toFixed(3)} ratio preserved)`);
        
        // Process with Sharp (this is where the crash might happen)
        try {
            const optimizedBuffer = await sharp(buffer)
                .resize(newWidth, newHeight, {
                    kernel: sharp.kernel.lanczos3,
                    withoutEnlargement: true,
                    fastShrinkOnLoad: true
                })
                .png({
                    quality: IMAGE_CONFIG.preprocessQuality,
                    compressionLevel: 6,
                    adaptiveFiltering: true,
                    palette: false
                })
                .toBuffer();
            
            const compressionRatio = ((size - optimizedBuffer.length) / size * 100);
            const processingTime = Date.now() - startTime;
            
            console.log(`✅ Resize completed: ${(optimizedBuffer.length / 1024 / 1024).toFixed(2)}MB (${compressionRatio.toFixed(1)}% size change) in ${processingTime}ms`);
            
            return {
                buffer: optimizedBuffer,
                optimized: true,
                originalDimensions: { width, height },
                finalDimensions: { width: newWidth, height: newHeight },
                compressionRatio,
                processingTime,
                aspectRatioPreserved: true,
                recommendedModel: 'medium',
                strategy: 'resized_large_image'
            };
            
        } catch (sharpError) {
            console.error('❌ Sharp resizing failed:', sharpError.message);
            console.log('🔄 Falling back to original image without resizing');
            
            // If resizing fails, use original image
            return {
                buffer,
                optimized: false,
                originalDimensions: { width, height },
                finalDimensions: { width, height },
                compressionRatio: 0,
                processingTime: Date.now() - startTime,
                recommendedModel: 'medium',
                strategy: 'resize_failed_using_original',
                resizeError: sharpError.message
            };
        }
        
    } catch (error) {
        console.error('❌ Error in image optimization:', error);
        // If anything fails, just use the original buffer
        return {
            buffer,
            optimized: false,
            originalDimensions: { width: 'unknown', height: 'unknown' },
            finalDimensions: { width: 'unknown', height: 'unknown' },
            compressionRatio: 0,
            processingTime: 0,
            recommendedModel: 'medium',
            strategy: 'error_fallback_to_original',
            error: error.message
        };
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
        let model = req.body.model || 'medium'; // Changed to let instead of const
        const outputFormat = req.body.outputFormat || 'png';
        const outputQuality = parseFloat(req.body.outputQuality) || 1.0;
        const skipOptimization = req.body.skipOptimization === 'true';

        console.log(`🚀 Starting background removal: ${req.file.originalname} (${(originalBuffer.length / 1024 / 1024).toFixed(2)}MB)`);
        
        // Always use medium model unless explicitly requested otherwise
        model = req.body.model || 'medium';

        // Step 1: Analyze image but avoid unnecessary resizing
        let optimizationResult;
        if (!skipOptimization) {
            try {
                optimizationResult = await optimizeImageForProcessing(originalBuffer, req.file.originalname);
                optimizedBuffer = optimizationResult.buffer;
                
                console.log(`📋 Processing strategy: ${optimizationResult.strategy}`);
                if (optimizationResult.resizeError) {
                    console.warn(`⚠️ Resize error (using original): ${optimizationResult.resizeError}`);
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
                    strategy: 'optimization_failed'
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

        // Step 2: Create Blob for AI processing (with error handling)
        const { Blob } = require('buffer');
        try {
            inputForProcessing = new Blob([optimizedBuffer], { type: 'image/png' });
            console.log(`📦 Created blob for AI processing: ${(optimizedBuffer.length / 1024 / 1024).toFixed(2)}MB`);
        } catch (blobError) {
            console.error('❌ Failed to create blob for AI processing:', blobError.message);
            return res.status(500).json({
                success: false,
                message: 'Failed to prepare image for AI processing',
                error: blobError.message
            });
        }

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

        // Step 4: Process the image with AI (with enhanced error handling)
        const aiStartTime = Date.now();
        
        try {
            console.log(`🤖 Starting AI background removal with ${model} model...`);
            logMemoryUsage('before AI processing');
            
            // Force garbage collection before AI processing
            if (global.gc) {
                global.gc();
                console.log('🗑️  Pre-AI garbage collection completed');
            }
            
            // Set up timeout (more conservative timeouts)
            const timeoutDuration = model === 'large' ? 8 * 60 * 1000 : 
                                  model === 'medium' ? 4 * 60 * 1000 : 
                                  2 * 60 * 1000; // Reduced timeouts
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => {
                    reject(new Error(`Processing timeout - ${model} model took longer than ${timeoutDuration / 60000} minutes`));
                }, timeoutDuration);
            });

            // Configure IMG.LY with more conservative settings
            const config = {
                debug: false,
                proxyToWorker: false,
                model: model,
                output: {
                    format: outputFormat === 'jpg' ? 'image/jpeg' : `image/${outputFormat}`,
                    quality: Math.min(outputQuality, 0.9) // Cap quality to prevent memory issues
                },
                // Add memory optimization options if available
                device: 'cpu', // Force CPU processing for stability
                publicPath: undefined // Disable public path to reduce memory overhead
            };

            const processingPromise = removeBackground(inputForProcessing, config);
            const result = await Promise.race([processingPromise, timeoutPromise]);
            
            logMemoryUsage('after AI processing');

            // Convert result to buffer with better error handling
            if (!result) {
                throw new Error('AI processing returned null/undefined result');
            }

            if (result instanceof Blob) {
                const arrayBuffer = await result.arrayBuffer();
                if (!arrayBuffer || arrayBuffer.byteLength === 0) {
                    throw new Error('AI processing returned empty blob');
                }
                processedBuffer = Buffer.from(arrayBuffer);
            } else if (Buffer.isBuffer(result)) {
                processedBuffer = result;
            } else if (result instanceof ArrayBuffer) {
                if (result.byteLength === 0) {
                    throw new Error('AI processing returned empty ArrayBuffer');
                }
                processedBuffer = Buffer.from(result);
            } else if (result instanceof Uint8Array) {
                if (result.length === 0) {
                    throw new Error('AI processing returned empty Uint8Array');
                }
                processedBuffer = Buffer.from(result);
            } else if (result && typeof result.arrayBuffer === 'function') {
                const arrayBuffer = await result.arrayBuffer();
                if (!arrayBuffer || arrayBuffer.byteLength === 0) {
                    throw new Error('AI processing returned empty buffer via arrayBuffer()');
                }
                processedBuffer = Buffer.from(arrayBuffer);
            } else {
                // Last resort - try to convert whatever we got
                try {
                    processedBuffer = Buffer.from(result);
                    if (processedBuffer.length === 0) {
                        throw new Error('Converted result is empty');
                    }
                } catch (conversionError) {
                    throw new Error(`Failed to convert AI result to buffer: ${conversionError.message}`);
                }
            }

        } catch (aiError) {
            console.error('❌ AI processing failed:', {
                error: aiError.message,
                stack: aiError.stack,
                model: model,
                imageSize: `${optimizationResult.finalDimensions.width}x${optimizationResult.finalDimensions.height}`,
                bufferSize: `${(optimizedBuffer.length / 1024 / 1024).toFixed(2)}MB`
            });
            
            // Try to recover memory after failed processing
            optimizedBuffer = null;
            inputForProcessing = null;
            
            if (global.gc) {
                global.gc();
                console.log('🗑️  Emergency garbage collection after AI failure');
            }
            
            return res.status(500).json({
                success: false,
                message: 'AI background removal failed',
                error: aiError.message,
                model: model,
                optimized: optimizationResult.optimized,
                suggestion: model === 'medium' ? 'Try using small model for better stability' : 'Image may be too complex for processing'
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