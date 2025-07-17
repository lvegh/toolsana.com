const express = require('express');
const multer = require('multer');
const { removeBackground } = require('@imgly/background-removal-node');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const logger = require('../utils/logger');
const fs = require('fs');
const path = require('path');

const router = express.Router();

// Global process error handlers
process.on('uncaughtException', (error) => {
    logger.error('🔥 Uncaught Exception in AI module:', {
        error: error.message,
        stack: error.stack,
        name: error.name
    });
    // Don't exit process, just log
});

process.on('unhandledRejection', (reason, promise) => {
    logger.error('🔥 Unhandled Rejection in AI module:', {
        reason: reason,
        promise: promise
    });
});

// Configure multer for image file uploads
const uploadImage = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 20 * 1024 * 1024, // 20MB limit for AI processing
    },
    fileFilter: (req, file, cb) => {
        if (!['image/png', 'image/jpeg', 'image/webp'].includes(file.mimetype)) {
            return cb(new Error('Only PNG, JPEG, and WebP files are allowed.'));
        }
        cb(null, true);
    }
});

// Track processing state to prevent concurrent processing
let isProcessing = false;
let processingStartTime = null;

/**
 * POST /api/ai/remove-background
 * Remove background from image using AI
 */
router.post('/remove-background', enhancedSecurityWithRateLimit(basicRateLimit), uploadImage.single('file'), async (req, res) => {
    // Prevent concurrent processing which can cause memory issues
    if (isProcessing) {
        return sendError(res, 'Another image is currently being processed. Please wait and try again.', 429);
    }

    let tempFilePath = null; // Keep for potential debugging, but won't be used
    
    try {
        // Check if file was uploaded
        if (!req.file) {
            return sendError(res, 'No file provided', 400);
        }

        isProcessing = true;
        processingStartTime = Date.now();

        const originalBuffer = req.file.buffer;
        const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
        const model = req.body.model || 'medium';
        const outputFormat = req.body.outputFormat || 'png';
        const outputQuality = parseFloat(req.body.outputQuality) || 1.0;

        // Validate model parameter
        const validModels = ['small', 'medium', 'large'];
        if (!validModels.includes(model)) {
            return sendError(res, `Invalid model. Must be one of: ${validModels.join(', ')}`, 400);
        }

        // Validate output format
        const validFormats = ['png', 'jpg', 'jpeg', 'webp'];
        if (!validFormats.includes(outputFormat.toLowerCase())) {
            return sendError(res, `Invalid output format. Must be one of: ${validFormats.join(', ')}`, 400);
        }

        // Validate quality parameter
        if (outputQuality < 0.1 || outputQuality > 1.0) {
            return sendError(res, 'Output quality must be between 0.1 and 1.0', 400);
        }

        logger.info('Starting AI background removal', {
            originalName: req.file.originalname,
            originalSize: originalBuffer.length,
            mimetype: req.file.mimetype,
            model,
            outputFormat,
            outputQuality
        });

        // Check file size for processing
        if (originalBuffer.length > 15 * 1024 * 1024) {
            logger.warn('Large file detected, processing may take longer', {
                fileSize: originalBuffer.length,
                filename: req.file.originalname
            });
        }

        // Create a Blob with proper MIME type - this preserves format information
        const { Blob } = require('buffer'); // Use Node.js built-in Blob polyfill
        const blob = new Blob([originalBuffer], { type: req.file.mimetype });
        
        logger.info('Created Blob for processing', { 
            originalBufferLength: originalBuffer.length,
            mimeType: req.file.mimetype,
            blobSize: blob.size
        });

        // Log memory usage before processing
        const memBefore = process.memoryUsage();
        logger.info('Memory before processing:', {
            rss: Math.round(memBefore.rss / 1024 / 1024) + 'MB',
            heapUsed: Math.round(memBefore.heapUsed / 1024 / 1024) + 'MB',
            heapTotal: Math.round(memBefore.heapTotal / 1024 / 1024) + 'MB',
            external: Math.round(memBefore.external / 1024 / 1024) + 'MB'
        });

        // Process the image with AI background removal
        const startTime = Date.now();
        let processedBuffer;

        try {
            // Configure AI background removal options
            const config = {
                publicPath: path.join(__dirname, '..', '..', 'node_modules', '@imgly', 'background-removal-node', 'dist') + path.sep,
                debug: true,
                proxyToWorker: true, // Use worker thread to prevent blocking
                model: model,
                output: {
                    format: outputFormat === 'jpg' ? 'image/jpeg' : `image/${outputFormat}`,
                    quality: outputQuality
                }
            };

            logger.info('Processing with config:', config);

            // Set up timeout to prevent hanging
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => {
                    reject(new Error('Processing timeout - operation took longer than 5 minutes'));
                }, 5 * 60 * 1000); // 5 minutes timeout
            });

            // Race between processing and timeout
            const processingPromise = removeBackground(blob, config);
            
            const result = await Promise.race([processingPromise, timeoutPromise]);

            logger.info('AI processing result info:', {
                type: typeof result,
                constructor: result?.constructor?.name,
                isBlob: result instanceof Blob,
                blobSize: result instanceof Blob ? result.size : 'N/A',
                blobType: result instanceof Blob ? result.type : 'N/A',
                isBuffer: Buffer.isBuffer(result),
                isArrayBuffer: result instanceof ArrayBuffer,
                isUint8Array: result instanceof Uint8Array,
                hasArrayBuffer: typeof result?.arrayBuffer === 'function',
                length: result?.length || result?.byteLength || 'unknown'
            });

            // Convert result to buffer - Handle Blob result properly
            if (result instanceof Blob) {
                // Handle Blob result (most common case)
                const arrayBuffer = await result.arrayBuffer();
                processedBuffer = Buffer.from(arrayBuffer);
            } else if (Buffer.isBuffer(result)) {
                processedBuffer = result;
            } else if (result instanceof ArrayBuffer) {
                processedBuffer = Buffer.from(result);
            } else if (result instanceof Uint8Array) {
                processedBuffer = Buffer.from(result);
            } else if (result && typeof result.arrayBuffer === 'function') {
                // Handle other Blob-like objects
                const arrayBuffer = await result.arrayBuffer();
                processedBuffer = Buffer.from(arrayBuffer);
            } else if (result && result.buffer && result.buffer instanceof ArrayBuffer) {
                // Handle typed arrays
                processedBuffer = Buffer.from(result.buffer, result.byteOffset, result.byteLength);
            } else {
                // Last resort - try direct conversion
                try {
                    processedBuffer = Buffer.from(result);
                } catch (conversionError) {
                    logger.error('Failed to convert result to buffer:', {
                        error: conversionError.message,
                        resultType: typeof result,
                        resultConstructor: result?.constructor?.name,
                        resultKeys: result ? Object.keys(result) : []
                    });
                    throw new Error(`Unable to process AI result - unexpected format: ${typeof result}`);
                }
            }

        } catch (aiError) {
            logger.error('AI background removal failed', {
                error: aiError.message,
                stack: aiError.stack,
                originalName: req.file.originalname,
                model,
                outputFormat,
                errorName: aiError.name,
                errorCode: aiError.code,
                processingTime: Date.now() - startTime
            });

            // Clean up is not needed since we're not using temp files
            logger.info('Processing failed, no cleanup needed');

            // Provide helpful error messages based on common issues
            if (aiError.message.includes('timeout') || aiError.message.includes('Timeout')) {
                return sendError(res, 'Processing timeout. Please try with a smaller image or try again later.', 504);
            } else if (aiError.message.includes('memory') || aiError.message.includes('allocation') || aiError.message.includes('Memory')) {
                return sendError(res, 'Image too large for AI processing. Please try with a smaller image.', 413);
            } else if (aiError.message.includes('model') || aiError.message.includes('Model')) {
                return sendError(res, 'AI model could not be loaded. The service may be temporarily unavailable.', 503);
            } else if (aiError.message.includes('format') || aiError.message.includes('decode') || aiError.message.includes('unsupported')) {
                return sendError(res, 'Invalid or unsupported image format. Please ensure the image is not corrupted.', 400);
            } else if (aiError.message.includes('network') || aiError.message.includes('fetch')) {
                return sendError(res, 'Network error while processing. Please try again later.', 503);
            } else if (aiError.message.includes('worker') || aiError.message.includes('Worker')) {
                return sendError(res, 'AI processing worker failed. Please try again.', 500);
            } else {
                return sendError(res, 'AI background removal failed. Please try again with a different image.', 500, {
                    details: process.env.NODE_ENV === 'development' ? aiError.message : undefined
                });
            }
        }

        const processingTime = Date.now() - startTime;

        // Log memory usage after processing
        const memAfter = process.memoryUsage();
        logger.info('Memory after processing:', {
            rss: Math.round(memAfter.rss / 1024 / 1024) + 'MB',
            heapUsed: Math.round(memAfter.heapUsed / 1024 / 1024) + 'MB',
            heapTotal: Math.round(memAfter.heapTotal / 1024 / 1024) + 'MB',
            external: Math.round(memAfter.external / 1024 / 1024) + 'MB'
        });

        // Verify the processed buffer is valid
        if (!processedBuffer || processedBuffer.length === 0) {
            logger.error('AI processing resulted in empty buffer');
            return sendError(res, 'AI processing failed to generate output. The image may be too complex or corrupted.', 500);
        }

        // Basic validation of the processed buffer
        if (processedBuffer.length < 100) {
            logger.error('AI processing resulted in suspiciously small buffer', {
                size: processedBuffer.length
            });
            return sendError(res, 'AI processing may have failed. Please try again with a different image.', 500);
        }

        // Generate appropriate filename and mime type
        let filename, mimeType;
        switch (outputFormat.toLowerCase()) {
            case 'jpg':
            case 'jpeg':
                filename = `${originalName}_no_bg.jpg`;
                mimeType = 'image/jpeg';
                break;
            case 'webp':
                filename = `${originalName}_no_bg.webp`;
                mimeType = 'image/webp';
                break;
            default:
                filename = `${originalName}_no_bg.png`;
                mimeType = 'image/png';
        }

        const compressionRatio = ((originalBuffer.length - processedBuffer.length) / originalBuffer.length * 100).toFixed(2);

        logger.info('AI background removal completed', {
            originalName: req.file.originalname,
            originalSize: originalBuffer.length,
            processedSize: processedBuffer.length,
            compressionRatio: compressionRatio + '%',
            processingTime: processingTime + 'ms',
            model,
            outputFormat,
            outputQuality,
            filename
        });

        // Set response headers
        res.set({
            'Content-Type': mimeType,
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length': processedBuffer.length.toString(),
            'X-Original-Filename': req.file.originalname,
            'X-Original-Size': originalBuffer.length.toString(),
            'X-Processed-Size': processedBuffer.length.toString(),
            'X-Compression-Ratio': compressionRatio + '%',
            'X-Processing-Time': processingTime.toString(),
            'X-AI-Model': model,
            'X-Output-Format': outputFormat,
            'X-Output-Quality': outputQuality.toString(),
            'X-Engine': 'imgly-background-removal-node'
        });

        // Send the processed image
        res.send(processedBuffer);

    } catch (error) {
        logger.error('AI background removal error:', {
            error: error.message,
            stack: error.stack,
            originalName: req.file?.originalname,
            fileSize: req.file?.size,
            model: req.body?.model,
            outputFormat: req.body?.outputFormat,
            outputQuality: req.body?.outputQuality,
            processingTime: processingStartTime ? Date.now() - processingStartTime : 'unknown'
        });

        if (error.message.includes('File must be an image')) {
            return sendError(res, 'File must be an image', 400);
        }

        if (error.message.includes('AI processing resulted in empty buffer')) {
            return sendError(res, 'AI processing failed to generate output. The image may be too complex or corrupted.', 500);
        }

        if (error.message.includes('File too large')) {
            return sendError(res, 'File too large for processing', 413);
        }

        if (error.message.includes('Another image is currently being processed')) {
            return sendError(res, 'Server is busy processing another image. Please try again in a moment.', 429);
        }

        return sendError(res, 'Failed to process image with AI background removal', 500, {
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    } finally {
        // Always clean up
        isProcessing = false;
        processingStartTime = null;
        
        // No temp files to clean up since we use Uint8Array directly
        logger.info('Processing completed, state reset');

        // Force garbage collection if available
        if (global.gc) {
            global.gc();
            logger.info('Forced garbage collection');
        }
    }
});

// Health check endpoint to monitor processing state
router.get('/health', (req, res) => {
    const memUsage = process.memoryUsage();
    res.json({
        status: 'ok',
        isProcessing,
        processingTime: processingStartTime ? Date.now() - processingStartTime : null,
        memory: {
            rss: Math.round(memUsage.rss / 1024 / 1024) + 'MB',
            heapUsed: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
            heapTotal: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB',
            external: Math.round(memUsage.external / 1024 / 1024) + 'MB'
        },
        uptime: process.uptime()
    });
});

/**
 * POST /api/ai/check-device-capability
 * Check if device is capable of running AI background removal locally
 */
router.post('/check-device-capability', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
    try {
        const {
            userAgent,
            hardwareConcurrency,
            deviceMemory,
            connection,
            maxTouchPoints,
            webgl,
            canvas,
            imageSize
        } = req.body;

        logger.info('Device capability check requested', {
            userAgent: userAgent?.substring(0, 100),
            hardwareConcurrency,
            deviceMemory,
            connection: connection?.effectiveType,
            maxTouchPoints,
            hasWebGL: !!webgl,
            hasCanvas: !!canvas,
            imageSize
        });

        // Initialize capability score
        let capabilityScore = 0;
        const requirements = {
            minimumScore: 95,
            factors: {}
        };

        // Check CPU cores (worth 25 points)
        if (hardwareConcurrency) {
            if (hardwareConcurrency >= 8) {
                capabilityScore += 25;
                requirements.factors.cpu = 'excellent';
            } else if (hardwareConcurrency >= 4) {
                capabilityScore += 20;
                requirements.factors.cpu = 'good';
            } else if (hardwareConcurrency >= 2) {
                capabilityScore += 10;
                requirements.factors.cpu = 'fair';
            } else {
                capabilityScore += 0;
                requirements.factors.cpu = 'poor';
            }
        } else {
            capabilityScore += 0;
            requirements.factors.cpu = 'unknown';
        }

        // Check device memory (worth 30 points)
        if (deviceMemory) {
            if (deviceMemory >= 8) {
                capabilityScore += 30;
                requirements.factors.memory = 'excellent';
            } else if (deviceMemory >= 4) {
                capabilityScore += 25;
                requirements.factors.memory = 'good';
            } else if (deviceMemory >= 2) {
                capabilityScore += 15;
                requirements.factors.memory = 'fair';
            } else {
                capabilityScore += 0;
                requirements.factors.memory = 'poor';
            }
        } else {
            capabilityScore += 0;
            requirements.factors.memory = 'unknown';
        }

        // Check browser (worth 20 points)
        if (userAgent) {
            const ua = userAgent.toLowerCase();
            if (ua.includes('chrome') && !ua.includes('mobile')) {
                capabilityScore += 20;
                requirements.factors.browser = 'excellent';
            } else if (ua.includes('firefox') && !ua.includes('mobile')) {
                capabilityScore += 18;
                requirements.factors.browser = 'good';
            } else if (ua.includes('safari') && !ua.includes('mobile')) {
                capabilityScore += 15;
                requirements.factors.browser = 'fair';
            } else if (ua.includes('mobile') || ua.includes('android') || ua.includes('iphone')) {
                capabilityScore += 5;
                requirements.factors.browser = 'mobile';
            } else {
                capabilityScore += 10;
                requirements.factors.browser = 'unknown';
            }
        } else {
            capabilityScore += 0;
            requirements.factors.browser = 'unknown';
        }

        // Check WebGL support (worth 15 points)
        if (webgl) {
            if (webgl.webgl2) {
                capabilityScore += 15;
                requirements.factors.webgl = 'webgl2';
            } else if (webgl.webgl1) {
                capabilityScore += 10;
                requirements.factors.webgl = 'webgl1';
            } else {
                capabilityScore += 0;
                requirements.factors.webgl = 'none';
            }
        } else {
            capabilityScore += 0;
            requirements.factors.webgl = 'unknown';
        }

        // Check network connection (worth 10 points)
        if (connection) {
            if (connection.effectiveType === '4g') {
                capabilityScore += 10;
                requirements.factors.network = 'fast';
            } else if (connection.effectiveType === '3g') {
                capabilityScore += 5;
                requirements.factors.network = 'moderate';
            } else {
                capabilityScore += 0;
                requirements.factors.network = 'slow';
            }
        } else {
            capabilityScore += 5;
            requirements.factors.network = 'unknown';
        }

        // Adjust score based on image size
        if (imageSize) {
            if (imageSize > 10 * 1024 * 1024) {
                capabilityScore -= 20;
                requirements.factors.imageSize = 'very_large';
            } else if (imageSize > 5 * 1024 * 1024) {
                capabilityScore -= 10;
                requirements.factors.imageSize = 'large';
            } else if (imageSize > 2 * 1024 * 1024) {
                capabilityScore -= 5;
                requirements.factors.imageSize = 'medium';
            } else {
                requirements.factors.imageSize = 'small';
            }
        }

        // Determine recommendation
        const useClientSide = capabilityScore >= requirements.minimumScore;
        const recommendation = useClientSide ? 'client' : 'server';

        const result = {
            capabilityScore,
            recommendation,
            useClientSide,
            requirements,
            reasoning: {
                score: capabilityScore,
                threshold: requirements.minimumScore,
                factors: requirements.factors,
                recommendation: useClientSide
                    ? 'Device is capable of running AI background removal locally'
                    : 'Device should use server-side AI processing for better performance'
            }
        };

        logger.info('Device capability assessment completed', {
            score: capabilityScore,
            recommendation,
            useClientSide,
            factors: requirements.factors
        });

        return sendSuccess(res, 'Device capability assessed', result);

    } catch (error) {
        logger.error('Device capability check error:', {
            error: error.message,
            stack: error.stack,
            requestBody: req.body
        });

        return sendSuccess(res, 'Device capability check failed, defaulting to server-side processing', {
            capabilityScore: 0,
            recommendation: 'server',
            useClientSide: false,
            error: 'Assessment failed',
            reasoning: {
                recommendation: 'Defaulting to server-side processing due to assessment failure'
            }
        });
    }
});

/**
 * GET /api/ai/info
 * Get AI service information
 */
router.get('/info', basicRateLimit, (req, res) => {
    const info = {
        service: 'AI Background Removal API',
        version: '1.0.0',
        engine: '@imgly/background-removal-node',
        supportedModels: [
            'small',
            'medium',
            'large'
        ],
        supportedFormats: {
            input: ['jpg', 'jpeg', 'png', 'webp'],
            output: ['png', 'jpg', 'jpeg', 'webp']
        },
        endpoints: {
            remove_background: 'POST /api/remove-background',
            check_device_capability: 'POST /api/check-device-capability',
            health: 'GET /api/ai/health',
            info: 'GET /api/ai/info'
        },
        limits: {
            maxFileSize: '20MB',
            supportedImageTypes: ['image/jpeg', 'image/png', 'image/webp'],
            outputQualityRange: '0.1-1.0',
            concurrentProcessing: false
        },
        features: {
            aiBackgroundRemoval: true,
            multipleModelSizes: true,
            deviceCapabilityCheck: true,
            outputFormatControl: true,
            qualityControl: true,
            performanceOptimization: true,
            healthMonitoring: true,
            memoryManagement: true
        }
    };

    sendSuccess(res, 'AI service information', info);
});

module.exports = router;