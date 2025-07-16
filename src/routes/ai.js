const express = require('express');
const multer = require('multer');
const { removeBackground } = require('@imgly/background-removal-node');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const logger = require('../utils/logger');
const sharp = require('sharp');

const router = express.Router();

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

/**
 * POST /api/ai/remove-background
 * Remove background from image using AI
 */
router.post('/remove-background', enhancedSecurityWithRateLimit(basicRateLimit), uploadImage.single('file'), async (req, res) => {
    try {
        // Check if file was uploaded
        if (!req.file) {
            return sendError(res, 'No file provided', 400);
        }

        const originalBuffer = req.file.buffer;
        const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
        const model = req.body.model || 'medium'; // Updated to use size-based model
        const outputFormat = req.body.outputFormat || 'png';
        const outputQuality = parseFloat(req.body.outputQuality) || 1.0;

        // Validate model parameter - Updated to use new enum values
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

        // Process the image with AI background removal
        const startTime = Date.now();

        let processedBuffer;
        try {
            // Configure AI background removal options - Updated config structure
            const config = {
                model: model, // Now uses 'small', 'medium', or 'large'
                output: {
                    format: outputFormat === 'jpg' ? 'image/jpeg' : `image/${outputFormat}`,
                    quality: outputQuality
                }
            };

            logger.info('Processing with config:', config);

            const blob = new Blob([originalBuffer], { type: req.file.mimetype });

            // Process the image
            const result = await removeBackground(blob, config);

            logger.info('AI processing result type:', {
                type: typeof result,
                constructor: result?.constructor?.name,
                isBuffer: Buffer.isBuffer(result),
                isArrayBuffer: result instanceof ArrayBuffer,
                hasArrayBuffer: typeof result?.arrayBuffer === 'function',
                length: result?.length || result?.byteLength || 'unknown'
            });

            // Convert result to buffer - Handle different result types
            if (Buffer.isBuffer(result)) {
                processedBuffer = result;
            } else if (result instanceof ArrayBuffer) {
                processedBuffer = Buffer.from(result);
            } else if (result instanceof Uint8Array) {
                processedBuffer = Buffer.from(result);
            } else if (result && typeof result.arrayBuffer === 'function') {
                const arrayBuffer = await result.arrayBuffer();
                processedBuffer = Buffer.from(arrayBuffer);
            } else if (result && result.buffer) {
                // Handle typed arrays
                processedBuffer = Buffer.from(result.buffer);
            } else {
                // Last resort - try to convert to string then buffer
                try {
                    processedBuffer = Buffer.from(result);
                } catch (conversionError) {
                    logger.error('Failed to convert result to buffer:', {
                        error: conversionError.message,
                        resultType: typeof result,
                        resultConstructor: result?.constructor?.name
                    });
                    throw new Error('Unable to process AI result - unexpected format');
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
                errorCode: aiError.code
            });

            // Provide helpful error messages based on common issues
            if (aiError.message.includes('Invalid enum value') || aiError.message.includes('Expected')) {
                return sendError(res, `Invalid model parameter. Use 'small', 'medium', or 'large'.`, 400);
            } else if (aiError.message.includes('model') || aiError.message.includes('Model')) {
                return sendError(res, 'AI model could not be loaded. The service may be temporarily unavailable.', 503);
            } else if (aiError.message.includes('memory') || aiError.message.includes('allocation') || aiError.message.includes('Memory')) {
                return sendError(res, 'Image too large for AI processing. Please try with a smaller image.', 413);
            } else if (aiError.message.includes('format') || aiError.message.includes('decode') || aiError.message.includes('unsupported')) {
                return sendError(res, 'Invalid or unsupported image format. Please ensure the image is not corrupted.', 400);
            } else if (aiError.message.includes('timeout') || aiError.message.includes('Timeout')) {
                return sendError(res, 'Processing timeout. Please try with a smaller image or try again later.', 504);
            } else if (aiError.message.includes('network') || aiError.message.includes('fetch')) {
                return sendError(res, 'Network error while processing. Please try again later.', 503);
            } else {
                return sendError(res, 'AI background removal failed. Please try again with a different image.', 500, {
                    details: process.env.NODE_ENV === 'development' ? aiError.message : undefined
                });
            }
        }

        const processingTime = Date.now() - startTime;

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
            outputQuality: req.body?.outputQuality
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

        return sendError(res, 'Failed to process image with AI background removal', 500, {
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
    }
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
            // Missing CPU info - assume worst case
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
            // Missing memory info - assume worst case
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
            capabilityScore += 5; // Assume moderate if unknown
            requirements.factors.network = 'unknown';
        }

        // Adjust score based on image size
        if (imageSize) {
            if (imageSize > 10 * 1024 * 1024) { // > 10MB
                capabilityScore -= 20;
                requirements.factors.imageSize = 'very_large';
            } else if (imageSize > 5 * 1024 * 1024) { // > 5MB
                capabilityScore -= 10;
                requirements.factors.imageSize = 'large';
            } else if (imageSize > 2 * 1024 * 1024) { // > 2MB
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

        // If we can't assess capability, default to server-side
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
            'small',    // Fast, lower quality
            'medium',   // Balanced (default)
            'large'     // Slow, higher quality
        ],
        supportedFormats: {
            input: ['jpg', 'jpeg', 'png', 'webp'],
            output: ['png', 'jpg', 'jpeg', 'webp']
        },
        endpoints: {
            remove_background: 'POST /api/remove-background',
            check_device_capability: 'POST /api/check-device-capability',
            info: 'GET /api/ai/info'
        },
        limits: {
            maxFileSize: '20MB',
            supportedImageTypes: ['image/jpeg', 'image/png', 'image/webp'],
            outputQualityRange: '0.1-1.0'
        },
        features: {
            aiBackgroundRemoval: true,
            multipleModelSizes: true,
            deviceCapabilityCheck: true,
            outputFormatControl: true,
            qualityControl: true,
            performanceOptimization: true
        },
        usage: {
            remove_background: {
                method: 'POST',
                endpoint: '/api/remove-background',
                contentType: 'multipart/form-data',
                fields: {
                    file: 'Image file (required)',
                    model: 'Model size: small, medium, large (optional, default: medium)',
                    outputFormat: 'Output format (optional, default: png)',
                    outputQuality: 'Output quality 0.1-1.0 (optional, default: 1.0)'
                },
                response: 'Image file with background removed'
            },
            check_device_capability: {
                method: 'POST',
                endpoint: '/api/check-device-capability',
                contentType: 'application/json',
                fields: {
                    userAgent: 'Browser user agent string',
                    hardwareConcurrency: 'Number of CPU cores',
                    deviceMemory: 'Device memory in GB',
                    connection: 'Network connection info',
                    webgl: 'WebGL support information',
                    imageSize: 'Size of image to process'
                },
                response: 'Device capability assessment and recommendation'
            }
        }
    };

    sendSuccess(res, 'AI service information', info);
});

module.exports = router;