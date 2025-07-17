const express = require('express');
const multer = require('multer');
const { removeBackground } = require('@imgly/background-removal-node');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const fs = require('fs');
const path = require('path');

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

// Configure multer for file uploads with disk storage
// Configure multer
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

// Processing state
let isProcessing = false;
let processingStartTime = null;


/**
 * POST /api/ai/remove-background
 * Remove background from image using AI
 */
router.post('/remove-background', uploadImage.single('file'), async (req, res) => {
      console.log('🎯 ==> BACKGROUND REMOVAL REQUEST STARTED (STANDALONE)');

    // Prevent concurrent processing
    if (isProcessing) {
        console.log('⏸️  Request blocked - another image is being processed');
        return res.status(429).json({
            success: false,
            message: 'Another image is currently being processed. Please wait and try again.'
        });
    }

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
        isProcessing = true;
        processingStartTime = Date.now();

        // Extract request parameters
        const originalBuffer = req.file.buffer;
        const originalName = req.file.originalname.replace(/\.[^/.]+$/, '');
        const model = req.body.model || 'small';
        const outputFormat = req.body.outputFormat || 'png';
        const outputQuality = parseFloat(req.body.outputQuality) || 1.0;

        console.log('📋 Request details:', {
            originalName: req.file.originalname,
            originalSize: originalBuffer.length,
            mimetype: req.file.mimetype,
            model,
            outputFormat,
            outputQuality,
            timestamp: new Date().toISOString()
        });

        // Log memory usage before processing
        const memBefore = process.memoryUsage();
        console.log('📊 Memory before processing:', {
            rss: Math.round(memBefore.rss / 1024 / 1024) + 'MB',
            heapUsed: Math.round(memBefore.heapUsed / 1024 / 1024) + 'MB',
            heapTotal: Math.round(memBefore.heapTotal / 1024 / 1024) + 'MB',
            external: Math.round(memBefore.external / 1024 / 1024) + 'MB'
        });

        // Create Blob with MIME type
        console.log('🔧 Creating Blob with MIME type...');
        const { Blob } = require('buffer');
        const inputForProcessing = new Blob([originalBuffer], { type: req.file.mimetype });
        console.log('✅ Successfully created Blob:', {
            size: inputForProcessing.size,
            type: inputForProcessing.type
        });

        // Configure IMG.LY background removal
        const config = {
            debug: true,
            proxyToWorker: false, // Disable worker threads
            model: model,
            output: {
                format: outputFormat === 'jpg' ? 'image/jpeg' : `image/${outputFormat}`,
                quality: outputQuality
            }
        };

        console.log('⚙️  IMG.LY Configuration:', JSON.stringify(config, null, 2));

        // Process the image
        const startTime = Date.now();
        let processedBuffer;

        try {
            console.log('🚀 Starting background removal with Blob input:', {
                blobSize: inputForProcessing.size,
                blobType: inputForProcessing.type
            });

            // Add delay for model stabilization
            console.log('⏳ Adding 1 second delay for model stabilization...');
            await new Promise(resolve => setTimeout(resolve, 1000));

            console.log('📥 About to call removeBackground with Blob:', {
                inputType: typeof inputForProcessing,
                isBlob: inputForProcessing instanceof Blob,
                inputConstructor: inputForProcessing?.constructor?.name
            });

            // Set up timeout
            const timeoutPromise = new Promise((_, reject) => {
                setTimeout(() => {
                    reject(new Error('Processing timeout - operation took longer than 5 minutes'));
                }, 5 * 60 * 1000);
            });

            const processingPromise = removeBackground(inputForProcessing, config);
            console.log('🎬 removeBackground function called, waiting for result...');

            const result = await Promise.race([processingPromise, timeoutPromise]);
            console.log('🎉 Processing completed! Result received');

            // Analyze the result
            console.log('📋 AI processing result analysis:', {
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

            // Convert result to buffer
            console.log('🔄 Converting result to buffer...');
            if (result instanceof Blob) {
                console.log('✅ Result is Blob, converting with arrayBuffer()');
                const arrayBuffer = await result.arrayBuffer();
                processedBuffer = Buffer.from(arrayBuffer);
            } else if (Buffer.isBuffer(result)) {
                console.log('✅ Result is already Buffer');
                processedBuffer = result;
            } else if (result instanceof ArrayBuffer) {
                console.log('✅ Result is ArrayBuffer, converting to Buffer');
                processedBuffer = Buffer.from(result);
            } else if (result instanceof Uint8Array) {
                console.log('✅ Result is Uint8Array, converting to Buffer');
                processedBuffer = Buffer.from(result);
            } else if (result && typeof result.arrayBuffer === 'function') {
                console.log('✅ Result has arrayBuffer method, converting');
                const arrayBuffer = await result.arrayBuffer();
                processedBuffer = Buffer.from(arrayBuffer);
            } else {
                console.log('❌ Unknown result format, attempting direct conversion');
                processedBuffer = Buffer.from(result);
            }

            console.log('✅ Buffer conversion successful:', {
                bufferLength: processedBuffer.length,
                bufferType: typeof processedBuffer
            });

        } catch (aiError) {
            console.error('❌ AI background removal failed:', {
                error: aiError.message,
                name: aiError.name,
                stack: aiError.stack,
                code: aiError.code,
                originalName: req.file.originalname,
                model,
                outputFormat,
                processingTime: Date.now() - startTime
            });

            return res.status(500).json({
                success: false,
                message: 'AI background removal failed',
                error: aiError.message
            });
        }

        const processingTime = Date.now() - startTime;

        // Log memory usage after processing
        const memAfter = process.memoryUsage();
        console.log('📊 Memory after processing:', {
            rss: Math.round(memAfter.rss / 1024 / 1024) + 'MB',
            heapUsed: Math.round(memAfter.heapUsed / 1024 / 1024) + 'MB',
            heapTotal: Math.round(memAfter.heapTotal / 1024 / 1024) + 'MB',
            external: Math.round(memAfter.external / 1024 / 1024) + 'MB'
        });

        // Validate processed buffer
        if (!processedBuffer || processedBuffer.length === 0) {
            console.error('❌ AI processing resulted in empty buffer');
            return res.status(500).json({
                success: false,
                message: 'AI processing failed to generate output'
            });
        }

        // Generate filename
        const filename = `${originalName}_no_bg.png`;
        const compressionRatio = ((originalBuffer.length - processedBuffer.length) / originalBuffer.length * 100).toFixed(2);

        console.log('✅ AI background removal SUCCESS (STANDALONE):', {
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
            'Content-Type': 'image/png',
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length': processedBuffer.length.toString(),
            'X-Original-Filename': req.file.originalname,
            'X-Original-Size': originalBuffer.length.toString(),
            'X-Processed-Size': processedBuffer.length.toString(),
            'X-Compression-Ratio': compressionRatio + '%',
            'X-Processing-Time': processingTime.toString(),
            'X-AI-Model': model,
            'X-Engine': 'imgly-background-removal-node'
        });

        // Send the processed image
        res.send(processedBuffer);

    } catch (error) {
        console.error('💥 OUTER ERROR in background removal:', {
            error: error.message,
            name: error.name,
            stack: error.stack,
            timestamp: new Date().toISOString()
        });

        return res.status(500).json({
            success: false,
            message: 'Failed to process image',
            error: error.message
        });
    } finally {
        // Always clean up state
        console.log('🧹 Cleaning up processing state...');
        isProcessing = false;
        processingStartTime = null;

        // Force garbage collection if available
        if (global.gc) {
            global.gc();
            console.log('🗑️  Forced garbage collection');
        }

        console.log('🎯 <== BACKGROUND REMOVAL REQUEST COMPLETED (STANDALONE)');
    }

});

// Health check endpoint
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
 * Device capability assessment endpoint
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

        console.log('📋 Device capability check:', {
            userAgent: userAgent?.substring(0, 100),
            hardwareConcurrency,
            deviceMemory,
            connection: connection?.effectiveType,
            maxTouchPoints,
            hasWebGL: !!webgl,
            hasCanvas: !!canvas,
            imageSize
        });

        // Calculate capability score
        let capabilityScore = 0;
        const requirements = { minimumScore: 100, factors: {} };

        // CPU cores (25 points)
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
            requirements.factors.cpu = 'poor';
        }

        // Device memory (30 points)
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
            requirements.factors.memory = 'poor';
        }

        // Browser (20 points)
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
            } else {
                capabilityScore += 5;
                requirements.factors.browser = 'mobile';
            }
        }

        // WebGL (15 points)
        if (webgl?.webgl2) {
            capabilityScore += 15;
            requirements.factors.webgl = 'webgl2';
        } else if (webgl?.webgl1) {
            capabilityScore += 10;
            requirements.factors.webgl = 'webgl1';
        } else {
            requirements.factors.webgl = 'none';
        }

        // Network (10 points)
        if (connection?.effectiveType === '4g') {
            capabilityScore += 10;
            requirements.factors.network = 'fast';
        } else if (connection?.effectiveType === '3g') {
            capabilityScore += 5;
            requirements.factors.network = 'moderate';
        } else {
            capabilityScore += 5;
            requirements.factors.network = 'unknown';
        }

        // Image size penalty
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

        const useClientSide = capabilityScore >= requirements.minimumScore;
        const result = {
            capabilityScore,
            recommendation: useClientSide ? 'client' : 'server',
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

        console.log('✅ Device capability assessment result:', {
            score: capabilityScore,
            recommendation: result.recommendation,
            useClientSide,
            factors: requirements.factors
        });

        return sendSuccess(res, 'Device capability assessed', result);

    } catch (error) {
        console.error('💥 Device capability check error:', {
            error: error.message,
            stack: error.stack
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
 * API information endpoint
 */
router.get('/info', basicRateLimit, (req, res) => {
    const info = {
        service: 'AI Background Removal API',
        version: '1.0.0',
        engine: '@imgly/background-removal-node',
        supportedModels: ['small', 'medium', 'large'],
        supportedFormats: {
            input: ['jpg', 'jpeg', 'png', 'webp'],
            output: ['png', 'jpg', 'jpeg', 'webp']
        },
        endpoints: {
            remove_background: 'POST /api/ai/remove-background',
            check_device_capability: 'POST /api/ai/check-device-capability',
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