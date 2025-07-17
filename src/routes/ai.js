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
const uploadImage = multer({
    storage: multer.diskStorage({
        destination: function (req, file, cb) {
            const uploadDir = path.join(__dirname, '..', '..', 'uploads');
            fs.mkdirSync(uploadDir, { recursive: true });
            cb(null, uploadDir);
        },
        filename: function (req, file, cb) {
            // Generate unique filename with proper extension
            const ext = path.extname(file.originalname);
            const filename = `upload_${Date.now()}_${Math.random().toString(36).substr(2, 9)}${ext}`;
            cb(null, filename);
        }
    }),
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

// Processing state tracking
let isProcessing = false;
let processingStartTime = null;

/**
 * POST /api/ai/remove-background
 * Remove background from image using AI
 */
router.post('/remove-background', enhancedSecurityWithRateLimit(basicRateLimit), uploadImage.single('file'), async (req, res) => {
     try {
        console.log(req.file.path);
        const imagePath = req.file.path; // Replace with actual test image
        if (!fs.existsSync(imagePath)) {
            console.error('❌ Test image not found. Please provide a test image at:', imagePath);
            return sendError(res, 'Test image not found.', 400);
        }

        const imageBuffer = fs.readFileSync(imagePath);

        const getMimeType = (filePath) => {
            const ext = filePath.toLowerCase().split('.').pop();
            switch (ext) {
                case 'jpg':
                case 'jpeg':
                    return 'image/jpeg';
                case 'png':
                    return 'image/png';
                case 'webp':
                    return 'image/webp';
                default:
                    return 'image/jpeg';
            }
        };

        const mimeType = getMimeType(imagePath);

        const { Blob } = require('buffer');
        const blob = new Blob([imageBuffer], { type: mimeType });

        console.log('📁 Image loaded:', {
            size: imageBuffer.length,
            mimeType: mimeType,
            blobSize: blob.size
        });

        console.log('🔧 Testing with minimal config...');

        const result = await removeBackground(blob, {
            model: 'small',
            debug: true,
            output: {
                format: 'image/png',
                quality: 1.0
            }
        });

        console.log('✅ Success! Result:', {
            type: typeof result,
            length: result?.length || result?.byteLength,
            constructor: result?.constructor?.name
        });

        let outputBuffer;
        if (Buffer.isBuffer(result)) {
            outputBuffer = result;
        } else if (result instanceof Uint8Array) {
            outputBuffer = Buffer.from(result);
        } else if (result instanceof ArrayBuffer) {
            outputBuffer = Buffer.from(result);
        } else {
            outputBuffer = Buffer.from(await result.arrayBuffer());
        }

        const filename = 'test-output.png';

        // === ✅ KEEPING THE ORIGINAL RESPONSE LOGIC HERE ===
        res.set({
            'Content-Type': 'image/png',
            'Content-Disposition': `attachment; filename="${filename}"`,
            'Content-Length': outputBuffer.length.toString(),
            'X-Original-Filename': 'test-image.jpg',
            'X-Original-Size': imageBuffer.length.toString(),
            'X-Processed-Size': outputBuffer.length.toString(),
            'X-Compression-Ratio': ((imageBuffer.length - outputBuffer.length) / imageBuffer.length * 100).toFixed(2) + '%',
            'X-Processing-Time': 'test-mode',
            'X-AI-Model': 'small',
            'X-Output-Format': 'png',
            'X-Output-Quality': '1.0',
            'X-Engine': 'imgly-background-removal-node'
        });

        res.send(outputBuffer);

    } catch (error) {
        console.error('💥 Error during background removal test:', error);
        return sendError(res, 'Internal Server Error', 500, {
            details: process.env.NODE_ENV === 'development' ? error.message : undefined
        });
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