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