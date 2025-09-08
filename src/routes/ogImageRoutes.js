const express = require('express');
const router = express.Router();
const { body, query, validationResult } = require('express-validator');
const rateLimit = require('express-rate-limit');
const { generateOGImage, getTemplates, getCacheKey } = require('../services/ogImageService');
const redis = require('../config/redis');

// Rate limiter specific for OG image generation
const ogRateLimit = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 requests per minute
  message: 'Too many image generation requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Validation middleware
const validateOGParams = [
  query('title').optional().isString().isLength({ max: 100 }).trim(),
  query('subtitle').optional().isString().isLength({ max: 200 }).trim(),
  query('template').optional().isIn(['minimal', 'gradient', 'modern', 'tech', 'bold']),
  query('bgColor').optional().matches(/^#[0-9A-F]{6}$/i),
  query('textColor').optional().matches(/^#[0-9A-F]{6}$/i),
  query('width').optional().isInt({ min: 200, max: 2000 }).toInt(),
  query('height').optional().isInt({ min: 200, max: 2000 }).toInt(),
  query('format').optional().isIn(['png', 'jpeg', 'jpg', 'webp']),
  query('alignment').optional().isIn(['left', 'center', 'right']),
  query('padding').optional().isInt({ min: 0, max: 200 }).toInt(),
];

/**
 * Generate OG image with caching
 */
async function generateWithCache(params, res) {
  const cacheKey = getCacheKey(params);
  
  try {
    // Check Redis cache
    if (redis && redis.isReady) {
      const cached = await redis.getBuffer(cacheKey);
      if (cached) {
        res.set('X-Cache', 'HIT');
        return cached;
      }
    }
  } catch (error) {
    console.error('Redis cache error:', error);
  }

  // Generate new image
  const result = await generateOGImage(params);
  
  // Cache the result (10 minutes for preview, 24 hours for final)
  if (redis && redis.isReady) {
    try {
      const ttl = params.final ? 86400 : 600;
      await redis.setex(cacheKey, ttl, result.buffer);
    } catch (error) {
      console.error('Redis cache set error:', error);
    }
  }

  res.set('X-Cache', 'MISS');
  return result.buffer;
}

/**
 * GET /api/og-image/preview
 * Generate preview OG image
 */
router.get('/preview', ogRateLimit, validateOGParams, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const params = {
      title: req.query.title || 'Preview',
      subtitle: req.query.subtitle,
      template: req.query.template || 'minimal',
      bgColor: req.query.bgColor,
      bgGradient: req.query.bgGradient ? JSON.parse(req.query.bgGradient) : undefined,
      textColor: req.query.textColor,
      fontSize: req.query.fontSize ? JSON.parse(req.query.fontSize) : undefined,
      width: req.query.width || 1200,
      height: req.query.height || 630,
      format: req.query.format || 'png',
      alignment: req.query.alignment || 'center',
      padding: req.query.padding || 60,
    };

    const imageBuffer = await generateWithCache(params, res);
    const mimeType = `image/${params.format === 'jpg' ? 'jpeg' : params.format}`;

    res.set({
      'Content-Type': mimeType,
      'Cache-Control': 'public, max-age=3600',
    });

    res.send(imageBuffer);
  } catch (error) {
    console.error('OG preview generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate image',
      message: error.message 
    });
  }
});

/**
 * GET /api/og-image/download
 * Generate and download OG image
 */
router.get('/download', ogRateLimit, validateOGParams, async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const params = {
      title: req.query.title || 'OpenGraph Image',
      subtitle: req.query.subtitle,
      template: req.query.template || 'minimal',
      bgColor: req.query.bgColor,
      bgGradient: req.query.bgGradient ? JSON.parse(req.query.bgGradient) : undefined,
      textColor: req.query.textColor,
      fontSize: req.query.fontSize ? JSON.parse(req.query.fontSize) : undefined,
      width: req.query.width || 1200,
      height: req.query.height || 630,
      format: req.query.format || 'png',
      alignment: req.query.alignment || 'center',
      padding: req.query.padding || 60,
      final: true, // Mark as final for longer cache
    };

    const imageBuffer = await generateWithCache(params, res);
    const mimeType = `image/${params.format === 'jpg' ? 'jpeg' : params.format}`;
    const filename = `og-image-${Date.now()}.${params.format}`;

    res.set({
      'Content-Type': mimeType,
      'Content-Disposition': `attachment; filename="${filename}"`,
      'Cache-Control': 'public, max-age=86400',
    });

    res.send(imageBuffer);
  } catch (error) {
    console.error('OG download generation error:', error);
    res.status(500).json({ 
      error: 'Failed to generate image',
      message: error.message 
    });
  }
});

/**
 * GET /api/og-image/templates
 * Get available templates
 */
router.get('/templates', async (req, res) => {
  try {
    const templates = getTemplates();
    res.json({
      success: true,
      templates,
      platformSizes: [
        { id: 'og-standard', width: 1200, height: 630, name: 'Standard OG (Facebook, LinkedIn)' },
        { id: 'twitter-large', width: 1200, height: 675, name: 'Twitter Summary Card Large' },
        { id: 'twitter-small', width: 1200, height: 600, name: 'Twitter Summary Card' },
        { id: 'instagram-square', width: 1080, height: 1080, name: 'Instagram Square' },
        { id: 'pinterest', width: 1000, height: 1500, name: 'Pinterest Pin' },
      ],
    });
  } catch (error) {
    console.error('Error fetching templates:', error);
    res.status(500).json({ 
      error: 'Failed to fetch templates',
      message: error.message 
    });
  }
});

/**
 * GET /api/og/:encodedParams
 * Dynamic OG image URL for sharing
 */
router.get('/:encodedParams', async (req, res) => {
  try {
    // Decode parameters from URL (handle base64url encoding)
    const base64 = req.params.encodedParams.replace(/-/g, '+').replace(/_/g, '/');
    const decoded = Buffer.from(base64, 'base64').toString('utf-8');
    const params = JSON.parse(decoded);

    // Validate basic params
    if (!params.title) {
      return res.status(400).json({ error: 'Title is required' });
    }

    const imageParams = {
      title: params.title,
      subtitle: params.subtitle,
      template: params.template || 'minimal',
      bgColor: params.bgColor,
      bgGradient: params.bgGradient,
      textColor: params.textColor,
      fontSize: params.fontSize,
      width: params.width || 1200,
      height: params.height || 630,
      format: params.format || 'png',
      alignment: params.alignment || 'center',
      padding: params.padding || 60,
      final: true,
    };

    const imageBuffer = await generateWithCache(imageParams, res);
    const mimeType = `image/${imageParams.format === 'jpg' ? 'jpeg' : imageParams.format}`;

    res.set({
      'Content-Type': mimeType,
      'Cache-Control': 'public, max-age=86400',
    });

    res.send(imageBuffer);
  } catch (error) {
    console.error('Dynamic OG generation error:', error);
    
    // Generate fallback image
    try {
      const fallback = await generateOGImage({
        title: 'OpenGraph Image',
        subtitle: 'Generated with Toolsana',
        template: 'minimal',
      });
      res.type('image/png').send(fallback.buffer);
    } catch (fallbackError) {
      res.status(500).json({ error: 'Failed to generate image' });
    }
  }
});

module.exports = router;