const satori = require('satori').default;
const sharp = require('sharp');
const path = require('path');
const fs = require('fs').promises;
const crypto = require('crypto');

// Cache for fonts
let fontsCache = null;

/**
 * Load fonts for Satori
 */
async function loadFonts() {
  if (fontsCache) return fontsCache;

  try {
    // For now, we'll use a system font approach
    // In production, you'd load actual font files
    fontsCache = [
      {
        name: 'Inter',
        data: Buffer.from(''), // Placeholder - will use default fonts
        weight: 400,
        style: 'normal',
      },
      {
        name: 'Inter',
        data: Buffer.from(''), // Placeholder
        weight: 700,
        style: 'normal',
      }
    ];

    return fontsCache;
  } catch (error) {
    console.error('Error loading fonts:', error);
    return [];
  }
}

/**
 * Generate cache key from parameters
 */
function getCacheKey(params) {
  const normalized = JSON.stringify(params, Object.keys(params).sort());
  return `og:${crypto.createHash('md5').update(normalized).digest('hex')}`;
}

/**
 * Convert hex color to RGB
 */
function hexToRgb(hex) {
  const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return result ? {
    r: parseInt(result[1], 16),
    g: parseInt(result[2], 16),
    b: parseInt(result[3], 16)
  } : { r: 0, g: 0, b: 0 };
}

/**
 * Create gradient string from gradient config
 */
function createGradient(gradient) {
  if (!gradient) return null;
  
  const { direction = '135deg', from = '#667eea', to = '#764ba2' } = gradient;
  return `linear-gradient(${direction}, ${from}, ${to})`;
}

/**
 * Get contrasting text color
 */
function getContrastColor(bgColor) {
  const rgb = hexToRgb(bgColor);
  const luminance = (0.299 * rgb.r + 0.587 * rgb.g + 0.114 * rgb.b) / 255;
  return luminance > 0.5 ? '#000000' : '#ffffff';
}

/**
 * Template renderers
 */
const templates = {
  minimal: (options) => ({
    type: 'div',
    props: {
      style: {
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: options.alignment || 'center',
        justifyContent: 'center',
        backgroundColor: options.bgColor || '#ffffff',
        padding: options.padding || 60,
        fontFamily: 'Inter, sans-serif',
      },
      children: [
        options.title && {
          type: 'h1',
          props: {
            style: {
              fontSize: options.fontSize?.title || 72,
              fontWeight: 700,
              color: options.textColor || getContrastColor(options.bgColor || '#ffffff'),
              margin: 0,
              lineHeight: 1.2,
              textAlign: options.alignment || 'center',
            },
            children: options.title,
          },
        },
        options.subtitle && {
          type: 'p',
          props: {
            style: {
              fontSize: options.fontSize?.subtitle || 32,
              color: options.textColor || getContrastColor(options.bgColor || '#ffffff'),
              opacity: 0.8,
              marginTop: 20,
              margin: 0,
              lineHeight: 1.4,
              textAlign: options.alignment || 'center',
            },
            children: options.subtitle,
          },
        },
      ].filter(Boolean),
    },
  }),

  gradient: (options) => ({
    type: 'div',
    props: {
      style: {
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: options.alignment || 'center',
        justifyContent: 'center',
        backgroundImage: createGradient(options.bgGradient) || 'linear-gradient(135deg, #667eea, #764ba2)',
        padding: options.padding || 60,
        fontFamily: 'Inter, sans-serif',
      },
      children: [
        options.title && {
          type: 'h1',
          props: {
            style: {
              fontSize: options.fontSize?.title || 80,
              fontWeight: 700,
              color: options.textColor || '#ffffff',
              margin: 0,
              lineHeight: 1.1,
              textAlign: options.alignment || 'center',
              textShadow: '0 2px 4px rgba(0,0,0,0.1)',
            },
            children: options.title,
          },
        },
        options.subtitle && {
          type: 'p',
          props: {
            style: {
              fontSize: options.fontSize?.subtitle || 36,
              color: options.textColor || '#ffffff',
              opacity: 0.95,
              marginTop: 24,
              margin: 0,
              lineHeight: 1.4,
              textAlign: options.alignment || 'center',
              textShadow: '0 1px 2px rgba(0,0,0,0.1)',
            },
            children: options.subtitle,
          },
        },
      ].filter(Boolean),
    },
  }),

  modern: (options) => ({
    type: 'div',
    props: {
      style: {
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        backgroundColor: options.bgColor || '#0f172a',
        padding: 0,
        fontFamily: 'Inter, sans-serif',
        position: 'relative',
      },
      children: [
        // Top accent bar
        {
          type: 'div',
          props: {
            style: {
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: 8,
              backgroundImage: 'linear-gradient(90deg, #3b82f6, #8b5cf6)',
            },
          },
        },
        // Main content
        {
          type: 'div',
          props: {
            style: {
              flex: 1,
              display: 'flex',
              flexDirection: 'column',
              alignItems: options.alignment || 'center',
              justifyContent: 'center',
              padding: options.padding || 80,
            },
            children: [
              options.title && {
                type: 'h1',
                props: {
                  style: {
                    fontSize: options.fontSize?.title || 76,
                    fontWeight: 700,
                    color: options.textColor || '#ffffff',
                    margin: 0,
                    lineHeight: 1.2,
                    textAlign: options.alignment || 'center',
                  },
                  children: options.title,
                },
              },
              options.subtitle && {
                type: 'p',
                props: {
                  style: {
                    fontSize: options.fontSize?.subtitle || 32,
                    color: options.textColor || '#94a3b8',
                    marginTop: 24,
                    margin: 0,
                    lineHeight: 1.4,
                    textAlign: options.alignment || 'center',
                  },
                  children: options.subtitle,
                },
              },
            ].filter(Boolean),
          },
        },
      ],
    },
  }),

  tech: (options) => ({
    type: 'div',
    props: {
      style: {
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: options.alignment || 'left',
        justifyContent: 'center',
        backgroundColor: '#000000',
        backgroundImage: 'radial-gradient(circle at 20% 50%, #1a1a2e 0%, #000000 50%)',
        padding: options.padding || 80,
        fontFamily: 'monospace',
        position: 'relative',
      },
      children: [
        // Terminal-like prompt
        {
          type: 'div',
          props: {
            style: {
              fontSize: 24,
              color: '#22c55e',
              marginBottom: 20,
              fontFamily: 'monospace',
            },
            children: '> _',
          },
        },
        options.title && {
          type: 'h1',
          props: {
            style: {
              fontSize: options.fontSize?.title || 72,
              fontWeight: 700,
              color: '#ffffff',
              margin: 0,
              lineHeight: 1.2,
              fontFamily: 'monospace',
            },
            children: options.title,
          },
        },
        options.subtitle && {
          type: 'p',
          props: {
            style: {
              fontSize: options.fontSize?.subtitle || 28,
              color: '#64748b',
              marginTop: 20,
              margin: 0,
              lineHeight: 1.4,
              fontFamily: 'monospace',
            },
            children: options.subtitle,
          },
        },
      ].filter(Boolean),
    },
  }),

  bold: (options) => ({
    type: 'div',
    props: {
      style: {
        width: '100%',
        height: '100%',
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: options.bgColor || '#dc2626',
        padding: options.padding || 60,
        fontFamily: 'Inter, sans-serif',
      },
      children: [
        options.title && {
          type: 'h1',
          props: {
            style: {
              fontSize: options.fontSize?.title || 96,
              fontWeight: 900,
              color: options.textColor || '#ffffff',
              margin: 0,
              lineHeight: 1,
              textAlign: 'center',
              textTransform: 'uppercase',
              letterSpacing: -2,
            },
            children: options.title,
          },
        },
        options.subtitle && {
          type: 'p',
          props: {
            style: {
              fontSize: options.fontSize?.subtitle || 32,
              fontWeight: 600,
              color: options.textColor || '#ffffff',
              opacity: 0.9,
              marginTop: 24,
              margin: 0,
              lineHeight: 1.3,
              textAlign: 'center',
              textTransform: 'uppercase',
              letterSpacing: 2,
            },
            children: options.subtitle,
          },
        },
      ].filter(Boolean),
    },
  }),
};

/**
 * Convert JSX-like structure to React elements for Satori
 */
function jsxToReact(jsx) {
  const React = {
    createElement: (type, props, ...children) => {
      return { type, props: { ...props, children: children.flat() } };
    }
  };

  if (!jsx) return null;
  if (typeof jsx === 'string') return jsx;
  if (Array.isArray(jsx)) return jsx.map(jsxToReact);
  
  const { type, props } = jsx;
  const { children, ...restProps } = props || {};
  
  return React.createElement(
    type,
    restProps,
    children ? jsxToReact(children) : null
  );
}

/**
 * Generate OG image
 */
async function generateOGImage(options) {
  try {
    // Set defaults
    const config = {
      width: options.width || 1200,
      height: options.height || 630,
      title: options.title || 'OpenGraph Image',
      subtitle: options.subtitle || '',
      template: options.template || 'minimal',
      bgColor: options.bgColor || '#ffffff',
      bgGradient: options.bgGradient,
      textColor: options.textColor,
      fontSize: options.fontSize || {},
      padding: options.padding || 60,
      alignment: options.alignment || 'center',
      format: options.format || 'png',
    };

    // Get template
    const templateFn = templates[config.template] || templates.minimal;
    const jsx = templateFn(config);
    const element = jsxToReact(jsx);

    // Load fonts
    const fonts = await loadFonts();

    // Generate SVG with Satori
    const svg = await satori(element, {
      width: config.width,
      height: config.height,
      fonts: fonts.length > 0 ? fonts : undefined,
    });

    // Convert SVG to image buffer using Sharp
    let imageBuffer = Buffer.from(svg);
    
    // Convert based on format
    if (config.format === 'png') {
      imageBuffer = await sharp(imageBuffer)
        .png({ quality: 90, compressionLevel: 9 })
        .toBuffer();
    } else if (config.format === 'jpeg' || config.format === 'jpg') {
      imageBuffer = await sharp(imageBuffer)
        .jpeg({ quality: 85, progressive: true })
        .toBuffer();
    } else if (config.format === 'webp') {
      imageBuffer = await sharp(imageBuffer)
        .webp({ quality: 85 })
        .toBuffer();
    }

    return {
      buffer: imageBuffer,
      mimeType: `image/${config.format === 'jpg' ? 'jpeg' : config.format}`,
      cacheKey: getCacheKey(config),
    };
  } catch (error) {
    console.error('Error generating OG image:', error);
    throw error;
  }
}

/**
 * Get available templates
 */
function getTemplates() {
  return Object.keys(templates).map(id => ({
    id,
    name: id.charAt(0).toUpperCase() + id.slice(1),
    description: getTemplateDescription(id),
  }));
}

function getTemplateDescription(id) {
  const descriptions = {
    minimal: 'Clean and simple design with centered text',
    gradient: 'Modern gradient background with bold typography',
    modern: 'Sleek dark theme with accent colors',
    tech: 'Developer-focused terminal style',
    bold: 'High-impact design with uppercase text',
  };
  return descriptions[id] || 'Custom template';
}

module.exports = {
  generateOGImage,
  getTemplates,
  getCacheKey,
};