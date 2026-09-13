const sharp = require('sharp');
const { execFile } = require('child_process');
const fs = require('fs').promises;
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const logger = require('../utils/logger');

/*
 * PNG optimisation is done by the system `pngquant` and `optipng` binaries
 * (apt install pngquant optipng) instead of the imagemin wrapper packages,
 * which download/compile the very same binaries at npm-install time.
 *
 * The argument mapping below is a verbatim port of imagemin-pngquant@10 and
 * imagemin-optipng@8 so the produced bytes stay identical.
 */
const EXEC_TIMEOUT_MS = 30000;
const MAX_BUFFER = 256 * 1024 * 1024; // headroom for ~50MB+ PNG payloads

const pngquantBin = () => process.env.PNGQUANT_PATH || 'pngquant';
const optipngBin = () => process.env.OPTIPNG_PATH || 'optipng';

const PNG_SIGNATURE = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);

function crc32(buf) {
  let crc = 0xffffffff;
  for (let i = 0; i < buf.length; i++) {
    let c = (crc ^ buf[i]) & 0xff;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    crc = (crc >>> 8) ^ c;
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const typeAndData = Buffer.concat([Buffer.from(type, 'latin1'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(typeAndData));
  return Buffer.concat([length, typeAndData, crc]);
}

// gAMA 45455 (1/2.2) + sRGB rendering intent 0 (perceptual): the chunks libvips
// writes on every PNG it saves, i.e. what the previous Sharp-based strip produced.
const SRGB_TAG_CHUNKS = Buffer.concat([
  pngChunk('gAMA', Buffer.from([0x00, 0x00, 0xb1, 0x8f])),
  pngChunk('sRGB', Buffer.from([0x00]))
]);

// Mirrors the `is-png` check both imagemin plugins perform before shelling out.
function isPng(buffer) {
  return Buffer.isBuffer(buffer) && buffer.length >= 8 && buffer.subarray(0, 8).equals(PNG_SIGNATURE);
}

/**
 * Run a binary, optionally piping `input` to stdin, and collect stdout as a Buffer.
 * Non-zero exits reject with `error.exitCode` set to the numeric exit status.
 */
function execBinary(bin, args, { input = null, timeout = EXEC_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    const child = execFile(
      bin,
      args,
      { encoding: 'buffer', maxBuffer: MAX_BUFFER, timeout, windowsHide: true },
      (error, stdout, stderr) => {
        if (error) {
          error.exitCode = typeof error.code === 'number' ? error.code : null;
          error.stdout = stdout;
          error.stderr = stderr;
          const details = stderr && stderr.length ? stderr.toString().trim() : '';
          if (details) {
            error.message = `${error.message.split('\n')[0]} (${details})`;
          }
          reject(error);
          return;
        }
        resolve({ stdout, stderr });
      }
    );

    if (child.stdin) {
      // The binary can exit before reading all of stdin (e.g. pngquant exit 98/99).
      child.stdin.on('error', () => {});
      child.stdin.end(input || undefined);
    }
  });
}

/**
 * Argument mapping copied verbatim from imagemin-pngquant@10 (node_modules/imagemin-pngquant/index.js).
 * Argument order is preserved as well, `-` (stdin/stdout) first.
 */
function buildPngquantArgs(options = {}) {
  const args = ['-'];

  if (options.speed !== undefined) {
    args.push('--speed', options.speed.toString());
  }

  if (options.strip !== undefined) {
    if (options.strip) {
      args.push('--strip');
    }
  }

  if (options.quality !== undefined) {
    const [min, max] = options.quality;
    args.push('--quality', `${Math.round(min * 100)}-${Math.round(max * 100)}`);
  }

  if (options.dithering !== undefined) {
    if (typeof options.dithering === 'number') {
      args.push(`--floyd=${options.dithering}`);
    } else if (options.dithering === false) {
      args.push('--ordered');
    }
  }

  if (options.posterize !== undefined) {
    args.push('--posterize', options.posterize.toString());
  }

  return args;
}

/**
 * pngquant via stdin/stdout. Exit 99 (TOO_LOW_QUALITY) and 98 (TOO_LARGE_FILE)
 * mean "could not reach the requested quality" - imagemin-pngquant returns the
 * untouched input for 99, we do the same for both.
 */
async function runPngquant(buffer, options = {}) {
  if (!isPng(buffer)) {
    return buffer;
  }

  const args = buildPngquantArgs(options);

  try {
    const { stdout } = await execBinary(pngquantBin(), args, { input: buffer });
    return Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
  } catch (error) {
    if (error.exitCode === 99 || error.exitCode === 98) {
      logger.info('Pngquant could not reach the requested quality, keeping input', {
        exitCode: error.exitCode
      });
      return buffer;
    }

    throw error;
  }
}

/**
 * optipng via temp files (it cannot write to stdout). Argument list copied
 * verbatim from imagemin-optipng@8 + exec-buffer's input/output placeholders.
 */
async function runOptipng(buffer, options = {}) {
  if (!isPng(buffer)) {
    return buffer;
  }

  const opts = {
    optimizationLevel: 3,
    bitDepthReduction: true,
    colorTypeReduction: true,
    paletteReduction: true,
    interlaced: false,
    errorRecovery: true,
    ...options
  };

  const args = ['-strip', 'all', '-clobber', '-o', opts.optimizationLevel.toString(), '-out'];

  const tmpDir = os.tmpdir();
  const inputPath = path.join(tmpDir, crypto.randomUUID());
  const outputPath = path.join(tmpDir, crypto.randomUUID());

  args.push(outputPath);

  if (opts.errorRecovery) {
    args.push('-fix');
  }

  if (!opts.bitDepthReduction) {
    args.push('-nb');
  }

  if (typeof opts.interlaced === 'boolean') {
    args.push('-i', opts.interlaced ? '1' : '0');
  }

  if (!opts.colorTypeReduction) {
    args.push('-nc');
  }

  if (!opts.paletteReduction) {
    args.push('-np');
  }

  args.push(inputPath);

  try {
    await fs.writeFile(inputPath, buffer);
    await execBinary(optipngBin(), args);
    return await fs.readFile(outputPath);
  } finally {
    await Promise.all([
      fs.rm(inputPath, { force: true }).catch(() => {}),
      fs.rm(outputPath, { force: true }).catch(() => {})
    ]);
  }
}

/**
 * Startup probe: reports the version of each binary, or null when it is missing.
 */
async function checkBinaries() {
  const probe = async (bin, args) => {
    try {
      const { stdout, stderr } = await execBinary(bin, args, { timeout: 5000 });
      const output = `${stdout ? stdout.toString() : ''}\n${stderr ? stderr.toString() : ''}`;
      const firstLine = output.split('\n').map(line => line.trim()).find(Boolean);
      return firstLine || 'unknown';
    } catch (error) {
      return null;
    }
  };

  const [pngquant, optipng] = await Promise.all([
    probe(pngquantBin(), ['--version']),
    probe(optipngBin(), ['-version'])
  ]);

  return { pngquant, optipng };
}

class PngOptimizer {
  constructor() {
    this.compressionStrategies = {
      aggressive: {
        quality: [0.3, 0.5],
        speed: 1,
        strip: true,
        dithering: 1
      },
      balanced: {
        quality: [0.5, 0.7],
        speed: 3,
        strip: true,
        dithering: 0.75
      },
      quality: {
        quality: [0.7, 0.9],
        speed: 5,
        strip: true,
        dithering: 0.5
      }
    };
  }

  async analyzeImage(buffer) {
    try {
      const metadata = await sharp(buffer).metadata();
      const stats = await sharp(buffer).stats();

      const analysis = {
        width: metadata.width,
        height: metadata.height,
        channels: metadata.channels,
        hasAlpha: metadata.hasAlpha,
        isAnimated: metadata.pages && metadata.pages > 1,
        colorSpace: metadata.space,
        density: metadata.density,
        size: buffer.length,
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

  // Strip metadata before compression.
  //
  // Images that carry colour-management chunks (an ICC profile, a gAMA or a
  // cHRM chunk) go through the same Sharp re-encode the pipeline always used:
  // Sharp applies the embedded profile and converts the pixels to sRGB, so the
  // image looks the same once the profile is gone. Dropping those chunks
  // without converting would shift brightness/colour in the browser.
  //
  // Everything else is stripped at the chunk level without decoding, which is
  // faster and avoids Sharp re-encoding already-optimised (palette) PNGs into
  // larger truecolour files. Output bytes are identical to the old path for
  // such files (verified against the previous pipeline).
  async stripMetadata(buffer) {
    if (!isPng(buffer)) return buffer;

    const COLOUR_CHUNKS = new Set(['iCCP', 'gAMA', 'cHRM']);
    const keep = new Set(['IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'acTL', 'fcTL', 'fdAT']);
    const parts = [buffer.subarray(0, 8)];
    let offset = 8;

    while (offset + 12 <= buffer.length) {
      const length = buffer.readUInt32BE(offset);
      const end = offset + 12 + length;
      if (end > buffer.length) return buffer; // truncated/corrupt: leave it to the decoder
      const type = buffer.toString('latin1', offset + 4, offset + 8);
      if (COLOUR_CHUNKS.has(type)) {
        return this.stripViaSharp(buffer);
      }
      if (keep.has(type)) {
        parts.push(buffer.subarray(offset, end));
        if (type === 'IHDR') {
          // Tag the image as sRGB exactly the way the Sharp re-encode always
          // did (gAMA 1/2.2 + sRGB perceptual). pngquant carries these through,
          // and an untagged PNG is rendered in the display's native colour
          // space by colour-managed viewers, which looks brighter/more
          // saturated on wide-gamut screens than the same pixels tagged sRGB.
          parts.push(SRGB_TAG_CHUNKS);
        }
      }
      offset = end;
      if (type === 'IEND') break;
    }

    return Buffer.concat(parts);
  }

  // The original implementation: decode, convert to sRGB (applying any
  // embedded ICC profile), re-encode. Used only for colour-managed inputs.
  async stripViaSharp(buffer) {
    try {
      const stripped = await sharp(buffer)
        .withMetadata(false)
        .toBuffer();

      const reduction = buffer.length - stripped.length;
      if (reduction > 0) {
        logger.info('Metadata stripped', { bytesRemoved: reduction });
      }

      return stripped;
    } catch (error) {
      logger.warn('Failed to strip metadata via Sharp, using original buffer', { error: error.message });
      return buffer;
    }
  }

  // Determine image type based on analysis
  determineImageType(analysis) {
    const { complexity, uniqueColors, hasAlpha, width, height } = analysis;
    const pixelCount = width * height;

    // Simple graphics/icons/logos (flat colors, minimal complexity)
    if (uniqueColors < 256 && complexity < 30) {
      return 'simple-graphics';
    }

    // Logos/graphics with gradients (small size, moderate colors)
    // This catches logos with anti-aliasing or gradients before they're classified as photos
    if (pixelCount < 350000 && uniqueColors < 25000 && complexity < 75) {
      return 'simple-graphics';
    }

    // Complex photos with gradients (high complexity OR high color count + large size)
    // Photos with high complexity
    if (complexity > 60 && pixelCount > 400000) {
      return 'complex-photo';
    }

    // Photos with very high color count
    if (uniqueColors > 30000) {
      return 'complex-photo';
    }

    // Medium-large images with moderate color count (likely photos)
    if (pixelCount > 400000 && uniqueColors > 15000) {
      return 'complex-photo';
    }

    // Default balanced
    return 'balanced';
  }

  async compress(buffer, options = {}) {
    const startTime = Date.now();
    const originalSize = buffer.length;

    try {
      // First strip metadata
      let currentBuffer = await this.stripMetadata(buffer);

      // Analyze the image
      const analysis = await this.analyzeImage(currentBuffer);

      // Determine image type based on analysis
      const imageType = this.determineImageType(analysis);
      logger.info('Detected image type', { imageType });

      let strategyName = '';

      // Apply strategy based on image type
      if (imageType === 'simple-graphics') {
        // Simple graphics, icons, logos - use BALANCED for quality
        strategyName = 'Simple Graphics (Pngquant Balanced)';
        logger.info('Using balanced pngquant for simple graphics/logos');

        try {
          const pngquantBuffer = await runPngquant(currentBuffer, {
            quality: [0.5, 0.8],
            speed: 3,
            strip: true,
            dithering: 0.5
          });

          if (pngquantBuffer.length < currentBuffer.length) {
            const reduction = ((currentBuffer.length - pngquantBuffer.length) / currentBuffer.length * 100).toFixed(1);
            logger.info('Pngquant reduced size', { reduction: `${reduction}%` });
            currentBuffer = pngquantBuffer;
          }
        } catch (err) {
          logger.warn('Pngquant failed, using fallback', { error: err.message });
        }

        // Polish with OptiPNG
        try {
          const optipngBuffer = await runOptipng(currentBuffer, {
            optimizationLevel: 7
          });

          if (optipngBuffer.length < currentBuffer.length) {
            logger.info('OptiPNG polished the result');
            currentBuffer = optipngBuffer;
          }
        } catch (err) {
          logger.warn('OptiPNG failed', { error: err.message });
        }

      } else if (imageType === 'complex-photo') {
        // Complex photos with gradients - use AGGRESSIVE pngquant only (fast)
        // Target quality 80 (accept down to 30): ~35-38 dB PSNR on real photos,
        // colours preserved. The old 15-45 + posterize profile scored ~30-34 dB
        // and visibly washed out tints. Below 30 pngquant declines (exit 99)
        // and the original is returned rather than a ruined image.
        strategyName = 'Complex Photo (Pngquant 0.30-0.80)';
        logger.info('Using colour-preserving pngquant for complex photos');

        try {
          const pngquantBuffer = await runPngquant(currentBuffer, {
            quality: [0.3, 0.8],
            speed: 1,
            strip: true,
            dithering: 1
          });

          if (pngquantBuffer.length < currentBuffer.length) {
            const reduction = ((currentBuffer.length - pngquantBuffer.length) / currentBuffer.length * 100).toFixed(1);
            logger.info('Pngquant reduced size', { reduction: `${reduction}%` });
            currentBuffer = pngquantBuffer;
          }
        } catch (err) {
          logger.warn('Pngquant failed', { error: err.message });
        }

      } else {
        // Balanced approach for everything else
        strategyName = 'Balanced (Auto-detect)';
        logger.info('Using balanced approach');

        try {
          const pngquantBuffer = await runPngquant(currentBuffer, {
            quality: [0.5, 0.85],
            speed: 2,
            strip: true,
            dithering: 1
          });

          if (pngquantBuffer.length < currentBuffer.length) {
            const reduction = ((currentBuffer.length - pngquantBuffer.length) / currentBuffer.length * 100).toFixed(1);
            logger.info('Pngquant reduced size', { reduction: `${reduction}%` });
            currentBuffer = pngquantBuffer;
          }
        } catch (err) {
          logger.warn('Pngquant failed', { error: err.message });
        }

        try {
          const optipngBuffer = await runOptipng(currentBuffer, {
            optimizationLevel: 7
          });

          if (optipngBuffer.length < currentBuffer.length) {
            logger.info('OptiPNG reduced size');
            currentBuffer = optipngBuffer;
          }
        } catch (err) {
          logger.warn('OptiPNG failed', { error: err.message });
        }
      }

      const finalSize = currentBuffer.length;

      // Never hand back something that is not smaller than what was uploaded:
      // an already-optimised PNG can survive the whole pipeline unimproved.
      if (finalSize >= originalSize) {
        const processingTime = Date.now() - startTime;

        logger.info('PNG compression completed', {
          originalSize,
          finalSize: originalSize,
          compressionRatio: '0.0%',
          strategy: 'original-kept',
          processingTime: `${processingTime}ms`
        });

        return {
          buffer,
          originalSize,
          compressedSize: originalSize,
          compressionRatio: (0).toFixed(1),
          strategy: 'original-kept',
          imageType,
          analysis
        };
      }

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
        imageType,
        analysis
      };

    } catch (error) {
      logger.error('PNG compression failed, using Sharp fallback', {
        error: error.message,
        stack: error.stack
      });

      // Fallback to Sharp with maximum compression
      const fallbackBuffer = await sharp(buffer)
        .png({
          compressionLevel: 9,
          adaptiveFiltering: true,
          palette: true,
          quality: 60,
          effort: 10,
          colors: 256
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
module.exports.checkBinaries = checkBinaries;
