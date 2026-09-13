const sharp = require('sharp');
const logger = require('../utils/logger');

/*
 * WebP re-compression that respects what came in.
 *
 * A lossless WebP (screenshots, logos, anything converted from PNG) re-encoded
 * as lossy comes back larger AND softer — a 29 KB lossless screenshot became a
 * 71 KB lossy one. So: lossless input -> near-lossless at the requested
 * quality (edges stay pixel-exact), or plain lossless if that is smaller;
 * lossy input -> lossy at the requested quality. Never return output larger
 * than the input.
 */
const DEFAULT_QUALITY = 80;
const EFFORT = 6;

// RIFF/WEBP container: chunk tag at offset 12 is VP8 (lossy), VP8L (lossless)
// or VP8X (extended: walk the chunks to find the bitstream).
function isLosslessWebp(buffer) {
  if (buffer.length < 16 || buffer.toString('latin1', 8, 12) !== 'WEBP') return false;
  const tag = buffer.toString('latin1', 12, 16);
  if (tag === 'VP8L') return true;
  if (tag !== 'VP8X') return false;
  let offset = 30; // 12 + 'VP8X' + size (4) + 10-byte header
  while (offset + 8 <= buffer.length) {
    const chunk = buffer.toString('latin1', offset, offset + 4);
    const size = buffer.readUInt32LE(offset + 4);
    if (chunk === 'VP8L') return true;
    if (chunk === 'VP8 ') return false;
    offset += 8 + size + (size & 1);
  }
  return false;
}

/**
 * @param {Buffer} buffer  source WebP
 * @param {{quality?: number}} [options]
 * @returns {Promise<{buffer: Buffer, quality: number, mode: string, originalKept: boolean}>}
 */
async function compressWebp(buffer, options = {}) {
  const quality = options.quality ?? DEFAULT_QUALITY;
  const started = Date.now();
  const lossless = isLosslessWebp(buffer);
  let out;
  let mode;

  if (lossless) {
    const [near, pure] = await Promise.all([
      sharp(buffer).rotate().webp({ nearLossless: true, quality, effort: EFFORT }).toBuffer(),
      sharp(buffer).rotate().webp({ lossless: true, effort: EFFORT }).toBuffer()
    ]);
    if (pure.length <= near.length) {
      out = pure;
      mode = 'lossless';
    } else {
      out = near;
      mode = 'near-lossless';
    }
  } else {
    out = await sharp(buffer).rotate().webp({ quality, effort: EFFORT }).toBuffer();
    mode = 'lossy';
  }

  const ms = Date.now() - started;
  if (out.length >= buffer.length) {
    logger.info('WebP compression kept original (no smaller result)', {
      originalSize: buffer.length, attemptedSize: out.length, quality, mode, ms
    });
    return { buffer, quality, mode: 'original-kept', originalKept: true };
  }

  logger.info('WebP compression completed', {
    originalSize: buffer.length, compressedSize: out.length, quality, mode, ms
  });
  return { buffer: out, quality, mode, originalKept: false };
}

module.exports = { compressWebp, isLosslessWebp, DEFAULT_QUALITY };
