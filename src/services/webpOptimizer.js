const sharp = require('sharp');
const logger = require('../utils/logger');

/*
 * WebP re-compression that respects what came in, with automatic quality.
 *
 * A lossless WebP (screenshots, logos, anything converted from PNG) re-encoded
 * as lossy comes back larger AND softer — a 29 KB lossless screenshot became a
 * 71 KB lossy one. So: lossless input -> near-lossless at the requested
 * quality (edges stay pixel-exact), or plain lossless if that is smaller;
 * lossy input -> lossy at the requested quality. Never return output larger
 * than the input.
 */

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

const SSIM_TARGET = 0.99;
const LOSSY_Q_MIN = 60;
const LOSSY_Q_MAX = 90;
const LOSSY_Q_FALLBACK = 80;
const NEAR_LOSSLESS_LEVELS = [40, 60, 80]; // lower = more smoothing = smaller
const SEARCH_EFFORT = 4; // trial encodes: quality decisions barely change, ~2x faster
const FINAL_EFFORT = 6;

async function lumaPlane(buffer) {
  const { data, info } = await sharp(buffer)
    .rotate()
    .resize({ width: 1024, withoutEnlargement: true })
    .flatten({ background: '#ffffff' })
    .grayscale()
    .raw()
    .toBuffer({ resolveWithObject: true });
  return { d: data, w: info.width, h: info.height };
}

// Mean SSIM over 8x8 windows (stride 4) on the luma plane.
function ssim(a, b) {
  if (a.w !== b.w || a.h !== b.h) return 0;
  const C1 = (0.01 * 255) ** 2;
  const C2 = (0.03 * 255) ** 2;
  let total = 0;
  let n = 0;
  for (let y = 0; y + 8 <= a.h; y += 4) {
    for (let x = 0; x + 8 <= a.w; x += 4) {
      let ma = 0;
      let mb = 0;
      for (let j = 0; j < 8; j++) {
        const row = (y + j) * a.w + x;
        for (let i = 0; i < 8; i++) {
          ma += a.d[row + i];
          mb += b.d[row + i];
        }
      }
      ma /= 64;
      mb /= 64;
      let va = 0;
      let vb = 0;
      let cov = 0;
      for (let j = 0; j < 8; j++) {
        const row = (y + j) * a.w + x;
        for (let i = 0; i < 8; i++) {
          const da = a.d[row + i] - ma;
          const db = b.d[row + i] - mb;
          va += da * da;
          vb += db * db;
          cov += da * db;
        }
      }
      va /= 63;
      vb /= 63;
      cov /= 63;
      total += ((2 * ma * mb + C1) * (2 * cov + C2)) / ((ma * ma + mb * mb + C1) * (va + vb + C2));
      n++;
    }
  }
  return n ? total / n : 1;
}

const encodeLossy = (buffer, quality, effort) =>
  sharp(buffer).rotate().webp({ quality, effort }).toBuffer();
const encodeNearLossless = (buffer, quality, effort) =>
  sharp(buffer).rotate().webp({ nearLossless: true, quality, effort }).toBuffer();
const encodeLossless = (buffer, effort) =>
  sharp(buffer).rotate().webp({ lossless: true, effort }).toBuffer();

/**
 * Automatic mode: the lowest setting that still measures visually equivalent
 * (luma SSIM >= 0.99) to the input, searched at a lower effort, then encoded
 * once at full effort.
 */
async function autoLossy(buffer) {
  const source = await lumaPlane(buffer);
  const cache = new Map();
  const tryQ = async (q) => {
    if (!cache.has(q)) {
      const out = await encodeLossy(buffer, q, SEARCH_EFFORT);
      cache.set(q, ssim(source, await lumaPlane(out)));
    }
    return cache.get(q);
  };
  let lo = LOSSY_Q_MIN;
  let hi = LOSSY_Q_MAX;
  let quality = null;
  let score = null;
  while (lo <= hi) {
    const mid = Math.round((lo + hi) / 2);
    const s = await tryQ(mid);
    if (s >= SSIM_TARGET) {
      quality = mid;
      score = s;
      hi = mid - 1;
    } else {
      lo = mid + 1;
    }
  }
  if (quality === null) {
    quality = LOSSY_Q_FALLBACK;
    score = await tryQ(quality);
  }
  return { out: await encodeLossy(buffer, quality, FINAL_EFFORT), quality, ssim: score, mode: 'lossy' };
}

async function autoLossless(buffer) {
  const source = await lumaPlane(buffer);
  let chosen = null;
  for (const level of NEAR_LOSSLESS_LEVELS) {
    const out = await encodeNearLossless(buffer, level, SEARCH_EFFORT);
    const s = ssim(source, await lumaPlane(out));
    if (s >= SSIM_TARGET) {
      chosen = { quality: level, ssim: s };
      break;
    }
  }
  const pure = await encodeLossless(buffer, FINAL_EFFORT);
  if (!chosen) return { out: pure, quality: 100, ssim: 1, mode: 'lossless' };
  const near = await encodeNearLossless(buffer, chosen.quality, FINAL_EFFORT);
  return pure.length <= near.length
    ? { out: pure, quality: 100, ssim: 1, mode: 'lossless' }
    : { out: near, quality: chosen.quality, ssim: chosen.ssim, mode: 'near-lossless' };
}

/**
 * @param {Buffer} buffer  source WebP
 * @param {{quality?: number}} [options]  explicit quality disables the search
 * @returns {Promise<{buffer: Buffer, quality: number, ssim: number|null, mode: string, originalKept: boolean}>}
 */
async function compressWebp(buffer, options = {}) {
  const started = Date.now();
  const lossless = isLosslessWebp(buffer);
  let result;

  if (options.quality) {
    const quality = options.quality;
    if (lossless) {
      const [near, pure] = await Promise.all([
        encodeNearLossless(buffer, quality, FINAL_EFFORT),
        encodeLossless(buffer, FINAL_EFFORT)
      ]);
      result = pure.length <= near.length
        ? { out: pure, quality: 100, ssim: null, mode: 'lossless' }
        : { out: near, quality, ssim: null, mode: 'near-lossless' };
    } else {
      result = { out: await encodeLossy(buffer, quality, FINAL_EFFORT), quality, ssim: null, mode: 'lossy' };
    }
  } else {
    result = lossless ? await autoLossless(buffer) : await autoLossy(buffer);
  }

  const ms = Date.now() - started;
  const { out, quality, ssim: score, mode } = result;
  if (out.length >= buffer.length) {
    logger.info('WebP compression kept original (no smaller result)', {
      originalSize: buffer.length, attemptedSize: out.length, quality, mode, ms
    });
    return { buffer, quality, ssim: score, mode: 'original-kept', originalKept: true };
  }

  logger.info('WebP compression completed', {
    originalSize: buffer.length, compressedSize: out.length, quality, mode,
    ssim: score === null ? undefined : Number(score.toFixed(4)), ms
  });
  return { buffer: out, quality, ssim: score, mode, originalKept: false };
}

module.exports = { compressWebp, isLosslessWebp, SSIM_TARGET };
