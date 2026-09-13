const sharp = require('sharp');
const logger = require('../utils/logger');

/*
 * JPEG compression with a perceptual target instead of a fixed quality.
 *
 * mozjpeg (via Sharp) already does progressive scans, trellis quantisation and
 * optimal Huffman tables, so encoder-side there is nothing left to squeeze.
 * What changes the outcome is *which* quality each image gets: a phone photo
 * can drop to q70 invisibly, a flat gradient needs q85 to avoid banding, and an
 * already-compressed q70 JPEG re-encoded at q75 only gets bigger.
 *
 * We binary-search the lowest quality whose luma SSIM against the source stays
 * above SSIM_TARGET (measured on a <=1024 px grayscale copy, so the metric is
 * cheap), then never return a result larger than the input. Calibrated against
 * TinyJPG: on a 1.18 MB q92 photo TinyJPG returns 348 KB, this returns ~359 KB.
 */
const SSIM_TARGET = 0.99;
const Q_MIN = 60;
const Q_MAX = 85;
const Q_FALLBACK = 75;
const ENCODE_OPTIONS = { mozjpeg: true, chromaSubsampling: '4:2:0' };

async function lumaPlane(buffer) {
  const { data, info } = await sharp(buffer)
    .rotate()
    .resize({ width: 1024, withoutEnlargement: true })
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

async function encode(buffer, quality) {
  return sharp(buffer).rotate().jpeg({ quality, ...ENCODE_OPTIONS }).toBuffer();
}

/**
 * @param {Buffer} buffer  source JPEG
 * @param {{quality?: number}} [options]  explicit quality disables the search
 * @returns {Promise<{buffer: Buffer, quality: number|null, ssim: number|null, originalKept: boolean, strategy: string}>}
 */
async function compressJpeg(buffer, options = {}) {
  const started = Date.now();

  if (options.quality) {
    const out = await encode(buffer, options.quality);
    return finish(buffer, out, options.quality, null, 'fixed-quality', started);
  }

  const source = await lumaPlane(buffer);
  const cache = new Map();
  const tryQuality = async (q) => {
    if (!cache.has(q)) {
      const out = await encode(buffer, q);
      cache.set(q, { out, ssim: ssim(source, await lumaPlane(out)) });
    }
    return cache.get(q);
  };

  // Binary search for the lowest quality that still meets the target.
  let lo = Q_MIN;
  let hi = Q_MAX;
  let best = null;
  while (lo <= hi) {
    const mid = Math.round((lo + hi) / 2);
    const r = await tryQuality(mid);
    if (r.ssim >= SSIM_TARGET) {
      best = { q: mid, ...r };
      hi = mid - 1;
    } else {
      lo = mid + 1;
    }
  }
  if (!best) {
    // Even Q_MAX misses the target: the source is noisy or gradient-heavy and
    // SSIM cannot be satisfied at any sane size. Fall back to the historical
    // default rather than shipping a Q_MAX file several times larger.
    const r = await tryQuality(Q_FALLBACK);
    best = { q: Q_FALLBACK, ...r };
  }

  return finish(buffer, best.out, best.q, best.ssim, 'ssim-target', started);
}

function finish(input, out, quality, ssimValue, strategy, started) {
  const ms = Date.now() - started;
  if (out.length >= input.length) {
    logger.info('JPEG compression kept original (no smaller result)', {
      originalSize: input.length, attemptedSize: out.length, quality, ms
    });
    return { buffer: input, quality, ssim: ssimValue, originalKept: true, strategy: 'original-kept' };
  }
  logger.info('JPEG compression completed', {
    originalSize: input.length, compressedSize: out.length, quality,
    ssim: ssimValue === null ? undefined : Number(ssimValue.toFixed(4)), strategy, ms
  });
  return { buffer: out, quality, ssim: ssimValue, originalKept: false, strategy };
}

module.exports = { compressJpeg, SSIM_TARGET, Q_MIN, Q_MAX, Q_FALLBACK };
