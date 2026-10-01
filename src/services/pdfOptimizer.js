const { PDFDocument, PDFName, PDFRawStream } = require('pdf-lib');
const sharp = require('sharp');
const logger = require('../utils/logger');

/**
 * PDF compression by re-encoding the raster images embedded in the document.
 *
 * Why only images: a PDF's size is dominated by whatever it embeds. Scanned
 * documents and image-heavy brochures are almost entirely JPEG data, so
 * re-encoding those streams at a lower quality (and optionally downsampling
 * them) is where essentially all of the savings are. Text, vector artwork, and
 * font programs are already compressed efficiently and are deliberately left
 * untouched — rasterising them would shrink the file but destroy the text
 * layer, which is never an acceptable trade for a "compress" operation.
 *
 * Consequence to surface to users: a text-only PDF will barely shrink. That is
 * correct behaviour, not a failure.
 */

// Only DCTDecode streams are touched. Their stream contents are a complete
// JPEG file, so they can be handed straight to Sharp and written back. Other
// filters (FlateDecode in particular) hold raw samples whose interpretation
// depends on ColorSpace, BitsPerComponent, and Decode arrays — rebuilding those
// correctly is error-prone, and getting it wrong corrupts the page silently.
const RECOMPRESSIBLE_FILTER = 'DCTDecode';

const nameOf = (value) => (value ? value.toString().replace(/^\//, '') : null);

/**
 * Collects the image XObjects that are safe to re-encode.
 */
function findRecompressibleImages(pdfDoc) {
  const candidates = [];

  for (const [ref, obj] of pdfDoc.context.enumerateIndirectObjects()) {
    if (!(obj instanceof PDFRawStream)) continue;

    const dict = obj.dict;
    if (nameOf(dict.get(PDFName.of('Subtype'))) !== 'Image') continue;
    if (nameOf(dict.get(PDFName.of('Filter'))) !== RECOMPRESSIBLE_FILTER) continue;

    candidates.push({ ref, stream: obj, dict });
  }

  return candidates;
}

/**
 * Re-encodes one embedded JPEG. Returns null when the image should be left
 * exactly as it is.
 */
async function recompressImage(bytes, { quality, maxImageWidth }) {
  // The image dictionary's /ColorSpace (ICCBased, Separation, Lab, ...) decides
  // how the samples are rendered, not any ICC profile inside the JPEG. So the
  // samples must survive unchanged: no ICC -> sRGB transform (ignoreIcc) and
  // the same number of channels, so the original /ColorSpace stays valid.
  const metadata = await sharp(bytes, { ignoreIcc: true }).metadata();

  // Sharp converts CMYK to sRGB on encode, which would no longer agree with
  // the stream's /DeviceCMYK ColorSpace entry and would shift every colour on
  // the page. Not worth the risk for the size saved.
  if (metadata.space === 'cmyk') {
    return { skipped: 'cmyk' };
  }

  if (metadata.channels !== 1 && metadata.channels !== 3) {
    return { skipped: 'channels' };
  }

  let pipeline = sharp(bytes, { ignoreIcc: true });
  const shouldResize = Boolean(maxImageWidth) && metadata.width > maxImageWidth;
  if (shouldResize) {
    pipeline = pipeline.resize({ width: maxImageWidth, withoutEnlargement: true });
  }
  // Sharp writes single-channel input as 3-channel sRGB by default, which would
  // no longer match a /DeviceGray, /Separation or SMask image. Keep it 1-channel.
  if (metadata.channels === 1) {
    pipeline = pipeline.toColourspace('b-w');
  }

  const output = await pipeline.jpeg({ quality, mozjpeg: true }).toBuffer();
  const outputMeta = await sharp(output, { ignoreIcc: true }).metadata();

  if (outputMeta.channels !== metadata.channels) {
    return { skipped: 'channels' };
  }

  // Re-encoding can enlarge an image that was already aggressively compressed.
  // Keeping the original is always the better outcome.
  if (output.length >= bytes.length) {
    return { skipped: 'no-gain' };
  }

  return {
    buffer: output,
    width: outputMeta.width,
    height: outputMeta.height,
    channels: outputMeta.channels,
  };
}

/**
 * Compresses a PDF buffer.
 *
 * @param {Buffer} inputBuffer Raw PDF bytes.
 * @param {object} options
 * @param {number} options.quality JPEG quality applied to embedded images (1-100).
 * @param {number|null} options.maxImageWidth Downsample images wider than this, in pixels.
 * @returns {Promise<{buffer: Buffer, stats: object}>}
 */
async function compress(inputBuffer, { quality = 75, maxImageWidth = null } = {}) {
  const originalSize = inputBuffer.length;

  const pdfDoc = await PDFDocument.load(inputBuffer, {
    // Surfaces encrypted documents as an error rather than silently emitting a
    // broken file. The route turns this into a clear 400.
    ignoreEncryption: false,
    updateMetadata: false,
  });

  const candidates = findRecompressibleImages(pdfDoc);

  let imagesRecompressed = 0;
  let imagesSkipped = 0;
  let imageBytesBefore = 0;
  let imageBytesAfter = 0;

  for (const { ref, stream, dict } of candidates) {
    const original = Buffer.from(stream.contents);

    try {
      const result = await recompressImage(original, { quality, maxImageWidth });

      if (!result || result.skipped) {
        imagesSkipped += 1;
        continue;
      }

      const newDict = dict.clone(pdfDoc.context);
      newDict.set(PDFName.of('Width'), pdfDoc.context.obj(result.width));
      newDict.set(PDFName.of('Height'), pdfDoc.context.obj(result.height));
      newDict.set(PDFName.of('Length'), pdfDoc.context.obj(result.buffer.length));
      newDict.set(PDFName.of('BitsPerComponent'), pdfDoc.context.obj(8));
      // The samples keep their meaning and channel count, so the original
      // /ColorSpace (with its ICC profile, spot colour or Lab definition) stays.
      // Overwriting it with DeviceRGB/DeviceGray dropped ICC profiles and
      // turned Separation tints into inverted greys.
      if (!dict.get(PDFName.of('ColorSpace'))) {
        newDict.set(
          PDFName.of('ColorSpace'),
          PDFName.of(result.channels === 1 ? 'DeviceGray' : 'DeviceRGB')
        );
      }
      // Any decode parameters described the previous encoding.
      newDict.delete(PDFName.of('DecodeParms'));

      pdfDoc.context.assign(ref, PDFRawStream.of(newDict, new Uint8Array(result.buffer)));

      imagesRecompressed += 1;
      imageBytesBefore += original.length;
      imageBytesAfter += result.buffer.length;
    } catch (error) {
      // One unreadable image must not fail the whole document.
      imagesSkipped += 1;
      logger.warn('Skipped an embedded image during PDF compression', {
        error: error.message,
      });
    }
  }

  // Object streams pack the document's indirect objects together and compress
  // them, which reclaims some structural overhead independently of the images.
  const outputBytes = await pdfDoc.save({ useObjectStreams: true });
  let buffer = Buffer.from(outputBytes);

  // Rewriting a PDF can make it larger (text-only files, or ones already
  // saved compactly). Never hand back a bigger "_compressed" file: return the
  // original bytes, reported as 0% saved (same convention as the PNG and WebP
  // compressors, whose clients read equal sizes as "already optimal").
  const originalKept = buffer.length >= originalSize;
  if (originalKept) {
    logger.info('PDF compression kept original (no smaller result)', {
      originalSize, attemptedSize: buffer.length, imagesRecompressed,
    });
    buffer = Buffer.isBuffer(inputBuffer) ? inputBuffer : Buffer.from(inputBuffer);
  }

  return {
    buffer,
    stats: {
      originalSize,
      compressedSize: buffer.length,
      compressionRatio: Number((((originalSize - buffer.length) / originalSize) * 100).toFixed(1)),
      originalKept,
      pageCount: pdfDoc.getPageCount(),
      imagesFound: candidates.length,
      // Nothing was changed in the file that is returned when it was kept.
      imagesRecompressed: originalKept ? 0 : imagesRecompressed,
      imagesSkipped: originalKept ? candidates.length : imagesSkipped,
      imageBytesBefore,
      imageBytesAfter,
    },
  };
}

module.exports = { compress };
