/**
 * Classifies errors thrown while decoding user-supplied files.
 *
 * Sharp/libvips, pdf-lib and pdf.js report a corrupt, truncated, unsupported
 * or encrypted upload as an ordinary Error. Route catch-blocks used to answer
 * every one of those with HTTP 500, which made a bad file look like a server
 * fault and gave the user no reason. classifyInputError() recognises the
 * input-caused failures by message and returns a safe, user-facing status and
 * message (never the raw libvips text, which can contain paths and internals).
 * It returns null for anything else so the caller keeps its generic 500.
 */

const KINDS = new Set(['image', 'pdf', 'svg', 'base64']);

// Errors our own routes throw after a conversion that produced bad output.
// They are server faults even though they contain the word "corrupted".
const SERVER_SIDE = /resulting file is corrupted|invalid or corrupted|encoding failed|conversion failed/i;

const IMAGE_EMPTY = /input buffer is empty|input file is empty/i;
const IMAGE_PIXEL_LIMIT = /exceeds pixel limit/i;
const IMAGE_COMPOSITE = /image to composite must have same dimensions or smaller/i;
const IMAGE_CODEC_UNSUPPORTED = /unsupported feature|support for this compression format has not been built in|unsupported codec/i;
const IMAGE_TRUNCATED = /premature end of|libpng read error|unexpected end of|truncated/i;
const IMAGE_UNSUPPORTED = /input (buffer|file) contains unsupported image format|^unsupported image format/i;
const IMAGE_CORRUPT = new RegExp([
  'corrupt header',
  'bad seek',
  'unable to parse image',
  'invalid frame data',
  'xml parse error',
  'VipsJpeg',
  'vipspng',
  '\\b(png|jpeg|jpg|webp|heif|gif|tiff|svg)load',
].join('|'), 'i');

const PDF_ENCRYPTED = /encrypt/i;
const PDF_INVALID = /no pdf header found|failed to parse|invalid pdf structure|expected instance of pdf|invalidpdfexception|missingpdfexception|invalid object ref|end of file reached|unexpected end of/i;

const BASE64_INVALID = /base64/i;

function imageLabel(format) {
  const label = typeof format === 'string' ? format.trim().toUpperCase() : '';
  return /^[A-Z0-9]{2,6}$/.test(label) ? label : '';
}

function classifyImage(message, kind, format) {
  const label = kind === 'svg' ? 'SVG' : imageLabel(format);
  const noun = label ? `a valid ${label} image` : 'a valid image';

  if (IMAGE_PIXEL_LIMIT.test(message)) {
    return { status: 422, message: 'Image is too large (pixel limit exceeded).' };
  }
  if (IMAGE_COMPOSITE.test(message)) {
    return { status: 422, message: 'The image dimensions are not compatible with this operation.' };
  }
  if (IMAGE_EMPTY.test(message)) {
    return { status: 400, message: 'The uploaded file is empty.' };
  }
  if (IMAGE_CODEC_UNSUPPORTED.test(message)) {
    return { status: 415, message: 'This image uses a compression format that is not supported.' };
  }
  if (IMAGE_TRUNCATED.test(message)) {
    return { status: 400, message: 'The image file is incomplete or corrupted.' };
  }
  if (IMAGE_UNSUPPORTED.test(message) || IMAGE_CORRUPT.test(message)) {
    return { status: 400, message: `The file isn't ${noun} or is corrupted.` };
  }
  return null;
}

function classifyPdf(message) {
  if (PDF_ENCRYPTED.test(message)) {
    return { status: 422, message: 'This PDF is encrypted; remove the password and try again.' };
  }
  if (PDF_INVALID.test(message)) {
    return { status: 400, message: 'This file is not a valid PDF, or it is corrupted.' };
  }
  return null;
}

/**
 * @param {Error} err
 * @param {'image'|'pdf'|'svg'|'base64'} kind
 * @param {{ format?: string }} [options] expected format of the route (e.g. 'PNG')
 * @returns {{ status: 400|415|422, message: string } | null}
 */
function classifyInputError(err, kind, options = {}) {
  if (!err || !KINDS.has(kind)) return null;
  const message = typeof err === 'string' ? err : String(err.message || '');
  if (!message || SERVER_SIDE.test(message)) return null;

  if (kind === 'pdf') return classifyPdf(message);

  if (kind === 'base64' && BASE64_INVALID.test(message)) {
    return { status: 400, message: 'The data is not valid Base64.' };
  }

  return classifyImage(message, kind, options.format);
}

module.exports = { classifyInputError };
