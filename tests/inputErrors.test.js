/**
 * Input-error classification: corrupt / unsupported / truncated / encrypted
 * user files must be answered with a 4xx and a specific message, not the
 * generic 500. Errors are provoked with the real sharp and pdf-lib so the
 * message strings the classifier matches are the ones the libraries emit.
 */

jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }));
jest.mock('../src/middleware/rateLimit', () => ({ basicRateLimit: (req, res, next) => next() }));
jest.mock('../src/middleware/enhancedSecurity', () => ({ enhancedSecurityWithRateLimit: () => (req, res, next) => next() }));
jest.mock('@neplex/vectorizer', () => ({ vectorize: jest.fn(), ColorMode: {}, Hierarchical: {}, PathSimplifyMode: {} }));

const sharp = require('sharp');
const { PDFDocument } = require('pdf-lib');
const { classifyInputError } = require('../src/utils/inputErrors');
const convertRouter = require('../src/routes/convert');
const compressRouter = require('../src/routes/compress');
const pdfRouter = require('../src/routes/pdf');

async function post(router, path, req) {
  const layer = router.stack.find((l) => l.route && l.route.path === path && l.route.methods.post);
  if (!layer) throw new Error(`route ${path} not found`);
  const { handle } = layer.route.stack[layer.route.stack.length - 1];
  const res = { statusCode: 200, headers: {}, body: null };
  res.set = (h) => { Object.assign(res.headers, h); return res; };
  res.status = (c) => { res.statusCode = c; return res; };
  res.json = (b) => { res.body = b; return res; };
  res.send = (b) => { res.body = b; return res; };
  await handle({ body: {}, ...req }, res);
  return res;
}

const upload = (buffer, originalname, mimetype) => ({ buffer, originalname, mimetype, size: buffer.length });

const capture = async (fn) => {
  try { await fn(); } catch (e) { return e; }
  throw new Error('expected the call to fail');
};

let png;
let jpg;
let garbage;
let pdf;

beforeAll(async () => {
  const background = { r: 200, g: 30, b: 30 };
  png = await sharp({ create: { width: 300, height: 300, channels: 3, background } }).png().toBuffer();
  jpg = await sharp({ create: { width: 300, height: 300, channels: 3, background } }).jpeg().toBuffer();
  garbage = Buffer.from('this is not an image at all, just plain text pretending to be one');
  const doc = await PDFDocument.create();
  doc.addPage();
  pdf = Buffer.from(await doc.save());
});

describe('classifyInputError with real library errors', () => {
  test('garbage bytes: unsupported image format', async () => {
    const err = await capture(() => sharp(garbage).png().toBuffer());
    expect(classifyInputError(err, 'image', { format: 'PNG' })).toEqual({
      status: 400,
      message: "The file isn't a valid PNG image or is corrupted.",
    });
    expect(classifyInputError(err, 'image').message).toBe("The file isn't a valid image or is corrupted.");
  });

  test('truncated JPEG', async () => {
    const err = await capture(() => sharp(jpg.subarray(0, 200)).png().toBuffer());
    expect(classifyInputError(err, 'image', { format: 'JPG' }).status).toBe(400);
  });

  test('truncated JPEG body (premature end)', async () => {
    const err = await capture(() => sharp(jpg.subarray(0, jpg.length - 100), { failOn: 'error' }).png().toBuffer());
    expect(classifyInputError(err, 'image').status).toBe(400);
  });

  test('truncated PNG', async () => {
    const err = await capture(() => sharp(png.subarray(0, png.length - 30)).jpeg().toBuffer());
    expect(classifyInputError(err, 'image').status).toBe(400);
  });

  test('empty buffer', async () => {
    const err = await capture(() => sharp(Buffer.alloc(0)).png().toBuffer());
    expect(classifyInputError(err, 'image')).toEqual({ status: 400, message: 'The uploaded file is empty.' });
  });

  test('pixel limit', async () => {
    const err = await capture(() => sharp(png, { limitInputPixels: 10 }).jpeg().toBuffer());
    expect(classifyInputError(err, 'image')).toEqual({ status: 422, message: 'Image is too large (pixel limit exceeded).' });
  });

  test('composite larger than base', async () => {
    const err = await capture(() => sharp(png).composite([{ input: { create: { width: 900, height: 900, channels: 3, background: '#0f0' } } }]).toBuffer());
    expect(classifyInputError(err, 'image').status).toBe(422);
  });

  test('broken SVG', async () => {
    const err = await capture(() => sharp(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><rect')).png().toBuffer());
    expect(classifyInputError(err, 'svg').message).toBe("The file isn't a valid SVG image or is corrupted.");
  });

  test('not a PDF', async () => {
    const err = await capture(() => PDFDocument.load(garbage));
    expect(classifyInputError(err, 'pdf')).toEqual({ status: 400, message: 'This file is not a valid PDF, or it is corrupted.' });
  });

  test('truncated PDF', async () => {
    const err = await capture(() => PDFDocument.load(pdf.subarray(0, 40)));
    expect(classifyInputError(err, 'pdf').status).toBe(400);
  });

  test('encrypted PDF', async () => {
    const encrypted = Buffer.from(pdf.toString('latin1').replace('/Root', '/Encrypt << /Filter /Standard >> /Root'), 'latin1');
    const err = await capture(() => PDFDocument.load(encrypted));
    expect(classifyInputError(err, 'pdf')).toEqual({ status: 422, message: 'This PDF is encrypted; remove the password and try again.' });
  });

  test('base64 problems', () => {
    expect(classifyInputError(new Error('Invalid Base64 string'), 'base64')).toEqual({ status: 400, message: 'The data is not valid Base64.' });
  });

  test('never leaks raw library text or paths', async () => {
    const err = await capture(() => sharp(jpg.subarray(0, 200)).png().toBuffer());
    expect(classifyInputError(err, 'image').message).not.toMatch(/vips|\n|\//i);
  });

  test('server-side faults are not classified', () => {
    expect(classifyInputError(new Error('Image conversion failed - resulting file is corrupted'), 'image')).toBeNull();
    expect(classifyInputError(new Error('Converted image is invalid or corrupted'), 'image')).toBeNull();
    expect(classifyInputError(new Error('Input file is missing: /srv/x.png'), 'image')).toBeNull();
    expect(classifyInputError(new Error('connect ECONNREFUSED 127.0.0.1:6379'), 'image')).toBeNull();
    expect(classifyInputError(new Error('anything'), 'unknown')).toBeNull();
    expect(classifyInputError(null, 'image')).toBeNull();
  });
});

describe('routes answer bad input with 4xx', () => {
  test('garbage bytes as PNG -> 400 with a specific message', async () => {
    const res = await post(convertRouter, '/png-to-webp', { file: upload(garbage, 'fake.png', 'image/png') });
    expect(res.statusCode).toBe(400);
    expect(res.body.success).toBe(false);
    expect(res.body.message).toBe("The file isn't a valid PNG image or is corrupted.");
  });

  test('truncated JPEG -> 400', async () => {
    const res = await post(convertRouter, '/jpg-to-png', { file: upload(jpg.subarray(0, 200), 'cut.jpg', 'image/jpeg') });
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toMatch(/JPG|incomplete|corrupted/);
  });

  test('valid PNG still converts with 200', async () => {
    const res = await post(convertRouter, '/png-to-webp', { file: upload(png, 'ok.png', 'image/png') });
    expect(res.statusCode).toBe(200);
    expect(Buffer.isBuffer(res.body)).toBe(true);
    expect((await sharp(res.body).metadata()).format).toBe('webp');
  });

  test('garbage JPG on the compress route -> 400', async () => {
    const res = await post(compressRouter, '/jpg', { file: upload(garbage, 'fake.jpg', 'image/jpeg') });
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toBe("The file isn't a valid JPG image or is corrupted.");
  });

  test('garbage as PDF -> 400', async () => {
    const res = await post(pdfRouter, '/compress', { file: upload(garbage, 'fake.pdf', 'application/pdf') });
    expect(res.statusCode).toBe(400);
    expect(res.body.message).toBe('This file is not a valid PDF, or it is corrupted.');
  });
});
