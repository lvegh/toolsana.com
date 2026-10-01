/**
 * Regression tests for the image/PDF conversion fixes of 2026-09-30:
 * encoder options the clients send (0 is a real value, out-of-range values
 * are clamped), animated WebP handling, the base64-to-image data-URL parser,
 * and the PDF compressor's colour-space and never-larger guarantees.
 *
 * Everything is generated in memory with Sharp / pdf-lib; no network, Redis or
 * disk access, so the suite is safe for CI.
 */

jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }));
jest.mock('../src/middleware/rateLimit', () => ({ basicRateLimit: (req, res, next) => next() }));
jest.mock('../src/middleware/enhancedSecurity', () => ({ enhancedSecurityWithRateLimit: () => (req, res, next) => next() }));
jest.mock('@neplex/vectorizer', () => ({ vectorize: jest.fn(), ColorMode: {}, Hierarchical: {}, PathSimplifyMode: {} }));

const sharp = require('sharp');
const { PDFDocument, PDFName, PDFRawStream, PDFArray } = require('pdf-lib');
const convertRouter = require('../src/routes/convert');
const { compressWebp, isLosslessWebp } = require('../src/services/webpOptimizer');
const pdfOptimizer = require('../src/services/pdfOptimizer');

/** Calls the final handler of a POST route directly with a fake req/res. */
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

function noise(width, height, channels, seed = 1) {
  const buf = Buffer.alloc(width * height * channels);
  let x = seed;
  for (let i = 0; i < buf.length; i++) {
    x = (x * 1103515245 + 12345) >>> 0;
    buf[i] = ((((i / channels) % width) / width) * 180 + (x >>> 26)) & 255;
  }
  return buf;
}

let jpg;
let transparentPng;
let animatedLossy;
let animatedLossless;

beforeAll(async () => {
  jpg = await sharp(noise(320, 240, 3), { raw: { width: 320, height: 240, channels: 3 } }).jpeg({ quality: 92 }).toBuffer();
  const rgba = Buffer.alloc(32 * 32 * 4);
  for (let y = 8; y < 24; y++) for (let x = 8; x < 24; x++) { const o = (y * 32 + x) * 4; rgba[o] = 255; rgba[o + 3] = 255; }
  transparentPng = await sharp(rgba, { raw: { width: 32, height: 32, channels: 4 } }).png().toBuffer();
  const frames = await Promise.all([0, 1, 2, 3].map((i) =>
    sharp(noise(96, 64, 3, i + 7), { raw: { width: 96, height: 64, channels: 3 } }).png().toBuffer()));
  animatedLossy = await sharp(frames, { join: { animated: true } }).webp({ quality: 95, delay: 100, loop: 0 }).toBuffer();
  animatedLossless = await sharp(frames, { join: { animated: true } }).webp({ lossless: true, delay: 100, loop: 0 }).toBuffer();
});

describe('encoder options', () => {
  it('jpg-to-webp honours lossless and quality', async () => {
    const file = upload(jpg, 'a.jpg', 'image/jpeg');
    const lossless = await post(convertRouter, '/jpg-to-webp', { file, body: { quality: '80', lossless: 'true', effort: '4' } });
    expect(lossless.statusCode).toBe(200);
    expect(isLosslessWebp(lossless.body)).toBe(true);
    const q30 = await post(convertRouter, '/jpg-to-webp', { file, body: { quality: '30', lossless: 'false', effort: '4' } });
    const q90 = await post(convertRouter, '/jpg-to-webp', { file, body: { quality: '90', lossless: 'false', effort: '4' } });
    expect(q30.body.length).toBeLessThan(q90.body.length);
  });

  it('jpg-to-avif honours compressionType=lossless', async () => {
    const file = upload(jpg, 'a.jpg', 'image/jpeg');
    const lossy = await post(convertRouter, '/jpg-to-avif', { file, body: { quality: '50', compressionType: 'lossy' } });
    const lossless = await post(convertRouter, '/jpg-to-avif', { file, body: { quality: '50', compressionType: 'lossless' } });
    expect(lossless.statusCode).toBe(200);
    expect(lossless.headers['X-Compression-Type']).toBe('lossless');
    expect(lossless.body.length).toBeGreaterThan(lossy.body.length * 3);
  });

  it('PNG compression level 0 is used, not replaced by the default', async () => {
    const file = upload(jpg, 'a.jpg', 'image/jpeg');
    const level0 = await post(convertRouter, '/jpg-to-png', { file, body: { compressionLevel: '0' } });
    const level9 = await post(convertRouter, '/jpg-to-png', { file, body: { compressionLevel: '9' } });
    expect(level0.headers['X-Compression-Level']).toBe('0');
    expect(level0.body.length).toBeGreaterThan(level9.body.length);
  });

  it('webp-to-avif clamps speed 10 instead of failing', async () => {
    const webp = await sharp(jpg).webp({ quality: 90 }).toBuffer();
    const res = await post(convertRouter, '/webp-to-avif', { file: upload(webp, 'a.webp', 'image/webp'), body: { quality: '50', speed: '10' } });
    expect(res.statusCode).toBe(200);
    expect(res.headers['X-Speed']).toBe('9');
  });
});

describe('webp compressor and animation', () => {
  it('detects lossless bitstreams inside animation frames', () => {
    expect(isLosslessWebp(animatedLossless)).toBe(true);
    expect(isLosslessWebp(animatedLossy)).toBe(false);
  });

  it('keeps every frame and never returns a larger file', async () => {
    for (const input of [animatedLossy, animatedLossless]) {
      const result = await compressWebp(input);
      const meta = await sharp(result.buffer).metadata();
      expect(meta.pages).toBe(4);
      expect(result.buffer.length).toBeLessThanOrEqual(input.length);
    }
  });
});

describe('base64-to-image', () => {
  const run = (base64Data, outputFormat) => post(convertRouter, '/base64-to-image', { body: { base64Data, outputFormat } });

  it('accepts data URLs with extra parameters and wrapped lines', async () => {
    const b64 = transparentPng.toString('base64');
    for (const input of [
      `data:image/png;charset=utf-8;base64,${b64}`,
      `data:image/png;name=logo.png;base64,${b64}`,
      `data:image/png;base64,${b64.replace(/.{20}/g, '$&\r\n')}`,
    ]) {
      const res = await run(input);
      expect(res.statusCode).toBe(200);
      expect(Buffer.compare(res.body, transparentPng)).toBe(0);
    }
  });

  it('flattens transparency onto white when converting to JPEG', async () => {
    const res = await run(`data:image/png;base64,${transparentPng.toString('base64')}`, 'jpg');
    const { data } = await sharp(res.body).raw().toBuffer({ resolveWithObject: true });
    // Corner pixel: was 0,0,0 before the fix. Allow a little JPEG ringing.
    for (const channel of [data[0], data[1], data[2]]) expect(channel).toBeGreaterThan(230);
  });

  it('returns the original bytes when the source is already the requested format', async () => {
    const res = await run(`data:image/jpeg;base64,${jpg.toString('base64')}`, 'jpg');
    expect(res.headers['X-Converted']).toBe('false');
    expect(Buffer.compare(res.body, jpg)).toBe(0);
  });
});

describe('pdf compressor', () => {
  it('keeps Separation/ICCBased colour spaces and single-channel samples', async () => {
    const doc = await PDFDocument.create();
    const ctx = doc.context;
    const page = doc.addPage([400, 400]);
    const gray = await sharp(noise(2000, 800, 1), { raw: { width: 2000, height: 800, channels: 1 } })
      .toColourspace('b-w').jpeg({ quality: 95 }).toBuffer();
    const rgb = await sharp(noise(2000, 800, 3), { raw: { width: 2000, height: 800, channels: 3 } }).jpeg({ quality: 95 }).toBuffer();
    const tint = ctx.obj({ FunctionType: 2, Domain: [0, 1], C0: [0, 0, 0, 0], C1: [0, 0.9, 0.8, 0], N: 1 });
    const separation = ctx.obj([PDFName.of('Separation'), PDFName.of('Spot'), PDFName.of('DeviceCMYK'), tint]);
    const icc = ctx.obj([PDFName.of('ICCBased'), ctx.register(ctx.stream(Buffer.from('icc'), { N: 3 }))]);
    const image = (bytes, cs) => ctx.register(PDFRawStream.of(ctx.obj({
      Type: 'XObject', Subtype: 'Image', Width: 2000, Height: 800, BitsPerComponent: 8,
      ColorSpace: cs, Filter: 'DCTDecode', Length: bytes.length,
    }), new Uint8Array(bytes)));
    const sepRef = image(gray, separation);
    const iccRef = image(rgb, icc);
    page.node.set(PDFName.of('Resources'), ctx.obj({ XObject: ctx.obj({ A: sepRef, B: iccRef }) }));
    const input = Buffer.from(await doc.save());

    const { buffer, stats } = await pdfOptimizer.compress(input, { quality: 70, maxImageWidth: 1000 });
    expect(stats.imagesRecompressed).toBe(2);
    const out = await PDFDocument.load(buffer);
    const sep = out.context.lookup(sepRef);
    const sepCs = sep.dict.get(PDFName.of('ColorSpace'));
    expect(sepCs).toBeInstanceOf(PDFArray);
    expect(sepCs.get(0).toString()).toBe('/Separation');
    expect((await sharp(Buffer.from(sep.contents)).metadata()).channels).toBe(1);
    const iccCs = out.context.lookup(iccRef).dict.get(PDFName.of('ColorSpace'));
    expect(iccCs.get(0).toString()).toBe('/ICCBased');
  });

  it('returns the original bytes when the rewrite is not smaller', async () => {
    const body = ['<</Type/Catalog/Pages 2 0 R>>', '<</Type/Pages/Kids[3 0 R]/Count 1>>', '<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>'];
    let pdf = '%PDF-1.4\n';
    const offsets = body.map((o, i) => { const at = pdf.length; pdf += `${i + 1} 0 obj${o}endobj\n`; return at; });
    const xref = pdf.length;
    pdf += `xref\n0 4\n0000000000 65535 f \n${offsets.map((o) => `${String(o).padStart(10, '0')} 00000 n \n`).join('')}`;
    pdf += `trailer<</Size 4/Root 1 0 R>>\nstartxref\n${xref}\n%%EOF`;
    const input = Buffer.from(pdf, 'latin1');

    const { buffer, stats } = await pdfOptimizer.compress(input, { quality: 70, maxImageWidth: 1600 });
    expect(Buffer.compare(buffer, input)).toBe(0);
    expect(stats.originalKept).toBe(true);
    expect(stats.compressionRatio).toBe(0);
  });
});
