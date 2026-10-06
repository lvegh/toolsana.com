/**
 * Upload file names in response headers. multer >= 2.3 decodes the %22 / %0A
 * a browser sends for `"` and LF in a filename, so the routes must not copy
 * `file.originalname` into Content-Disposition / X-Original-Filename as is:
 * a quote broke the quoted filename and a newline made Node throw
 * ERR_INVALID_CHAR, turning a finished conversion into a 500.
 */

jest.mock('../src/utils/logger', () => ({ info: jest.fn(), warn: jest.fn(), error: jest.fn(), debug: jest.fn() }));
jest.mock('../src/middleware/rateLimit', () => ({ basicRateLimit: (req, res, next) => next() }));
jest.mock('../src/middleware/enhancedSecurity', () => ({ enhancedSecurityWithRateLimit: () => (req, res, next) => next() }));

const express = require('express');
const request = require('supertest');
const sharp = require('sharp');
const { headerSafeFilename, attachmentDisposition } = require('../src/utils/headerFilename');
const compressRouter = require('../src/routes/compress');

describe('headerSafeFilename', () => {
  test('keeps an ordinary name unchanged', () => {
    expect(headerSafeFilename('holiday photo (1).jpg')).toBe('holiday photo (1).jpg');
  });

  test('replaces quotes, backslashes and control characters', () => {
    expect(headerSafeFilename('my "best" photo.jpg')).toBe('my _best_ photo.jpg');
    expect(headerSafeFilename('a\\b.jpg')).toBe('a_b.jpg');
    expect(headerSafeFilename('line1\nline2\r.jpg')).toBe('line1_line2_.jpg');
    expect(headerSafeFilename('tab\there\u007f.jpg')).toBe('tab_here_.jpg');
  });

  test('keeps Latin-1 characters but replaces anything Node cannot put in a header', () => {
    expect(headerSafeFilename('café.jpg')).toBe('café.jpg');
    expect(headerSafeFilename('照片.jpg')).toBe('__.jpg');
  });

  test('falls back when nothing usable is left', () => {
    expect(headerSafeFilename('')).toBe('file');
    expect(headerSafeFilename(undefined)).toBe('file');
    expect(headerSafeFilename('   ', 'download')).toBe('download');
  });

  test('attachmentDisposition quotes the safe name', () => {
    expect(attachmentDisposition('a"b.png')).toBe('attachment; filename="a_b.png"');
    expect(attachmentDisposition('')).toBe('attachment; filename="download"');
  });
});

describe('upload routes with awkward file names (real multer)', () => {
  let app;
  let jpg;

  beforeAll(async () => {
    app = express();
    app.use('/api/compress', compressRouter);
    jpg = await sharp({ create: { width: 64, height: 64, channels: 3, background: { r: 10, g: 120, b: 200 } } })
      .jpeg()
      .toBuffer();
  });

  // Built by hand so the filename reaches multer exactly as a browser encodes it.
  const multipart = (rawFilename, buffer) => {
    const boundary = '----toolzyhub-test';
    const body = Buffer.concat([
      Buffer.from(
        `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${rawFilename}"\r\n` +
          'Content-Type: image/jpeg\r\n\r\n'
      ),
      buffer,
      Buffer.from(`\r\n--${boundary}--\r\n`),
    ]);
    return { body, contentType: `multipart/form-data; boundary=${boundary}` };
  };

  const upload = (rawFilename) => {
    const { body, contentType } = multipart(rawFilename, jpg);
    return request(app).post('/api/compress/jpg').set('Content-Type', contentType).send(body);
  };

  test('a quote in the name gives a well-formed Content-Disposition', async () => {
    const res = await upload('my %22best%22 photo.jpg');
    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toBe('attachment; filename="my _best_ photo_compressed.jpg"');
    expect(res.headers['x-original-filename']).toBe('my _best_ photo.jpg');
  });

  test('a newline in the name no longer turns the conversion into a 500', async () => {
    const res = await upload('line1%0Aline2.jpg');
    expect(res.status).toBe(200);
    expect(res.headers['content-disposition']).toBe('attachment; filename="line1_line2_compressed.jpg"');
    expect(res.headers['x-original-filename']).toBe('line1_line2.jpg');
  });
});
