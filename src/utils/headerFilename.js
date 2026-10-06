/**
 * Make a client-supplied file name safe to put in a response header.
 *
 * multer >= 2.3 decodes the %22 / %0A / %0D a browser sends for `"`, LF and CR
 * in an upload's filename, so `file.originalname` can now contain characters
 * that either break the quoted `filename="..."` of Content-Disposition (`"`,
 * `\`) or make Node refuse the header outright (control characters throw
 * ERR_INVALID_CHAR, which turned a finished conversion into a 500). Node also
 * rejects anything above U+00FF, which only appears once multer's
 * `defParamCharset: 'utf8'` is turned on.
 *
 * Each such character becomes `_`; the rest of the name is kept as is.
 */

const isUnsafe = (code) =>
  code < 0x20 || // control characters, including CR and LF
  code === 0x7f || // DEL
  code === 0x22 || // "
  code === 0x5c || // \
  code > 0xff; // not representable in a Node header value

function headerSafeFilename(name, fallback = 'file') {
  let safe = '';
  for (const char of String(name ?? '')) {
    safe += isUnsafe(char.codePointAt(0)) ? '_' : char;
  }
  safe = safe.trim();
  return safe || fallback;
}

/** `attachment; filename="..."` with the name made header-safe. */
function attachmentDisposition(name) {
  return `attachment; filename="${headerSafeFilename(name, 'download')}"`;
}

module.exports = { headerSafeFilename, attachmentDisposition };
