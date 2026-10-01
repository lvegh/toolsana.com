const http = require('http');
const logger = require('../utils/logger');

/**
 * Custom Error Class
 */
class AppError extends Error {
  constructor(message, statusCode, isOperational = true) {
    super(message);
    this.statusCode = statusCode;
    this.isOperational = isOperational;
    this.status = `${statusCode}`.startsWith('4') ? 'fail' : 'error';
    
    Error.captureStackTrace(this, this.constructor);
  }
}

/**
 * Async Error Handler Wrapper
 */
const asyncHandler = (fn) => {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

/**
 * Handle Cast Errors (Invalid ObjectId, etc.)
 */
const handleCastError = (error) => {
  const message = `Invalid ${error.path}: ${error.value}`;
  return new AppError(message, 400);
};

/**
 * Handle Duplicate Field Errors
 */
const handleDuplicateFieldsError = (error) => {
  const value = error.errmsg.match(/(["'])(\\?.)*?\1/)[0];
  const message = `Duplicate field value: ${value}. Please use another value!`;
  return new AppError(message, 400);
};

/**
 * Handle Validation Errors
 */
const handleValidationError = (error) => {
  const errors = Object.values(error.errors).map(el => el.message);
  const message = `Invalid input data. ${errors.join('. ')}`;
  return new AppError(message, 400);
};

/**
 * Handle JWT Errors
 */
const handleJWTError = () => {
  return new AppError('Invalid token. Please log in again!', 401);
};

/**
 * Handle JWT Expired Error
 */
const handleJWTExpiredError = () => {
  return new AppError('Your token has expired! Please log in again.', 401);
};

/**
 * Handle Multer Errors (File Upload)
 */
const handleMulterError = (error) => {
  if (error.code === 'LIMIT_FILE_SIZE') {
    return new AppError('File too large', 400);
  }
  if (error.code === 'LIMIT_FILE_COUNT') {
    return new AppError('Too many files', 400);
  }
  if (error.code === 'LIMIT_UNEXPECTED_FILE') {
    return new AppError('Unexpected file field', 400);
  }
  return new AppError('File upload error', 400);
};

/**
 * Send Error Response for Development
 */
const sendErrorDev = (err, req, res) => {
  // Log error details
  logger.error('Development Error:', {
    error: err,
    stack: err.stack,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent')
  });

  return res.status(err.statusCode).json({
    success: false,
    error: err,
    message: err.message,
    stack: err.stack,
    url: req.originalUrl,
    timestamp: new Date().toISOString()
  });
};

/**
 * Send Error Response for Production
 */
const sendErrorProd = (err, req, res) => {
  // Log error details (without exposing to client)
  logger.error('Production Error:', {
    message: err.message,
    statusCode: err.statusCode,
    isOperational: err.isOperational,
    url: req.originalUrl,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    stack: err.stack
  });

  // Operational, trusted error: send message to client
  if (err.isOperational) {
    return res.status(err.statusCode).json({
      success: false,
      message: err.message,
      timestamp: new Date().toISOString()
    });
  }

  // Programming or other unknown error: don't leak error details
  return res.status(500).json({
    success: false,
    message: 'Something went wrong!',
    timestamp: new Date().toISOString()
  });
};

/**
 * Handle Rate Limit Errors
 */
const handleRateLimitError = (error) => {
  return new AppError('Too many requests, please try again later', 429);
};

/**
 * Handle CORS Errors
 */
const handleCORSError = (error) => {
  return new AppError('CORS policy violation', 403);
};

/**
 * Handle File System Errors
 */
const handleFileSystemError = (error) => {
  if (error.code === 'ENOENT') {
    return new AppError('File not found', 404);
  }
  if (error.code === 'EACCES') {
    return new AppError('Permission denied', 403);
  }
  if (error.code === 'ENOSPC') {
    return new AppError('No space left on device', 507);
  }
  return new AppError('File system error', 500);
};

/**
 * Handle Database Connection Errors
 */
const handleDatabaseError = (error) => {
  if (error.code === 'ECONNREFUSED') {
    return new AppError('Database connection refused', 503);
  }
  if (error.code === 'ETIMEDOUT') {
    return new AppError('Database connection timeout', 503);
  }
  return new AppError('Database error', 503);
};

/**
 * Main Error Handler Middleware
 */
const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  // Set default values
  error.statusCode = error.statusCode || 500;
  error.status = error.status || 'error';

  // Handle specific error types
  if (err.name === 'CastError') error = handleCastError(error);
  if (err.code === 11000) error = handleDuplicateFieldsError(error);
  if (err.name === 'ValidationError') error = handleValidationError(error);
  if (err.name === 'JsonWebTokenError') error = handleJWTError();
  if (err.name === 'TokenExpiredError') error = handleJWTExpiredError();
  if (err.name === 'MulterError') error = handleMulterError(error);
  if (err.message && err.message.includes('rate limit')) error = handleRateLimitError(error);
  if (err.message && err.message.includes('CORS')) error = handleCORSError(error);
  if (err.code && ['ENOENT', 'EACCES', 'ENOSPC'].includes(err.code)) error = handleFileSystemError(error);
  if (err.code && ['ECONNREFUSED', 'ETIMEDOUT'].includes(err.code)) error = handleDatabaseError(error);

  // Send error response based on environment
  if (process.env.NODE_ENV === 'development') {
    sendErrorDev(error, req, res);
  } else {
    sendErrorProd(error, req, res);
  }
};

/**
 * Terminal error handler used by server.js.
 *
 * The `errorHandler` above is not mounted: its development branch serialises
 * the raw error and stack into the response, it maps CORS by substring, and it
 * answers multer's size limit with 400. This handler replaces the old
 * "every error is a 500" behaviour with a narrow allowlist of errors whose
 * status and message are known to be safe to show a caller. Anything else
 * stays a 500 with a generic message; details go to the log only.
 */

// Upload limits per route prefix. Multer does not put the configured limit on
// its LIMIT_FILE_SIZE error, so the message is built from this table. Keep in
// sync with the `limits.fileSize` values in routes/ai.js, format.js, pdf.js;
// every other upload route (compress, convert) uses 10 MB.
const UPLOAD_LIMIT_MB_BY_PREFIX = [
  ['/api/ai/', 20],
  ['/api/format/', 5],
  ['/api/pdf/', 25],
];
const DEFAULT_UPLOAD_LIMIT_MB = 10;

const uploadLimitMb = (req) => {
  const url = (req && (req.originalUrl || req.url)) || '';
  const hit = UPLOAD_LIMIT_MB_BY_PREFIX.find(([prefix]) => url.startsWith(prefix));
  return hit ? hit[1] : DEFAULT_UPLOAD_LIMIT_MB;
};

// Multer's own messages for its limit codes are fixed strings, but spell them
// out so a future multer version cannot change what reaches the client.
const MULTER_MESSAGES = {
  LIMIT_PART_COUNT: 'Too many parts in the upload',
  LIMIT_FILE_COUNT: 'Too many files',
  LIMIT_FIELD_KEY: 'Field name too long',
  LIMIT_FIELD_VALUE: 'Field value too long',
  LIMIT_FIELD_COUNT: 'Too many fields',
  LIMIT_UNEXPECTED_FILE: 'Unexpected file field',
  MISSING_FIELD_NAME: 'Upload field name missing',
};

// fileFilter rejections in the routes are plain `new Error('File must be a PNG
// image')` / `new Error('Only PNG, JPEG, and WebP files are allowed.')`. They
// carry no status, so they are recognised by their (server-authored) wording.
const FILE_TYPE_REJECTION = /^(File must be |Only [A-Za-z0-9 ,.-]+ files are allowed)/;

// busboy (multer's parser) errors for a malformed multipart body.
const MALFORMED_MULTIPART = /^(Multipart: |Unexpected end of form|Malformed part header|Malformed urlencoded form)/;

// body-parser sets `type` on every error it raises.
const BODY_PARSER_MESSAGES = {
  'entity.parse.failed': [400, 'Invalid JSON in request body'],
  'entity.verify.failed': [403, 'Request body verification failed'],
  'request.aborted': [400, 'Request aborted before the body was received'],
  'request.size.invalid': [400, 'Request size did not match Content-Length'],
  'encoding.unsupported': [415, 'Unsupported content encoding'],
  'charset.unsupported': [415, 'Unsupported charset'],
  'parameters.too.many': [413, 'Too many parameters in request body'],
};

const formatMb = (bytes) => {
  const mb = bytes / (1024 * 1024);
  return Number.isInteger(mb) ? String(mb) : mb.toFixed(1);
};

/**
 * Map an error to `{ status, message }` that is safe to send to a client.
 * Exported for tests.
 */
const classifyError = (err, req) => {
  const fallback = { status: 500, message: 'Internal server error' };
  if (!err || typeof err !== 'object') return fallback;

  // multer limit errors
  if (err.name === 'MulterError') {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return { status: 413, message: `File too large (max ${uploadLimitMb(req)} MB)` };
    }
    return { status: 400, message: MULTER_MESSAGES[err.code] || 'File upload error' };
  }

  const message = typeof err.message === 'string' ? err.message : '';

  // fileFilter rejections (wrong file type)
  if (FILE_TYPE_REJECTION.test(message) && !err.status && !err.statusCode) {
    return { status: 415, message: message.slice(0, 200) };
  }

  if (MALFORMED_MULTIPART.test(message) && !err.status && !err.statusCode) {
    return { status: 400, message: 'Malformed multipart upload' };
  }

  // body-parser (express.json / urlencoded / raw)
  if (typeof err.type === 'string') {
    if (err.type === 'entity.too.large') {
      const limit = typeof err.limit === 'number' && err.limit > 0 ? ` (max ${formatMb(err.limit)} MB)` : '';
      return { status: 413, message: `Request body too large${limit}` };
    }
    if (BODY_PARSER_MESSAGES[err.type]) {
      const [status, msg] = BODY_PARSER_MESSAGES[err.type];
      return { status, message: msg };
    }
  }

  // Anything that explicitly declares a client-error status (http-errors,
  // AppError, hand-built errors). `expose === false` means the author marked
  // the message as internal, so fall back to the standard reason phrase.
  const declared = Number(err.status || err.statusCode);
  if (Number.isInteger(declared) && declared >= 400 && declared < 500) {
    const reason = http.STATUS_CODES[declared] || 'Request error';
    const safeMessage = err.expose === false || !message ? reason : message.slice(0, 200);
    return { status: declared, message: safeMessage };
  }

  return fallback;
};

const apiErrorHandler = (err, req, res, next) => {
  const { status, message } = classifyError(err, req);

  if (status >= 500) {
    logger.error('Server error:', err);
  } else {
    logger.warn('Request error', {
      status,
      message,
      code: err && err.code,
      type: err && err.type,
      url: req.originalUrl,
      method: req.method,
    });
  }

  if (res.headersSent) {
    return next(err);
  }

  return sendError(res, message, status);
};

/**
 * Handle 404 Errors (Route Not Found)
 */
const notFoundHandler = (req, res, next) => {
  const err = new AppError(`Can't find ${req.originalUrl} on this server!`, 404);
  next(err);
};

/**
 * Handle Unhandled Promise Rejections
 */
const handleUnhandledRejection = (reason, promise) => {
  logger.error('Unhandled Promise Rejection:', {
    reason,
    promise,
    timestamp: new Date().toISOString()
  });
  
  // Close server gracefully
  process.exit(1);
};

/**
 * Handle Uncaught Exceptions
 */
const handleUncaughtException = (error) => {
  logger.error('Uncaught Exception:', {
    error: error.message,
    stack: error.stack,
    timestamp: new Date().toISOString()
  });
  
  // Close server gracefully
  process.exit(1);
};

/**
 * Validation Error Formatter
 */
const formatValidationErrors = (errors) => {
  return errors.map(error => ({
    field: error.param,
    message: error.msg,
    value: error.value
  }));
};

/**
 * API Response Helper
 */
const sendResponse = (res, statusCode, success, message, data = null, meta = null) => {
  const response = {
    success,
    message,
    timestamp: new Date().toISOString()
  };

  if (data !== null) {
    response.data = data;
  }

  if (meta !== null) {
    response.meta = meta;
  }

  return res.status(statusCode).json(response);
};

/**
 * Success Response Helper
 */
const sendSuccess = (res, message, data = null, statusCode = 200, meta = null) => {
  return sendResponse(res, statusCode, true, message, data, meta);
};

/**
 * Error Response Helper
 */
const sendError = (res, message, statusCode = 500, errors = null) => {
  const response = {
    success: false,
    message,
    timestamp: new Date().toISOString()
  };

  if (errors) {
    response.errors = errors;
  }

  return res.status(statusCode).json(response);
};

module.exports = {
  AppError,
  asyncHandler,
  errorHandler,
  apiErrorHandler,
  classifyError,
  notFoundHandler,
  handleUnhandledRejection,
  handleUncaughtException,
  formatValidationErrors,
  sendResponse,
  sendSuccess,
  sendError
};
