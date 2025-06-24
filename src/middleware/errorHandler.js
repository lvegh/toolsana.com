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
  notFoundHandler,
  handleUnhandledRejection,
  handleUncaughtException,
  formatValidationErrors,
  sendResponse,
  sendSuccess,
  sendError
};
