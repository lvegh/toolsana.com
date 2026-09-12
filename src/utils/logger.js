const winston = require('winston');
const DailyRotateFile = require('winston-daily-rotate-file');
const path = require('path');

// Create logs directory if it doesn't exist
const fs = require('fs');
const logsDir = path.join(__dirname, '../../logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

/**
 * Keys whose values must never reach a log file or the console.
 *
 * Logs are written to disk, rotated, and often shipped somewhere central, so a
 * secret that lands here outlives the request by a long way. Matching is on a
 * lowercased substring of the key name, so `smtpPass`, `SMTP_PASS` and
 * `authorization` are all covered by the entries below.
 */
const REDACT_KEY_PATTERNS = [
  'password', 'passwd', 'pass',
  'secret', 'token', 'apikey', 'api_key',
  // 'authorization', not bare 'auth': the latter also swallows `authMethod`,
  // `authType` and `authenticated`, which are diagnostic and carry no secret.
  'authorization', 'cookie',
  'credential', 'privatekey', 'private_key',
];

const REDACTED = '[REDACTED]';
const MAX_REDACT_DEPTH = 6;

/**
 * A key only counts as sensitive if its VALUE could actually hold a secret.
 * Booleans and numbers cannot, so `authenticated: true`, `hasPassword: false`
 * and `tokenLength: 64` stay readable — those are exactly the fields you want
 * when reading a security log, and redacting them destroys the diagnostic
 * value the log exists for.
 */
function shouldRedact(key, value) {
  if (typeof value === 'boolean' || typeof value === 'number') return false;
  const k = String(key).toLowerCase();
  return REDACT_KEY_PATTERNS.some((p) => k.includes(p));
}

function redactValue(value, depth = 0) {
  if (depth > MAX_REDACT_DEPTH) return value;
  if (Array.isArray(value)) return value.map((v) => redactValue(v, depth + 1));
  if (value && typeof value === 'object') {
    // Don't try to walk Errors/Buffers/Dates — winston formats those itself.
    if (value instanceof Error || Buffer.isBuffer(value) || value instanceof Date) return value;
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      out[k] = shouldRedact(k, v) ? REDACTED : redactValue(v, depth + 1);
    }
    return out;
  }
  return value;
}

/**
 * Winston format that scrubs sensitive keys from every log entry's metadata.
 */
const redactFormat = winston.format((info) => {
  for (const [k, v] of Object.entries(info)) {
    if (k === 'level' || k === 'message' || k === 'timestamp' || k === 'stack') continue;
    info[k] = shouldRedact(k, v) ? REDACTED : redactValue(v);
  }
  return info;
});

// Define log format
const logFormat = winston.format.combine(
  redactFormat(),
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.prettyPrint()
);

// Define console format for development
const consoleFormat = winston.format.combine(
  redactFormat(),
  winston.format.colorize(),
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let msg = `${timestamp} [${level}]: ${message}`;
    if (Object.keys(meta).length > 0) {
      msg += ` ${JSON.stringify(meta)}`;
    }
    return msg;
  })
);

// Create transports
const transports = [];

// Console transport (always enabled in development)
if (process.env.NODE_ENV !== 'production') {
  transports.push(
    new winston.transports.Console({
      format: consoleFormat,
      level: process.env.LOG_LEVEL || 'info'
    })
  );
}

// File transports
transports.push(
  // Error log file
  new DailyRotateFile({
    filename: path.join(logsDir, 'error-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    level: 'error',
    format: logFormat,
    maxSize: process.env.LOG_FILE_MAX_SIZE || '20m',
    maxFiles: process.env.LOG_FILE_MAX_FILES || '14d',
    zippedArchive: true
  }),
  
  // Combined log file
  new DailyRotateFile({
    filename: path.join(logsDir, 'combined-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    format: logFormat,
    maxSize: process.env.LOG_FILE_MAX_SIZE || '20m',
    maxFiles: process.env.LOG_FILE_MAX_FILES || '14d',
    zippedArchive: true
  }),
  
  // Access log file (for HTTP requests)
  new DailyRotateFile({
    filename: path.join(logsDir, 'access-%DATE%.log'),
    datePattern: 'YYYY-MM-DD',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    ),
    maxSize: process.env.LOG_FILE_MAX_SIZE || '20m',
    maxFiles: process.env.LOG_FILE_MAX_FILES || '14d',
    zippedArchive: true,
    level: 'http'
  })
);

// Create logger instance
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: {
    service: 'toolzyhub-api',
    environment: process.env.NODE_ENV || 'development',
    pid: process.pid
  },
  transports,
  // Handle exceptions and rejections
  exceptionHandlers: [
    new DailyRotateFile({
      filename: path.join(logsDir, 'exceptions-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: process.env.LOG_FILE_MAX_SIZE || '20m',
      maxFiles: process.env.LOG_FILE_MAX_FILES || '14d',
      zippedArchive: true
    })
  ],
  rejectionHandlers: [
    new DailyRotateFile({
      filename: path.join(logsDir, 'rejections-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      maxSize: process.env.LOG_FILE_MAX_SIZE || '20m',
      maxFiles: process.env.LOG_FILE_MAX_FILES || '14d',
      zippedArchive: true
    })
  ]
});

// Add custom log level for HTTP requests
winston.addColors({
  error: 'red',
  warn: 'yellow',
  info: 'cyan',
  http: 'magenta',
  debug: 'green'
});

// Custom methods for specific log types
logger.httpLog = (req, res, responseTime) => {
  const logData = {
    method: req.method,
    url: req.originalUrl,
    statusCode: res.statusCode,
    responseTime: `${responseTime}ms`,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    contentLength: res.get('Content-Length') || 0,
    timestamp: new Date().toISOString()
  };
  
  logger.log('http', 'HTTP Request', logData);
};

logger.securityLog = (event, details) => {
  logger.warn(`Security Event: ${event}`, {
    event,
    ...details,
    timestamp: new Date().toISOString()
  });
};

logger.performanceLog = (operation, duration, details = {}) => {
  logger.info(`Performance: ${operation}`, {
    operation,
    duration: `${duration}ms`,
    ...details,
    timestamp: new Date().toISOString()
  });
};

// Export logger
module.exports = logger;
