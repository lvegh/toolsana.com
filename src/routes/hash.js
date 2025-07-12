const express = require('express');
const bcrypt = require('bcrypt');
const argon2 = require('argon2');
const { blake2b } = require('@noble/hashes/blake2');
const { blake2s } = require('@noble/hashes/blake2');
const { blake3 } = require('@noble/hashes/blake3');
const { scrypt, randomBytes, timingSafeEqual } = require('crypto');
const { promisify } = require('util');
const { basicRateLimit } = require('../middleware/rateLimit');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();
const scryptAsync = promisify(scrypt);

/**
 * POST /api/hash/argon2generate
 * Generate argon2 hash from password
 */
router.post('/argon2generate', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { password, type, memoryCost, timeCost, parallelism, hashLength } = req.body;

    // Validate password
    if (!password || typeof password !== 'string') {
      return sendError(res, 'Password is required and must be a string', 400);
    }

    if (password.length < 1) {
      return sendError(res, 'Password cannot be empty', 400);
    }

    // Validate and set argon2 parameters
    const argonType = type || 'argon2id'; // argon2i, argon2d, argon2id
    const memCost = parseInt(memoryCost) || 65536; // Memory cost in KiB (64 MB default)
    const timeCostParam = parseInt(timeCost) || 3; // Time cost (iterations)
    const parallelismParam = parseInt(parallelism) || 4; // Parallelism (threads)
    const hashLen = parseInt(hashLength) || 32; // Hash length in bytes

    // Validate argon2 type
    if (!['argon2i', 'argon2d', 'argon2id'].includes(argonType)) {
      return sendError(res, 'Type must be argon2i, argon2d, or argon2id', 400);
    }

    // Validate parameter ranges
    if (memCost < 8 || memCost > 2097152) { // 8 KiB to 2 GiB
      return sendError(res, 'Memory cost must be between 8 and 2097152 KiB', 400);
    }

    if (timeCostParam < 1 || timeCostParam > 10) {
      return sendError(res, 'Time cost must be between 1 and 10', 400);
    }

    if (parallelismParam < 1 || parallelismParam > 16) {
      return sendError(res, 'Parallelism must be between 1 and 16', 400);
    }

    if (hashLen < 16 || hashLen > 64) {
      return sendError(res, 'Hash length must be between 16 and 64 bytes', 400);
    }

    // Calculate estimated memory usage
    const memoryUsageMB = Math.round(memCost * parallelismParam / 1024);

    logger.info('Starting argon2 hash generation', {
      passwordLength: password.length,
      type: argonType,
      memoryCost: memCost,
      timeCost: timeCostParam,
      parallelism: parallelismParam,
      hashLength: hashLen,
      estimatedMemoryMB: memoryUsageMB
    });

    const startTime = Date.now();

    // Set argon2 type
    let argon2TypeEnum;
    switch (argonType) {
      case 'argon2i':
        argon2TypeEnum = argon2.argon2i;
        break;
      case 'argon2d':
        argon2TypeEnum = argon2.argon2d;
        break;
      case 'argon2id':
      default:
        argon2TypeEnum = argon2.argon2id;
        break;
    }

    // Generate argon2 hash
    const hash = await argon2.hash(password, {
      type: argon2TypeEnum,
      memoryCost: memCost,
      timeCost: timeCostParam,
      parallelism: parallelismParam,
      hashLength: hashLen,
      saltLength: 16 // 16 bytes salt
    });

    const endTime = Date.now();
    const processingTime = endTime - startTime;

    logger.info('Argon2 hash generation completed', {
      type: argonType,
      memoryCost: memCost,
      timeCost: timeCostParam,
      parallelism: parallelismParam,
      hashLength: hashLen,
      actualHashLength: hash.length,
      memoryUsage: `${memoryUsageMB}MB`,
      processingTime: `${processingTime}ms`
    });

    return sendSuccess(res, 'Argon2 hash generated successfully', {
      hash,
      parameters: {
        type: argonType,
        memoryCost: memCost,
        timeCost: timeCostParam,
        parallelism: parallelismParam,
        hashLength: hashLen
      },
      memoryUsage: `${memoryUsageMB}MB`,
      processingTime: processingTime,
      algorithm: 'argon2',
      format: 'encoded'
    });

  } catch (error) {
    logger.error('Argon2 hash generation error:', {
      error: error.message,
      stack: error.stack,
      parameters: {
        type: req.body?.type,
        memoryCost: req.body?.memoryCost,
        timeCost: req.body?.timeCost,
        parallelism: req.body?.parallelism,
        hashLength: req.body?.hashLength
      }
    });

    if (error.message.includes('Invalid argon2 parameter')) {
      return sendError(res, 'Invalid argon2 parameters provided', 400);
    }

    if (error.message.includes('memory')) {
      return sendError(res, 'Argon2 parameters require too much memory', 400);
    }

    return sendError(res, 'Failed to generate argon2 hash', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/hash/argon2verify
 * Verify password against argon2 hash
 */
router.post('/argon2verify', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { password, hash } = req.body;

    // Validate inputs
    if (!password || typeof password !== 'string') {
      return sendError(res, 'Password is required and must be a string', 400);
    }

    if (!hash || typeof hash !== 'string') {
      return sendError(res, 'Hash is required and must be a string', 400);
    }

    // Validate hash format (argon2 hashes start with $argon2)
    if (!hash.startsWith('$argon2')) {
      return sendError(res, 'Invalid argon2 hash format - must start with $argon2', 400);
    }

    // Parse hash to extract parameters for logging
    let hashInfo = {};
    try {
      // Basic parsing for logging (argon2 library will do the real parsing)
      const parts = hash.split('$');
      if (parts.length >= 4) {
        hashInfo = {
          variant: parts[1], // argon2i, argon2d, or argon2id
          version: parts[2], // version number
          parameters: parts[3] // m=,t=,p= parameters
        };
      }
    } catch (parseError) {
      // Don't fail on parsing error, just log less info
      hashInfo = { note: 'Could not parse hash for detailed logging' };
    }

    logger.info('Starting argon2 hash verification', {
      passwordLength: password.length,
      hashLength: hash.length,
      hashPrefix: hash.substring(0, 20),
      parsedInfo: hashInfo
    });

    const startTime = Date.now();

    // Verify password against hash
    const isValid = await argon2.verify(hash, password);

    const endTime = Date.now();
    const processingTime = endTime - startTime;

    logger.info('Argon2 hash verification completed', {
      isValid,
      processingTime: `${processingTime}ms`,
      hashVariant: hashInfo.variant || 'unknown'
    });

    return sendSuccess(res, 'Argon2 hash verification completed', {
      isValid,
      processingTime: processingTime,
      algorithm: 'argon2',
      hashFormat: 'encoded',
      variant: hashInfo.variant || 'unknown'
    });

  } catch (error) {
    logger.error('Argon2 hash verification error:', {
      error: error.message,
      stack: error.stack,
      hashProvided: !!req.body?.hash,
      hashLength: req.body?.hash?.length
    });

    if (error.message.includes('Invalid hash') || error.message.includes('invalid encoded hash')) {
      return sendError(res, 'Invalid argon2 hash format', 400);
    }

    if (error.message.includes('memory')) {
      return sendError(res, 'Argon2 hash requires too much memory to verify', 400);
    }

    return sendError(res, 'Failed to verify argon2 hash', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/hash/bcryptgenerate
 * Generate bcrypt hash from password
 */
router.post('/bcryptgenerate', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { password, rounds } = req.body;

    // Validate password
    if (!password || typeof password !== 'string') {
      return sendError(res, 'Password is required and must be a string', 400);
    }

    if (password.length < 1) {
      return sendError(res, 'Password cannot be empty', 400);
    }

    // Validate rounds parameter
    const saltRounds = parseInt(rounds) || 10;
    if (saltRounds < 4 || saltRounds > 15) {
      return sendError(res, 'Rounds must be between 4 and 15', 400);
    }

    logger.info('Starting bcrypt hash generation', {
      passwordLength: password.length,
      rounds: saltRounds
    });

    const startTime = Date.now();

    // Generate bcrypt hash
    const hash = await bcrypt.hash(password, saltRounds);

    const endTime = Date.now();
    const processingTime = endTime - startTime;

    logger.info('Bcrypt hash generation completed', {
      rounds: saltRounds,
      hashLength: hash.length,
      processingTime: `${processingTime}ms`
    });

    return sendSuccess(res, 'Bcrypt hash generated successfully', {
      hash,
      rounds: saltRounds,
      processingTime: processingTime,
      algorithm: 'bcrypt',
      format: 'standard'
    });

  } catch (error) {
    logger.error('Bcrypt hash generation error:', {
      error: error.message,
      stack: error.stack,
      rounds: req.body?.rounds
    });

    if (error.message.includes('Invalid salt rounds')) {
      return sendError(res, 'Invalid salt rounds specified', 400);
    }

    return sendError(res, 'Failed to generate bcrypt hash', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/hash/bcryptverify
 * Verify password against bcrypt hash
 */
router.post('/bcryptverify', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { password, hash } = req.body;

    // Validate inputs
    if (!password || typeof password !== 'string') {
      return sendError(res, 'Password is required and must be a string', 400);
    }

    if (!hash || typeof hash !== 'string') {
      return sendError(res, 'Hash is required and must be a string', 400);
    }

    // Validate hash format
    if (!hash.startsWith('$2b$') && !hash.startsWith('$2a$') && !hash.startsWith('$2y$')) {
      return sendError(res, 'Invalid bcrypt hash format', 400);
    }

    if (hash.length !== 60) {
      return sendError(res, 'Invalid bcrypt hash length', 400);
    }

    logger.info('Starting bcrypt hash verification', {
      passwordLength: password.length,
      hashPrefix: hash.substring(0, 7)
    });

    const startTime = Date.now();

    // Verify password against hash
    const isValid = await bcrypt.compare(password, hash);

    const endTime = Date.now();
    const processingTime = endTime - startTime;

    logger.info('Bcrypt hash verification completed', {
      isValid,
      processingTime: `${processingTime}ms`,
      hashPrefix: hash.substring(0, 7)
    });

    return sendSuccess(res, 'Bcrypt hash verification completed', {
      isValid,
      processingTime: processingTime,
      algorithm: 'bcrypt',
      hashFormat: 'standard'
    });

  } catch (error) {
    logger.error('Bcrypt hash verification error:', {
      error: error.message,
      stack: error.stack,
      hashProvided: !!req.body?.hash
    });

    if (error.message.includes('Invalid salt revision')) {
      return sendError(res, 'Invalid bcrypt hash format or version', 400);
    }

    return sendError(res, 'Failed to verify bcrypt hash', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/hash/scryptgenerate
 * Generate scrypt hash from password
 */
router.post('/scryptgenerate', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { password, N, r, p, dkLen } = req.body;

    // Validate password
    if (!password || typeof password !== 'string') {
      return sendError(res, 'Password is required and must be a string', 400);
    }

    if (password.length < 1) {
      return sendError(res, 'Password cannot be empty', 400);
    }

    // Validate and set scrypt parameters
    const scryptN = parseInt(N) || 16384;
    const scryptR = parseInt(r) || 8;
    const scryptP = parseInt(p) || 1;
    const keyLength = parseInt(dkLen) || 32;

    // Validate parameter ranges
    if (scryptN < 4096 || scryptN > 1048576 || !Number.isInteger(Math.log2(scryptN))) {
      return sendError(res, 'N must be a power of 2 between 4096 and 1048576', 400);
    }

    if (scryptR < 1 || scryptR > 32) {
      return sendError(res, 'r must be between 1 and 32', 400);
    }

    if (scryptP < 1 || scryptP > 8) {
      return sendError(res, 'p must be between 1 and 8', 400);
    }

    if (keyLength < 16 || keyLength > 64) {
      return sendError(res, 'Key length must be between 16 and 64 bytes', 400);
    }

    // Calculate estimated memory usage
    const memoryUsage = Math.round(scryptN * scryptR * 128 / 1024 / 1024);

    logger.info('Starting scrypt hash generation', {
      passwordLength: password.length,
      N: scryptN,
      r: scryptR,
      p: scryptP,
      keyLength,
      estimatedMemoryMB: memoryUsage
    });

    const startTime = Date.now();

    // Generate random salt (16 bytes)
    const salt = randomBytes(16);

    // Generate scrypt hash
    const derivedKey = await scryptAsync(password, salt, keyLength, {
      N: scryptN,
      r: scryptR,
      p: scryptP
    });

    const endTime = Date.now();
    const processingTime = endTime - startTime;

    // Create scrypt hash in standard format: $7$N$r$p$salt$hash
    // Use URL-safe base64 to avoid issues with $ splitting
    const saltBase64 = salt.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const hashBase64 = derivedKey.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    const scryptHash = `$7$${scryptN.toString(16)}$${scryptR.toString(16)}$${scryptP.toString(16)}$${saltBase64}$${hashBase64}`;

    logger.info('Scrypt hash generation completed', {
      N: scryptN,
      r: scryptR,
      p: scryptP,
      keyLength,
      saltLength: salt.length,
      hashLength: scryptHash.length,
      memoryUsage: `${memoryUsage}MB`,
      processingTime: `${processingTime}ms`
    });

    return sendSuccess(res, 'Scrypt hash generated successfully', {
      hash: scryptHash,
      parameters: {
        N: scryptN,
        r: scryptR,
        p: scryptP,
        keyLength
      },
      memoryUsage: `${memoryUsage}MB`,
      processingTime: processingTime,
      algorithm: 'scrypt',
      format: 'standard'
    });

  } catch (error) {
    logger.error('Scrypt hash generation error:', {
      error: error.message,
      stack: error.stack,
      parameters: {
        N: req.body?.N,
        r: req.body?.r,
        p: req.body?.p,
        dkLen: req.body?.dkLen
      }
    });

    if (error.message.includes('Invalid scrypt parameter')) {
      return sendError(res, 'Invalid scrypt parameters provided', 400);
    }

    if (error.message.includes('memory')) {
      return sendError(res, 'Scrypt parameters require too much memory', 400);
    }

    return sendError(res, 'Failed to generate scrypt hash', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/hash/scryptverify
 * Verify password against scrypt hash
 */
router.post('/scryptverify', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { password, hash } = req.body;

    // Validate inputs
    if (!password || typeof password !== 'string') {
      return sendError(res, 'Password is required and must be a string', 400);
    }

    if (!hash || typeof hash !== 'string') {
      return sendError(res, 'Hash is required and must be a string', 400);
    }

    // Validate hash format
    if (!hash.startsWith('$7$')) {
      return sendError(res, 'Invalid scrypt hash format - must start with $7$', 400);
    }

    // Parse scrypt hash: $7$N$r$p$salt$hash
    const parts = hash.split('$').filter(part => part !== '');

    // Log the parts for debugging
    logger.info('Parsing scrypt hash', {
      hashLength: hash.length,
      partsCount: parts.length,
      parts: parts
    });

    if (parts.length !== 6) {
      return sendError(res, `Invalid scrypt hash format - expected 6 parts after filtering, got ${parts.length}. Parts: ${JSON.stringify(parts)}`, 400);
    }

    const [version, NHex, rHex, pHex, saltBase64, hashBase64] = parts;

    if (version !== '7') {
      return sendError(res, 'Invalid scrypt hash version', 400);
    }

    // Parse parameters
    const scryptN = parseInt(NHex, 16);
    const scryptR = parseInt(rHex, 16);
    const scryptP = parseInt(pHex, 16);

    // Validate parsed parameters
    if (isNaN(scryptN) || isNaN(scryptR) || isNaN(scryptP)) {
      return sendError(res, 'Invalid scrypt parameters in hash', 400);
    }

    // Decode salt and expected hash (convert URL-safe base64 back to standard)
    const saltBase64Standard = saltBase64.replace(/-/g, '+').replace(/_/g, '/');
    const hashBase64Standard = hashBase64.replace(/-/g, '+').replace(/_/g, '/');

    // Add padding if needed
    const saltPadded = saltBase64Standard + '==='.slice(0, (4 - saltBase64Standard.length % 4) % 4);
    const hashPadded = hashBase64Standard + '==='.slice(0, (4 - hashBase64Standard.length % 4) % 4);

    let salt, expectedHash;
    try {
      salt = Buffer.from(saltPadded, 'base64');
      expectedHash = Buffer.from(hashPadded, 'base64');
    } catch (decodeError) {
      return sendError(res, `Invalid base64 encoding in hash: ${decodeError.message}`, 400);
    }

    if (salt.length === 0 || expectedHash.length === 0) {
      return sendError(res, 'Invalid salt or hash in scrypt format', 400);
    }

    logger.info('Starting scrypt hash verification', {
      passwordLength: password.length,
      hashLength: hash.length,
      hashFormat: hash.substring(0, 30),
      N: scryptN,
      r: scryptR,
      p: scryptP,
      keyLength: expectedHash.length,
      saltLength: salt.length
    });

    const startTime = Date.now();

    // Generate hash with same parameters
    const derivedKey = await scryptAsync(password, salt, expectedHash.length, {
      N: scryptN,
      r: scryptR,
      p: scryptP
    });

    // Use timing-safe comparison
    const isValid = timingSafeEqual(derivedKey, expectedHash);

    const endTime = Date.now();
    const processingTime = endTime - startTime;

    logger.info('Scrypt hash verification completed', {
      isValid,
      processingTime: `${processingTime}ms`,
      parameters: { N: scryptN, r: scryptR, p: scryptP }
    });

    return sendSuccess(res, 'Scrypt hash verification completed', {
      isValid,
      parameters: {
        N: scryptN,
        r: scryptR,
        p: scryptP,
        keyLength: expectedHash.length
      },
      processingTime: processingTime,
      algorithm: 'scrypt',
      format: 'standard'
    });

  } catch (error) {
    logger.error('Scrypt hash verification error:', {
      error: error.message,
      stack: error.stack,
      hashProvided: !!req.body?.hash
    });

    if (error.message.includes('Invalid scrypt parameter')) {
      return sendError(res, 'Invalid scrypt parameters in hash', 400);
    }

    if (error.message.includes('memory')) {
      return sendError(res, 'Scrypt hash requires too much memory to verify', 400);
    }

    return sendError(res, 'Failed to verify scrypt hash', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/hash/blakegenerate
 * Generate BLAKE hash (BLAKE2b, BLAKE2s, or BLAKE3) from input data
 */
router.post('/blakegenerate', async (req, res) => {
  try {
    const { input, algorithm = 'blake2b', keyLength, key } = req.body;
    if (!input || typeof input !== 'string') return sendError(res, 'Input is required');

    const normalizedKey = key && key.trim().length > 0 ? key.trim() : null;
    const selectedAlgorithm = algorithm.toLowerCase();
    const defaultLengths = { blake2b: 64, blake2s: 32, blake3: 32 };
    const maxLengths = defaultLengths;
    const hashLength = selectedAlgorithm === 'blake3'
      ? 32
      : parseInt(keyLength) || defaultLengths[selectedAlgorithm];

    if (!['blake2b', 'blake2s', 'blake3'].includes(selectedAlgorithm)) {
      return sendError(res, 'Unsupported algorithm');
    }

    if (hashLength < 1 || hashLength > maxLengths[selectedAlgorithm]) {
      return sendError(res, `Hash length must be between 1 and ${maxLengths[selectedAlgorithm]} bytes`);
    }

    if (normalizedKey && Buffer.byteLength(normalizedKey, 'utf8') > maxLengths[selectedAlgorithm]) {
      return sendError(res, `Key cannot exceed ${maxLengths[selectedAlgorithm]} bytes`);
    }

    if (selectedAlgorithm === 'blake3' && normalizedKey) {
      const keyLengthBytes = Buffer.byteLength(normalizedKey, 'utf8');
      if (keyLengthBytes !== 32) return sendError(res, 'BLAKE3 secret key must be exactly 32 bytes');
    }

    const inputBuffer = Buffer.from(input, 'utf8');
    const keyBuffer = normalizedKey ? Buffer.from(normalizedKey, 'utf8') : undefined;
    let digest;

    if (selectedAlgorithm === 'blake2b') {
      digest = Buffer.from(blake2b(inputBuffer, { key: keyBuffer, dkLen: hashLength })).toString('hex');
    } else if (selectedAlgorithm === 'blake2s') {
      digest = Buffer.from(blake2s(inputBuffer, { key: keyBuffer, dkLen: hashLength })).toString('hex');
    } else {
      digest = Buffer.from(blake3(inputBuffer, keyBuffer ? { key: keyBuffer } : undefined)).toString('hex').substring(0, hashLength * 2);
    }

    return sendSuccess(res, 'Hash generated', {
      hash: digest,
      algorithm: selectedAlgorithm.toUpperCase(),
      keyLength: hashLength,
      hasSecretKey: !!normalizedKey
    });
  } catch (err) {
    return sendError(res, 'Internal error during hash generation', 500);
  }
});


/**
 * POST /api/hash/blakeverify
 * Verify input data against BLAKE hash (BLAKE2b, BLAKE2s, or BLAKE3)
 */
router.post('/blakeverify', async (req, res) => {
  try {
    const { input, hash, algorithm = 'blake2b', keyLength, key } = req.body;
    if (!input || typeof input !== 'string') return sendError(res, 'Input is required');
    if (!hash || typeof hash !== 'string' || !/^[a-fA-F0-9]+$/.test(hash)) return sendError(res, 'Valid hex hash required');

    const normalizedKey = key && key.trim().length > 0 ? key.trim() : null;
    const selectedAlgorithm = algorithm.toLowerCase();
    const defaultLengths = { blake2b: 64, blake2s: 32, blake3: 32 };
    const maxLengths = defaultLengths;
    const hashLength = selectedAlgorithm === 'blake3'
      ? 32
      : parseInt(keyLength) || (hash.length / 2);

    if (!['blake2b', 'blake2s', 'blake3'].includes(selectedAlgorithm)) {
      return sendError(res, 'Unsupported algorithm');
    }

    if (hashLength < 1 || hashLength > maxLengths[selectedAlgorithm]) {
      return sendError(res, `Hash length must be between 1 and ${maxLengths[selectedAlgorithm]} bytes`);
    }

    if (hash.length !== hashLength * 2) {
      return sendError(res, 'Hash length mismatch with provided value');
    }

    if (normalizedKey && Buffer.byteLength(normalizedKey, 'utf8') > maxLengths[selectedAlgorithm]) {
      return sendError(res, `Key cannot exceed ${maxLengths[selectedAlgorithm]} bytes`);
    }

    if (selectedAlgorithm === 'blake3' && normalizedKey) {
      const keyLengthBytes = Buffer.byteLength(normalizedKey, 'utf8');
      if (keyLengthBytes !== 32) return sendError(res, 'BLAKE3 secret key must be exactly 32 bytes');
    }

    const inputBuffer = Buffer.from(input, 'utf8');
    const keyBuffer = normalizedKey ? Buffer.from(normalizedKey, 'utf8') : undefined;
    let computedDigest;

    if (selectedAlgorithm === 'blake2b') {
      computedDigest = Buffer.from(blake2b(inputBuffer, { key: keyBuffer, dkLen: hashLength })).toString('hex');
    } else if (selectedAlgorithm === 'blake2s') {
      computedDigest = Buffer.from(blake2s(inputBuffer, { key: keyBuffer, dkLen: hashLength })).toString('hex');
    } else {
      computedDigest = Buffer.from(blake3(inputBuffer, keyBuffer ? { key: keyBuffer } : undefined)).toString('hex').substring(0, hashLength * 2);
    }

    const expectedBuffer = Buffer.from(hash.toLowerCase(), 'hex');
    const actualBuffer = Buffer.from(computedDigest.toLowerCase(), 'hex');
    const crypto = require('crypto');

    const isValid = expectedBuffer.length === actualBuffer.length && crypto.timingSafeEqual(expectedBuffer, actualBuffer);

    return sendSuccess(res, 'Hash verification complete', {
      isValid,
      algorithm: selectedAlgorithm.toUpperCase(),
      keyLength: hashLength,
      hasSecretKey: !!normalizedKey
    });
  } catch (err) {
    return sendError(res, 'Internal error during hash verification', 500);
  }
});


/**
 * GET /api/hash/info
 * Get hash service information
 */
router.get('/info', enhancedSecurityWithRateLimit(basicRateLimit), (req, res) => {
  const info = {
    service: 'Password Hashing & Cryptographic Hash API',
    version: '1.0.0',
    supportedAlgorithms: [
      'argon2',
      'bcrypt',
      'scrypt',
      'blake2b',
      'blake2s',
      'blake3'
    ],
    endpoints: {
      argon2_generate: 'POST /api/hash/argon2generate',
      argon2_verify: 'POST /api/hash/argon2verify',
      bcrypt_generate: 'POST /api/hash/bcryptgenerate',
      bcrypt_verify: 'POST /api/hash/bcryptverify',
      scrypt_generate: 'POST /api/hash/scryptgenerate',
      scrypt_verify: 'POST /api/hash/scryptverify',
      blake_generate: 'POST /api/hash/blakegenerate',
      blake_verify: 'POST /api/hash/blakeverify',
      info: 'GET /api/hash/info'
    },
    limits: {
      argon2: {
        memoryCost: '8-2097152 KiB',
        timeCost: '1-10',
        parallelism: '1-16',
        hashLength: '16-64 bytes'
      },
      bcrypt: {
        minRounds: 4,
        maxRounds: 15,
        defaultRounds: 10
      },
      scrypt: {
        N: 'Power of 2 between 4096 and 1048576',
        r: '1-32',
        p: '1-8',
        keyLength: '16-64 bytes'
      },
      blake: {
        blake2b: {
          maxLength: 64,
          defaultLength: 64,
          description: 'Up to 64 bytes (128 hex chars)'
        },
        blake2s: {
          maxLength: 32,
          defaultLength: 32,
          description: 'Up to 32 bytes (64 hex chars)'
        },
        blake3: {
          maxLength: 32,
          defaultLength: 32,
          description: 'Up to 32 bytes (64 hex chars)'
        }
      },
      input: {
        minLength: 1,
        maxLength: 'No specific limit'
      }
    },
    features: {
      timingSafeComparison: true,
      standardFormats: true,
      memoryEstimation: true,
      performanceLogging: true,
      keyedHashing: true, // For BLAKE algorithms
      modernCrypto: true
    },
    usage: {
      blake_generate: {
        method: 'POST',
        endpoint: '/api/hash/blakegenerate',
        contentType: 'application/json',
        body: {
          input: 'Data to hash (required)',
          algorithm: 'blake2b, blake2s, or blake3 (optional, default: blake2b)',
          keyLength: 'Hash length in bytes (optional, uses algorithm default)',
          key: 'Secret key for keyed hashing (optional)'
        },
        response: {
          hash: 'Generated BLAKE hash in hex format',
          parameters: 'Hash parameters used',
          processingTime: 'Time taken in milliseconds'
        }
      },
      blake_verify: {
        method: 'POST',
        endpoint: '/api/hash/blakeverify',
        contentType: 'application/json',
        body: {
          input: 'Data to verify (required)',
          hash: 'BLAKE hash to verify against (required)',
          algorithm: 'blake2b, blake2s, or blake3 (required)',
          keyLength: 'Hash length in bytes (optional, auto-detected)',
          key: 'Secret key if hash was keyed (optional)'
        },
        response: {
          isValid: 'Boolean indicating if input matches hash',
          parameters: 'Hash parameters used',
          processingTime: 'Time taken in milliseconds'
        }
      },
      bcrypt_generate: {
        method: 'POST',
        endpoint: '/api/hash/bcryptgenerate',
        contentType: 'application/json',
        body: {
          password: 'Password to hash (required)',
          rounds: 'Salt rounds 4-15 (optional, default: 10)'
        },
        response: {
          hash: 'Generated bcrypt hash',
          rounds: 'Salt rounds used',
          processingTime: 'Time taken in milliseconds'
        }
      },
      bcrypt_verify: {
        method: 'POST',
        endpoint: '/api/hash/bcryptverify',
        contentType: 'application/json',
        body: {
          password: 'Password to verify (required)',
          hash: 'Bcrypt hash to verify against (required)'
        },
        response: {
          isValid: 'Boolean indicating if password matches',
          processingTime: 'Time taken in milliseconds'
        }
      },
      scrypt_generate: {
        method: 'POST',
        endpoint: '/api/hash/scryptgenerate',
        contentType: 'application/json',
        body: {
          password: 'Password to hash (required)',
          N: 'CPU/memory cost (optional, default: 16384)',
          r: 'Block size (optional, default: 8)',
          p: 'Parallelization (optional, default: 1)',
          dkLen: 'Key length in bytes (optional, default: 32)'
        },
        response: {
          hash: 'Generated scrypt hash',
          parameters: 'Scrypt parameters used',
          memoryUsage: 'Estimated memory usage',
          processingTime: 'Time taken in milliseconds'
        }
      },
      scrypt_verify: {
        method: 'POST',
        endpoint: '/api/hash/scryptverify',
        contentType: 'application/json',
        body: {
          password: 'Password to verify (required)',
          hash: 'Scrypt hash to verify against (required)'
        },
        response: {
          isValid: 'Boolean indicating if password matches',
          parameters: 'Scrypt parameters from hash',
          processingTime: 'Time taken in milliseconds'
        }
      }
    }
  };

  sendSuccess(res, 'Hash service information', info);
});

module.exports = router;
