const express = require('express');
const net = require('net');
const macLookup = require('mac-lookup');
const { basicRateLimit, createCustomRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { redisUtils } = require('../config/redis');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * VERY AGGRESSIVE rate limiters for port scanning
 * Single port check: 20 requests per hour
 */
const singlePortRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  message: {
    success: false,
    message: 'Single port check limit exceeded. Please try again later.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    return `port-check-single:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  }
});

/**
 * Port range scanning: 5 requests per hour (VERY RESTRICTIVE)
 */
const portRangeRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: {
    success: false,
    message: 'Port range scan limit exceeded. Please try again in 1 hour.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    return `port-check-range:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  }
});

/**
 * Common service detection database
 */
const SERVICE_DATABASE = {
  20: 'FTP-DATA',
  21: 'FTP',
  22: 'SSH/SFTP',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  143: 'IMAP',
  443: 'HTTPS',
  465: 'SMTPS',
  587: 'SMTP (Submission)',
  993: 'IMAPS',
  995: 'POP3S',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Proxy',
  8443: 'HTTPS-Alt',
  27017: 'MongoDB'
};

/**
 * Validate hostname/IP address
 * CRITICAL: Prevent scanning private networks and localhost
 */
function validateHost(host) {
  if (!host || typeof host !== 'string') {
    return { valid: false, error: 'Host is required' };
  }

  // Clean and normalize
  let cleanHost = host.trim().toLowerCase();

  // Remove protocol if present
  cleanHost = cleanHost.replace(/^https?:\/\//, '');
  cleanHost = cleanHost.replace(/^ftp:\/\//, '');

  // Remove path and port if present
  cleanHost = cleanHost.replace(/\/.*$/, '');
  cleanHost = cleanHost.replace(/:.*$/, '');

  // Block localhost and local variations
  const localhostPatterns = [
    /^localhost$/i,
    /^127\./,
    /^0\.0\.0\.0$/,
    /^::1$/,
    /^::$/
  ];

  for (const pattern of localhostPatterns) {
    if (pattern.test(cleanHost)) {
      return { valid: false, error: 'Scanning localhost is not allowed' };
    }
  }

  // Block private IP ranges (RFC 1918)
  const privateIpPatterns = [
    /^10\./,                              // 10.0.0.0/8
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,    // 172.16.0.0/12
    /^192\.168\./,                        // 192.168.0.0/16
    /^169\.254\./,                        // 169.254.0.0/16 (link-local)
    /^fc00:/,                             // fc00::/7 (unique local)
    /^fd00:/,                             // fd00::/8 (unique local)
    /^fe80:/                              // fe80::/10 (link-local)
  ];

  for (const pattern of privateIpPatterns) {
    if (pattern.test(cleanHost)) {
      return { valid: false, error: 'Scanning private IP addresses is not allowed' };
    }
  }

  // Block reserved/special IPs
  const reservedPatterns = [
    /^0\./,           // 0.0.0.0/8
    /^100\.6[4-9]\./,  // 100.64.0.0/10 (carrier-grade NAT)
    /^100\.[7-9][0-9]\./,
    /^100\.1[0-2][0-9]\./,
    /^192\.0\.0\./,   // 192.0.0.0/24 (IETF protocol assignments)
    /^192\.0\.2\./,   // 192.0.2.0/24 (TEST-NET-1)
    /^198\.51\.100\./, // 198.51.100.0/24 (TEST-NET-2)
    /^203\.0\.113\./,  // 203.0.113.0/24 (TEST-NET-3)
    /^224\./,         // 224.0.0.0/4 (multicast)
    /^2[3-5][0-9]\./,  // 240.0.0.0/4 (reserved)
    /^255\.255\.255\.255$/ // broadcast
  ];

  for (const pattern of reservedPatterns) {
    if (pattern.test(cleanHost)) {
      return { valid: false, error: 'Scanning reserved IP addresses is not allowed' };
    }
  }

  // Validate format (hostname or IPv4/IPv6)
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*\.[a-zA-Z]{2,}$/;
  const ipv4Regex = /^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)$/;
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d)|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.){3}(25[0-5]|(2[0-4]|1\d|[1-9]|)\d))$/;

  if (!domainRegex.test(cleanHost) && !ipv4Regex.test(cleanHost) && !ipv6Regex.test(cleanHost)) {
    return { valid: false, error: 'Invalid hostname or IP address format' };
  }

  return { valid: true, cleanHost };
}

/**
 * Validate port number(s)
 */
function validatePorts(ports) {
  if (!ports) {
    return { valid: false, error: 'Port(s) required' };
  }

  let portArray = [];

  // Handle single port
  if (typeof ports === 'number') {
    portArray = [ports];
  }
  // Handle array of ports
  else if (Array.isArray(ports)) {
    portArray = ports;
  }
  // Handle string (could be single port or comma-separated)
  else if (typeof ports === 'string') {
    portArray = ports.split(',').map(p => parseInt(p.trim(), 10));
  } else {
    return { valid: false, error: 'Invalid port format' };
  }

  // Validate each port
  for (const port of portArray) {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return { valid: false, error: `Invalid port number: ${port}. Must be between 1-65535` };
    }
  }

  // Enforce maximum 10 ports per request
  if (portArray.length > 10) {
    return { valid: false, error: 'Maximum 10 ports allowed per request' };
  }

  return { valid: true, ports: portArray };
}

/**
 * Check if a port is open with timeout
 */
function checkPort(host, port, timeout = 3000) {
  return new Promise((resolve) => {
    const startTime = Date.now();
    const socket = new net.Socket();

    let banner = null;
    let bannerTimeout = null;

    // Set socket timeout
    socket.setTimeout(timeout);

    // Connection successful - port is open
    socket.on('connect', () => {
      const responseTime = Date.now() - startTime;

      // Try to grab banner (first bytes sent by service)
      bannerTimeout = setTimeout(() => {
        socket.destroy();
        resolve({
          port,
          status: 'open',
          service: SERVICE_DATABASE[port] || 'Unknown',
          responseTime,
          banner: banner || null
        });
      }, 500); // Wait 500ms for banner

      socket.on('data', (data) => {
        clearTimeout(bannerTimeout);
        banner = data.toString('utf8', 0, Math.min(data.length, 200)).trim();
        socket.destroy();
        resolve({
          port,
          status: 'open',
          service: SERVICE_DATABASE[port] || 'Unknown',
          responseTime,
          banner
        });
      });
    });

    // Connection failed - port is closed or filtered
    socket.on('error', (error) => {
      const responseTime = Date.now() - startTime;
      clearTimeout(bannerTimeout);

      resolve({
        port,
        status: error.code === 'ETIMEDOUT' ? 'filtered' : 'closed',
        service: SERVICE_DATABASE[port] || 'Unknown',
        responseTime,
        banner: null
      });
    });

    // Timeout
    socket.on('timeout', () => {
      const responseTime = Date.now() - startTime;
      clearTimeout(bannerTimeout);
      socket.destroy();

      resolve({
        port,
        status: 'filtered',
        service: SERVICE_DATABASE[port] || 'Unknown',
        responseTime,
        banner: null
      });
    });

    // Attempt connection
    socket.connect(port, host);
  });
}

/**
 * Detect abuse patterns
 */
async function detectAbuse(req, host, ports) {
  const abuseKey = `port-scan-abuse:${req.ip}`;

  // Track scanning activity
  const activity = await redisUtils.get(abuseKey) || {
    scans: 0,
    hosts: new Set(),
    totalPorts: 0,
    firstScan: Date.now()
  };

  activity.scans++;
  activity.hosts.add(host);
  activity.totalPorts += ports.length;
  activity.lastScan = Date.now();

  // Store activity for 24 hours
  await redisUtils.setex(abuseKey, 86400, {
    scans: activity.scans,
    hosts: Array.from(activity.hosts),
    totalPorts: activity.totalPorts,
    firstScan: activity.firstScan,
    lastScan: activity.lastScan
  });

  // Detect suspicious patterns
  const timeWindow = Date.now() - activity.firstScan;
  const hoursActive = timeWindow / (60 * 60 * 1000);

  // Abuse thresholds
  const isAbuse =
    activity.scans > 50 || // More than 50 scans
    activity.hosts.size > 20 || // Scanning more than 20 different hosts
    activity.totalPorts > 100 || // Scanned more than 100 ports total
    (hoursActive < 1 && activity.scans > 10); // More than 10 scans in less than 1 hour

  if (isAbuse) {
    logger.securityLog('PORT SCAN ABUSE DETECTED', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      scans: activity.scans,
      uniqueHosts: activity.hosts.size,
      totalPorts: activity.totalPorts,
      hoursActive: hoursActive.toFixed(2),
      currentHost: host,
      currentPorts: ports
    });

    // Send notification (implement as needed)
    // await sendSecurityAlert('Port Scan Abuse Detected', activity);
  }

  return isAbuse;
}

/**
 * Custom rate limiter for MAC lookup endpoints
 * 60 requests per hour per user
 */
const macLookupRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 60,
  message: {
    success: false,
    message: 'Too many MAC lookup requests. Please try again later.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    return `mac-lookup:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  }
});

/**
 * Validate and normalize MAC address format
 * Supports various formats: 00:1A:2B:3C:4D:5E, 00-1A-2B-3C-4D-5E, 001A.2B3C.4D5E, 001A2B3C4D5E
 */
function validateAndNormalizeMac(mac) {
  if (!mac || typeof mac !== 'string') {
    return { valid: false, error: 'MAC address is required' };
  }

  // Clean MAC address - remove whitespace
  let cleanMac = mac.trim().toUpperCase();

  // Security: Check for suspicious patterns
  const suspiciousPatterns = [
    /<script/i,
    /javascript:/i,
    /on\w+\s*=/i,
    /\.\.\//,
    /<iframe/i,
    /eval\(/i,
    /[<>'"]/
  ];

  for (const pattern of suspiciousPatterns) {
    if (pattern.test(cleanMac)) {
      return { valid: false, error: 'Suspicious input detected' };
    }
  }

  // Remove all separators to get the plain format
  const plainMac = cleanMac.replace(/[:\-\.]/g, '');

  // Validate length (should be exactly 12 hex characters)
  if (plainMac.length !== 12) {
    return { valid: false, error: 'Invalid MAC address length. Must be 12 hex characters.' };
  }

  // Validate that all characters are valid hexadecimal
  const hexRegex = /^[0-9A-F]{12}$/;
  if (!hexRegex.test(plainMac)) {
    return { valid: false, error: 'Invalid MAC address format. Must contain only hexadecimal characters (0-9, A-F).' };
  }

  // Extract OUI (first 6 characters / 3 octets)
  const oui = plainMac.substring(0, 6);

  // Generate all format variations
  const formats = {
    colon: plainMac.match(/.{1,2}/g).join(':'),        // 00:1A:2B:3C:4D:5E
    hyphen: plainMac.match(/.{1,2}/g).join('-'),       // 00-1A-2B-3C-4D-5E
    dot: plainMac.match(/.{1,4}/g).join('.'),          // 001A.2B3C.4D5E
    plain: plainMac                                     // 001A2B3C4D5E
  };

  return {
    valid: true,
    cleanMac: plainMac,
    oui,
    formats
  };
}

/**
 * Lookup vendor information from OUI database
 */
async function lookupVendor(oui) {
  try {
    // mac-lookup expects colon-separated format
    const ouiFormatted = oui.match(/.{1,2}/g).join(':');

    // Perform lookup
    const vendorInfo = await macLookup.lookup(ouiFormatted);

    if (vendorInfo) {
      return {
        success: true,
        vendor: {
          name: vendorInfo,
          // Note: mac-lookup only provides vendor name
          // For more detailed info, would need IEEE database
          address: null,
          country: null
        }
      };
    }

    return {
      success: false,
      error: 'Vendor not found in OUI database'
    };
  } catch (error) {
    // mac-lookup throws error if OUI not found
    if (error.message && error.message.includes('not found')) {
      return {
        success: false,
        error: 'Vendor not found in OUI database'
      };
    }

    logger.error('MAC vendor lookup error:', {
      error: error.message,
      stack: error.stack,
      oui
    });

    return {
      success: false,
      error: 'Failed to lookup vendor information'
    };
  }
}

/**
 * Check if MAC address is in a special reserved range
 */
function checkSpecialMacAddress(mac) {
  const firstOctet = parseInt(mac.substring(0, 2), 16);

  // Check for multicast MAC (LSB of first octet is 1)
  const isMulticast = (firstOctet & 0x01) === 1;

  // Check for locally administered MAC (second LSB of first octet is 1)
  const isLocallyAdministered = (firstOctet & 0x02) === 2;

  // Check for broadcast MAC (FF:FF:FF:FF:FF:FF)
  const isBroadcast = mac === 'FFFFFFFFFFFF';

  return {
    isMulticast,
    isLocallyAdministered,
    isBroadcast,
    isUniversallyAdministered: !isLocallyAdministered
  };
}

/**
 * POST /api/network/mac-lookup
 * Perform MAC address vendor lookup using IEEE OUI database
 */
router.post('/mac-lookup', macLookupRateLimit, async (req, res) => {
  const startTime = Date.now();

  try {
    const { mac } = req.body;

    // Validate and normalize MAC address
    const validation = validateAndNormalizeMac(mac);
    if (!validation.valid) {
      logger.securityLog('Invalid MAC address in lookup', {
        ip: req.ip,
        mac,
        error: validation.error
      });
      return sendError(res, validation.error, 400);
    }

    const { cleanMac, oui, formats } = validation;

    // Check Redis cache (30 day TTL - OUI database rarely changes)
    const cacheKey = `mac-lookup:${oui}`;
    const cached = await redisUtils.get(cacheKey);

    if (cached) {
      logger.info('MAC lookup served from cache', { oui, mac: formats.colon });

      const responseTime = Date.now() - startTime;

      return sendSuccess(res, 'MAC address vendor information retrieved from cache', {
        mac: formats.colon,
        oui: oui.match(/.{1,2}/g).join(':'),
        vendor: cached.vendor,
        formats,
        properties: checkSpecialMacAddress(cleanMac),
        cached: true,
        responseTime,
        timestamp: new Date().toISOString()
      });
    }

    // Perform vendor lookup
    const vendorLookup = await lookupVendor(oui);
    const responseTime = Date.now() - startTime;

    if (!vendorLookup.success) {
      // Still return MAC information even if vendor not found
      logger.info('MAC lookup completed - vendor not found', {
        oui,
        mac: formats.colon,
        responseTime
      });

      return sendSuccess(res, 'MAC address processed, but vendor information not found', {
        mac: formats.colon,
        oui: oui.match(/.{1,2}/g).join(':'),
        vendor: null,
        formats,
        properties: checkSpecialMacAddress(cleanMac),
        cached: false,
        responseTime,
        timestamp: new Date().toISOString(),
        note: 'This OUI is not registered in the database or is from a private/unregistered range'
      }, 200);
    }

    // Prepare response
    const result = {
      mac: formats.colon,
      oui: oui.match(/.{1,2}/g).join(':'),
      vendor: vendorLookup.vendor,
      formats,
      properties: checkSpecialMacAddress(cleanMac),
      cached: false,
      responseTime
    };

    // Cache result for 30 days (2592000 seconds)
    // OUI database is relatively static, changes are infrequent
    await redisUtils.setex(cacheKey, 2592000, { vendor: vendorLookup.vendor });

    logger.info('MAC lookup completed successfully', {
      oui,
      mac: formats.colon,
      vendor: vendorLookup.vendor.name,
      responseTime
    });

    sendSuccess(res, 'MAC address vendor information retrieved successfully', {
      ...result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('MAC lookup error:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    sendError(res, 'Failed to perform MAC address lookup', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/network/mac-validate
 * Validate MAC address format without vendor lookup
 */
router.post('/mac-validate', basicRateLimit, async (req, res) => {
  try {
    const { mac } = req.body;

    // Validate and normalize MAC address
    const validation = validateAndNormalizeMac(mac);

    if (!validation.valid) {
      return sendError(res, validation.error, 400);
    }

    const { cleanMac, oui, formats } = validation;
    const properties = checkSpecialMacAddress(cleanMac);

    logger.info('MAC validation completed', {
      mac: formats.colon,
      ip: req.ip
    });

    sendSuccess(res, 'MAC address is valid', {
      valid: true,
      mac: formats.colon,
      oui: oui.match(/.{1,2}/g).join(':'),
      formats,
      properties,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('MAC validation error:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    sendError(res, 'Failed to validate MAC address', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/network/port-checker
 * Check if port(s) are open on a host
 */
router.post('/port-checker', async (req, res) => {
  const startTime = Date.now();

  try {
    const { host, ports } = req.body;

    // Validate host
    const hostValidation = validateHost(host);
    if (!hostValidation.valid) {
      logger.securityLog('Invalid host in port checker', {
        ip: req.ip,
        host,
        error: hostValidation.error
      });
      return sendError(res, hostValidation.error, 400);
    }

    const cleanHost = hostValidation.cleanHost;

    // Validate ports
    const portValidation = validatePorts(ports);
    if (!portValidation.valid) {
      logger.securityLog('Invalid ports in port checker', {
        ip: req.ip,
        host: cleanHost,
        ports,
        error: portValidation.error
      });
      return sendError(res, portValidation.error, 400);
    }

    const portArray = portValidation.ports;
    const isRangeScan = portArray.length > 1;

    // Apply appropriate rate limiting
    if (isRangeScan) {
      // Check range scan rate limit manually
      const rateLimitKey = `port-check-range:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
      const attempts = await redisUtils.get(rateLimitKey) || 0;

      if (attempts >= 5) {
        logger.securityLog('Port range scan rate limit exceeded', {
          ip: req.ip,
          host: cleanHost,
          ports: portArray,
          attempts
        });
        return sendError(res, 'Port range scan limit exceeded. Please try again in 1 hour.', 429);
      }

      // Increment attempts
      await redisUtils.setex(rateLimitKey, 3600, attempts + 1);
    } else {
      // Check single port rate limit manually
      const rateLimitKey = `port-check-single:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
      const attempts = await redisUtils.get(rateLimitKey) || 0;

      if (attempts >= 20) {
        logger.securityLog('Single port check rate limit exceeded', {
          ip: req.ip,
          host: cleanHost,
          port: portArray[0],
          attempts
        });
        return sendError(res, 'Single port check limit exceeded. Please try again later.', 429);
      }

      // Increment attempts
      await redisUtils.setex(rateLimitKey, 3600, attempts + 1);
    }

    // Detect abuse patterns
    const isAbuse = await detectAbuse(req, cleanHost, portArray);
    if (isAbuse) {
      logger.securityLog('Port scan abuse detected - blocking request', {
        ip: req.ip,
        host: cleanHost,
        ports: portArray
      });
      return sendError(res, 'Abuse detected. Your access has been temporarily restricted.', 429);
    }

    // Check cache for recent scans (5 minute TTL)
    const cacheKey = `port-check:${cleanHost}:${portArray.sort().join(',')}`;
    const cached = await redisUtils.get(cacheKey);

    if (cached) {
      logger.info('Port check served from cache', {
        host: cleanHost,
        ports: portArray
      });
      return sendSuccess(res, 'Port check results retrieved from cache', {
        ...cached,
        cached: true,
        timestamp: new Date().toISOString()
      });
    }

    // Perform port checks
    logger.info('Starting port check', {
      ip: req.ip,
      host: cleanHost,
      ports: portArray,
      isRangeScan
    });

    const checkPromises = portArray.map(port => checkPort(cleanHost, port, 3000));
    const results = await Promise.all(checkPromises);

    const totalTime = Date.now() - startTime;

    // Prepare response
    const response = {
      host: cleanHost,
      results: results.sort((a, b) => a.port - b.port),
      totalPorts: results.length,
      openPorts: results.filter(r => r.status === 'open').length,
      closedPorts: results.filter(r => r.status === 'closed').length,
      filteredPorts: results.filter(r => r.status === 'filtered').length,
      totalResponseTime: totalTime,
      scannedAt: new Date().toISOString(),
      cached: false
    };

    // Cache results for 5 minutes
    await redisUtils.setex(cacheKey, 300, response);

    logger.info('Port check completed', {
      host: cleanHost,
      totalPorts: results.length,
      openPorts: response.openPorts,
      responseTime: totalTime
    });

    sendSuccess(res, 'Port check completed successfully', response);

  } catch (error) {
    logger.error('Port checker error:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    sendError(res, 'Failed to perform port check', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/network/info
 * Get network services information
 */
router.get('/info', async (req, res) => {
  const info = {
    service: 'Network Services',
    version: '1.0.0',
    description: 'Network-related tools including MAC address lookup and port checking',
    services: {
      macLookup: {
        name: 'MAC Address Lookup',
        description: 'Query vendor information from IEEE OUI database',
        endpoints: {
          lookup: 'POST /api/network/mac-lookup',
          validate: 'POST /api/network/mac-validate'
        },
        features: [
          'MAC address vendor lookup (OUI database)',
          'MAC address validation',
          'Multiple MAC format support (colon, hyphen, dot, plain)',
          'MAC address normalization',
          'Special MAC address detection (multicast, broadcast, locally administered)',
          'OUI extraction',
          'Response time measurement',
          'Redis caching with 30-day TTL',
          'Rate limiting: 60 requests per hour'
        ]
      },
      portChecker: {
        name: 'Port Checker',
        description: 'Check if ports are open on remote hosts',
        endpoint: 'POST /api/network/port-checker',
        features: [
          'TCP port connectivity testing',
          'Common service detection',
          'Banner grabbing',
          'Response time measurement',
          'Single port and port range scanning (max 10 ports)',
          'Aggressive rate limiting',
          'Private IP blocking',
          'Abuse pattern detection'
        ]
      }
    },
    features: [
      'TCP port connectivity testing',
      'Common service detection (HTTP, HTTPS, SSH, FTP, SMTP, MySQL, PostgreSQL, etc.)',
      'Optional banner grabbing',
      'Response time measurement',
      'Single port and port range scanning (max 10 ports)',
      'Aggressive rate limiting to prevent abuse',
      'Private IP blocking (prevents internal network scanning)',
      'Abuse pattern detection and blocking',
      'Redis caching with 5-minute TTL',
      'Comprehensive security logging'
    ],
    security: {
      rateLimiting: {
        singlePort: '20 requests per hour per user',
        portRange: '5 requests per hour per user (max 10 ports per scan)'
      },
      protections: [
        'Private IP address blocking (RFC 1918)',
        'Localhost scanning prevention',
        'Reserved IP range blocking',
        'Abuse pattern detection',
        'Automatic blocking on suspicious activity',
        'Comprehensive security event logging',
        '3-second timeout per port'
      ],
      blockedTargets: [
        'localhost (127.0.0.1, ::1)',
        'Private networks (10.x.x.x, 172.16-31.x.x, 192.168.x.x)',
        'Link-local addresses (169.254.x.x, fe80::)',
        'Reserved/special IP ranges',
        'Broadcast addresses'
      ]
    },
    supportedServices: SERVICE_DATABASE,
    limitations: [
      'Maximum 10 ports per request',
      'Single port: 20 checks per hour',
      'Port range: 5 scans per hour',
      '3-second timeout per port',
      'No scanning of private/internal networks',
      'No scanning of localhost',
      'Abuse detection triggers automatic blocking'
    ],
    endpoint: {
      method: 'POST',
      path: '/api/network/port-checker',
      requestBody: {
        host: 'example.com or 93.184.216.34 (required)',
        ports: '80 or [80, 443, 8080] or "80,443,8080" (required, max 10)'
      },
      responseFormat: {
        host: 'string',
        results: 'array of port check results',
        totalPorts: 'number',
        openPorts: 'number',
        closedPorts: 'number',
        filteredPorts: 'number',
        totalResponseTime: 'number (ms)',
        scannedAt: 'ISO 8601',
        cached: 'boolean'
      }
    },
    usage: {
      singlePortExample: {
        request: {
          method: 'POST',
          url: '/api/network/port-checker',
          body: {
            host: 'example.com',
            ports: 80
          }
        },
        response: {
          success: true,
          message: 'Port check completed successfully',
          data: {
            host: 'example.com',
            results: [
              {
                port: 80,
                status: 'open',
                service: 'HTTP',
                responseTime: 45,
                banner: 'nginx/1.18.0'
              }
            ],
            totalPorts: 1,
            openPorts: 1,
            closedPorts: 0,
            filteredPorts: 0,
            totalResponseTime: 52,
            scannedAt: '2025-01-15T10:30:00Z',
            cached: false
          }
        }
      },
      multiplePortsExample: {
        request: {
          method: 'POST',
          url: '/api/network/port-checker',
          body: {
            host: 'example.com',
            ports: [80, 443, 22, 3306]
          }
        },
        response: {
          success: true,
          message: 'Port check completed successfully',
          data: {
            host: 'example.com',
            results: [
              {
                port: 22,
                status: 'closed',
                service: 'SSH/SFTP',
                responseTime: 48,
                banner: null
              },
              {
                port: 80,
                status: 'open',
                service: 'HTTP',
                responseTime: 45,
                banner: 'nginx/1.18.0'
              },
              {
                port: 443,
                status: 'open',
                service: 'HTTPS',
                responseTime: 52,
                banner: null
              },
              {
                port: 3306,
                status: 'filtered',
                service: 'MySQL',
                responseTime: 3002,
                banner: null
              }
            ],
            totalPorts: 4,
            openPorts: 2,
            closedPorts: 1,
            filteredPorts: 1,
            totalResponseTime: 3150,
            scannedAt: '2025-01-15T10:30:00Z',
            cached: false
          }
        }
      }
    }
  };

  sendSuccess(res, 'Port checker service information', info);
});

module.exports = router;
