const express = require('express');
const macLookup = require('mac-lookup');
const whois = require('whois');
const axios = require('axios');
const { basicRateLimit, createCustomRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { redisUtils } = require('../config/redis');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Custom rate limiter for network lookup endpoints
 * 60 requests per hour per user
 */
const networkRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 60,
  message: {
    success: false,
    message: 'Too many network lookup requests. Please try again later.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    // Combine IP + User-Agent for more specific rate limiting
    return `network:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  }
});

/**
 * Custom rate limiter for ASN lookup endpoints
 * 30 requests per hour per user (ASN lookups are more intensive)
 */
const asnRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 30,
  message: {
    success: false,
    message: 'Too many ASN lookup requests. Please try again later.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    return `asn-lookup:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  }
});

/**
 * Validate and normalize ASN format
 * Accepts ASN with or without "AS" prefix
 * Valid range: AS1 - AS4294967295 (32-bit ASN)
 */
function validateAsn(asn) {
  if (!asn) {
    return { valid: false, error: 'ASN is required' };
  }

  // Convert to string and clean
  let cleanAsn = String(asn).trim().toUpperCase();

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
    if (pattern.test(cleanAsn)) {
      return { valid: false, error: 'Suspicious input detected' };
    }
  }

  // Remove "AS" prefix if present
  const asnNumber = cleanAsn.replace(/^AS/i, '');

  // Validate that it's a number
  if (!/^\d+$/.test(asnNumber)) {
    return { valid: false, error: 'ASN must be a valid number' };
  }

  const asnInt = parseInt(asnNumber, 10);

  // Validate ASN range (1 to 4294967295 for 32-bit ASN)
  if (asnInt < 1 || asnInt > 4294967295) {
    return {
      valid: false,
      error: 'ASN must be between 1 and 4294967295'
    };
  }

  // Check for reserved ASNs
  const reservedRanges = [
    { start: 0, end: 0, name: 'Reserved' },
    { start: 23456, end: 23456, name: 'AS_TRANS (Documentation)' },
    { start: 64496, end: 64511, name: 'Reserved for Documentation' },
    { start: 64512, end: 65534, name: 'Private Use' },
    { start: 65535, end: 65535, name: 'Reserved' },
    { start: 65536, end: 65551, name: 'Reserved for Documentation' },
    { start: 4200000000, end: 4294967294, name: 'Private Use (32-bit)' },
    { start: 4294967295, end: 4294967295, name: 'Reserved' }
  ];

  let reservedInfo = null;
  for (const range of reservedRanges) {
    if (asnInt >= range.start && asnInt <= range.end) {
      reservedInfo = range.name;
      break;
    }
  }

  return {
    valid: true,
    asn: asnInt,
    asnFormatted: `AS${asnInt}`,
    isReserved: reservedInfo !== null,
    reservedInfo
  };
}

/**
 * Query WHOIS information for ASN
 * Uses Team Cymru's WHOIS service for ASN lookups
 */
function queryAsnWhois(asn) {
  return new Promise((resolve, reject) => {
    const options = {
      server: 'whois.cymru.com',
      query: `-v AS${asn}`,
      timeout: 10000
    };

    whois.lookup(options.query, options, (err, data) => {
      if (err) {
        logger.error('ASN WHOIS lookup error:', {
          error: err.message,
          asn
        });
        return reject(err);
      }

      resolve(data);
    });
  });
}

/**
 * Parse Team Cymru WHOIS response
 */
function parseTeamCymruResponse(data, asn) {
  try {
    const lines = data.split('\n').filter(line => line.trim() && !line.startsWith('#'));

    if (lines.length === 0) {
      return null;
    }

    // Team Cymru format: ASN | Country | Registry | Allocated | AS Name
    const mainLine = lines.find(line => line.includes('|'));

    if (!mainLine) {
      return null;
    }

    const parts = mainLine.split('|').map(p => p.trim());

    if (parts.length < 5) {
      return null;
    }

    return {
      asn: parts[0],
      country: parts[1] || null,
      registry: parts[2] || null,
      allocated: parts[3] || null,
      organization: parts[4] || null
    };
  } catch (error) {
    logger.error('Error parsing Team Cymru response:', {
      error: error.message,
      data
    });
    return null;
  }
}

/**
 * Query RIPEstat Data API for additional ASN information
 */
async function queryRipestat(asn) {
  try {
    const response = await axios.get(`https://stat.ripe.net/data/as-overview/data.json`, {
      params: {
        resource: `AS${asn}`
      },
      timeout: 10000,
      headers: {
        'User-Agent': 'Toolsana-API/1.0'
      }
    });

    if (response.data && response.data.data) {
      const data = response.data.data;
      return {
        holder: data.holder || null,
        announced: data.announced !== undefined ? data.announced : null,
        type: data.type || null,
        block: data.block || null
      };
    }

    return null;
  } catch (error) {
    logger.warn('RIPEstat query failed:', {
      error: error.message,
      asn
    });
    return null;
  }
}

/**
 * Query RIPEstat for ASN prefixes (announced networks)
 */
async function queryAsnPrefixes(asn) {
  try {
    const response = await axios.get(`https://stat.ripe.net/data/announced-prefixes/data.json`, {
      params: {
        resource: `AS${asn}`
      },
      timeout: 10000,
      headers: {
        'User-Agent': 'Toolsana-API/1.0'
      }
    });

    if (response.data && response.data.data && response.data.data.prefixes) {
      const prefixes = response.data.data.prefixes;

      const ipv4Prefixes = prefixes
        .filter(p => p.prefix && p.prefix.includes('.'))
        .map(p => p.prefix)
        .slice(0, 50); // Limit to first 50 prefixes

      const ipv6Prefixes = prefixes
        .filter(p => p.prefix && p.prefix.includes(':'))
        .map(p => p.prefix)
        .slice(0, 50); // Limit to first 50 prefixes

      return {
        ipv4: ipv4Prefixes,
        ipv6: ipv6Prefixes,
        total: prefixes.length
      };
    }

    return { ipv4: [], ipv6: [], total: 0 };
  } catch (error) {
    logger.warn('ASN prefixes query failed:', {
      error: error.message,
      asn
    });
    return { ipv4: [], ipv6: [], total: 0 };
  }
}

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
 * POST /api/network/asn-lookup
 * Perform ASN WHOIS lookup and retrieve routing information
 */
router.post('/asn-lookup', asnRateLimit, async (req, res) => {
  const startTime = Date.now();

  try {
    const { asn } = req.body;

    // Validate ASN
    const validation = validateAsn(asn);
    if (!validation.valid) {
      logger.securityLog('Invalid ASN in lookup', {
        ip: req.ip,
        asn,
        error: validation.error
      });
      return sendError(res, validation.error, 400);
    }

    const { asn: asnInt, asnFormatted, isReserved, reservedInfo } = validation;

    // Check if this is a reserved ASN
    if (isReserved) {
      logger.info('Reserved ASN lookup attempted', {
        asn: asnFormatted,
        reservedInfo,
        ip: req.ip
      });

      return sendSuccess(res, 'Reserved ASN detected', {
        asn: asnFormatted,
        reserved: true,
        reservedInfo,
        note: 'This ASN is reserved and not allocated to any organization',
        responseTime: Date.now() - startTime,
        timestamp: new Date().toISOString()
      });
    }

    // Check Redis cache (7 day TTL - ASN info changes infrequently)
    const cacheKey = `asn-lookup:${asnInt}`;
    const cached = await redisUtils.get(cacheKey);

    if (cached) {
      logger.info('ASN lookup served from cache', { asn: asnFormatted });

      const responseTime = Date.now() - startTime;

      return sendSuccess(res, 'ASN information retrieved from cache', {
        ...cached,
        cached: true,
        responseTime,
        timestamp: new Date().toISOString()
      });
    }

    // Perform WHOIS lookup
    logger.info('Performing ASN WHOIS lookup', {
      asn: asnFormatted,
      ip: req.ip
    });

    let whoisData = null;
    try {
      const whoisResponse = await queryAsnWhois(asnInt);
      whoisData = parseTeamCymruResponse(whoisResponse, asnInt);
    } catch (error) {
      logger.warn('WHOIS lookup failed, continuing with RIPEstat', {
        asn: asnFormatted,
        error: error.message
      });
    }

    // Query RIPEstat for additional information
    const [ripestatData, prefixesData] = await Promise.all([
      queryRipestat(asnInt),
      queryAsnPrefixes(asnInt)
    ]);

    const responseTime = Date.now() - startTime;

    // If no data found from any source
    if (!whoisData && !ripestatData) {
      logger.info('ASN not found in any database', {
        asn: asnFormatted,
        responseTime
      });

      return sendSuccess(res, 'ASN not found', {
        asn: asnFormatted,
        found: false,
        note: 'This ASN may not be allocated or is not yet announced in BGP',
        responseTime,
        timestamp: new Date().toISOString()
      }, 404);
    }

    // Combine data from all sources
    const result = {
      asn: asnFormatted,
      organization: whoisData?.organization || ripestatData?.holder || null,
      fullName: ripestatData?.holder || whoisData?.organization || null,
      registry: whoisData?.registry || null,
      country: whoisData?.country || null,
      allocated: whoisData?.allocated || null,
      type: ripestatData?.type || null,
      announced: ripestatData?.announced,
      prefixes: {
        ipv4: prefixesData.ipv4,
        ipv6: prefixesData.ipv6,
        total: prefixesData.total
      },
      contact: {
        // Contact information would come from RIR WHOIS if needed
        email: null
      },
      cached: false,
      responseTime
    };

    // Cache result for 7 days (604800 seconds)
    await redisUtils.setex(cacheKey, 604800, result);

    logger.info('ASN lookup completed successfully', {
      asn: asnFormatted,
      organization: result.organization,
      registry: result.registry,
      responseTime
    });

    sendSuccess(res, 'ASN information retrieved successfully', {
      ...result,
      timestamp: new Date().toISOString()
    });

  } catch (error) {
    logger.error('ASN lookup error:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    sendError(res, 'Failed to perform ASN lookup', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * POST /api/network/mac-lookup
 * Perform MAC address vendor lookup using IEEE OUI database
 */
router.post('/mac-lookup', networkRateLimit, async (req, res) => {
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
 * GET /api/network/info
 * Get network lookup service information
 */
router.get('/info', basicRateLimit, (req, res) => {
  const info = {
    service: 'Network Lookup Service',
    version: '1.0.0',
    description: 'Query network-related information including ASN and MAC address lookups',
    features: [
      'ASN (Autonomous System Number) WHOIS lookup',
      'BGP routing prefix information',
      'MAC address vendor lookup (OUI database)',
      'MAC address validation',
      'Multiple MAC format support (colon, hyphen, dot, plain)',
      'MAC address normalization',
      'Special MAC address detection (multicast, broadcast, locally administered)',
      'OUI extraction',
      'Response time measurement',
      'Redis caching with long TTL',
      'Rate limiting protection',
      'Input sanitization and validation',
      'Comprehensive error handling'
    ],
    endpoints: {
      asnLookup: {
        method: 'POST',
        path: '/api/network/asn-lookup',
        description: 'Lookup ASN information including organization, registry, and prefixes',
        rateLimit: {
          requests: 30,
          window: '1 hour'
        },
        requestBody: {
          asn: 'ASN number with or without AS prefix (e.g., "15169" or "AS15169") (required)'
        },
        responseFormat: {
          asn: 'string (formatted with AS prefix)',
          organization: 'string (short name)',
          fullName: 'string (full organization name)',
          registry: 'string (ARIN, RIPE, APNIC, etc.)',
          country: 'string (ISO country code)',
          allocated: 'string (allocation date)',
          type: 'string (ASN type)',
          announced: 'boolean (whether announced in BGP)',
          prefixes: {
            ipv4: 'array of IPv4 prefixes',
            ipv6: 'array of IPv6 prefixes',
            total: 'number (total prefix count)'
          },
          contact: {
            email: 'string (contact email if available)'
          },
          cached: 'boolean',
          responseTime: 'number (ms)',
          timestamp: 'ISO 8601'
        },
        cacheTTL: '7 days'
      },
      macLookup: {
        method: 'POST',
        path: '/api/network/mac-lookup',
        description: 'Lookup vendor information for a MAC address',
        rateLimit: {
          requests: 60,
          window: '1 hour'
        },
        requestBody: {
          mac: 'MAC address in any format (required)'
        },
        supportedFormats: [
          '00:1A:2B:3C:4D:5E (colon-separated)',
          '00-1A-2B-3C-4D-5E (hyphen-separated)',
          '001A.2B3C.4D5E (dot-separated Cisco format)',
          '001A2B3C4D5E (plain format)'
        ],
        responseFormat: {
          mac: 'string (normalized colon format)',
          oui: 'string (first 3 octets)',
          vendor: {
            name: 'string',
            address: 'string (if available)',
            country: 'string (if available)'
          },
          formats: {
            colon: 'string',
            hyphen: 'string',
            dot: 'string',
            plain: 'string'
          },
          properties: {
            isMulticast: 'boolean',
            isLocallyAdministered: 'boolean',
            isBroadcast: 'boolean',
            isUniversallyAdministered: 'boolean'
          },
          cached: 'boolean',
          responseTime: 'number (ms)',
          timestamp: 'ISO 8601'
        },
        cacheTTL: '30 days'
      },
      macValidate: {
        method: 'POST',
        path: '/api/network/mac-validate',
        description: 'Validate MAC address format without vendor lookup',
        rateLimit: {
          requests: 100,
          window: '15 minutes'
        },
        requestBody: {
          mac: 'MAC address in any format (required)'
        },
        responseFormat: {
          valid: 'boolean',
          mac: 'string (normalized)',
          oui: 'string',
          formats: 'object',
          properties: 'object',
          timestamp: 'ISO 8601'
        }
      }
    },
    caching: {
      enabled: true,
      backend: 'Redis',
      ttl: {
        asnLookup: '7 days (ASN information rarely changes)',
        macLookup: '30 days (OUI database is relatively static)'
      }
    },
    security: {
      inputValidation: true,
      xssProtection: true,
      suspiciousInputDetection: true,
      rateLimiting: true,
      ipBasedLimiting: true,
      reservedAsnDetection: true
    },
    dataSources: {
      asnWhois: 'Team Cymru WHOIS service (whois.cymru.com)',
      asnData: 'RIPEstat Data API',
      prefixes: 'RIPEstat Announced Prefixes API',
      macVendor: 'IEEE OUI database via mac-lookup'
    },
    limitations: [
      'ASN lookup: 30 requests per hour per user',
      'MAC lookup: 60 requests per hour per user',
      'ASN range: 1 to 4294967295 (32-bit)',
      'Reserved ASNs are detected but return limited information',
      'Prefix lists limited to first 50 IPv4 and 50 IPv6 prefixes',
      'Contact information may not be available for all ASNs',
      'OUI database may not include all vendors',
      'Private/unregistered MAC addresses will not return vendor info'
    ],
    usage: {
      asnLookupExample: {
        request: {
          method: 'POST',
          url: '/api/network/asn-lookup',
          body: { asn: 'AS15169' }
        },
        response: {
          success: true,
          message: 'ASN information retrieved successfully',
          data: {
            asn: 'AS15169',
            organization: 'GOOGLE',
            fullName: 'Google LLC',
            registry: 'ARIN',
            country: 'US',
            allocated: '2000-03-30',
            type: 'Content',
            announced: true,
            prefixes: {
              ipv4: ['8.8.8.0/24', '8.8.4.0/24'],
              ipv6: ['2001:4860::/32'],
              total: 256
            },
            contact: {
              email: null
            },
            cached: false,
            responseTime: 1245,
            timestamp: '2025-01-25T10:30:00Z'
          }
        }
      },
      macLookupExample: {
        request: {
          method: 'POST',
          url: '/api/network/mac-lookup',
          body: { mac: '00:1A:2B:3C:4D:5E' }
        },
        response: {
          success: true,
          message: 'MAC address vendor information retrieved successfully',
          data: {
            mac: '00:1A:2B:3C:4D:5E',
            oui: '00:1A:2B',
            vendor: {
              name: 'Cisco Systems, Inc',
              address: null,
              country: null
            },
            formats: {
              colon: '00:1A:2B:3C:4D:5E',
              hyphen: '00-1A-2B-3C-4D-5E',
              dot: '001A.2B3C.4D5E',
              plain: '001A2B3C4D5E'
            },
            properties: {
              isMulticast: false,
              isLocallyAdministered: false,
              isBroadcast: false,
              isUniversallyAdministered: true
            },
            cached: false,
            responseTime: 5,
            timestamp: '2025-01-25T10:30:00Z'
          }
        }
      }
    },
    notes: [
      'ASN lookups query multiple sources for comprehensive information',
      'Team Cymru WHOIS provides basic allocation data',
      'RIPEstat API provides detailed routing and prefix information',
      'MAC addresses are case-insensitive',
      'All response MAC addresses are normalized to uppercase colon-separated format',
      'OUI (Organizationally Unique Identifier) is the first 3 octets (6 hex digits)',
      'Multicast MACs have LSB of first octet set to 1',
      'Locally administered MACs have second LSB of first octet set to 1',
      'Broadcast MAC is FF:FF:FF:FF:FF:FF',
      'Reserved ASNs (0, 23456, 64496-64511, 64512-65534, etc.) are detected',
      'ASN prefix lists are limited to 50 entries per IP version for performance'
    ]
  };

  sendSuccess(res, 'Network service information', info);
});

module.exports = router;
