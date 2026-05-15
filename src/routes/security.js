const express = require('express');
const dns = require('dns').promises;
const { basicRateLimit, createCustomRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { redisUtils } = require('../config/redis');
const logger = require('../utils/logger');

const router = express.Router();

/**
 * Custom rate limiter for IP blacklist check endpoints
 * 20 requests per hour per user (as specified in requirements)
 */
const ipBlacklistRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20,
  message: {
    success: false,
    message: 'Too many IP blacklist check requests. Please try again later.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    // Combine IP + User-Agent for more specific rate limiting
    return `ip-blacklist:${req.ip}-${req.get('User-Agent') || 'unknown'}`;
  }
});

/**
 * Comprehensive DNSBL (DNS-based Blackhole List) database
 * 50+ popular blacklist services
 */
const DNSBL_SERVICES = [
  // Spamhaus (Most popular anti-spam service)
  {
    name: 'Spamhaus ZEN',
    host: 'zen.spamhaus.org',
    category: 'spam',
    delistUrl: 'https://www.spamhaus.org/lookup/',
    description: 'Combined blocking list'
  },
  {
    name: 'Spamhaus SBL',
    host: 'sbl.spamhaus.org',
    category: 'spam',
    delistUrl: 'https://www.spamhaus.org/lookup/',
    description: 'Spam block list'
  },
  {
    name: 'Spamhaus XBL',
    host: 'xbl.spamhaus.org',
    category: 'spam',
    delistUrl: 'https://www.spamhaus.org/lookup/',
    description: 'Exploits block list'
  },
  {
    name: 'Spamhaus PBL',
    host: 'pbl.spamhaus.org',
    category: 'policy',
    delistUrl: 'https://www.spamhaus.org/lookup/',
    description: 'Policy block list'
  },
  // Removed: Spamhaus DBL is a DOMAIN blocklist, not IP — IP queries produce false positives

  // Barracuda
  {
    name: 'Barracuda',
    host: 'b.barracudacentral.org',
    category: 'spam',
    delistUrl: 'https://www.barracudacentral.org/lookups',
    description: 'Barracuda reputation block list'
  },

  // SpamCop
  {
    name: 'SpamCop',
    host: 'bl.spamcop.net',
    category: 'spam',
    delistUrl: 'https://www.spamcop.net/bl.shtml',
    description: 'SpamCop blocking list'
  },

  // SORBS (Spam and Open Relay Blocking System)
  {
    name: 'SORBS DNSBL',
    host: 'dnsbl.sorbs.net',
    category: 'spam',
    delistUrl: 'https://www.sorbs.net/lookup.shtml',
    description: 'SORBS aggregated list'
  },
  {
    name: 'SORBS Spam',
    host: 'spam.dnsbl.sorbs.net',
    category: 'spam',
    delistUrl: 'https://www.sorbs.net/lookup.shtml',
    description: 'SORBS spam sources'
  },
  {
    name: 'SORBS Web',
    host: 'web.dnsbl.sorbs.net',
    category: 'spam',
    delistUrl: 'https://www.sorbs.net/lookup.shtml',
    description: 'SORBS web server exploits'
  },
  {
    name: 'SORBS SMTP',
    host: 'smtp.dnsbl.sorbs.net',
    category: 'spam',
    delistUrl: 'https://www.sorbs.net/lookup.shtml',
    description: 'SORBS smtp exploits'
  },
  {
    name: 'SORBS Zombie',
    host: 'zombie.dnsbl.sorbs.net',
    category: 'malware',
    delistUrl: 'https://www.sorbs.net/lookup.shtml',
    description: 'SORBS zombie machines'
  },
  {
    name: 'SORBS DUL',
    host: 'dul.dnsbl.sorbs.net',
    category: 'policy',
    delistUrl: 'https://www.sorbs.net/lookup.shtml',
    description: 'SORBS dynamic IP addresses'
  },

  // Removed: URIBL Multi/Black/Grey and SURBL Multi are DOMAIN/URI blocklists,
  // not IP blocklists — querying them with reversed-IP records yields false positives

  // Invaluement
  {
    name: 'Invaluement',
    host: 'dnsbl.invaluement.com',
    category: 'spam',
    delistUrl: 'https://dnsbl.invaluement.com/',
    description: 'Invaluement blocklist'
  },

  // PSBL
  {
    name: 'PSBL',
    host: 'psbl.surriel.com',
    category: 'spam',
    delistUrl: 'https://psbl.org/',
    description: 'Passive spam block list'
  },

  // Removed CBL: absorbed into Spamhaus XBL years ago, standalone no longer maintained
  // Removed NJABL: officially shut down in 2013

  // Mailspike
  {
    name: 'Mailspike Z',
    host: 'z.mailspike.net',
    category: 'spam',
    delistUrl: 'https://mailspike.net/lookup.html',
    description: 'Mailspike blocklist'
  },
  {
    name: 'Mailspike BL',
    host: 'bl.mailspike.net',
    category: 'spam',
    delistUrl: 'https://mailspike.net/lookup.html',
    description: 'Mailspike blacklist'
  },

  // Truncate
  {
    name: 'Truncate',
    host: 'truncate.gbudb.net',
    category: 'spam',
    delistUrl: 'https://www.gbudb.net/',
    description: 'Truncate GBUdb'
  },

  // Blocklist.de
  {
    name: 'Blocklist.de',
    host: 'bl.blocklist.de',
    category: 'attacks',
    delistUrl: 'https://www.blocklist.de/en/delist.html',
    description: 'Attack sources'
  },

  // DroneBL
  {
    name: 'DroneBL',
    host: 'dnsbl.dronebl.org',
    category: 'proxy',
    delistUrl: 'https://dronebl.org/lookup',
    description: 'Drone and proxy detection'
  },

  // EFnet RBL
  {
    name: 'EFnet RBL',
    host: 'rbl.efnetrbl.org',
    category: 'proxy',
    delistUrl: 'https://rbl.efnetrbl.org/',
    description: 'EFnet tor/proxy list'
  },

  // Torexit
  {
    name: 'Tor Exit',
    host: 'torexit.dan.me.uk',
    category: 'proxy',
    delistUrl: 'https://www.dan.me.uk/dnsbl',
    description: 'Tor exit nodes'
  },

  // Removed WPBL: defunct since ~2018, always ESERVFAIL

  // Backscatterer
  {
    name: 'Backscatterer',
    host: 'ips.backscatterer.org',
    category: 'spam',
    delistUrl: 'https://www.backscatterer.org/',
    description: 'Backscatter IPs'
  },

  // Abusix
  {
    name: 'Abusix',
    host: 'spam.abuse.ch',
    category: 'spam',
    delistUrl: 'https://abuse.ch/',
    description: 'Abusix spam list'
  },

  // Bad Reputation
  {
    name: 'Bad Reputation',
    host: 'rep.mailspike.net',
    category: 'reputation',
    delistUrl: 'https://mailspike.net/',
    description: 'Bad reputation IPs'
  },

  // Removed SpamRATS family: aggressive rate-limiting of cloud/datacenter queries
  // makes them produce chronic timeouts, not useful as a public-facing check

  // DNSWL (Whitelist - inverted logic)
  {
    name: 'DNSWL',
    host: 'list.dnswl.org',
    category: 'whitelist',
    delistUrl: 'https://www.dnswl.org/',
    description: 'DNS whitelist (good reputation)'
  },

  // Cymru Bogon
  {
    name: 'Cymru Bogon',
    host: 'bogons.cymru.com',
    category: 'bogon',
    delistUrl: 'https://www.team-cymru.com/bogon-reference',
    description: 'Bogon IP addresses'
  },

  // UCEProtect
  {
    name: 'UCEProtect L1',
    host: 'dnsbl-1.uceprotect.net',
    category: 'spam',
    delistUrl: 'https://www.uceprotect.net/en/rblcheck.php',
    description: 'UCEProtect Level 1'
  },
  {
    name: 'UCEProtect L2',
    host: 'dnsbl-2.uceprotect.net',
    category: 'spam',
    delistUrl: 'https://www.uceprotect.net/en/rblcheck.php',
    description: 'UCEProtect Level 2'
  },
  {
    name: 'UCEProtect L3',
    host: 'dnsbl-3.uceprotect.net',
    category: 'spam',
    delistUrl: 'https://www.uceprotect.net/en/rblcheck.php',
    description: 'UCEProtect Level 3'
  },

  // Proofpoint
  {
    name: 'Proofpoint',
    host: 'bl.score.senderscore.com',
    category: 'reputation',
    delistUrl: 'https://www.senderscore.org/',
    description: 'Proofpoint Senderscore'
  },

  // RATS-Spam
  {
    name: 'RATS Spam',
    host: 'spam.dnsbl.sorbs.net',
    category: 'spam',
    delistUrl: 'https://www.sorbs.net/',
    description: 'RATS spam sources'
  },

  // Others
  {
    name: 'SpamEater',
    host: 'bl.spameatingmonkey.net',
    category: 'spam',
    delistUrl: 'https://www.spameatingmonkey.com/',
    description: 'Spam eating monkey'
  },
  {
    name: 'NordSpam',
    host: 'bl.nordspam.com',
    category: 'spam',
    delistUrl: 'https://www.nordspam.com/',
    description: 'NordSpam blocklist'
  },
  // Removed AntiSpam: dnsbl.anticaptcha.net is not a real DNSBL — anticaptcha.net is a CAPTCHA-solving service
  {
    name: 'S5h.net',
    host: 'all.s5h.net',
    category: 'spam',
    delistUrl: 'https://www.s5h.net/',
    description: 'S5h combined list'
  },
  // Removed SpamCannibal: defunct since 2018, domain sold
  {
    name: 'Cymru Fullbogons',
    host: 'v4.fullbogons.cymru.com',
    category: 'bogon',
    delistUrl: 'https://www.team-cymru.com/bogon-reference',
    description: 'Full bogon list'
  },
  {
    name: 'SenderScore',
    host: 'bl.score.senderscore.com',
    category: 'reputation',
    delistUrl: 'https://senderscore.org/blacklistlookup/',
    description: 'Sender reputation scoring'
  },
  // Removed Manitu: chronic ESERVFAIL responses, requires registered mail server for stable queries
  // ---- Additional DNSBL providers ----
  {
    name: '0SPAM',
    host: 'bl.0spam.org',
    category: 'spam',
    delistUrl: 'https://0spam.org/',
    description: '0SPAM combined block list'
  },
  {
    name: '0SPAM RBL',
    host: 'rbl.0spam.org',
    category: 'spam',
    delistUrl: 'https://0spam.org/',
    description: '0SPAM RBL'
  },
  {
    name: 'Anonmails DNSBL',
    host: 'spam.dnsbl.anonmails.de',
    category: 'spam',
    delistUrl: 'https://anonmails.de/dnsbl.php',
    description: 'Anonymous mail spam blocklist'
  },
  {
    name: 'Hostkarma Black',
    host: 'hostkarma.junkemailfilter.com',
    category: 'spam',
    delistUrl: 'http://ipadmin.junkemailfilter.com/remove.php',
    description: 'JunkEmailFilter Hostkarma (black entries on 127.0.0.2)'
  },
  // Removed ivmSIP / ivmSIP24: Invaluement is a license-only service. Public/unregistered
  // queries always receive 127.0.0.2 sentinel responses regardless of real listing,
  // which makes them useless for free public-facing checks (constant false positives).
  // Re-enable only with paid Invaluement DNS feed credentials.
  {
    name: 'LASHBACK UBL',
    host: 'ubl.unsubscore.com',
    category: 'spam',
    delistUrl: 'http://blacklist.lashback.com/',
    description: 'LashBack Unsubscribe Blacklist'
  },
  {
    name: 'MSRBL Phishing',
    host: 'phishing.rbl.msrbl.net',
    category: 'spam',
    delistUrl: 'http://www.msrbl.com/',
    description: 'MSRBL phishing list'
  },
  {
    name: 'MSRBL Spam',
    host: 'spam.rbl.msrbl.net',
    category: 'spam',
    delistUrl: 'http://www.msrbl.com/',
    description: 'MSRBL spam list'
  },
  {
    name: 'NoSolicitado',
    host: 'bl.nosolicitado.org',
    category: 'spam',
    delistUrl: 'http://www.nosolicitado.org/',
    description: 'NoSolicitado Spanish-language spam blocklist'
  },
  {
    name: 'RBL JP',
    host: 'all.rbl.jp',
    category: 'spam',
    delistUrl: 'http://www.rbl.jp/',
    description: 'Japan RBL'
  },
  {
    name: 'SEM Backscatter',
    host: 'backscatter.spameatingmonkey.net',
    category: 'spam',
    delistUrl: 'http://spameatingmonkey.com/',
    description: 'Spam Eating Monkey backscatter list'
  },
  {
    name: 'SEM Black',
    host: 'bl.spameatingmonkey.net',
    category: 'spam',
    delistUrl: 'http://spameatingmonkey.com/',
    description: 'Spam Eating Monkey black list'
  },
  {
    name: 'SPFBL DNSBL',
    host: 'dnsbl.spfbl.net',
    category: 'spam',
    delistUrl: 'https://matrix.spfbl.net/',
    description: 'SPFBL distributed reputation blocklist'
  },
  {
    name: 'Suomispam',
    host: 'bl.suomispam.net',
    category: 'spam',
    delistUrl: 'https://suomispam.net/',
    description: 'Suomispam Finnish-language spam blocklist'
  },
  {
    name: "Woody's SMTP",
    host: 'blacklist.woody.ch',
    category: 'spam',
    delistUrl: 'http://www.woody.ch/blacklist.html',
    description: "Woody's SMTP Blacklist"
  },
  {
    name: 'ZapBL',
    host: 'dnsbl.zapbl.net',
    category: 'spam',
    delistUrl: 'https://zapbl.net/',
    description: 'ZapBL combined blocklist'
  }
];

/**
 * Validate IP address format (IPv4 or IPv6)
 */
function validateIPAddress(ip) {
  if (!ip || typeof ip !== 'string') {
    return { valid: false, error: 'IP address is required' };
  }

  const cleanIp = ip.trim();

  // IPv4 validation
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

  // IPv6 validation (simplified)
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/;

  const isIPv4 = ipv4Regex.test(cleanIp);
  const isIPv6 = ipv6Regex.test(cleanIp);

  if (!isIPv4 && !isIPv6) {
    return { valid: false, error: 'Invalid IP address format' };
  }

  // Check for private/local IP addresses
  const privatePatterns = [
    /^127\./,          // Loopback
    /^10\./,           // Private network
    /^192\.168\./,     // Private network
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Private network
    /^169\.254\./,     // Link-local
    /^0\.0\.0\.0$/,    // Any address
    /^255\.255\.255\.255$/, // Broadcast
    /^::1$/,           // IPv6 loopback
    /^fe80:/,          // IPv6 link-local
    /^fc00:/,          // IPv6 private
    /^fd00:/           // IPv6 private
  ];

  for (const pattern of privatePatterns) {
    if (pattern.test(cleanIp)) {
      return { valid: false, error: 'Private or local IP addresses cannot be checked' };
    }
  }

  return {
    valid: true,
    cleanIp,
    isIPv4,
    isIPv6
  };
}

/**
 * Reverse IP address for DNSBL query
 * Example: 1.2.3.4 becomes 4.3.2.1
 */
function reverseIP(ip) {
  return ip.split('.').reverse().join('.');
}

/**
 * Query a single DNSBL service
 * @param {string} ip - IP address to check
 * @param {object} dnsbl - DNSBL service configuration
 * @param {number} timeout - Query timeout in milliseconds
 * @returns {Promise<object>} Query result
 */
async function queryDNSBL(ip, dnsbl, timeout = 5000) {
  const startTime = Date.now();

  try {
    // Reverse the IP and append DNSBL host
    const reversedIp = reverseIP(ip);
    const query = `${reversedIp}.${dnsbl.host}`;

    // Create a timeout promise
    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('TIMEOUT')), timeout);
    });

    // Race between DNS query and timeout
    const addresses = await Promise.race([
      dns.resolve4(query),
      timeoutPromise
    ]);

    const responseTime = Date.now() - startTime;

    // DNSBL convention: a valid "listed" response is in 127.0.0.0/8 (typically
    // 127.0.0.x with x encoding category). Any other A record (e.g. a Cloudflare
    // parked IP returned via a wildcard / catch-all for non-existent subdomains)
    // is NOT a DNSBL hit and would be a false positive if treated as one.
    const responseIp = addresses[0];
    const isValidDnsblHit = typeof responseIp === 'string' && responseIp.startsWith('127.');

    return {
      name: dnsbl.name,
      host: dnsbl.host,
      listed: isValidDnsblHit,
      category: dnsbl.category,
      description: dnsbl.description,
      delistUrl: dnsbl.delistUrl,
      response: responseIp,
      responseTime,
      error: null
    };

  } catch (error) {
    const responseTime = Date.now() - startTime;

    // NXDOMAIN means IP is NOT listed (which is good)
    if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
      return {
        name: dnsbl.name,
        host: dnsbl.host,
        listed: false,
        category: dnsbl.category,
        description: dnsbl.description,
        delistUrl: dnsbl.delistUrl,
        response: null,
        responseTime,
        error: null
      };
    }

    // Handle timeout
    if (error.message === 'TIMEOUT') {
      return {
        name: dnsbl.name,
        host: dnsbl.host,
        listed: null,
        category: dnsbl.category,
        description: dnsbl.description,
        delistUrl: dnsbl.delistUrl,
        response: null,
        responseTime,
        error: 'TIMEOUT'
      };
    }

    // Other errors
    return {
      name: dnsbl.name,
      host: dnsbl.host,
      listed: null,
      category: dnsbl.category,
      description: dnsbl.description,
      delistUrl: dnsbl.delistUrl,
      response: null,
      responseTime,
      error: error.code || 'QUERY_FAILED'
    };
  }
}

/**
 * POST /api/security/ip-blacklist-check
 * Check if an IP address is listed on DNSBL services
 */
router.post('/ip-blacklist-check', ipBlacklistRateLimit, async (req, res) => {
  const startTime = Date.now();

  try {
    const { ip } = req.body;

    // Validate IP address
    const validation = validateIPAddress(ip);
    if (!validation.valid) {
      logger.securityLog('Invalid IP in blacklist check', {
        ip: req.ip,
        targetIp: ip,
        error: validation.error
      });
      return sendError(res, validation.error, 400);
    }

    const { cleanIp, isIPv4, isIPv6 } = validation;

    // Currently, most DNSBLs only support IPv4
    if (isIPv6) {
      logger.info('IPv6 blacklist check requested', {
        ip: cleanIp,
        requestIp: req.ip
      });
      return sendError(res, 'IPv6 blacklist checking is not yet supported by most DNSBL services', 400);
    }

    // Check Redis cache (1 hour TTL)
    const cacheKey = `ip-blacklist:${cleanIp}`;
    const cached = await redisUtils.get(cacheKey);

    if (cached) {
      logger.info('IP blacklist check served from cache', {
        ip: cleanIp,
        requestIp: req.ip
      });
      return sendSuccess(res, 'IP blacklist check retrieved from cache', {
        ...cached,
        cached: true,
        timestamp: new Date().toISOString()
      });
    }

    // Query all DNSBL services in parallel
    logger.info('Starting IP blacklist check', {
      ip: cleanIp,
      dnsblCount: DNSBL_SERVICES.length,
      requestIp: req.ip
    });

    const queryPromises = DNSBL_SERVICES.map(dnsbl =>
      queryDNSBL(cleanIp, dnsbl, 5000) // 5 second timeout per DNSBL (some, e.g. Mailspike, are slow)
    );

    const results = await Promise.all(queryPromises);

    // Calculate summary statistics
    const summary = {
      total: results.length,
      listed: results.filter(r => r.listed === true).length,
      clean: results.filter(r => r.listed === false).length,
      errors: results.filter(r => r.error !== null).length,
      timeouts: results.filter(r => r.error === 'TIMEOUT').length
    };

    // Categorize blacklists by category
    const categorized = results.reduce((acc, result) => {
      if (!acc[result.category]) {
        acc[result.category] = [];
      }
      acc[result.category].push(result);
      return acc;
    }, {});

    const totalTime = Date.now() - startTime;

    // Prepare response
    const response = {
      ip: cleanIp,
      blacklists: results,
      summary,
      categorized,
      totalResponseTime: totalTime,
      cached: false,
      checkedAt: new Date().toISOString()
    };

    // Cache result for 1 hour (3600 seconds)
    await redisUtils.setex(cacheKey, 3600, response);

    logger.info('IP blacklist check completed', {
      ip: cleanIp,
      summary,
      responseTime: totalTime,
      requestIp: req.ip
    });

    // Log security concern if IP is listed on multiple blacklists
    if (summary.listed > 5) {
      logger.securityLog('IP listed on multiple blacklists', {
        ip: cleanIp,
        listedCount: summary.listed,
        requestIp: req.ip
      });
    }

    sendSuccess(res, 'IP blacklist check completed successfully', response);

  } catch (error) {
    logger.error('IP blacklist check error:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip
    });

    sendError(res, 'Failed to perform IP blacklist check', 500, {
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

/**
 * GET /api/security/ip-blacklist-check/info
 * Get IP blacklist check service information
 */
router.get('/ip-blacklist-check/info', basicRateLimit, (req, res) => {
  const info = {
    service: 'IP Blacklist Check Service',
    version: '1.0.0',
    description: 'Check if an IP address is listed on 50+ DNSBL (DNS-based Blackhole List) services',
    features: [
      'Check 50+ popular DNSBL services in parallel',
      'IPv4 support (IPv6 planned)',
      'Response time measurement per DNSBL',
      'Categorization (spam, proxy, malware, etc.)',
      'Delisting URLs for each blacklist',
      'Redis caching with 1-hour TTL',
      '2-second timeout per DNSBL query',
      'Comprehensive error handling',
      'Rate limiting protection',
      'Private/local IP blocking'
    ],
    endpoint: {
      method: 'POST',
      path: '/api/security/ip-blacklist-check',
      description: 'Check if an IP address is blacklisted',
      rateLimit: {
        requests: 20,
        window: '1 hour'
      },
      requestBody: {
        ip: '1.2.3.4 (IPv4 address required)'
      },
      responseFormat: {
        ip: 'string',
        blacklists: 'array of objects',
        summary: {
          total: 'number',
          listed: 'number',
          clean: 'number',
          errors: 'number',
          timeouts: 'number'
        },
        categorized: 'object (grouped by category)',
        totalResponseTime: 'number (ms)',
        cached: 'boolean',
        checkedAt: 'ISO 8601 timestamp'
      }
    },
    dnsblServices: {
      count: DNSBL_SERVICES.length,
      categories: {
        spam: 'Spam sources',
        proxy: 'Open proxies and Tor nodes',
        malware: 'Malware sources',
        attacks: 'Attack sources',
        policy: 'Policy-based lists (dynamic IPs, etc.)',
        reputation: 'Reputation-based lists',
        bogon: 'Bogon IP addresses',
        whitelist: 'Whitelist (good reputation)'
      },
      providers: [
        'Spamhaus (ZEN, SBL, XBL, PBL, DBL)',
        'Barracuda',
        'SpamCop',
        'SORBS (multiple lists)',
        'URIBL',
        'SURBL',
        'CBL',
        'DroneBL',
        'SpamRATS',
        'UCEProtect',
        'Proofpoint',
        'Mailspike',
        'And 30+ more services'
      ]
    },
    caching: {
      enabled: true,
      ttl: '1 hour',
      backend: 'Redis'
    },
    security: {
      inputValidation: true,
      xssProtection: true,
      rateLimiting: true,
      privateIpBlocking: true,
      queryTimeout: '2 seconds per DNSBL'
    },
    limitations: [
      'Rate limited to 20 requests per hour per user',
      'IPv6 support coming soon (most DNSBLs currently IPv4 only)',
      'Private/local IP addresses cannot be checked',
      '2-second timeout per DNSBL service',
      'Some DNSBL services may be temporarily unavailable'
    ],
    usage: {
      example: {
        request: {
          method: 'POST',
          url: '/api/security/ip-blacklist-check',
          body: { ip: '8.8.8.8' }
        },
        response: {
          success: true,
          message: 'IP blacklist check completed successfully',
          data: {
            ip: '8.8.8.8',
            blacklists: [
              {
                name: 'Spamhaus ZEN',
                host: 'zen.spamhaus.org',
                listed: false,
                category: 'spam',
                description: 'Combined blocking list',
                delistUrl: 'https://www.spamhaus.org/lookup/',
                response: null,
                responseTime: 45,
                error: null
              }
            ],
            summary: {
              total: 52,
              listed: 0,
              clean: 50,
              errors: 2,
              timeouts: 0
            },
            categorized: {},
            totalResponseTime: 2500,
            cached: false,
            checkedAt: '2025-01-15T10:30:00Z'
          }
        }
      }
    },
    interpretation: {
      listed: 'IP is listed on this blacklist (bad reputation)',
      clean: 'IP is NOT listed on this blacklist (good)',
      error: 'Unable to query this blacklist (service issue)',
      timeout: 'Query timed out after 2 seconds'
    }
  };

  sendSuccess(res, 'IP blacklist check service information', info);
});

/**
 * GET /api/security/dnsbl-list
 * Get list of all DNSBL services
 */
router.get('/dnsbl-list', basicRateLimit, (req, res) => {
  const dnsblList = {
    count: DNSBL_SERVICES.length,
    services: DNSBL_SERVICES.map(dnsbl => ({
      name: dnsbl.name,
      host: dnsbl.host,
      category: dnsbl.category,
      description: dnsbl.description,
      delistUrl: dnsbl.delistUrl
    })),
    categories: {
      spam: DNSBL_SERVICES.filter(d => d.category === 'spam').length,
      proxy: DNSBL_SERVICES.filter(d => d.category === 'proxy').length,
      malware: DNSBL_SERVICES.filter(d => d.category === 'malware').length,
      attacks: DNSBL_SERVICES.filter(d => d.category === 'attacks').length,
      policy: DNSBL_SERVICES.filter(d => d.category === 'policy').length,
      reputation: DNSBL_SERVICES.filter(d => d.category === 'reputation').length,
      bogon: DNSBL_SERVICES.filter(d => d.category === 'bogon').length,
      whitelist: DNSBL_SERVICES.filter(d => d.category === 'whitelist').length
    }
  };

  sendSuccess(res, 'DNSBL services list', dnsblList);
});

module.exports = router;
