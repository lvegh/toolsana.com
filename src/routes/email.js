const express = require('express');
const { simpleParser } = require('mailparser');
const dns = require('dns').promises;
const net = require('net');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { createCustomRateLimit, ipKey } = require('../middleware/rateLimit');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');
const { sendSuccess, sendError, AppError } = require('../middleware/errorHandler');
const { safeFetch, screenHostname } = require('../utils/ssrfGuard');
const { logOutbound } = require('../utils/outboundLog');
const logger = require('../utils/logger');
const { body, validationResult } = require('express-validator');
const { redisUtils } = require('../config/redis');
const { analyzeSPFRecord } = require('../services/spfParser');
const { validatePublicDomain, organizationalDomain } = require('../utils/dnsNames');
const {
  parseAuthenticationResults,
  calculateSpamScore,
  authenticationWarnings,
  classifyIP,
  extractHopIP,
  extractTimestamp,
  computeTimings,
  reverseIPForDnsbl,
  classifyDnsblAnswer,
} = require('../services/emailTrace');

// SPF results are cached briefly; callers can bypass the cache with
// { fresh: true } in the body or ?fresh=1 (rate limiting still applies).
const SPF_CACHE_TTL_SECONDS = 300;
const wantsFresh = (req) => req.body?.fresh === true || req.query?.fresh === '1' || req.query?.fresh === 'true';

const router = express.Router();

/**
 * Rate limiter for email trace endpoint
 * 30 requests per hour per user
 */
const emailTraceRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 30,
  message: {
    success: false,
    message: 'Too many email trace requests. You can perform 30 traces per hour. Please try again later.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    return `email-trace:${ipKey(req)}`;
  },
  handler: (req, res) => {
    logger.securityLog('Email trace rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method
    });

    res.status(429).json({
      success: false,
      message: 'Too many email trace requests. You can perform 30 traces per hour. Please try again later.',
      retryAfter: 3600
    });
  }
});

/**
 * Rate limiter for SPF checker endpoint
 * 30 requests per hour per user to prevent DNS abuse
 */
const spfCheckerRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 30,
  message: {
    success: false,
    message: 'Too many SPF checker requests. You can perform 30 checks per hour. Please try again later.',
    retryAfter: 3600
  },
  keyGenerator: (req) => {
    return `spf-checker:${ipKey(req)}`;
  },
  handler: (req, res) => {
    logger.securityLog('SPF checker rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method
    });

    res.status(429).json({
      success: false,
      message: 'Too many SPF checker requests. You can perform 30 checks per hour. Please try again later.',
      retryAfter: 3600
    });
  }
});

/**
 * Validation rules for email trace endpoint
 */
const emailTraceValidation = [
  body('headers')
    .trim()
    .notEmpty()
    .withMessage('Email headers are required')
    .isLength({ max: 100000 })
    .withMessage('Headers must not exceed 100000 characters')
    .custom((value) => {
      // Check if it looks like email headers
      const hasReceivedHeader = /^Received:/mi.test(value);
      const hasFromHeader = /^From:/mi.test(value);

      if (!hasReceivedHeader && !hasFromHeader) {
        throw new Error('Input does not appear to be valid email headers');
      }

      return true;
    })
];

/**
 * Validation rules for SPF checker endpoint
 */
const spfCheckerValidation = [
  body('domain')
    .trim()
    .notEmpty()
    .withMessage('Domain is required')
    .isLength({ max: 255 })
    .withMessage('Domain must not exceed 255 characters')
  // Format and private-name checks run in the handler via validatePublicDomain
  // (anchored rules; accepts punycode TLDs).
];

/**
 * Handle validation errors
 */
const handleValidationErrors = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    logger.securityLog('Email trace validation errors', {
      errors: errors.array(),
      ip: req.ip,
      url: req.originalUrl
    });

    // Put the first specific reason in `message` (what clients display).
    const first = errors.array()[0];
    const message = first && typeof first.msg === 'string' && first.msg !== 'Invalid value' ? first.msg : 'Validation failed';
    return sendError(res, message, 400, errors.array().map(err => ({
      field: err.path,
      message: err.msg,
      value: typeof err.value === 'string' ? err.value.substring(0, 50) + '...' : err.value
    })));
  }
  next();
};

/**
 * Parse Received headers to build email route
 */
function parseReceivedHeaders(headers) {
  const receivedHeaders = [];

  // Extract all Received headers
  const headerLines = headers.split('\n');
  let currentReceived = '';
  let inReceived = false;

  for (const line of headerLines) {
    if (line.match(/^Received:/i)) {
      if (currentReceived) {
        receivedHeaders.push(currentReceived.trim());
      }
      currentReceived = line;
      inReceived = true;
    } else if (inReceived) {
      if (line.startsWith('\t') || line.startsWith(' ')) {
        // Continuation of previous header
        currentReceived += ' ' + line.trim();
      } else {
        // New header, save previous
        if (currentReceived) {
          receivedHeaders.push(currentReceived.trim());
        }
        currentReceived = '';
        inReceived = false;
      }
    }
  }

  // Add last one
  if (currentReceived) {
    receivedHeaders.push(currentReceived.trim());
  }

  return receivedHeaders.reverse(); // Reverse to get chronological order
}

/**
 * Extract server name from Received header
 */
function extractServer(receivedHeader) {
  // Look for "from" or "by" server names
  const fromMatch = receivedHeader.match(/from\s+([^\s(]+)/i);
  const byMatch = receivedHeader.match(/by\s+([^\s(]+)/i);

  return fromMatch?.[1] || byMatch?.[1] || 'unknown';
}

/**
 * geoip-lite reads its whole IP database (~280 MB) into memory when it is
 * required, so load it on the first lookup instead of in every cluster
 * instance at boot. The load is synchronous (~70 ms) and happens once per
 * instance.
 */
let geoip = null;
function getGeoip() {
  if (!geoip) {
    geoip = require('geoip-lite');
  }
  return geoip;
}

/**
 * Perform IP geolocation with caching
 */
async function geolocateIP(ip) {
  // Check cache first (7 day TTL)
  const cacheKey = `geo:${ip}`;
  const cached = await redisUtils.get(cacheKey);

  if (cached) {
    return { ...cached, cached: true };
  }

  // Use geoip-lite for fast, local geolocation
  const geo = getGeoip().lookup(ip);

  if (!geo) {
    return {
      country: null,
      city: null,
      lat: null,
      lon: null,
      cached: false
    };
  }

  const result = {
    country: geo.country || null,
    region: geo.region || null,
    city: geo.city || null,
    lat: geo.ll?.[0] || null,
    lon: geo.ll?.[1] || null,
    postalCode: geo.metro ? String(geo.metro) : null,
    timezone: geo.timezone || null,
    cached: false
  };

  // Cache for 7 days
  await redisUtils.setex(cacheKey, 604800, result);

  return result;
}

/**
 * Reverse DNS (PTR) lookup with Redis caching (7 day TTL).
 * Returns the hostname or null on no record / error.
 */
async function getReverseDNS(ip) {
  const cacheKey = `ptr:${ip}`;
  const cached = await redisUtils.get(cacheKey);
  if (cached !== null && cached !== undefined) return cached === '' ? null : cached;

  try {
    const records = await dns.reverse(ip);
    const hostname = (records && records[0]) || null;
    await redisUtils.setex(cacheKey, 604800, hostname || '');
    return hostname;
  } catch (error) {
    // ENOTFOUND etc. — no PTR is valid (not an error)
    await redisUtils.setex(cacheKey, 604800, '');
    return null;
  }
}

/**
 * RDAP / WHOIS lookup via rdap.org (auto-routes to the correct RIR).
 * Returns a normalised subset of fields plus the raw payload for "show full WHOIS".
 * Cached in Redis for 24 hours.
 */
async function getRDAPInfo(ip) {
  const cacheKey = `rdap:${ip}`;
  const cached = await redisUtils.get(cacheKey);
  if (cached) return cached;

  try {
    const res = await fetch(`https://rdap.org/ip/${encodeURIComponent(ip)}`, {
      headers: { 'Accept': 'application/rdap+json' },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      const empty = { organization: null, abuseContact: null, networkRange: null, networkName: null, registrationDate: null, registry: null, raw: null };
      await redisUtils.setex(cacheKey, 86400, empty);
      return empty;
    }
    const raw = await res.json();

    // Extract organization name from entities (look for "registrant", then "abuse" contact, then any org with vCard)
    let organization = null;
    let abuseContact = null;
    const walkEntities = (entities) => {
      if (!Array.isArray(entities)) return;
      for (const ent of entities) {
        const roles = ent.roles || [];
        const vcard = ent.vcardArray && ent.vcardArray[1];
        if (Array.isArray(vcard)) {
          for (const field of vcard) {
            if (!Array.isArray(field)) continue;
            const [name, , , value] = field;
            if (name === 'fn' && !organization && (roles.includes('registrant') || roles.includes('administrative') || roles.length === 0)) {
              organization = typeof value === 'string' ? value : null;
            }
            if (name === 'email' && roles.includes('abuse') && !abuseContact) {
              abuseContact = typeof value === 'string' ? value : null;
            }
          }
        }
        // Recurse into nested entities (some RIRs nest the abuse contact)
        if (ent.entities) walkEntities(ent.entities);
      }
    };
    walkEntities(raw.entities);

    // Network range / name
    let networkRange = null;
    if (raw.startAddress && raw.endAddress) {
      networkRange = `${raw.startAddress} - ${raw.endAddress}`;
    } else if (raw.handle) {
      networkRange = raw.handle;
    }
    const networkName = raw.name || null;

    // Registration date from events (look for "registration" or earliest event)
    let registrationDate = null;
    if (Array.isArray(raw.events)) {
      const regEvent = raw.events.find(e => e.eventAction === 'registration')
        || raw.events.find(e => e.eventAction === 'last changed');
      if (regEvent) registrationDate = regEvent.eventDate || null;
    }

    // RIR / registry name
    const registry = raw.port43 || (raw.notices && raw.notices[0]?.title) || null;

    const info = {
      organization,
      abuseContact,
      networkRange,
      networkName,
      registrationDate,
      registry,
      raw,
    };

    await redisUtils.setex(cacheKey, 86400, info);
    return info;
  } catch (error) {
    logger.debug('RDAP lookup failed', { ip, error: error.message });
    const empty = { organization: null, abuseContact: null, networkRange: null, networkName: null, registrationDate: null, registry: null, raw: null };
    return empty;
  }
}

/**
 * Get ASN / organization name for an IP via Team Cymru.
 *
 * This requires TWO DNS queries:
 *   1. `<reversed-ip>.origin.asn.cymru.com` returns:
 *        AS_NUMBER | IP_PREFIX | COUNTRY | RIR | ALLOCATED_DATE
 *      (parts[4] is the allocation date, NOT the org name — historic bug source)
 *   2. `AS<num>.asn.cymru.com` returns:
 *        AS_NUMBER | COUNTRY | RIR | ALLOCATED_DATE | ORG_NAME
 *      (parts[4] here IS the org name, which is what we want to display)
 */
async function getASNInfo(ip) {
  try {
    // IPv4: 4.3.2.1.origin.asn.cymru.com; IPv6: nibble-reversed under origin6.
    const reversedIP = reverseIPForDnsbl(ip);
    if (!reversedIP) return { asn: null, isp: null };
    const originZone = net.isIP(ip) === 6 ? 'origin6.asn.cymru.com' : 'origin.asn.cymru.com';
    const originQuery = `${reversedIP}.${originZone}`;
    const originTxt = await dns.resolveTxt(originQuery);
    if (!originTxt || originTxt.length === 0) {
      return { asn: null, isp: null };
    }

    const originRecord = originTxt[0].join('');
    const originParts = originRecord.split('|').map(p => p.trim());
    const asNumber = originParts[0];
    if (!asNumber) {
      return { asn: null, isp: null };
    }
    const asn = `AS${asNumber}`;

    // Second lookup to resolve the organization name behind the AS number.
    try {
      const orgQuery = `AS${asNumber}.asn.cymru.com`;
      const orgTxt = await dns.resolveTxt(orgQuery);
      if (orgTxt && orgTxt.length > 0) {
        const orgRecord = orgTxt[0].join('');
        const orgParts = orgRecord.split('|').map(p => p.trim());
        if (orgParts.length >= 5 && orgParts[4]) {
          return { asn, isp: orgParts[4] };
        }
      }
    } catch (orgError) {
      logger.debug('ASN org-name lookup failed', { ip, asn, error: orgError.message });
    }

    // Fall back to just the AS number if the org-name lookup didn't yield one.
    return { asn, isp: null };
  } catch (error) {
    logger.debug('ASN lookup failed for IP', { ip, error: error.message });
    return { asn: null, isp: null };
  }
}

/**
 * DNSBL zones checked for sending IPs. Only zones that publish IPv6 data are
 * queried for IPv6 addresses.
 */
const TRACE_DNSBLS = [
  { host: 'zen.spamhaus.org', ipv6: true },
  { host: 'bl.spamcop.net', ipv6: false },
  { host: 'dnsbl.sorbs.net', ipv6: false }
];

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(Object.assign(new Error('TIMEOUT'), { code: 'ETIMEOUT' })), ms);
    })
  ]).finally(() => clearTimeout(timer));
}

/**
 * Check one IP against the trace DNSBLs.
 * Only 127.0.0.x answers count as listings; 127.255.255.x answers (Spamhaus
 * "public resolver" / rate-limit codes) and lookup failures are reported as
 * "unavailable", never as listed.
 * @returns {Promise<{ ip, listedOn: string[], unavailable: string[] }>}
 */
async function checkBlacklist(ip) {
  const reversed = reverseIPForDnsbl(ip);
  const isV6 = net.isIP(ip) === 6;
  const zones = TRACE_DNSBLS.filter((z) => !isV6 || z.ipv6);
  const listedOn = [];
  const unavailable = [];
  if (!reversed) return { ip, listedOn, unavailable };

  await Promise.all(zones.map(async (zone) => {
    try {
      const answers = await withTimeout(dns.resolve4(`${reversed}.${zone.host}`), 5000);
      const verdict = classifyDnsblAnswer(answers);
      if (verdict === 'listed') listedOn.push(zone.host);
      else if (verdict === 'unavailable') unavailable.push(zone.host);
    } catch (error) {
      // NXDOMAIN / NODATA = not listed. Anything else = we could not check.
      if (error.code !== 'ENOTFOUND' && error.code !== 'ENODATA') unavailable.push(zone.host);
    }
  }));

  return { ip, listedOn, unavailable };
}

/**
 * POST /api/email/trace-email
 * Trace email route and analyze headers
 */
router.post('/trace-email',
  enhancedSecurityWithRateLimit(emailTraceRateLimit),
  emailTraceValidation,
  handleValidationErrors,
  async (req, res) => {
    const requestId = `email-trace-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const startTime = Date.now();

    try {
      const { headers: rawHeaders } = req.body;

      logger.info('Email trace request received', {
        requestId,
        headersLength: rawHeaders.length,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Parse email headers with mailparser
      let parsedEmail;
      try {
        parsedEmail = await simpleParser(rawHeaders);
      } catch (parseError) {
        logger.warn('Mailparser failed, using manual parsing', {
          requestId,
          error: parseError.message
        });
        // Continue with manual parsing
      }

      // Extract basic metadata
      const fromMatch = rawHeaders.match(/^From:\s*(.+?)$/mi);
      const toMatch = rawHeaders.match(/^To:\s*(.+?)$/mi);
      const subjectMatch = rawHeaders.match(/^Subject:\s*(.+?)$/mi);
      const dateMatch = rawHeaders.match(/^Date:\s*(.+?)$/mi);
      const messageIdMatch = rawHeaders.match(/^Message-ID:\s*(.+?)$/mi);

      const metadata = {
        from: parsedEmail?.from?.text || fromMatch?.[1]?.trim() || null,
        to: parsedEmail?.to?.text || toMatch?.[1]?.trim() || null,
        subject: parsedEmail?.subject || subjectMatch?.[1]?.trim() || null,
        // An unparseable Date header must not turn the whole trace into a 500.
        date: (() => {
          const d = parsedEmail?.date instanceof Date && !Number.isNaN(parsedEmail.date.getTime())
            ? parsedEmail.date
            : (dateMatch ? new Date(dateMatch[1]) : null);
          return d && !Number.isNaN(d.getTime()) ? d.toISOString() : (dateMatch ? dateMatch[1].trim() : null);
        })(),
        messageId: parsedEmail?.messageId || messageIdMatch?.[1]?.trim() || null
      };

      // Parse Received headers to build route (chronological order)
      const receivedHeaders = parseReceivedHeaders(rawHeaders);

      logger.info('Parsing email route', {
        requestId,
        receivedHeaderCount: receivedHeaders.length
      });

      // Every Received header is a hop. Private / reserved addresses (internal
      // relays, 10.x, 192.168.x, loopback) are kept and marked, but not sent to
      // geolocation / WHOIS / blacklist lookups.
      const MAX_ENRICHED_IPS = 15;
      const enrichment = new Map();
      const enrich = (ip) => {
        if (!enrichment.has(ip)) {
          enrichment.set(ip, Promise.all([
            geolocateIP(ip),
            getASNInfo(ip),
            getReverseDNS(ip),
            getRDAPInfo(ip),
          ]));
        }
        return enrichment.get(ip);
      };

      const route = [];
      const allIPs = new Set();
      const publicIPs = [];

      for (const receivedHeader of receivedHeaders) {
        const timestamp = extractTimestamp(receivedHeader);
        const server = extractServer(receivedHeader);
        const ip = extractHopIP(receivedHeader);
        const ipType = ip ? classifyIP(ip) : null;
        const isPrivate = ipType === 'private';

        const hop = {
          timestamp,
          server,
          ip,
          private: isPrivate,
          hostname: null,
          location: { country: null, region: null, city: null, lat: null, lon: null, postalCode: null, timezone: null },
          isp: null,
          asn: null,
          whois: null,
        };

        if (ip) allIPs.add(ip);

        if (ip && ipType === 'public') {
          if (!publicIPs.includes(ip)) publicIPs.push(ip);
          if (enrichment.has(ip) || enrichment.size < MAX_ENRICHED_IPS) {
            const [location, asnInfo, hostname, whois] = await enrich(ip);
            hop.hostname = hostname;
            hop.location = {
              country: location.country,
              region: location.region,
              city: location.city,
              lat: location.lat,
              lon: location.lon,
              postalCode: location.postalCode || null,
              timezone: location.timezone || null,
            };
            hop.isp = asnInfo.isp;
            hop.asn = asnInfo.asn;
            hop.whois = {
              organization: whois.organization,
              abuseContact: whois.abuseContact,
              networkRange: whois.networkRange,
              networkName: whois.networkName,
              registrationDate: whois.registrationDate,
              registry: whois.registry,
              raw: whois.raw,
            };
          }
        }

        route.push(hop);
      }

      // Per-hop delay and total transit time from the Received timestamps.
      const timing = computeTimings(route);

      // Parse authentication results (status per method; see services/emailTrace)
      const authentication = parseAuthenticationResults(rawHeaders);

      // Check the first public sending IPs against blacklists.
      const warningDetails = [];
      const blacklistResults = await Promise.all(publicIPs.slice(0, 3).map((ip) => checkBlacklist(ip)));
      let listedIpCount = 0;
      for (const r of blacklistResults) {
        if (r.listedOn.length > 0) {
          listedIpCount++;
          warningDetails.push({
            severity: 'high',
            message: `IP ${r.ip} is listed on ${r.listedOn.length} blacklist(s): ${r.listedOn.join(', ')}`
          });
        }
        if (r.unavailable.length > 0) {
          warningDetails.push({
            severity: 'low',
            message: `Blacklist check unavailable for ${r.ip} on ${r.unavailable.join(', ')} (the list did not answer our query); this is not a listing`
          });
        }
      }

      warningDetails.push(...authenticationWarnings(authentication));

      // Toolsana heuristic score: each auth method counted once, plus listed IPs.
      const spamScore = calculateSpamScore(authentication, listedIpCount);

      const responseTime = Date.now() - startTime;

      const result = {
        metadata,
        route,
        authentication,
        spamScore,
        spamScoreSource: 'toolsana-heuristic',
        warnings: warningDetails.map((w) => w.message),
        warningDetails,
        blacklists: blacklistResults,
        statistics: {
          totalHops: route.length,
          uniqueIPs: allIPs.size,
          privateHops: route.filter((h) => h.private).length,
          countries: [...new Set(route.map(r => r.location.country).filter(Boolean))],
          totalTime: timing.totalTime,
          totalTimeSeconds: timing.totalSeconds,
          responseTime
        }
      };

      logger.info('Email trace completed successfully', {
        requestId,
        hops: route.length,
        ips: allIPs.size,
        spamScore,
        responseTime
      });

      sendSuccess(res, 'Email trace completed successfully', result);

    } catch (error) {
      logger.error('Email trace error', {
        requestId,
        error: error.message,
        stack: error.stack,
        ip: req.ip
      });

      return sendError(res, 'Failed to trace email', 500, {
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

/**
 * POST /api/email/spf-checker
 * Check and analyze SPF record for a domain
 *
 * Implements RFC 7208 compliance checking:
 * - Parses SPF mechanisms (a, mx, ip4, ip6, include, exists, ptr, all)
 * - Parses qualifiers (+, -, ~, ?)
 * - Recursively resolves includes and redirects
 * - Tracks DNS lookup count (max 10 per RFC)
 * - Validates syntax strictly
 * - Detects common issues and security problems
 * - Extracts all allowed IP ranges
 */
router.post('/spf-checker',
  enhancedSecurityWithRateLimit(spfCheckerRateLimit),
  spfCheckerValidation,
  handleValidationErrors,
  async (req, res) => {
    const startTime = Date.now();
    const requestId = `spf-check-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

    try {
      // Anchored validation: rejects IP literals, localhost, *.local, *.internal
      // (and other private-only names) without rejecting top10.com or site127.io.
      const validation = validatePublicDomain(req.body.domain);
      if (!validation.valid) {
        if (validation.reason === 'private') {
          logger.securityLog('Suspicious domain in SPF check', {
            requestId,
            domain: req.body.domain,
            ip: req.ip,
            userAgent: req.get('User-Agent')
          });
          return sendError(res, `${validation.error} for security reasons`, 403);
        }
        return sendError(res, validation.error, 400);
      }
      // Historic behaviour: the checker looks at the apex, not www.
      const domain = validation.cleanDomain.replace(/^www\./, '');
      const fresh = wantsFresh(req);

      logger.info('SPF checker request received', {
        requestId,
        domain,
        fresh,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });

      // Short-lived Redis cache (key versioned: v2 changed the lookup counting).
      const cacheKey = `spf-check:v2:${domain}`;
      const cached = fresh ? null : await redisUtils.get(cacheKey);

      if (cached) {
        logger.info('SPF check served from cache', {
          requestId,
          domain
        });

        const cachedAt = cached.analyzedAt || null;
        return sendSuccess(res, 'SPF record retrieved from cache', {
          ...cached,
          cached: true,
          cachedAt,
          cacheAgeSeconds: cachedAt ? Math.max(0, Math.round((Date.now() - Date.parse(cachedAt)) / 1000)) : null,
          timestamp: new Date().toISOString()
        });
      }

      // Perform SPF analysis
      let spfResults;

      try {
        spfResults = await analyzeSPFRecord(domain);
      } catch (error) {
        logger.error('SPF analysis failed', {
          requestId,
          domain,
          error: error.message,
          code: error.code
        });

        // Handle specific DNS errors
        let errorMessage = 'Failed to analyze SPF record';
        let statusCode = 500;

        if (error.code === 'ENOTFOUND') {
          errorMessage = 'Domain not found';
          statusCode = 404;
        } else if (error.code === 'ENODATA') {
          errorMessage = 'No SPF record found for this domain';
          statusCode = 404;
        } else if (error.code === 'ETIMEOUT') {
          errorMessage = 'DNS lookup timeout';
          statusCode = 408;
        } else if (error.code === 'ESERVFAIL') {
          errorMessage = 'DNS server failure';
          statusCode = 503;
        }

        return sendError(res, errorMessage, statusCode, {
          domain,
          dnsError: error.code
        });
      }

      const totalTime = Date.now() - startTime;

      // Prepare response data
      const responseData = {
        domain: spfResults.domain,
        record: spfResults.record,
        valid: spfResults.valid,
        mechanisms: spfResults.mechanisms.map(m => ({
          type: m.type,
          value: m.value,
          qualifier: m.qualifier,
          qualifierName: m.qualifierName,
          original: m.original
        })),
        modifiers: spfResults.modifiers || {},
        allowedIPs: spfResults.allowedIPs,
        // Counted recursively through include/redirect, the way receivers count.
        totalDnsLookups: spfResults.dnsLookups,
        dnsLookupsIsLowerBound: spfResults.dnsLookupsIsLowerBound || false,
        maxDnsLookups: 10,
        voidLookups: spfResults.voidLookups || 0,
        limitExceededAt: spfResults.limitExceededAt || null,
        lookupBreakdown: spfResults.lookupBreakdown || [],
        issues: spfResults.issues,
        warnings: spfResults.warnings,
        lookupTime: totalTime,
        cached: false,
        cachedAt: null,
        analyzedAt: new Date().toISOString()
      };

      await redisUtils.setex(cacheKey, SPF_CACHE_TTL_SECONDS, responseData);

      logger.info('SPF check completed', {
        requestId,
        domain,
        valid: spfResults.valid,
        dnsLookups: spfResults.dnsLookups,
        mechanismCount: spfResults.mechanisms.length,
        issueCount: spfResults.issues.length,
        warningCount: spfResults.warnings.length,
        ipv4Count: spfResults.allowedIPs.ipv4.length,
        ipv6Count: spfResults.allowedIPs.ipv6.length,
        lookupTime: totalTime
      });

      return sendSuccess(res, 'SPF record analyzed successfully', responseData);

    } catch (error) {
      logger.error('SPF checker error', {
        requestId,
        error: error.message,
        stack: error.stack,
        ip: req.ip
      });

      return sendError(res, 'An error occurred during SPF analysis', 500, {
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }
);

/**
 * GET /api/email/info
 * Get information about the email API
 */
router.get('/info', async (req, res) => {
  const info = {
    name: 'Email Validation & Analysis API',
    version: '1.0.0',
    description: 'Comprehensive email infrastructure validation tools including SPF analysis and email header tracing',
    endpoints: {
      spfChecker: {
        method: 'POST',
        path: '/api/email/spf-checker',
        description: 'Check and analyze SPF (Sender Policy Framework) records for email authentication',
        rateLimit: '30 requests per hour per user',
        caching: '5 minutes (send { fresh: true } to bypass)',
        requestBody: {
          domain: 'string (required, domain name to check)'
        },
        features: [
          'RFC 7208 compliance checking',
          'SPF mechanism parsing (a, mx, ip4, ip6, include, exists, ptr, all)',
          'Qualifier parsing (+, -, ~, ?)',
          'Recursive include and redirect resolution',
          'DNS lookup counting (max 10 per RFC)',
          'Syntax validation',
          'Security issue detection',
          'IP range extraction',
          'Multiple SPF record detection',
          'Deprecated mechanism warnings'
        ]
      },
      traceEmail: {
        method: 'POST',
        path: '/api/email/trace-email',
        description: 'Analyze email headers to trace route and check authentication',
        rateLimit: '30 requests per hour per user',
        requestBody: {
          headers: 'Raw email headers (string, required, max 100KB)'
        },
        responseFormat: {
          metadata: {
            from: 'string (sender email)',
            to: 'string (recipient email)',
            subject: 'string (email subject)',
            date: 'string (ISO 8601 timestamp)',
            messageId: 'string (unique message ID)'
          },
          route: [
            {
              timestamp: 'string (ISO 8601)',
              server: 'string (mail server hostname)',
              ip: 'string (IP address)',
              location: {
                country: 'string (ISO country code)',
                region: 'string',
                city: 'string',
                lat: 'number (latitude)',
                lon: 'number (longitude)'
              },
              isp: 'string (ISP name)',
              asn: 'string (AS number)'
            }
          ],
          authentication: {
            spf: {
              pass: 'boolean (true/false/null)',
              domain: 'string (checked domain)'
            },
            dkim: {
              pass: 'boolean (true/false/null)',
              selector: 'string (DKIM selector)'
            },
            dmarc: {
              pass: 'boolean (true/false/null)',
              policy: 'string (DMARC policy)'
            }
          },
          spamScore: 'number (0-10, higher = more suspicious)',
          warnings: 'array of strings',
          statistics: {
            totalHops: 'number',
            uniqueIPs: 'number',
            countries: 'array of country codes',
            responseTime: 'number (ms)'
          }
        }
      }
    },
    spfMechanisms: {
      all: 'Matches all IPs (should be last mechanism)',
      a: 'Matches A/AAAA records of specified domain',
      mx: 'Matches MX records of specified domain',
      ip4: 'Matches specified IPv4 address or range',
      ip6: 'Matches specified IPv6 address or range',
      include: 'Includes SPF record of specified domain',
      exists: 'Checks if specified domain exists',
      ptr: 'Deprecated - validates PTR records (not recommended)'
    },
    spfQualifiers: {
      '+': 'Pass - Allow sender (default)',
      '-': 'Fail - Reject sender',
      '~': 'SoftFail - Accept but mark as suspicious',
      '?': 'Neutral - No policy'
    },
    features: [
      'SPF record validation per RFC 7208',
      'Recursive include and redirect resolution',
      'DNS lookup count tracking (max 10)',
      'Parse email headers and extract metadata',
      'Trace complete email route through mail servers',
      'IP geolocation with geoip-lite (fast, local)',
      'ASN/ISP lookup via DNS',
      'SPF, DKIM, DMARC authentication checking',
      'Basic DNSBL blacklist checking',
      'Spam score calculation',
      'Security warnings generation',
      'Response time tracking',
      'Redis caching (24h for SPF, 7d for geolocation)'
    ],
    dataSources: {
      geolocation: 'geoip-lite (MaxMind GeoLite2)',
      asn: 'Team Cymru DNS-based ASN lookup',
      blacklists: ['zen.spamhaus.org', 'bl.spamcop.net', 'dnsbl.sorbs.net']
    },
    security: {
      rateLimit: '30 requests per hour per user',
      inputValidation: true,
      maxHeaderSize: '100KB',
      xssProtection: true,
      privateIPFiltering: true
    },
    usage: {
      example: {
        request: {
          method: 'POST',
          url: '/api/email/trace-email',
          body: {
            headers: 'Received: from mail.example.com...\nFrom: sender@example.com...'
          }
        },
        response: {
          success: true,
          message: 'Email trace completed successfully',
          data: {
            metadata: {
              from: 'sender@example.com',
              to: 'recipient@example.com',
              subject: 'Test Email',
              date: '2025-01-25T10:30:00Z',
              messageId: '<abc123@example.com>'
            },
            route: [],
            authentication: {},
            spamScore: 2.3,
            warnings: [],
            statistics: {}
          }
        }
      }
    },
    notes: [
      'Only public IPs are included in route trace',
      'Private IPs (10.x, 172.16-31.x, 192.168.x) are filtered out',
      'Geolocation data is cached for 7 days',
      'ASN lookup may fail for some IPs',
      'Blacklist checking is basic and not comprehensive',
      'Authentication results depend on email headers being present',
      'Spam score is indicative only, not definitive'
    ]
  };

  return sendSuccess(res, 'Email API information retrieved', info);
});

/**
 * Rate limit specifically for SMTP testing — tighter than SPF because each
 * request makes a real outbound TCP connection and (optionally) sends a real email.
 */
// Standard SMTP submission/transfer ports. See the note at the port check
// in the smtp-test handler for why this is an allowlist rather than a range.
const SMTP_ALLOWED_PORTS = [25, 465, 587, 2525];

const smtpTestRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10,
  message: {
    success: false,
    message: 'Too many SMTP test requests. You can perform 10 tests per hour. Please try again later.',
    retryAfter: 3600
  },
  keyGenerator: (req) => `smtp-test:${ipKey(req)}`,
  handler: (req, res) => {
    logger.securityLog('SMTP test rate limit exceeded', {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      url: req.originalUrl,
      method: req.method
    });
    res.status(429).json({
      success: false,
      message: 'Too many SMTP test requests. You can perform 10 tests per hour. Please try again later.',
      retryAfter: 3600
    });
  }
});

// Host screening (private/loopback/link-local rejection, by IP literal and by
// DNS resolution) lives in ../utils/ssrfGuard — see screenHostname/safeFetch.
// It prevents the SMTP tester and BIMI fetcher from being used as an
// internal-network port-scanner / SSRF tool.

/**
 * POST /api/email/smtp-test
 * Test an SMTP server's connection, authentication, TLS, and optionally send
 * a test email. Two modes — `testMode: 'connection'` only verifies the
 * handshake / auth; `testMode: 'send'` additionally delivers a small test message.
 *
 * Privacy: credentials and message content live only in the request scope.
 * Never logged. Logs record outcome (success/fail/category) but never secrets.
 */
router.post('/smtp-test', enhancedSecurityWithRateLimit(smtpTestRateLimit), async (req, res) => {
  const startTime = Date.now();
  const {
    hostname,
    port,
    security,
    username,
    password,
    fromEmail,
    toEmail,
    testMode
  } = req.body || {};

  // ---- Validation ----
  if (!hostname || typeof hostname !== 'string') {
    return sendError(res, 'SMTP hostname is required', 400);
  }
  if (!/^[a-zA-Z0-9.\-:]+$/.test(hostname) || hostname.length > 253) {
    return sendError(res, 'Invalid SMTP hostname format', 400);
  }
  const portNum = Number(port);
  // Only the four standard mail-submission/transfer ports.
  //
  // This used to accept 1-65535, which made the tool a general-purpose TCP
  // connect primitive: a caller could walk every port of a public host and
  // learn what was listening from the error categorisation below. Restricting
  // it costs nothing real — SMTP does not live anywhere else — and removes
  // both the port-scanning use and the "connections to odd ports across many
  // hosts" pattern that reads as bot traffic to blocklist operators.
  if (!SMTP_ALLOWED_PORTS.includes(portNum)) {
    return sendError(
      res,
      `Unsupported port. SMTP testing is limited to ${SMTP_ALLOWED_PORTS.join(', ')}.`,
      400
    );
  }
  const sec = ['STARTTLS', 'TLS', 'NONE'].includes(security) ? security : 'STARTTLS';
  const mode = testMode === 'send' ? 'send' : 'connection';

  // Send mode requires SMTP credentials for the target server.
  //
  // Without this, anyone could point the tool at a third party's OPEN relay
  // and have us submit mail through it — our IP lands in the Received headers
  // of whatever gets sent. Requiring auth confines send mode to servers the
  // caller can already authenticate to, which is the legitimate use case
  // ("does my SMTP setup work?") and is not a relay for anyone else.
  //
  // Connection testing stays open: it is the useful majority of the tool and
  // does not put mail on the wire.
  if (mode === 'send' && !(username && password)) {
    return sendError(
      res,
      'Send mode requires SMTP username and password. Connection testing is available without credentials.',
      400
    );
  }

  const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (mode === 'send') {
    if (!fromEmail || !emailRe.test(fromEmail)) {
      return sendError(res, 'A valid From email is required for send mode', 400);
    }
    if (!toEmail || !emailRe.test(toEmail)) {
      return sendError(res, 'A valid To email is required for send mode', 400);
    }
  } else if (fromEmail && !emailRe.test(fromEmail)) {
    return sendError(res, 'From email is malformed', 400);
  } else if (toEmail && !emailRe.test(toEmail)) {
    return sendError(res, 'To email is malformed', 400);
  }

  // Block internal targets to prevent the tool being used as an SSRF probe.
  const hostCheck = await screenHostname(hostname);
  if (!hostCheck.valid) {
    return sendError(res, 'Refusing to connect to private, loopback, or unresolvable host', 400);
  }

  // Highest blocklist-risk path in the codebase: repeated SMTP connections to
  // many hosts from one IP is the fingerprint Spamhaus XBL/CSS looks for, and
  // mode 'send' actually delivers mail. Record every attempt so abuse is
  // visible here before it is visible to a blocklist operator.
  logOutbound({
    tool: 'smtp-test',
    targetHost: hostname,
    targetPort: portNum,
    method: mode,
    req,
    extra: { security: sec, authenticated: Boolean(username) },
  });

  // ---- Build transport config ----
  const transportConfig = {
    host: hostname,
    port: portNum,
    secure: sec === 'TLS' || portNum === 465,
    requireTLS: sec === 'STARTTLS',
    ignoreTLS: sec === 'NONE',
    connectionTimeout: 10000,
    greetingTimeout: 10000,
    socketTimeout: 15000,
  };
  if (username && password) {
    transportConfig.auth = { user: username, pass: password };
  }

  logger.info('SMTP test starting', {
    ip: req.ip,
    hostname,
    port: portNum,
    security: sec,
    mode,
    hasAuth: !!(username && password),
  });

  const transporter = nodemailer.createTransport(transportConfig);

  // ---- Result skeleton ----
  let connectionStatus = 'unknown';
  let authenticationStatus = username && password ? 'unknown' : 'not_tested';
  let sendStatus = mode === 'send' ? 'unknown' : 'not_tested';
  let tlsInfo;
  let serverResponse;
  let errorMessage;
  const warnings = [];

  /**
   * Map a nodemailer error into a categorised diagnostic outcome.
   * nodemailer attaches `.code` (e.g. EAUTH, ESOCKET, ETLS, EENVELOPE, EMESSAGE)
   * and `.responseCode` (the SMTP numeric status) where applicable.
   */
  const categoriseError = (err) => {
    const code = err && err.code;
    const response = err && (err.response || err.message);
    serverResponse = typeof response === 'string' ? response.slice(0, 500) : undefined;
    if (code === 'EAUTH') {
      // Auth failed but the server clearly responded — connection + TLS handshake succeeded.
      connectionStatus = 'success';
      authenticationStatus = 'failed';
      errorMessage = `Authentication failed: ${err.message}`;
    } else if (code === 'ETLS' || code === 'ECONNECTION' || code === 'ESOCKET') {
      connectionStatus = 'failed';
      errorMessage = `Connection or TLS error: ${err.message}`;
    } else if (code === 'EDNS') {
      connectionStatus = 'failed';
      errorMessage = `DNS resolution failed for ${hostname}: ${err.message}`;
    } else if (code === 'EENVELOPE') {
      // Got far enough to send MAIL FROM / RCPT TO — connection + auth succeeded.
      connectionStatus = 'success';
      if (username && password) authenticationStatus = 'success';
      sendStatus = 'failed';
      errorMessage = `Envelope rejected (FROM or TO refused): ${err.message}`;
    } else if (code === 'EMESSAGE') {
      connectionStatus = 'success';
      if (username && password) authenticationStatus = 'success';
      sendStatus = 'failed';
      errorMessage = `Message content rejected: ${err.message}`;
    } else {
      connectionStatus = 'failed';
      errorMessage = err && err.message ? err.message : 'Unknown SMTP error';
    }
  };

  try {
    // ---- Verify connection + auth ----
    await transporter.verify();
    connectionStatus = 'success';
    if (username && password) authenticationStatus = 'success';

    // Capture TLS info if the transport recorded a TLS handshake.
    // nodemailer doesn't expose this through verify(), so we derive from config
    // and known port conventions.
    if (sec === 'TLS' || sec === 'STARTTLS' || portNum === 465) {
      tlsInfo = {
        enabled: true,
        protocol: sec === 'TLS' || portNum === 465 ? 'TLS (implicit)' : 'STARTTLS',
      };
    } else {
      tlsInfo = { enabled: false };
      warnings.push('TLS is disabled — credentials and message content would be sent in plain text. Use STARTTLS (port 587) or TLS (port 465) for any production sending.');
    }

    if (mode === 'send') {
      const subject = 'SMTP Test from Toolsana';
      const text = `This is a test message sent by the Toolsana SMTP Test Tool at ${new Date().toISOString()}.\n\nIf you received this, your SMTP relay accepted authentication and delivered a test message successfully.\n\n— Toolsana`;
      try {
        const info = await transporter.sendMail({
          from: fromEmail,
          to: toEmail,
          subject,
          text,
        });
        sendStatus = 'success';
        if (info && info.response) {
          serverResponse = String(info.response).slice(0, 500);
        }
      } catch (sendErr) {
        categoriseError(sendErr);
      }
    }
  } catch (verifyErr) {
    categoriseError(verifyErr);
  }

  // Optional advisory: Gmail / Microsoft typically need app passwords for SMTP auth.
  const hostL = hostname.toLowerCase();
  if (authenticationStatus === 'failed' && (hostL.includes('gmail.com') || hostL.includes('googlemail') || hostL.includes('office365') || hostL.includes('outlook'))) {
    warnings.push('Gmail and Microsoft 365 require an "App Password" for SMTP — your regular account password will not work if the account has 2FA enabled.');
  }

  const processingTime = Date.now() - startTime;
  const success = connectionStatus === 'success'
    && (authenticationStatus === 'success' || authenticationStatus === 'not_tested')
    && (sendStatus === 'success' || sendStatus === 'not_tested');

  logger.info('SMTP test finished', {
    ip: req.ip,
    hostname,
    port: portNum,
    mode,
    connectionStatus,
    authenticationStatus,
    sendStatus,
    success,
    processingTimeMs: processingTime,
  });

  return sendSuccess(res, 'SMTP test completed', {
    success,
    connectionStatus,
    authenticationStatus,
    sendStatus: mode === 'send' ? sendStatus : 'not_tested',
    tlsInfo,
    serverResponse,
    errorMessage,
    processingTime,
    warnings,
  });
});

// ============================================================================
// DKIM Checker
// ============================================================================

const dkimRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  message: {
    success: false,
    message: 'Too many DKIM checker requests. You can perform 30 checks per hour. Please try again later.',
    retryAfter: 3600,
  },
  keyGenerator: (req) => `dkim-checker:${ipKey(req)}`,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many DKIM checker requests. You can perform 30 checks per hour. Please try again later.',
      retryAfter: 3600,
    });
  },
});

const COMMON_DKIM_SELECTORS = [
  'google',
  'selector1',
  'selector2',
  's1',
  's2',
  'mail',
  'default',
  'dkim',
  'k1',
  'k2',
  'k3',
  'mg',
  'mailgun',
  'pic',
  'pm',
  'smtpapi',
  'amazonses',
  'klaviyo1',
  'klaviyo2',
  'sendgrid',
  'brevo1',
  'brevo2',
  'mandrill',
  'zoho',
  'protonmail',
  'protonmail2',
  'protonmail3',
  'fastmail1',
  'fastmail2',
  'fastmail3',
  'mxvault',
  'litmus1',
  'litmus2',
];

const SELECTOR_NAME_RE = /^[a-zA-Z0-9_\-.]{1,63}$/;
const DOMAIN_NAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$/;

function parseDKIMRecord(raw) {
  const cleaned = raw.replace(/"\s*"/g, '').replace(/"/g, '').trim();
  const tags = {};
  const parts = cleaned.split(/\s*;\s*/);
  for (const part of parts) {
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    tags[key] = value;
  }
  return tags;
}

function detectRSAKeyLength(base64Key) {
  if (!base64Key) return null;
  try {
    const pem = `-----BEGIN PUBLIC KEY-----\n${base64Key.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    const key = crypto.createPublicKey({ key: pem, format: 'pem' });
    const details = key.asymmetricKeyDetails || {};
    return details.modulusLength || null;
  } catch {
    // Fall back: ASN.1 sniff. Find the largest INTEGER block in the SPKI which is the modulus.
    try {
      const buf = Buffer.from(base64Key, 'base64');
      // Walk SubjectPublicKeyInfo -> AlgorithmIdentifier + BIT STRING(RSAPublicKey)
      // Heuristic: look for the modulus INTEGER tag (0x02) with a long length encoding.
      for (let i = 0; i < buf.length - 4; i++) {
        if (buf[i] === 0x02 && buf[i + 1] === 0x82) {
          const len = (buf[i + 2] << 8) | buf[i + 3];
          // Strip optional leading 0x00 padding byte
          const lead = buf[i + 4] === 0x00 ? 1 : 0;
          const bitLen = (len - lead) * 8;
          if (bitLen >= 512 && bitLen <= 8192) return bitLen;
        }
      }
    } catch {
      // Fall through
    }
    return null;
  }
}

/**
 * @returns {Promise<{ raw: string|null, status: 'found'|'not_found'|'lookup_failed', errorCode?: string }>}
 * NXDOMAIN / NODATA mean "no record"; SERVFAIL, timeouts and refusals mean the
 * lookup itself failed and says nothing about whether the record exists.
 */
async function lookupDKIMSelector(domain, selector) {
  const host = `${selector}._domainkey.${domain}`;
  try {
    const txt = await dns.resolveTxt(host);
    if (!txt || txt.length === 0) return { raw: null, status: 'not_found' };
    // TXT records may be split into multiple strings; join them
    const raw = txt.map((arr) => arr.join('')).join('');
    if (!raw) return { raw: null, status: 'not_found' };
    return { raw, status: 'found' };
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return { raw: null, status: 'not_found' };
    return { raw: null, status: 'lookup_failed', errorCode: e.code || 'DNS_ERROR' };
  }
}

router.post(
  '/dkim-checker',
  enhancedSecurityWithRateLimit(dkimRateLimit),
  [
    body('domain')
      .trim()
      .notEmpty()
      .withMessage('Domain is required')
      .isLength({ max: 253 })
      .matches(DOMAIN_NAME_RE)
      .withMessage('Invalid domain format')
      .customSanitizer((v) => v.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '').replace(/:.*$/, '')),
    body('selector')
      .optional({ checkFalsy: true })
      .trim()
      .isLength({ max: 63 })
      .matches(SELECTOR_NAME_RE)
      .withMessage('Invalid selector format'),
    body('selectors')
      .optional()
      .isArray({ max: 25 })
      .withMessage('selectors must be an array of at most 25 items'),
  ],
  handleValidationErrors,
  async (req, res) => {
    const requestId = `dkim-check-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const startTime = Date.now();
    const { domain } = req.body;
    let { selector, selectors } = req.body;

    let candidateSelectors;
    if (selector) {
      candidateSelectors = [selector];
    } else if (Array.isArray(selectors) && selectors.length > 0) {
      candidateSelectors = selectors
        .map((s) => String(s).trim().toLowerCase())
        .filter((s) => SELECTOR_NAME_RE.test(s))
        .slice(0, 25);
    } else {
      candidateSelectors = COMMON_DKIM_SELECTORS;
    }

    const cacheKey = `dkim-check:${domain}:${candidateSelectors.join(',')}`;
    const cached = await redisUtils.get(cacheKey);
    if (cached) {
      return sendSuccess(res, 'DKIM record retrieved from cache', { ...cached, cached: true });
    }

    logger.info('DKIM checker request', { requestId, domain, selectorCount: candidateSelectors.length });

    const results = [];
    // Run lookups in parallel for auto-discovery, sequentially when single selector
    const rawResults = await Promise.all(
      candidateSelectors.map(async (sel) => {
        const lookup = await lookupDKIMSelector(domain, sel);
        return { selector: sel, raw: lookup.raw, status: lookup.status, errorCode: lookup.errorCode };
      })
    );

    for (const item of rawResults) {
      if (!item.raw) {
        results.push({
          selector: item.selector,
          found: false,
          // not_found = NXDOMAIN/NODATA; lookup_failed = SERVFAIL/timeout (unknown, retry)
          lookupStatus: item.status,
          lookupError: item.errorCode || null,
        });
        continue;
      }
      const tags = parseDKIMRecord(item.raw);
      const version = tags['v'] || null; // expected DKIM1
      const keyType = (tags['k'] || 'rsa').toLowerCase();
      const algorithms = (tags['h'] || '').split(':').filter(Boolean);
      const serviceType = tags['s'] || '*';
      const flags = (tags['t'] || '').split(':').filter(Boolean);
      const note = tags['n'] || null;
      const publicKey = tags['p'] || '';
      const hasPTag = Object.prototype.hasOwnProperty.call(tags, 'p');
      const revoked = publicKey.length === 0 && hasPTag;
      let keyLength = null;
      if (keyType === 'rsa' && publicKey && !revoked) {
        keyLength = detectRSAKeyLength(publicKey);
      }
      const issues = [];
      if (version && version !== 'DKIM1') {
        issues.push({ severity: 'warning', message: `Unexpected DKIM version: ${version} (expected DKIM1)` });
      }
      if (!hasPTag) {
        issues.push({ severity: 'error', message: 'Record has no p= tag. The public key tag is required (RFC 6376 section 3.6.1), so receivers cannot verify signatures for this selector' });
      } else if (revoked) {
        issues.push({ severity: 'error', message: 'Public key is empty — this selector has been revoked' });
      }
      if (keyType !== 'rsa' && keyType !== 'ed25519') {
        issues.push({ severity: 'warning', message: `Unusual key type: ${keyType} (most receivers expect rsa)` });
      }
      if (keyLength && keyLength < 1024) {
        issues.push({ severity: 'error', message: `Key length ${keyLength}-bit is below the 1024-bit minimum` });
      } else if (keyLength && keyLength < 2048) {
        issues.push({
          severity: 'warning',
          message: `Key length ${keyLength}-bit is below the modern 2048-bit recommendation (Google bulk-sender 2024 requirement)`,
        });
      }
      if (flags.includes('y')) {
        issues.push({ severity: 'info', message: 't=y testing flag is set — failures will not be enforced' });
      }
      if (algorithms.length > 0 && !algorithms.includes('sha256') && !algorithms.includes('rsa-sha256')) {
        issues.push({ severity: 'warning', message: 'Hash algorithm list does not include sha256 (rsa-sha1 alone is deprecated)' });
      }
      results.push({
        selector: item.selector,
        found: true,
        raw: item.raw,
        version,
        keyType,
        algorithms,
        serviceType,
        flags,
        note,
        publicKey,
        publicKeyTruncated: publicKey ? `${publicKey.slice(0, 64)}…` : null,
        keyLength,
        revoked,
        issues,
        valid: issues.filter((i) => i.severity === 'error').length === 0 && !revoked && hasPTag,
      });
    }

    const foundCount = results.filter((r) => r.found).length;
    const validCount = results.filter((r) => r.found && r.valid).length;
    const failedCount = results.filter((r) => !r.found && r.lookupStatus === 'lookup_failed').length;
    const response = {
      domain,
      timestamp: new Date().toISOString(),
      autoDiscovery: !selector && !Array.isArray(selectors),
      selectorsChecked: candidateSelectors,
      foundCount,
      validCount,
      failedCount,
      results,
      lookupTime: Date.now() - startTime,
      cached: false,
    };

    // Never cache a result that contains failed (retryable) lookups.
    if (foundCount > 0 && failedCount === 0) {
      await redisUtils.setex(cacheKey, 3600, response);
    }

    logger.info('DKIM check completed', { requestId, domain, foundCount, validCount, lookupTime: response.lookupTime });
    return sendSuccess(res, foundCount > 0 ? 'DKIM records analyzed successfully' : failedCount > 0 ? 'DNS lookup failed for some selectors - try again' : 'No DKIM records found for the checked selectors', response);
  }
);

// ============================================================================
// DMARC Checker (Generator runs client-side)
// ============================================================================

const dmarcRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000,
  max: 30,
  message: {
    success: false,
    message: 'Too many DMARC checker requests. You can perform 30 checks per hour. Please try again later.',
    retryAfter: 3600,
  },
  keyGenerator: (req) => `dmarc-checker:${ipKey(req)}`,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many DMARC checker requests. You can perform 30 checks per hour. Please try again later.',
      retryAfter: 3600,
    });
  },
});

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function parseDMARCRecord(raw) {
  const cleaned = raw.replace(/"\s*"/g, '').replace(/"/g, '').trim();
  const tags = {};
  const parts = cleaned.split(/\s*;\s*/);
  for (const part of parts) {
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    tags[key] = value;
  }
  return tags;
}

function parseMailtoList(value) {
  if (!value) return [];
  return value.split(',').map((s) => {
    const trimmed = s.trim();
    let url = trimmed;
    let limit = null;
    const bangIdx = trimmed.indexOf('!');
    if (bangIdx !== -1) {
      url = trimmed.slice(0, bangIdx);
      limit = trimmed.slice(bangIdx + 1);
    }
    const addr = url.replace(/^mailto:/i, '');
    return {
      raw: trimmed,
      address: addr,
      hasMailtoPrefix: /^mailto:/i.test(url),
      valid: EMAIL_RE.test(addr),
      sizeLimit: limit,
    };
  });
}

async function fetchDMARCRecord(domain) {
  const host = `_dmarc.${domain}`;
  try {
    const txt = await dns.resolveTxt(host);
    if (!txt || txt.length === 0) return null;
    // Return the first record that starts with v=DMARC1 (RFC says only one valid record)
    for (const arr of txt) {
      const joined = arr.join('');
      if (/^v\s*=\s*DMARC1/i.test(joined)) {
        return joined;
      }
    }
    return null;
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return null;
    throw e;
  }
}

/**
 * Find the DMARC record that applies to `domain`: its own _dmarc record or,
 * when there is none, the nearest parent record, walking up label by label and
 * stopping at the organizational (registrable) domain. The organizational
 * domain comes from a small public-suffix heuristic (utils/dnsNames).
 * Throws on DNS failures (SERVFAIL / timeout).
 */
async function resolveApplicableDMARC(domain) {
  const orgDomain = organizationalDomain(domain);
  const orgLabels = orgDomain.split('.').length;
  let current = domain;
  for (let i = 0; i < 10; i++) {
    const raw = await fetchDMARCRecord(current);
    if (raw) {
      return { raw, recordDomain: current, inherited: current !== domain, orgDomain };
    }
    if (current === orgDomain) break;
    const next = current.slice(current.indexOf('.') + 1);
    if (!next || next === current || next.split('.').length < orgLabels) break;
    current = next;
  }
  return { raw: null, recordDomain: null, inherited: false, orgDomain };
}

/** Policy that applies to `domain`: sp= (falling back to p=) when inherited. */
function effectiveDMARCPolicy(tags, inherited) {
  if (!tags) return null;
  if (inherited && tags.sp) return tags.sp;
  return tags.p || null;
}

function validateDMARCTags(tags) {
  const issues = [];

  if (!tags.v) {
    issues.push({ severity: 'error', message: 'Missing required v= tag' });
  } else if (tags.v !== 'DMARC1') {
    issues.push({ severity: 'error', message: `Unexpected version: ${tags.v} (must be DMARC1)` });
  }

  if (!tags.p) {
    issues.push({ severity: 'error', message: 'Missing required p= tag (none / quarantine / reject)' });
  } else if (!['none', 'quarantine', 'reject'].includes(tags.p)) {
    issues.push({ severity: 'error', message: `Invalid p= value: ${tags.p}` });
  }

  if (tags.sp && !['none', 'quarantine', 'reject'].includes(tags.sp)) {
    issues.push({ severity: 'error', message: `Invalid sp= value: ${tags.sp}` });
  }

  if (tags.pct !== undefined) {
    const pct = Number(tags.pct);
    if (!Number.isInteger(pct) || pct < 0 || pct > 100) {
      issues.push({ severity: 'error', message: `Invalid pct= value: ${tags.pct} (must be 0-100)` });
    } else if (tags.p === 'none' && pct !== 100) {
      issues.push({ severity: 'info', message: 'pct= has no effect when p=none' });
    }
  }

  for (const key of ['adkim', 'aspf']) {
    if (tags[key] && !['r', 's'].includes(tags[key])) {
      issues.push({ severity: 'error', message: `Invalid ${key}= value: ${tags[key]} (must be r or s)` });
    }
  }

  if (tags.fo !== undefined) {
    const allowed = new Set(['0', '1', 'd', 's']);
    const parts = tags.fo.split(':');
    if (!parts.every((p) => allowed.has(p))) {
      issues.push({ severity: 'warning', message: `fo= contains unknown value(s): ${tags.fo}` });
    }
  }

  if (tags.ri !== undefined) {
    const ri = Number(tags.ri);
    if (!Number.isInteger(ri) || ri < 0) {
      issues.push({ severity: 'error', message: `Invalid ri= value: ${tags.ri} (must be a non-negative integer)` });
    }
  }

  if (tags.rf !== undefined && !['afrf', 'iodef'].includes(tags.rf)) {
    issues.push({ severity: 'warning', message: `Unusual rf= value: ${tags.rf} (typically afrf)` });
  }

  const rua = parseMailtoList(tags.rua);
  for (const e of rua) {
    if (!e.valid) {
      issues.push({ severity: 'error', message: `Invalid rua address: ${e.raw}` });
    } else if (!e.hasMailtoPrefix) {
      issues.push({ severity: 'error', message: `rua= entry missing mailto: prefix (${e.raw})` });
    }
  }
  const ruf = parseMailtoList(tags.ruf);
  for (const e of ruf) {
    if (!e.valid) {
      issues.push({ severity: 'error', message: `Invalid ruf address: ${e.raw}` });
    } else if (!e.hasMailtoPrefix) {
      issues.push({ severity: 'error', message: `ruf= entry missing mailto: prefix (${e.raw})` });
    }
  }

  if (tags.p === 'none' && (!rua || rua.length === 0)) {
    issues.push({
      severity: 'warning',
      message:
        'p=none without rua= provides no monitoring data — the whole point of p=none is to collect aggregate reports. Add a rua= mailbox.',
    });
  }

  if (tags.p === 'none') {
    issues.push({
      severity: 'info',
      message:
        'p=none is monitoring-only — receivers will not change delivery on DMARC failures. Plan a ramp to quarantine then reject.',
    });
  }

  // 2024 Google / Yahoo bulk-sender compliance check
  const compliant2024 = tags.v === 'DMARC1' && !!tags.p && rua.some((e) => e.valid && e.hasMailtoPrefix);

  return { issues, rua, ruf, compliant2024 };
}

router.post(
  '/dmarc-checker',
  enhancedSecurityWithRateLimit(dmarcRateLimit),
  [
    body('domain')
      .trim()
      .notEmpty()
      .withMessage('Domain is required')
      .isLength({ max: 253 })
      .matches(DOMAIN_NAME_RE)
      .withMessage('Invalid domain format')
      .customSanitizer((v) => v.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '').replace(/:.*$/, '')),
  ],
  handleValidationErrors,
  async (req, res) => {
    const requestId = `dmarc-check-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const startTime = Date.now();
    const { domain } = req.body;

    // v2: results now include the organizational-domain fallback.
    const cacheKey = `dmarc-check:v2:${domain}`;
    const cached = await redisUtils.get(cacheKey);
    if (cached) {
      return sendSuccess(res, 'DMARC record retrieved from cache', { ...cached, cached: true });
    }

    let raw;
    let applicable;
    try {
      applicable = await resolveApplicableDMARC(domain);
      raw = applicable.raw;
    } catch (e) {
      logger.error('DMARC lookup failed', { requestId, domain, error: e.message, code: e.code });
      return sendError(res, e.code === 'ENOTFOUND' ? 'Domain not found' : 'DNS lookup failed', e.code === 'ENOTFOUND' ? 404 : 500, {
        dnsError: e.code,
      });
    }

    if (!raw) {
      const empty = {
        domain,
        timestamp: new Date().toISOString(),
        found: false,
        record: null,
        tags: null,
        issues: [
          {
            severity: 'error',
            message:
              'No DMARC record found at _dmarc.' +
              domain +
              (applicable.orgDomain && applicable.orgDomain !== domain ? ' or at the organizational domain _dmarc.' + applicable.orgDomain : '') +
              '. Bulk senders to Gmail / Yahoo (2024 requirements) must publish at least v=DMARC1; p=none; rua=mailto:dmarc@yourdomain.com',
          },
        ],
        rua: [],
        ruf: [],
        compliant2024: false,
        recordDomain: null,
        inherited: false,
        organizationalDomain: applicable.orgDomain,
        effectivePolicy: null,
        lookupTime: Date.now() - startTime,
        cached: false,
      };
      await redisUtils.setex(cacheKey, 3600, empty);
      return sendSuccess(res, 'No DMARC record found', empty);
    }

    const tags = parseDMARCRecord(raw);
    const { issues, rua, ruf, compliant2024 } = validateDMARCTags(tags);
    const effectivePolicy = effectiveDMARCPolicy(tags, applicable.inherited);
    if (applicable.inherited) {
      issues.unshift({
        severity: 'info',
        message: `No record at _dmarc.${domain}; the record at _dmarc.${applicable.recordDomain} applies to it` +
          (tags.sp ? ` with its subdomain policy sp=${tags.sp}.` : ` (no sp= tag, so p=${tags.p || '?'} applies to subdomains too).`),
      });
    }

    const response = {
      domain,
      timestamp: new Date().toISOString(),
      found: true,
      record: raw,
      tags,
      issues,
      rua,
      ruf,
      compliant2024,
      valid: issues.filter((i) => i.severity === 'error').length === 0,
      recordDomain: applicable.recordDomain,
      inherited: applicable.inherited,
      organizationalDomain: applicable.orgDomain,
      effectivePolicy,
      lookupTime: Date.now() - startTime,
      cached: false,
    };

    await redisUtils.setex(cacheKey, 3600, response);

    logger.info('DMARC check completed', {
      requestId,
      domain,
      found: true,
      compliant2024,
      issueCount: issues.length,
      lookupTime: response.lookupTime,
    });

    return sendSuccess(res, 'DMARC record analyzed successfully', response);
  }
);

// ============================================================================
// BIMI Checker (DNS + SVG Tiny PS validation + VMC + DMARC prerequisite)
// ============================================================================

const bimiRateLimit = createCustomRateLimit({
  windowMs: 60 * 60 * 1000,
  max: 20,
  message: {
    success: false,
    message: 'Too many BIMI checker requests. You can perform 20 checks per hour. Please try again later.',
    retryAfter: 3600,
  },
  keyGenerator: (req) => `bimi-checker:${ipKey(req)}`,
  handler: (req, res) => {
    res.status(429).json({
      success: false,
      message: 'Too many BIMI checker requests. You can perform 20 checks per hour. Please try again later.',
      retryAfter: 3600,
    });
  },
});

const BIMI_MAX_SVG_BYTES = 32 * 1024; // 32KB recommended
const BIMI_MAX_FETCH_BYTES = 256 * 1024; // hard cap defensively

const SVG_FORBIDDEN_ELEMENTS = [
  'script',
  'animate',
  'animateMotion',
  'animateTransform',
  'set',
  'foreignObject',
  'iframe',
  'video',
  'audio',
  'image',
];

const SVG_FORBIDDEN_ATTRS = [
  'onload',
  'onclick',
  'onerror',
  'onmouseover',
  'onmouseout',
  'href',
  'xlink:href',
];

function parseBIMIRecord(raw) {
  const cleaned = raw.replace(/"\s*"/g, '').replace(/"/g, '').trim();
  const tags = {};
  for (const part of cleaned.split(/\s*;\s*/)) {
    if (!part) continue;
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const value = part.slice(eq + 1).trim();
    tags[key] = value;
  }
  return tags;
}

async function fetchBIMIRecord(domain) {
  const host = `default._bimi.${domain}`;
  try {
    const txt = await dns.resolveTxt(host);
    if (!txt || txt.length === 0) return null;
    for (const arr of txt) {
      const joined = arr.join('');
      if (/^v\s*=\s*BIMI1/i.test(joined)) return joined;
    }
    return null;
  } catch (e) {
    if (e.code === 'ENOTFOUND' || e.code === 'ENODATA') return null;
    throw e;
  }
}

async function fetchSizedResource(url, maxBytes, acceptHeader) {
  const u = new URL(url);
  if (u.protocol !== 'https:' && u.protocol !== 'http:') {
    throw new Error('Only http/https URLs are allowed');
  }
  // SSRF guard: refuse hosts that resolve into private space. safeFetch below
  // re-screens every redirect hop; this pre-check just gives a clearer error.
  if (u.hostname) {
    const hostCheck = await screenHostname(u.hostname);
    if (!hostCheck.valid) throw new Error('Refusing to fetch from private/internal host');
  }
  if (u.protocol !== 'https:') {
    // BIMI requires HTTPS for logo and VMC — surface as a soft signal upstream
  }
  // safeFetch re-screens every redirect hop, so a public host cannot 302 us
  // onto a private address.
  const { response: res } = await safeFetch(url, {
    headers: acceptHeader ? { Accept: acceptHeader } : {},
    signal: AbortSignal.timeout(8000),
  });
  if (!res.ok) {
    return { ok: false, status: res.status, statusText: res.statusText, contentType: res.headers.get('content-type'), bytes: null, truncated: false };
  }
  const contentType = res.headers.get('content-type') || '';
  const buf = await res.arrayBuffer();
  const bytes = new Uint8Array(buf);
  const truncated = bytes.length > maxBytes;
  return {
    ok: true,
    status: res.status,
    statusText: res.statusText,
    contentType,
    bytes: bytes.slice(0, maxBytes),
    fullLength: bytes.length,
    truncated,
    isHttps: u.protocol === 'https:',
  };
}

function validateSVGTinyPS(svgText, fullByteLength) {
  const issues = [];
  let viewBox = null;
  let aspectRatioSquare = null;
  let baseProfile = null;

  if (fullByteLength > BIMI_MAX_SVG_BYTES) {
    issues.push({
      severity: 'warning',
      message: `SVG file size is ${fullByteLength} bytes — above the recommended 32KB limit for BIMI`,
    });
  }

  // Quick sanity check
  if (!/<svg[\s>]/i.test(svgText)) {
    issues.push({ severity: 'error', message: 'Not a valid SVG document (no <svg> root element found)' });
    return { issues, viewBox, aspectRatioSquare, baseProfile };
  }

  // baseProfile
  const baseProfileMatch = svgText.match(/baseProfile\s*=\s*"([^"]+)"/i);
  baseProfile = baseProfileMatch ? baseProfileMatch[1] : null;
  if (!baseProfile) {
    issues.push({ severity: 'error', message: 'Missing required baseProfile="tiny-ps" attribute on <svg> root element' });
  } else if (baseProfile !== 'tiny-ps') {
    issues.push({
      severity: 'error',
      message: `Incorrect baseProfile: "${baseProfile}" (BIMI requires baseProfile="tiny-ps")`,
    });
  }

  // viewBox & aspect ratio
  const viewBoxMatch = svgText.match(/viewBox\s*=\s*"([^"]+)"/i);
  if (viewBoxMatch) {
    viewBox = viewBoxMatch[1];
    const parts = viewBox.trim().split(/[\s,]+/).map(Number);
    if (parts.length === 4 && parts.every((n) => Number.isFinite(n))) {
      const [, , w, h] = parts;
      aspectRatioSquare = w === h;
      if (!aspectRatioSquare) {
        issues.push({
          severity: 'error',
          message: `viewBox is not square (${w}×${h}). BIMI requires a 1:1 aspect ratio.`,
        });
      }
    } else {
      issues.push({ severity: 'warning', message: 'viewBox is malformed' });
    }
  } else {
    issues.push({ severity: 'error', message: 'Missing required viewBox attribute on <svg> root element' });
  }

  // Forbidden elements
  for (const el of SVG_FORBIDDEN_ELEMENTS) {
    const re = new RegExp(`<\\s*${el}[\\s>/]`, 'i');
    if (re.test(svgText)) {
      issues.push({
        severity: 'error',
        message: `Forbidden element <${el}> found — not allowed in SVG Tiny PS`,
      });
    }
  }

  // Forbidden attributes (xlink:href / href can be permitted in <use> but we surface as warnings — BIMI bans external references)
  if (/xlink:href\s*=/i.test(svgText) || /\shref\s*=/i.test(svgText)) {
    issues.push({
      severity: 'warning',
      message: 'SVG contains href / xlink:href — BIMI forbids external resource references. Verify all references are internal (#id).',
    });
  }
  for (const attr of SVG_FORBIDDEN_ATTRS) {
    if (attr === 'href' || attr === 'xlink:href') continue;
    const re = new RegExp(`\\s${attr}\\s*=`, 'i');
    if (re.test(svgText)) {
      issues.push({
        severity: 'error',
        message: `Event handler attribute "${attr}" found — not allowed in SVG Tiny PS`,
      });
    }
  }

  // XML declaration / DOCTYPE
  if (/<!DOCTYPE/i.test(svgText)) {
    issues.push({ severity: 'warning', message: 'SVG contains a DOCTYPE declaration — BIMI recommends omitting it' });
  }

  // External font references
  if (/@font-face/i.test(svgText) || /<link\b/i.test(svgText)) {
    issues.push({ severity: 'error', message: 'External font / link references found — not allowed in SVG Tiny PS' });
  }

  return { issues, viewBox, aspectRatioSquare, baseProfile };
}

async function fetchDMARCForBIMI(domain) {
  try {
    const applicable = await resolveApplicableDMARC(domain);
    const raw = applicable.raw;
    if (!raw) return { found: false, eligible: false, raw: null, tags: null };
    const tags = parseDMARCRecord(raw);
    const pct = tags.pct === undefined ? 100 : Number(tags.pct);
    const policy = effectiveDMARCPolicy(tags, applicable.inherited);
    const eligible = (policy === 'quarantine' || policy === 'reject') && pct === 100;
    return { found: true, eligible, raw, tags, recordDomain: applicable.recordDomain, inherited: applicable.inherited, effectivePolicy: policy };
  } catch {
    return { found: false, eligible: false, raw: null, tags: null };
  }
}

router.post(
  '/bimi-checker',
  enhancedSecurityWithRateLimit(bimiRateLimit),
  [
    body('domain')
      .trim()
      .notEmpty()
      .withMessage('Domain is required')
      .isLength({ max: 253 })
      .matches(DOMAIN_NAME_RE)
      .withMessage('Invalid domain format')
      .customSanitizer((v) => v.toLowerCase().replace(/^https?:\/\//, '').replace(/^www\./, '').replace(/\/.*$/, '').replace(/:.*$/, '')),
  ],
  handleValidationErrors,
  async (req, res) => {
    const requestId = `bimi-check-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
    const startTime = Date.now();
    const { domain } = req.body;

    const cacheKey = `bimi-check:v2:${domain}`;
    const cached = await redisUtils.get(cacheKey);
    if (cached) {
      return sendSuccess(res, 'BIMI record retrieved from cache', { ...cached, cached: true });
    }

    let raw;
    try {
      raw = await fetchBIMIRecord(domain);
    } catch (e) {
      logger.error('BIMI lookup failed', { requestId, domain, error: e.message, code: e.code });
      return sendError(res, e.code === 'ENOTFOUND' ? 'Domain not found' : 'DNS lookup failed', e.code === 'ENOTFOUND' ? 404 : 500, {
        dnsError: e.code,
      });
    }

    // Always evaluate DMARC prerequisite — BIMI requires it regardless of whether BIMI record exists
    const dmarc = await fetchDMARCForBIMI(domain);

    if (!raw) {
      const issues = [
        {
          severity: 'error',
          message: `No BIMI record found at default._bimi.${domain}`,
        },
      ];
      if (!dmarc.eligible) {
        issues.push({
          severity: 'info',
          message:
            'DMARC prerequisite is not met — before publishing BIMI you must enforce DMARC at p=quarantine or p=reject with pct=100.',
        });
      }
      const empty = {
        domain,
        timestamp: new Date().toISOString(),
        found: false,
        record: null,
        tags: null,
        logo: null,
        vmc: null,
        dmarc,
        issues,
        lookupTime: Date.now() - startTime,
        cached: false,
      };
      await redisUtils.setex(cacheKey, 3600, empty);
      return sendSuccess(res, 'No BIMI record found', empty);
    }

    const tags = parseBIMIRecord(raw);
    const issues = [];

    if (tags.v !== 'BIMI1') {
      issues.push({ severity: 'error', message: `Unexpected version: ${tags.v} (must be BIMI1)` });
    }

    // Declination record: an empty l= (with no certificate) is how a domain
    // explicitly opts out of BIMI. It is valid, not an error, and the logo /
    // DMARC-enforcement prerequisites do not apply.
    const declined = Object.prototype.hasOwnProperty.call(tags, 'l') && tags.l === '' && !tags.a;
    if (declined && tags.v === 'BIMI1') {
      const response = {
        domain,
        timestamp: new Date().toISOString(),
        found: true,
        declined: true,
        record: raw,
        tags,
        logo: null,
        vmc: null,
        dmarc,
        issues: [
          {
            severity: 'info',
            message: 'This is a BIMI declination record (empty l=): the domain has opted out of showing a brand logo. No logo will be displayed, by design.',
          },
        ],
        valid: true,
        clientCompatibility: null,
        lookupTime: Date.now() - startTime,
        cached: false,
      };
      await redisUtils.setex(cacheKey, 3600, response);
      return sendSuccess(res, 'BIMI declination record found', response);
    }

    // DMARC prerequisite
    if (!dmarc.found) {
      issues.push({
        severity: 'error',
        message: 'No DMARC record found — BIMI requires DMARC at p=quarantine or p=reject with pct=100.',
      });
    } else if (!dmarc.eligible) {
      const pct = dmarc.tags.pct === undefined ? 100 : Number(dmarc.tags.pct);
      issues.push({
        severity: 'error',
        message: `DMARC policy is ${dmarc.inherited && dmarc.tags.sp ? 'sp' : 'p'}=${dmarc.effectivePolicy || 'unknown'}${pct !== 100 ? ` pct=${pct}` : ''} — BIMI requires p=quarantine or p=reject with pct=100.`,
      });
    }

    // Logo (l=) fetch and validate
    let logo = null;
    if (tags.l) {
      try {
        const resource = await fetchSizedResource(tags.l, BIMI_MAX_FETCH_BYTES, 'image/svg+xml');
        if (!resource.ok) {
          logo = { url: tags.l, fetched: false, status: resource.status, statusText: resource.statusText, contentType: resource.contentType };
          issues.push({
            severity: 'error',
            message: `Logo URL returned HTTP ${resource.status} ${resource.statusText} (${tags.l})`,
          });
        } else {
          const svgText = new TextDecoder('utf-8').decode(resource.bytes);
          const { issues: svgIssues, viewBox, aspectRatioSquare, baseProfile } = validateSVGTinyPS(svgText, resource.fullLength);
          logo = {
            url: tags.l,
            fetched: true,
            isHttps: resource.isHttps,
            contentType: resource.contentType,
            fileSize: resource.fullLength,
            withinSizeLimit: resource.fullLength <= BIMI_MAX_SVG_BYTES,
            baseProfile,
            viewBox,
            aspectRatioSquare,
            svgPreview: svgText.slice(0, 4096),
            svgValid: svgIssues.filter((i) => i.severity === 'error').length === 0,
            svgIssues,
          };
          if (!resource.isHttps) {
            issues.push({ severity: 'error', message: 'BIMI logo URL must use HTTPS' });
          }
          if (resource.contentType && !/svg/i.test(resource.contentType)) {
            issues.push({
              severity: 'warning',
              message: `Logo Content-Type is "${resource.contentType}" — expected image/svg+xml`,
            });
          }
          issues.push(...svgIssues);
        }
      } catch (e) {
        logo = { url: tags.l, fetched: false, error: e.message };
        issues.push({ severity: 'error', message: `Unable to fetch logo: ${e.message}` });
      }
    } else {
      issues.push({ severity: 'error', message: 'Missing l= (logo URL) tag' });
    }

    // VMC (a=) fetch
    let vmc = null;
    if (tags.a) {
      try {
        const resource = await fetchSizedResource(tags.a, BIMI_MAX_FETCH_BYTES, 'application/pem-certificate-chain');
        if (!resource.ok) {
          vmc = { url: tags.a, fetched: false, status: resource.status, statusText: resource.statusText };
          issues.push({
            severity: 'warning',
            message: `VMC URL returned HTTP ${resource.status} ${resource.statusText}. Gmail and Apple Mail require a valid VMC or CMC.`,
          });
        } else {
          const text = new TextDecoder('utf-8').decode(resource.bytes);
          const looksLikePem = /-----BEGIN CERTIFICATE-----/i.test(text);
          // Parse the leaf certificate to extract issuer / subject / validity.
          // Node's crypto.X509Certificate takes a single PEM cert; the response
          // may contain a chain, so isolate the first BEGIN/END block.
          let issuer = null;
          let issuerCN = null;
          let issuerO = null;
          let subject = null;
          let subjectO = null;
          let validFrom = null;
          let validTo = null;
          let expired = null;
          let expiringSoon = null;
          if (looksLikePem) {
            try {
              const firstCertMatch = text.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/);
              const firstCert = firstCertMatch ? firstCertMatch[0] : text;
              const cert = new crypto.X509Certificate(firstCert);
              // cert.issuer / cert.subject return DN as newline-separated key=value pairs
              // Node returns DN values with RFC 4514 backslash escaping
              // (e.g. "O=DigiCert\\, Inc."). Strip the backslash escapes
              // for display so users see "DigiCert, Inc." not "DigiCert\, Inc.".
              const unescapeDN = (v) => {
                let out = '';
                for (let i = 0; i < v.length; i++) {
                  if (v[i] === '\\' && i + 1 < v.length) {
                    out += v[i + 1];
                    i++;
                  } else {
                    out += v[i];
                  }
                }
                return out;
              };
              const parseDN = (dn) => {
                const out = {};
                if (!dn) return out;
                for (const line of dn.split(/\r?\n/)) {
                  const eq = line.indexOf('=');
                  if (eq === -1) continue;
                  const k = line.slice(0, eq).trim();
                  const v = unescapeDN(line.slice(eq + 1).trim());
                  if (k) out[k] = v;
                }
                return out;
              };
              const issuerDN = parseDN(cert.issuer);
              const subjectDN = parseDN(cert.subject);
              issuerCN = issuerDN.CN || null;
              issuerO = issuerDN.O || null;
              subject = subjectDN.CN || null;
              subjectO = subjectDN.O || null;
              // Canonicalise the issuing CA to one of the two known VMC issuers
              const issuerHaystack = `${issuerO || ''} ${issuerCN || ''}`;
              if (/DigiCert/i.test(issuerHaystack)) issuer = 'DigiCert';
              else if (/Entrust/i.test(issuerHaystack)) issuer = 'Entrust';
              else issuer = issuerO || issuerCN || null;

              validFrom = cert.validFrom || null;
              validTo = cert.validTo || null;
              if (validTo) {
                const expiry = Date.parse(validTo);
                if (!Number.isNaN(expiry)) {
                  const now = Date.now();
                  expired = expiry < now;
                  expiringSoon = !expired && expiry - now < 30 * 24 * 60 * 60 * 1000;
                }
              }
            } catch (parseErr) {
              logger.debug('VMC certificate parse failed', { error: parseErr.message });
            }
          }
          vmc = {
            url: tags.a,
            fetched: true,
            isHttps: resource.isHttps,
            contentType: resource.contentType,
            fileSize: resource.fullLength,
            looksLikePem,
            issuer,
            issuerCN,
            issuerO,
            subject,
            subjectO,
            validFrom,
            validTo,
            expired,
            expiringSoon,
          };
          if (!looksLikePem) {
            issues.push({ severity: 'warning', message: 'VMC URL did not return a PEM certificate chain — Gmail may reject the BIMI logo' });
          }
          if (!resource.isHttps) {
            issues.push({ severity: 'warning', message: 'VMC URL should use HTTPS' });
          }
          if (expired) {
            issues.push({
              severity: 'error',
              message: `VMC certificate expired on ${validTo}. Gmail will refuse to display the BIMI logo until a new VMC is issued.`,
            });
          } else if (expiringSoon) {
            issues.push({
              severity: 'warning',
              message: `VMC certificate expires in less than 30 days (on ${validTo}). Renew before expiry to avoid Gmail BIMI dropouts.`,
            });
          }
        }
      } catch (e) {
        vmc = { url: tags.a, fetched: false, error: e.message };
        issues.push({
          severity: 'warning',
          message: `Unable to fetch VMC: ${e.message}. Gmail and Apple Mail require a valid VMC or CMC.`,
        });
      }
    } else {
      issues.push({
        severity: 'info',
        message:
          'No certificate (a=) tag — your logo can display in Yahoo, AOL and Fastmail but not in Gmail or Apple Mail, which require a Verified Mark Certificate (VMC) or Common Mark Certificate (CMC).',
      });
    }

    const response = {
      domain,
      timestamp: new Date().toISOString(),
      found: true,
      record: raw,
      tags,
      logo,
      vmc,
      dmarc,
      issues,
      valid: issues.filter((i) => i.severity === 'error').length === 0,
      // Gmail and Apple Mail only show BIMI logos backed by a mark certificate
      // (VMC or CMC); Yahoo, AOL and Fastmail do not require one.
      clientCompatibility: {
        gmail: !!(vmc && vmc.fetched && vmc.looksLikePem && vmc.expired !== true) && dmarc.eligible && !!(logo && logo.svgValid),
        yahoo: dmarc.eligible && !!(logo && logo.svgValid),
        appleMail: !!(vmc && vmc.fetched && vmc.looksLikePem && vmc.expired !== true) && dmarc.eligible && !!(logo && logo.svgValid),
        aol: dmarc.eligible && !!(logo && logo.svgValid),
        fastmail: dmarc.eligible && !!(logo && logo.svgValid),
      },
      lookupTime: Date.now() - startTime,
      cached: false,
    };

    await redisUtils.setex(cacheKey, 3600, response);

    logger.info('BIMI check completed', {
      requestId,
      domain,
      hasVMC: !!tags.a,
      dmarcEligible: dmarc.eligible,
      issueCount: issues.length,
      lookupTime: response.lookupTime,
    });

    return sendSuccess(res, 'BIMI record analyzed successfully', response);
  }
);

module.exports = router;
