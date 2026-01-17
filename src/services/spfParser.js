const dns = require('dns').promises;
const logger = require('../utils/logger');

/**
 * SPF Parser Service
 * Implements RFC 7208 - Sender Policy Framework (SPF)
 */

/**
 * SPF Mechanism Types according to RFC 7208
 */
const SPF_MECHANISMS = {
  ALL: 'all',
  A: 'a',
  MX: 'mx',
  IP4: 'ip4',
  IP6: 'ip6',
  INCLUDE: 'include',
  EXISTS: 'exists',
  PTR: 'ptr'
};

/**
 * SPF Qualifiers
 */
const SPF_QUALIFIERS = {
  PASS: '+',      // Pass
  FAIL: '-',      // Fail
  SOFTFAIL: '~',  // SoftFail
  NEUTRAL: '?'    // Neutral
};

/**
 * SPF Modifiers
 */
const SPF_MODIFIERS = {
  REDIRECT: 'redirect',
  EXP: 'exp'
};

/**
 * Maximum DNS lookups allowed per RFC 7208 (Section 4.6.4)
 */
const MAX_DNS_LOOKUPS = 10;

/**
 * SPF Parser Class
 */
class SPFParser {
  constructor() {
    this.dnsLookupCount = 0;
    this.visitedDomains = new Set();
    this.allowedIPv4 = [];
    this.allowedIPv6 = [];
    this.mechanisms = [];
    this.modifiers = {};
    this.issues = [];
    this.warnings = [];
  }

  /**
   * Parse SPF record and extract all information
   */
  async parseSPFRecord(domain, record, isInclude = false) {
    if (!isInclude) {
      // Reset for main domain
      this.dnsLookupCount = 0;
      this.visitedDomains = new Set();
      this.allowedIPv4 = [];
      this.allowedIPv6 = [];
      this.mechanisms = [];
      this.modifiers = {};
      this.issues = [];
      this.warnings = [];
    }

    // Prevent infinite loops
    if (this.visitedDomains.has(domain)) {
      this.warnings.push({
        severity: 'medium',
        message: `Circular reference detected: ${domain}`,
        recommendation: 'Remove circular includes to prevent infinite loops'
      });
      return;
    }

    this.visitedDomains.add(domain);

    // Validate SPF version
    if (!record.startsWith('v=spf1')) {
      this.issues.push({
        severity: 'high',
        message: 'Invalid SPF record: Must start with "v=spf1"',
        recommendation: 'Ensure SPF record starts with "v=spf1"'
      });
      return;
    }

    // Split record into terms
    const terms = record.split(/\s+/).filter(term => term.length > 0);

    // Skip the version identifier
    for (let i = 1; i < terms.length; i++) {
      const term = terms[i];
      await this.parseTerm(term, domain);
    }
  }

  /**
   * Parse individual SPF term
   */
  async parseTerm(term, domain) {
    // Extract qualifier (default is '+' for pass)
    let qualifier = '+';
    let mechanism = term;

    if (['+', '-', '~', '?'].includes(term[0])) {
      qualifier = term[0];
      mechanism = term.substring(1);
    }

    // Check if it's a modifier (contains '=')
    if (mechanism.includes('=') && !mechanism.startsWith('ip4:') && !mechanism.startsWith('ip6:')) {
      await this.parseModifier(mechanism, domain);
      return;
    }

    // Parse mechanism
    const mechanismType = mechanism.split(':')[0].split('/')[0].toLowerCase();
    const mechanismValue = mechanism.includes(':') ? mechanism.split(':')[1] : null;

    const mechanismData = {
      type: mechanismType,
      value: mechanismValue,
      qualifier: qualifier,
      qualifierName: this.getQualifierName(qualifier),
      original: term
    };

    this.mechanisms.push(mechanismData);

    // Process mechanism based on type
    switch (mechanismType) {
      case SPF_MECHANISMS.ALL:
        await this.handleAll(qualifier);
        break;

      case SPF_MECHANISMS.A:
        await this.handleA(mechanismValue || domain, domain);
        break;

      case SPF_MECHANISMS.MX:
        await this.handleMX(mechanismValue || domain, domain);
        break;

      case SPF_MECHANISMS.IP4:
        this.handleIP4(mechanismValue);
        break;

      case SPF_MECHANISMS.IP6:
        this.handleIP6(mechanismValue);
        break;

      case SPF_MECHANISMS.INCLUDE:
        await this.handleInclude(mechanismValue, qualifier);
        break;

      case SPF_MECHANISMS.EXISTS:
        await this.handleExists(mechanismValue);
        break;

      case SPF_MECHANISMS.PTR:
        this.handlePTR(mechanismValue, qualifier);
        break;

      default:
        this.warnings.push({
          severity: 'low',
          message: `Unknown mechanism: ${mechanismType}`,
          recommendation: 'Verify mechanism syntax according to RFC 7208'
        });
    }
  }

  /**
   * Parse SPF modifier
   */
  async parseModifier(modifier, domain) {
    const [name, value] = modifier.split('=');

    if (name === SPF_MODIFIERS.REDIRECT) {
      this.modifiers.redirect = value;

      // Follow redirect
      if (this.dnsLookupCount < MAX_DNS_LOOKUPS) {
        try {
          const redirectedRecord = await this.lookupSPFRecord(value);
          if (redirectedRecord) {
            await this.parseSPFRecord(value, redirectedRecord, true);
          }
        } catch (error) {
          this.warnings.push({
            severity: 'high',
            message: `Failed to resolve redirect domain: ${value}`,
            recommendation: 'Verify redirect domain is valid and has an SPF record'
          });
        }
      }
    } else if (name === SPF_MODIFIERS.EXP) {
      this.modifiers.exp = value;
    } else {
      this.warnings.push({
        severity: 'low',
        message: `Unknown modifier: ${name}`,
        recommendation: 'Verify modifier syntax according to RFC 7208'
      });
    }
  }

  /**
   * Handle 'all' mechanism
   */
  async handleAll(qualifier) {
    if (qualifier === '+') {
      this.issues.push({
        severity: 'critical',
        message: 'Using "+all" allows all senders (extremely insecure)',
        recommendation: 'Change to "-all" (hard fail) or "~all" (soft fail)'
      });
    } else if (qualifier === '?') {
      this.warnings.push({
        severity: 'medium',
        message: 'Using "?all" provides no protection',
        recommendation: 'Change to "-all" (hard fail) or "~all" (soft fail)'
      });
    }
  }

  /**
   * Handle 'a' mechanism - lookup A/AAAA records
   */
  async handleA(targetDomain, baseDomain) {
    if (this.dnsLookupCount >= MAX_DNS_LOOKUPS) return;

    this.dnsLookupCount++;

    try {
      // Lookup A records (IPv4)
      const addresses = await dns.resolve4(targetDomain);
      addresses.forEach(ip => {
        if (!this.allowedIPv4.includes(ip)) {
          this.allowedIPv4.push(ip);
        }
      });

      // Try AAAA records (IPv6)
      try {
        const ipv6Addresses = await dns.resolve6(targetDomain);
        ipv6Addresses.forEach(ip => {
          if (!this.allowedIPv6.includes(ip)) {
            this.allowedIPv6.push(ip);
          }
        });
      } catch (ipv6Error) {
        // IPv6 not available, ignore
      }
    } catch (error) {
      this.warnings.push({
        severity: 'medium',
        message: `Failed to resolve A record for ${targetDomain}: ${error.code}`,
        recommendation: 'Verify domain exists and has A records'
      });
    }
  }

  /**
   * Handle 'mx' mechanism - lookup MX records then their A records
   */
  async handleMX(targetDomain, baseDomain) {
    if (this.dnsLookupCount >= MAX_DNS_LOOKUPS) return;

    this.dnsLookupCount++;

    try {
      const mxRecords = await dns.resolveMx(targetDomain);

      for (const mx of mxRecords) {
        if (this.dnsLookupCount >= MAX_DNS_LOOKUPS) break;

        // Lookup A records for each MX host
        await this.handleA(mx.exchange, targetDomain);
      }
    } catch (error) {
      this.warnings.push({
        severity: 'medium',
        message: `Failed to resolve MX record for ${targetDomain}: ${error.code}`,
        recommendation: 'Verify domain exists and has MX records'
      });
    }
  }

  /**
   * Handle 'ip4' mechanism - add IPv4 address/range
   */
  handleIP4(ipRange) {
    if (!ipRange) {
      this.warnings.push({
        severity: 'medium',
        message: 'ip4 mechanism missing IP address',
        recommendation: 'Specify IP address in format: ip4:192.0.2.0/24'
      });
      return;
    }

    // Validate IPv4 format
    const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
    if (!ipv4Regex.test(ipRange)) {
      this.warnings.push({
        severity: 'medium',
        message: `Invalid IPv4 format: ${ipRange}`,
        recommendation: 'Use valid IPv4 address or CIDR notation'
      });
      return;
    }

    if (!this.allowedIPv4.includes(ipRange)) {
      this.allowedIPv4.push(ipRange);
    }
  }

  /**
   * Handle 'ip6' mechanism - add IPv6 address/range
   */
  handleIP6(ipRange) {
    if (!ipRange) {
      this.warnings.push({
        severity: 'medium',
        message: 'ip6 mechanism missing IP address',
        recommendation: 'Specify IP address in format: ip6:2001:db8::/32'
      });
      return;
    }

    // Basic IPv6 validation
    const ipv6Regex = /^[0-9a-fA-F:]+(:\/\d{1,3})?$/;
    if (!ipv6Regex.test(ipRange)) {
      this.warnings.push({
        severity: 'medium',
        message: `Invalid IPv6 format: ${ipRange}`,
        recommendation: 'Use valid IPv6 address or CIDR notation'
      });
      return;
    }

    if (!this.allowedIPv6.includes(ipRange)) {
      this.allowedIPv6.push(ipRange);
    }
  }

  /**
   * Handle 'include' mechanism - recursively parse included domain
   */
  async handleInclude(includeDomain, qualifier) {
    if (!includeDomain) {
      this.warnings.push({
        severity: 'high',
        message: 'include mechanism missing domain',
        recommendation: 'Specify domain in format: include:_spf.example.com'
      });
      return;
    }

    if (this.dnsLookupCount >= MAX_DNS_LOOKUPS) {
      this.issues.push({
        severity: 'high',
        message: `DNS lookup limit reached before processing include:${includeDomain}`,
        recommendation: 'Reduce number of includes and DNS-dependent mechanisms'
      });
      return;
    }

    this.dnsLookupCount++;

    try {
      const includedRecord = await this.lookupSPFRecord(includeDomain);

      if (includedRecord) {
        // Recursively parse included SPF record
        await this.parseSPFRecord(includeDomain, includedRecord, true);
      }
    } catch (error) {
      this.warnings.push({
        severity: 'high',
        message: `Failed to resolve include domain ${includeDomain}: ${error.code}`,
        recommendation: 'Verify included domain exists and has valid SPF record'
      });
    }
  }

  /**
   * Handle 'exists' mechanism
   */
  async handleExists(domain) {
    if (!domain) {
      this.warnings.push({
        severity: 'medium',
        message: 'exists mechanism missing domain',
        recommendation: 'Specify domain in format: exists:%{ir}.%{l1r+-}._spf.%{d}'
      });
      return;
    }

    if (this.dnsLookupCount >= MAX_DNS_LOOKUPS) return;

    this.dnsLookupCount++;

    // Note: exists mechanism is complex with macro expansion
    // For basic implementation, we just note it's present
    this.warnings.push({
      severity: 'info',
      message: `exists mechanism used: ${domain}`,
      recommendation: 'Ensure macro expansion is correctly configured'
    });
  }

  /**
   * Handle 'ptr' mechanism (deprecated)
   */
  handlePTR(domain, qualifier) {
    this.warnings.push({
      severity: 'medium',
      message: 'ptr mechanism is deprecated per RFC 7208',
      recommendation: 'Replace ptr mechanism with explicit ip4/ip6 or include mechanisms'
    });

    if (this.dnsLookupCount < MAX_DNS_LOOKUPS) {
      this.dnsLookupCount++;
    }
  }

  /**
   * Lookup SPF record for a domain
   */
  async lookupSPFRecord(domain) {
    try {
      const txtRecords = await dns.resolveTxt(domain);

      // Find SPF records (must start with v=spf1)
      const spfRecords = txtRecords
        .map(record => Array.isArray(record) ? record.join('') : record)
        .filter(record => record.startsWith('v=spf1'));

      if (spfRecords.length === 0) {
        this.warnings.push({
          severity: 'high',
          message: `No SPF record found for ${domain}`,
          recommendation: 'Add SPF record to domain TXT records'
        });
        return null;
      }

      if (spfRecords.length > 1) {
        this.issues.push({
          severity: 'critical',
          message: `Multiple SPF records found for ${domain} (RFC violation)`,
          recommendation: 'Consolidate into a single SPF record'
        });
        // Use the first one
        return spfRecords[0];
      }

      return spfRecords[0];
    } catch (error) {
      if (error.code === 'ENOTFOUND') {
        this.warnings.push({
          severity: 'high',
          message: `Domain not found: ${domain}`,
          recommendation: 'Verify domain name is correct'
        });
      } else if (error.code === 'ENODATA') {
        this.warnings.push({
          severity: 'high',
          message: `No TXT records found for ${domain}`,
          recommendation: 'Add SPF record to domain TXT records'
        });
      } else {
        this.warnings.push({
          severity: 'high',
          message: `DNS lookup failed for ${domain}: ${error.message}`,
          recommendation: 'Check DNS configuration and network connectivity'
        });
      }
      throw error;
    }
  }

  /**
   * Get qualifier name from symbol
   */
  getQualifierName(qualifier) {
    switch (qualifier) {
      case '+': return 'Pass';
      case '-': return 'Fail';
      case '~': return 'SoftFail';
      case '?': return 'Neutral';
      default: return 'Unknown';
    }
  }

  /**
   * Validate SPF record structure and check for common issues
   */
  validateSPFRecord(record) {
    // Check DNS lookup limit
    if (this.dnsLookupCount > MAX_DNS_LOOKUPS) {
      this.issues.push({
        severity: 'critical',
        message: `Exceeded maximum DNS lookups (${this.dnsLookupCount}/${MAX_DNS_LOOKUPS})`,
        recommendation: 'Reduce includes, MX, A, and EXISTS mechanisms to stay under 10 lookups'
      });
    } else if (this.dnsLookupCount === MAX_DNS_LOOKUPS) {
      this.warnings.push({
        severity: 'high',
        message: `Reached maximum DNS lookups (${MAX_DNS_LOOKUPS})`,
        recommendation: 'Consider reducing includes to avoid hitting the limit'
      });
    }

    // Check if record has proper termination
    const hasTermination = this.mechanisms.some(m => m.type === 'all');
    if (!hasTermination) {
      this.warnings.push({
        severity: 'medium',
        message: 'SPF record does not have an "all" mechanism',
        recommendation: 'Add "-all" or "~all" at the end of your SPF record'
      });
    }

    // Check record length (DNS TXT record limit)
    if (record.length > 255) {
      this.warnings.push({
        severity: 'high',
        message: `SPF record length (${record.length}) exceeds single DNS string limit (255)`,
        recommendation: 'Split into multiple strings or use includes to reduce length'
      });
    }

    // Check for too many includes
    const includeCount = this.mechanisms.filter(m => m.type === 'include').length;
    if (includeCount > 5) {
      this.warnings.push({
        severity: 'medium',
        message: `High number of includes (${includeCount}) may cause performance issues`,
        recommendation: 'Consider consolidating includes or using direct IP addresses'
      });
    }

    // Check for void lookups (mechanisms that don't return results)
    // This is a simplification - full implementation would track actual DNS responses
  }

  /**
   * Get parsing results
   */
  getResults() {
    return {
      mechanisms: this.mechanisms,
      modifiers: this.modifiers,
      allowedIPs: {
        ipv4: this.allowedIPv4,
        ipv6: this.allowedIPv6
      },
      dnsLookups: this.dnsLookupCount,
      issues: this.issues,
      warnings: this.warnings,
      valid: this.issues.filter(i => i.severity === 'critical').length === 0
    };
  }
}

/**
 * Parse and analyze SPF record
 */
async function analyzeSPFRecord(domain) {
  const parser = new SPFParser();

  try {
    // Lookup SPF record
    const record = await parser.lookupSPFRecord(domain);

    if (!record) {
      return {
        domain,
        record: null,
        valid: false,
        mechanisms: [],
        allowedIPs: { ipv4: [], ipv6: [] },
        dnsLookups: parser.dnsLookupCount,
        issues: parser.issues,
        warnings: parser.warnings
      };
    }

    // Parse the record
    await parser.parseSPFRecord(domain, record, false);

    // Validate
    parser.validateSPFRecord(record);

    // Get results
    const results = parser.getResults();

    return {
      domain,
      record,
      ...results
    };

  } catch (error) {
    logger.error('SPF analysis error:', {
      domain,
      error: error.message,
      code: error.code
    });

    throw error;
  }
}

module.exports = {
  SPFParser,
  analyzeSPFRecord,
  SPF_MECHANISMS,
  SPF_QUALIFIERS,
  SPF_MODIFIERS,
  MAX_DNS_LOOKUPS
};
