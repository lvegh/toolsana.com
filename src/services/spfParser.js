const dnsPromises = require('dns').promises;
const net = require('net');
const logger = require('../utils/logger');

/**
 * SPF Parser Service
 * Implements the evaluation-limit rules of RFC 7208 (Sender Policy Framework).
 *
 * What receivers count (RFC 7208 §4.6.4) and what this parser therefore counts:
 * - Every `include`, `a`, `mx`, `ptr` and `exists` mechanism and every
 *   `redirect=` modifier costs one DNS lookup, in the record itself AND in every
 *   record reached through include/redirect, recursively.
 * - The address lookups for the hosts returned by an `mx` query do NOT count
 *   against the 10-lookup limit, but an `mx` returning more than 10 hosts is a
 *   permerror.
 * - More than 2 "void" lookups (NXDOMAIN or an empty answer) is a permerror.
 * - `redirect=` is only followed when the record has no `all` mechanism, and
 *   is evaluated after all mechanisms.
 *
 * The count keeps going past 10 (receivers stop there with permerror), so the
 * user sees how far over the limit the record is. To bound the work per
 * request, nested records are only fetched while the count is at most
 * RESOLVE_CAP; beyond that the count is reported as a lower bound.
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

const SPF_QUALIFIERS = {
  PASS: '+',
  FAIL: '-',
  SOFTFAIL: '~',
  NEUTRAL: '?'
};

const SPF_MODIFIERS = {
  REDIRECT: 'redirect',
  EXP: 'exp'
};

const MAX_DNS_LOOKUPS = 10;
const MAX_VOID_LOOKUPS = 2;
const MAX_MX_HOSTS = 10;
const RESOLVE_CAP = 30;
const MAX_DEPTH = 10;

const DNS_TERMS = new Set(['include', 'a', 'mx', 'ptr', 'exists']);
// NXDOMAIN / NOERROR-with-no-answer
const VOID_CODES = new Set(['ENOTFOUND', 'ENODATA']);

const MECHANISM_RE = /^(all|include|a|mx|ptr|ip4|ip6|exists)(?:([:/])(.*))?$/i;
const MODIFIER_RE = /^([a-z][a-z0-9_.-]*)=(.*)$/i;

function defaultResolver() {
  // Bounded timeouts: the default c-ares settings can take ~20 s per failing
  // query, which multiplies across nested includes.
  const r = new dnsPromises.Resolver({ timeout: 3000, tries: 2 });
  return r;
}

function getQualifierName(qualifier) {
  switch (qualifier) {
    case '+': return 'Pass';
    case '-': return 'Fail';
    case '~': return 'SoftFail';
    case '?': return 'Neutral';
    default: return 'Unknown';
  }
}

/**
 * Parse one SPF term (after "v=spf1").
 * @returns {{kind:'modifier', name, value} | {kind:'mechanism', type, qualifier, value, domain, cidr} | {kind:'invalid', reason}}
 */
function parseTerm(term) {
  let qualifier = '+';
  let body = term;
  if ('+-~?'.includes(term[0])) {
    qualifier = term[0];
    body = term.slice(1);
  }

  const mod = MODIFIER_RE.exec(body);
  if (mod && qualifier === '+' && term[0] !== '+') {
    return { kind: 'modifier', name: mod[1].toLowerCase(), value: mod[2] };
  }

  const m = MECHANISM_RE.exec(body);
  if (!m) return { kind: 'invalid', reason: `Unknown or malformed term "${term}"` };

  const type = m[1].toLowerCase();
  const sep = m[2] || null;
  const rest = m[3] !== undefined ? m[3] : null;
  // Keep the historic `value` shape: everything after the first colon.
  const value = sep === ':' ? rest : null;

  let domain = null;
  let cidr = null;
  if (type === 'a' || type === 'mx') {
    if (sep === ':') {
      const slash = rest.indexOf('/');
      domain = slash >= 0 ? rest.slice(0, slash) : rest;
      cidr = slash >= 0 ? rest.slice(slash) : null;
      if (!domain) return { kind: 'invalid', reason: `Empty domain in "${term}"` };
    } else if (sep === '/') {
      cidr = '/' + rest;
    }
  } else if (type === 'include' || type === 'exists') {
    if (sep !== ':' || !rest) return { kind: 'invalid', reason: `"${type}" requires a domain (${type}:example.com)` };
    domain = rest;
  } else if (type === 'ptr') {
    if (sep === '/') return { kind: 'invalid', reason: `Malformed term "${term}"` };
    domain = sep === ':' ? rest : null;
  } else if (type === 'ip4' || type === 'ip6') {
    if (sep !== ':' || !rest) return { kind: 'invalid', reason: `"${type}" requires an address (${type}:...)` };
  } else if (type === 'all') {
    if (sep) return { kind: 'invalid', reason: `"all" takes no argument ("${term}")` };
  }

  return { kind: 'mechanism', type, qualifier, value, domain, cidr };
}

function validIpRange(range, family) {
  const slash = range.indexOf('/');
  const addr = slash >= 0 ? range.slice(0, slash) : range;
  const prefix = slash >= 0 ? range.slice(slash + 1) : null;
  if (net.isIP(addr) !== family) return false;
  if (prefix === null) return true;
  if (!/^\d{1,3}$/.test(prefix)) return false;
  const n = Number(prefix);
  return family === 4 ? n <= 32 : n <= 128;
}

class SPFParser {
  constructor(options = {}) {
    this.resolver = options.resolver || defaultResolver();
    this.reset();
  }

  reset() {
    this.dnsLookupCount = 0;
    this.voidLookupCount = 0;
    this.lookupCountIsLowerBound = false;
    this.limitExceededAt = null;
    this.allowedIPv4 = [];
    this.allowedIPv6 = [];
    this.mechanisms = []; // top-level record only
    this.modifiers = {}; // top-level record only
    this.lookupBreakdown = []; // top-level DNS terms and what each cost, nested included
    this.issues = [];
    this.warnings = [];
    this.txtCache = new Map();
  }

  addIssue(severity, message, recommendation) {
    this.issues.push({ severity, message, recommendation });
  }

  addWarning(severity, message, recommendation) {
    this.warnings.push({ severity, message, recommendation });
  }

  addIPs(list, ips) {
    for (const ip of ips) if (!list.includes(ip)) list.push(ip);
  }

  /**
   * Count one DNS-querying term. Returns true while nested resolution is still
   * allowed (bounded work), false once RESOLVE_CAP is passed.
   */
  countLookup(term, where, chain) {
    this.dnsLookupCount++;
    if (this.dnsLookupCount === MAX_DNS_LOOKUPS + 1 && !this.limitExceededAt) {
      this.limitExceededAt = { term, inRecordOf: where, via: chain.slice() };
    }
    return this.dnsLookupCount <= RESOLVE_CAP;
  }

  /**
   * Fetch and classify the SPF TXT record of a domain (memoised per request).
   * @returns {Promise<{status:'found'|'multiple'|'none'|'error', record?, count?, void?, code?, error?}>}
   */
  fetchSpf(domain) {
    const key = domain.toLowerCase();
    if (!this.txtCache.has(key)) {
      this.txtCache.set(key, (async () => {
        try {
          const txt = await this.resolver.resolveTxt(key);
          const records = (txt || [])
            .map((r) => (Array.isArray(r) ? r.join('') : String(r)).trim())
            .filter((r) => /^v=spf1(\s|$)/i.test(r));
          if (records.length === 0) return { status: 'none', void: !txt || txt.length === 0 };
          if (records.length > 1) return { status: 'multiple', record: records[0], count: records.length };
          return { status: 'found', record: records[0] };
        } catch (error) {
          if (VOID_CODES.has(error.code)) return { status: 'none', void: true, code: error.code, error };
          return { status: 'error', code: error.code || 'DNS_ERROR', error };
        }
      })());
    }
    return this.txtCache.get(key);
  }

  async resolveAddresses(host) {
    const [v4, v6] = await Promise.allSettled([this.resolver.resolve4(host), this.resolver.resolve6(host)]);
    const ipv4 = v4.status === 'fulfilled' ? v4.value : [];
    const ipv6 = v6.status === 'fulfilled' ? v6.value : [];
    const errors = [v4, v6].filter((r) => r.status === 'rejected').map((r) => r.reason && r.reason.code);
    const hardError = errors.find((c) => c && !VOID_CODES.has(c)) || null;
    return { ipv4, ipv6, empty: ipv4.length === 0 && ipv6.length === 0, hardError };
  }

  /**
   * Evaluate one SPF record.
   * ctx: { depth, chain: string[] (terms leading here), ancestry: string[] (domains on the stack), viaInclude }
   */
  async evaluateRecord(domain, record, ctx) {
    const isTop = ctx.depth === 0;
    const terms = record.trim().split(/\s+/).slice(1);
    let redirectTarget = null;
    let hasAll = false;

    for (const term of terms) {
      const parsed = parseTerm(term);

      if (parsed.kind === 'invalid') {
        this.addIssue('critical', `${parsed.reason}${isTop ? '' : ` (in the SPF record of ${domain})`} - receivers return permerror`, 'Fix the term syntax according to RFC 7208');
        continue;
      }

      if (parsed.kind === 'modifier') {
        if (isTop) this.modifiers[parsed.name] = parsed.value;
        if (parsed.name === SPF_MODIFIERS.REDIRECT) {
          if (redirectTarget !== null) {
            this.addIssue('critical', `More than one redirect= modifier in the SPF record of ${domain} - receivers return permerror`, 'Keep a single redirect= modifier');
          } else {
            redirectTarget = parsed.value;
          }
        } else if (parsed.name === SPF_MODIFIERS.EXP) {
          // exp= is only fetched on failure and does not count toward the limit.
        } else if (isTop) {
          this.addWarning('low', `Unknown modifier "${parsed.name}" is ignored by receivers`, 'Remove it or check the spelling');
        }
        continue;
      }

      if (parsed.type === 'all') hasAll = true;
      if (isTop) {
        this.mechanisms.push({
          type: parsed.type,
          value: parsed.value,
          qualifier: parsed.qualifier,
          qualifierName: getQualifierName(parsed.qualifier),
          original: term
        });
      }

      const before = this.dnsLookupCount;
      await this.evaluateMechanism(parsed, term, domain, ctx);
      if (isTop && DNS_TERMS.has(parsed.type)) {
        this.lookupBreakdown.push({ term, lookups: this.dnsLookupCount - before });
      }
    }

    if (redirectTarget !== null) {
      if (hasAll) {
        if (isTop) {
          this.addWarning('low', `redirect=${redirectTarget} is ignored because the record also has an "all" mechanism`, 'Remove either the redirect= modifier or the all mechanism');
        }
      } else {
        const before = this.dnsLookupCount;
        await this.followNested('redirect', `redirect=${redirectTarget}`, redirectTarget, domain, ctx);
        if (isTop) this.lookupBreakdown.push({ term: `redirect=${redirectTarget}`, lookups: this.dnsLookupCount - before });
      }
    }

    return { hasAll, redirect: redirectTarget };
  }

  async evaluateMechanism(parsed, term, domain, ctx) {
    const where = domain;
    switch (parsed.type) {
      case SPF_MECHANISMS.ALL: {
        if (!ctx.viaInclude) {
          if (parsed.qualifier === '+') {
            this.addIssue('critical', 'Using "+all" allows every server on the internet to pass SPF for this domain', 'Change to "-all" (hard fail) or "~all" (soft fail)');
          } else if (parsed.qualifier === '?') {
            this.addWarning('medium', 'Using "?all" provides no protection (neutral result for unlisted senders)', 'Change to "-all" (hard fail) or "~all" (soft fail)');
          }
        } else if (parsed.qualifier === '+') {
          this.addIssue('critical', `The SPF record of ${domain} ends in "+all", so the include that reaches it matches every sender`, 'Remove that include or ask the provider to fix its record');
        }
        return;
      }

      case SPF_MECHANISMS.IP4:
      case SPF_MECHANISMS.IP6: {
        const family = parsed.type === 'ip4' ? 4 : 6;
        if (!validIpRange(parsed.value, family)) {
          this.addIssue('critical', `Invalid ${parsed.type} value "${parsed.value}"${ctx.depth ? ` (in the SPF record of ${domain})` : ''} - receivers return permerror`, family === 4 ? 'Use ip4:192.0.2.0/24 format' : 'Use ip6:2001:db8::/32 format');
          return;
        }
        this.addIPs(family === 4 ? this.allowedIPv4 : this.allowedIPv6, [parsed.value]);
        return;
      }

      case SPF_MECHANISMS.A: {
        const target = parsed.domain || domain;
        const mayResolve = this.countLookup(term, where, ctx.chain);
        if (!mayResolve || target.includes('%')) return;
        const res = await this.resolveAddresses(target);
        if (res.empty && !res.hardError) {
          this.voidLookupCount++;
          this.addWarning('medium', `"${term}" found no A/AAAA records for ${target} (void lookup)`, 'Remove the mechanism or publish the address records');
        } else if (res.empty && res.hardError) {
          this.addWarning('medium', `DNS lookup for "${term}" failed (${res.hardError}) - receivers would return temperror`, 'Check the DNS servers for that name');
        }
        this.addIPs(this.allowedIPv4, res.ipv4);
        this.addIPs(this.allowedIPv6, res.ipv6);
        return;
      }

      case SPF_MECHANISMS.MX: {
        const target = parsed.domain || domain;
        const mayResolve = this.countLookup(term, where, ctx.chain);
        if (!mayResolve || target.includes('%')) return;
        let mxRecords;
        try {
          mxRecords = await this.resolver.resolveMx(target);
        } catch (error) {
          if (VOID_CODES.has(error.code)) {
            this.voidLookupCount++;
            this.addWarning('medium', `"${term}" found no MX records for ${target} (void lookup)`, 'Remove the mechanism or publish MX records');
          } else {
            this.addWarning('medium', `DNS lookup for "${term}" failed (${error.code || 'error'}) - receivers would return temperror`, 'Check the DNS servers for that name');
          }
          return;
        }
        if (!mxRecords || mxRecords.length === 0) {
          this.voidLookupCount++;
          return;
        }
        if (mxRecords.length > MAX_MX_HOSTS) {
          this.addIssue('critical', `"${term}" returns ${mxRecords.length} MX hosts; more than ${MAX_MX_HOSTS} is a permerror (RFC 7208 section 4.6.4)`, 'Use ip4/ip6 ranges instead of mx for this domain');
        }
        // Address lookups of the MX hosts do not count toward the 10-lookup limit.
        const hosts = mxRecords.slice(0, MAX_MX_HOSTS).map((mx) => mx.exchange).filter(Boolean);
        const resolved = await Promise.all(hosts.map((h) => this.resolveAddresses(h)));
        for (const r of resolved) {
          this.addIPs(this.allowedIPv4, r.ipv4);
          this.addIPs(this.allowedIPv6, r.ipv6);
        }
        return;
      }

      case SPF_MECHANISMS.PTR: {
        this.countLookup(term, where, ctx.chain);
        this.addWarning('medium', `"${term}": the ptr mechanism is deprecated (RFC 7208 section 5.5)`, 'Replace ptr with explicit ip4/ip6 or include mechanisms');
        return;
      }

      case SPF_MECHANISMS.EXISTS: {
        this.countLookup(term, where, ctx.chain);
        this.addWarning('info', `exists mechanism used: ${parsed.domain}`, 'Ensure macro expansion is correctly configured');
        return;
      }

      case SPF_MECHANISMS.INCLUDE: {
        await this.followNested('include', term, parsed.domain, domain, ctx);
        return;
      }

      default:
        return;
    }
  }

  /**
   * Shared include / redirect handling.
   */
  async followNested(kind, term, target, fromDomain, ctx) {
    const mayResolve = this.countLookup(term, fromDomain, ctx.chain);
    if (!target) return;
    if (target.includes('%')) {
      this.lookupCountIsLowerBound = true;
      this.addWarning('info', `"${term}" uses SPF macros, so its nested lookups cannot be counted here`, 'Count the lookups of the expanded record manually');
      return;
    }
    if (!mayResolve || ctx.depth >= MAX_DEPTH) {
      this.lookupCountIsLowerBound = true;
      return;
    }
    const targetKey = target.toLowerCase();
    if (ctx.ancestry.includes(targetKey)) {
      this.addIssue('critical', `"${term}" loops back to ${target}, which is already being evaluated - receivers return permerror`, 'Remove the circular include/redirect');
      return;
    }

    const fetched = await this.fetchSpf(targetKey);
    if (fetched.status === 'error') {
      this.lookupCountIsLowerBound = true;
      this.addWarning('high', `DNS lookup for "${term}" failed (${fetched.code}) - receivers would return temperror`, 'Try again later or check the DNS servers of that domain');
      return;
    }
    if (fetched.status === 'none') {
      if (fetched.void) this.voidLookupCount++;
      this.addIssue('critical', `"${term}" points to ${target}, which has no SPF record - receivers return permerror (RFC 7208 section ${kind === 'include' ? '5.2' : '6.1'})`, 'Fix or remove this ' + kind);
      return;
    }
    if (fetched.status === 'multiple') {
      this.addIssue('critical', `${target} publishes ${fetched.count} SPF records - receivers return permerror`, 'Consolidate them into a single SPF record');
    }

    await this.evaluateRecord(targetKey, fetched.record, {
      depth: ctx.depth + 1,
      chain: [...ctx.chain, term],
      ancestry: [...ctx.ancestry, targetKey],
      viaInclude: kind === 'include' ? true : ctx.viaInclude
    });
  }

  finalize(record, topResult) {
    if (this.dnsLookupCount > MAX_DNS_LOOKUPS) {
      let where = '';
      if (this.limitExceededAt) {
        const path = [...this.limitExceededAt.via, this.limitExceededAt.term];
        where = ` The 11th lookup is ${path.join(' -> ')}.`;
      }
      this.addIssue(
        'critical',
        `Too many DNS lookups: ${this.lookupCountIsLowerBound ? 'at least ' : ''}${this.dnsLookupCount} (limit ${MAX_DNS_LOOKUPS}, counted through nested includes). Receivers stop at the 11th lookup and return permerror.${where}`,
        'Reduce includes, a, mx, ptr and exists mechanisms, or replace some includes with ip4/ip6 ranges'
      );
    } else if (this.dnsLookupCount === MAX_DNS_LOOKUPS) {
      this.addWarning('high', `At the DNS lookup limit (${MAX_DNS_LOOKUPS}/${MAX_DNS_LOOKUPS}); one more include or a provider change will break SPF`, 'Consider replacing some includes with ip4/ip6 ranges');
    } else if (this.dnsLookupCount >= 8) {
      this.addWarning('medium', `DNS lookup count is high: ${this.dnsLookupCount} of ${MAX_DNS_LOOKUPS}`, 'Leave headroom: providers can add lookups to their include records at any time');
    }

    if (this.voidLookupCount > MAX_VOID_LOOKUPS) {
      this.addIssue('critical', `${this.voidLookupCount} void lookups (names with no records); more than ${MAX_VOID_LOOKUPS} is a permerror (RFC 7208 section 4.6.4)`, 'Remove mechanisms that point to names without records');
    }

    if (!topResult.hasAll && !topResult.redirect) {
      this.addWarning('medium', 'SPF record has no "all" mechanism and no redirect= modifier, so unlisted senders get a neutral result', 'End the record with "-all" or "~all"');
    }

    if (record.length > 255) {
      this.addWarning('low', `SPF record is ${record.length} characters; it must be published as several strings of at most 255 characters each`, 'Most DNS providers split long TXT values automatically; verify yours does');
    }

    const includeCount = this.mechanisms.filter((m) => m.type === 'include').length;
    if (includeCount > 5) {
      this.addWarning('low', `High number of top-level includes (${includeCount})`, 'Consider consolidating includes or using direct IP addresses');
    }
  }

  getResults() {
    return {
      mechanisms: this.mechanisms,
      modifiers: this.modifiers,
      allowedIPs: {
        ipv4: this.allowedIPv4,
        ipv6: this.allowedIPv6
      },
      dnsLookups: this.dnsLookupCount,
      dnsLookupsIsLowerBound: this.lookupCountIsLowerBound,
      voidLookups: this.voidLookupCount,
      limitExceededAt: this.limitExceededAt,
      lookupBreakdown: this.lookupBreakdown,
      issues: this.issues,
      warnings: this.warnings,
      valid: this.issues.filter((i) => i.severity === 'critical').length === 0
    };
  }
}

/**
 * Parse and analyze the SPF record of a domain.
 * Throws the DNS error (with .code) when the domain itself does not resolve
 * (ENOTFOUND / ENODATA) or the lookup fails (ESERVFAIL / ETIMEOUT ...).
 */
async function analyzeSPFRecord(domain, options = {}) {
  const parser = new SPFParser(options);

  try {
    const top = await parser.fetchSpf(domain);

    if (top.status === 'error' || (top.status === 'none' && top.error)) {
      throw top.error;
    }

    if (top.status === 'none') {
      parser.addWarning('high', `No SPF record found for ${domain}`, 'Add an SPF record (a TXT record starting with v=spf1)');
      return {
        domain,
        record: null,
        valid: false,
        mechanisms: [],
        modifiers: {},
        allowedIPs: { ipv4: [], ipv6: [] },
        dnsLookups: 0,
        dnsLookupsIsLowerBound: false,
        voidLookups: 0,
        limitExceededAt: null,
        lookupBreakdown: [],
        issues: parser.issues,
        warnings: parser.warnings
      };
    }

    if (top.status === 'multiple') {
      parser.addIssue('critical', `Multiple SPF records found for ${domain} (${top.count}) - receivers return permerror`, 'Consolidate into a single SPF record');
    }

    const topResult = await parser.evaluateRecord(domain.toLowerCase(), top.record, {
      depth: 0,
      chain: [],
      ancestry: [domain.toLowerCase()],
      viaInclude: false
    });

    parser.finalize(top.record, topResult);

    return {
      domain,
      record: top.record,
      ...parser.getResults()
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
  parseTerm,
  SPF_MECHANISMS,
  SPF_QUALIFIERS,
  SPF_MODIFIERS,
  MAX_DNS_LOOKUPS
};
