/**
 * Edge-proxy authentication — the application-level half of origin lockdown.
 *
 * All legitimate browser traffic reaches this API through the Cloudflare Worker.
 * Nothing enforced that, so anyone who learned the origin hostname could talk to
 * it directly and thereby:
 *
 *   - skip the Worker's origin check and its edge rate limiting entirely;
 *   - forge `X-Forwarded-For`, since `trust proxy` makes `req.ip` the last hop.
 *     That resets rate-limit buckets at will, evades IP bans, and — because bans
 *     are keyed on the same value — lets an attacker get arbitrary third-party
 *     IPs banned by forging failed auth attempts against them.
 *
 * The Worker now sends a shared secret on EVERY forwarded request (including the
 * public ones that carry no API token), so the origin can tell edge traffic from
 * direct traffic. When that secret checks out, `CF-Connecting-IP` is trustworthy
 * and becomes the identity used for rate limiting and banning.
 *
 * This is defence in depth, NOT a replacement for network-level lockdown
 * (Cloudflare Authenticated Origin Pull, or a firewall allowing only Cloudflare
 * egress). It closes the same hole at the application layer, which is the part
 * that can live in the repo.
 */

const crypto = require('crypto');
const logger = require('../utils/logger');

/** Header the Worker sets. Non-standard on purpose — nothing else should send it. */
const EDGE_AUTH_HEADER = 'x-edge-auth';

/**
 * Header the Worker sets with the real client IP. Cloudflare may rewrite
 * `CF-Connecting-IP` on Worker subrequests to a non-proxied origin, so the
 * Worker sends this explicitly instead of relying on that header surviving.
 */
const EDGE_CLIENT_IP_HEADER = 'x-edge-client-ip';

/**
 * Paths that legitimately receive direct, non-edge traffic.
 *
 *  - /webhook/:id  is the product: users hand that URL to a third-party service
 *                  which then POSTs to it. Requiring an edge secret would break
 *                  the webhook tester for every real caller.
 *  - health probes  are meant to be polled directly by monitoring and by the
 *                  container runtime.
 */
const EXEMPT_EXACT = new Set(['/health', '/ready', '/live', '/metrics', '/status', '/version', '/health/detailed']);
const EXEMPT_PREFIXES = ['/webhook/'];

function isExempt(path) {
  if (EXEMPT_EXACT.has(path)) return true;
  return EXEMPT_PREFIXES.some((prefix) => path.startsWith(prefix));
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  return crypto.timingSafeEqual(bufA, bufB);
}

/**
 * Build the middleware. Returns a pass-through when EDGE_SECRET is unset, so
 * local development (which talks to the API directly, with no Worker in front)
 * keeps working. `assertProductionConfig` in server.js is what makes the secret
 * mandatory where it matters.
 */
function createEdgeProxyGuard() {
  // Explicit escape hatch for running WITHOUT an edge in front — a VPS-only
  // deployment, or an emergency migration off Cloudflare. Without this, the
  // production config assertion refuses to boot when EDGE_SECRET is missing,
  // which is correct for the normal topology but would block a migration at
  // exactly the wrong moment. Opting out has to be deliberate, not accidental.
  if (process.env.ALLOW_DIRECT_ORIGIN === 'true') {
    logger.warn(
      'ALLOW_DIRECT_ORIGIN=true - edge-proxy verification is OFF. The origin accepts direct requests, ' +
      'so X-Forwarded-For is caller-controlled again: restrict access at the firewall, and be aware ' +
      'that IP-based rate limiting and banning are only as trustworthy as your network perimeter.'
    );
    return (req, res, next) => next();
  }

  const secret = process.env.EDGE_SECRET;

  if (!secret) {
    logger.warn(
      'EDGE_SECRET not set - origin will accept direct requests. Fine for local dev; set it in any deployed environment.'
    );
    return (req, res, next) => next();
  }

  return (req, res, next) => {
    if (isExempt(req.path)) {
      return next();
    }

    if (!safeEqual(req.get(EDGE_AUTH_HEADER) || '', secret)) {
      logger.securityLog('Direct origin request rejected (missing/invalid edge secret)', {
        path: req.path,
        method: req.method,
        // req.ip is untrustworthy here by definition — that is the whole point —
        // so record the socket peer as well.
        reportedIp: req.ip,
        socketIp: req.socket?.remoteAddress,
      });

      return res.status(403).json({
        success: false,
        message: 'Direct access to this origin is not permitted',
        error: 'EDGE_REQUIRED',
      });
    }

    // The request demonstrably came through our edge, so the IP it reports is
    // the real client and cannot have been forged by the caller. Prefer the
    // Worker's explicit X-Edge-Client-IP header — Cloudflare may rewrite
    // CF-Connecting-IP on Worker subrequests to a non-proxied origin — and
    // fall back to CF-Connecting-IP. Both are only trusted here because the
    // edge secret check above already passed.
    const clientIp = req.get(EDGE_CLIENT_IP_HEADER) || req.get('cf-connecting-ip');
    if (clientIp) {
      req.trustedClientIp = clientIp;
    }

    return next();
  };
}

module.exports = { createEdgeProxyGuard, EDGE_AUTH_HEADER, EDGE_CLIENT_IP_HEADER };
