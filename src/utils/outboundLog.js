/**
 * Outbound request logging — abuse visibility.
 *
 * Several tools here make requests to third parties on a caller's behalf:
 * /api/fetch (arbitrary HTTP), /api/email/smtp-test (arbitrary SMTP), and the
 * link checker (crawls). That is the intended product, but it means our IP can
 * be the visible source of traffic somebody else chose to send.
 *
 * Without this, the first sign of abuse is an abuse complaint or a blocklist
 * entry — by which point the damage is done and we still can't tell what
 * happened. Every outbound-on-behalf-of-a-caller request logs one line with a
 * stable `event: 'outbound_request'` marker, so it can be grepped, shipped, or
 * alerted on:
 *
 *   grep '"event":"outbound_request"' logs/*.log \
 *     | jq -r '.targetHost' | sort | uniq -c | sort -rn | head
 *
 * Deliberately records the target HOST only, never the full URL, path, query,
 * headers or body: the point is to spot "one caller hammering one victim", and
 * user-supplied URLs routinely carry tokens and other secrets that must not be
 * written to disk.
 */

const logger = require('./logger');

/**
 * Extract a bare hostname from a URL string, or null if unparseable.
 * Never throws — logging must not be able to break a request.
 */
function hostOf(rawUrl) {
  try {
    return new URL(String(rawUrl)).hostname || null;
  } catch {
    return null;
  }
}

/**
 * Record one outbound request made on a caller's behalf.
 *
 * @param {object} params
 * @param {string} params.tool        Which tool initiated it (e.g. 'api-fetch').
 * @param {string} [params.targetHost] Destination host (preferred).
 * @param {string} [params.targetUrl]  Destination URL; host is extracted from it.
 * @param {number} [params.targetPort] Destination port, where meaningful.
 * @param {string} [params.method]     HTTP/SMTP method or mode.
 * @param {object} [params.req]        Express request, for the client IP.
 * @param {object} [params.extra]      Extra non-sensitive fields.
 */
function logOutbound({ tool, targetHost, targetUrl, targetPort, method, req, extra } = {}) {
  try {
    const host = targetHost || (targetUrl ? hostOf(targetUrl) : null);

    logger.info('Outbound request', {
      event: 'outbound_request',
      tool,
      targetHost: host,
      ...(targetPort ? { targetPort } : {}),
      ...(method ? { method } : {}),
      clientIp: req ? (req.ip || req.connection?.remoteAddress || null) : null,
      ...(extra || {}),
    });
  } catch (error) {
    // Visibility must never take down the request it is observing.
    logger.warn('Failed to log outbound request', { error: error.message, tool });
  }
}

module.exports = { logOutbound, hostOf };
