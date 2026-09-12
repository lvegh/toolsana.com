/**
 * Cloudflare Turnstile server-side verification.
 *
 * The contact form has rendered a Turnstile widget and posted its token as
 * `cf-turnstile-response` since it was built, but nothing on the server ever
 * looked at that field — the captcha was decorative, and the endpoint behind it
 * was an open relay into our SMTP credentials. This module is the missing half.
 *
 * Fails CLOSED: if the secret is not configured, verification fails rather than
 * waving the request through. Local development can opt out explicitly with
 * TURNSTILE_DISABLED=true, but that flag is only honoured when
 * NODE_ENV !== 'production' or ALLOW_DIRECT_ORIGIN === 'true' (the emergency
 * no-Cloudflare mode). In a normal production deployment the flag is ignored
 * and real verification runs anyway, so "it's dev" can never silently disable
 * the captcha in a deployed environment.
 */

const logger = require('./logger');

const SITEVERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
const VERIFY_TIMEOUT_MS = 5000;

/** The field name the widget posts, per Cloudflare's client-side integration. */
const TOKEN_FIELD = 'cf-turnstile-response';

/**
 * Verify a Turnstile token with Cloudflare.
 *
 * Note on `remoteip`: it is intentionally NOT sent. Requests reach this API
 * through the Cloudflare Worker, so `req.ip` is the Worker's address, not the
 * end user's — sending it would make every verification fail. Cloudflare treats
 * the parameter as optional.
 *
 * @param {string} token The `cf-turnstile-response` value from the client.
 * @returns {Promise<{success: boolean, reason?: string, codes?: string[]}>}
 */
let warnedIgnoredDisableFlag = false;

async function verifyTurnstileToken(token) {
  if (process.env.TURNSTILE_DISABLED === 'true') {
    if (process.env.NODE_ENV !== 'production' || process.env.ALLOW_DIRECT_ORIGIN === 'true') {
      logger.warn('Turnstile verification explicitly disabled via TURNSTILE_DISABLED');
      return { success: true, reason: 'disabled' };
    }

    if (!warnedIgnoredDisableFlag) {
      logger.warn(
        'TURNSTILE_DISABLED=true is set in production without ALLOW_DIRECT_ORIGIN=true - ignoring it and running real verification'
      );
      warnedIgnoredDisableFlag = true;
    }
  }

  const secret = process.env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    logger.error('TURNSTILE_SECRET_KEY is not configured - rejecting request (fail closed)');
    return { success: false, reason: 'not_configured' };
  }

  if (!token || typeof token !== 'string') {
    return { success: false, reason: 'missing_token' };
  }

  // Cloudflare caps tokens at 2048 chars; anything longer is not ours.
  if (token.length > 2048) {
    return { success: false, reason: 'malformed_token' };
  }

  const body = new URLSearchParams({ secret, response: token });

  let response;
  try {
    response = await fetch(SITEVERIFY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
      signal: AbortSignal.timeout(VERIFY_TIMEOUT_MS),
    });
  } catch (error) {
    // Network failure or timeout reaching Cloudflare. Fail closed: an attacker
    // who can disrupt egress must not thereby disable the captcha.
    logger.error('Turnstile verification request failed', { error: error.message });
    return { success: false, reason: 'verification_unavailable' };
  }

  if (!response.ok) {
    logger.error('Turnstile siteverify returned a non-OK status', { status: response.status });
    return { success: false, reason: 'verification_unavailable' };
  }

  let result;
  try {
    result = await response.json();
  } catch (error) {
    logger.error('Turnstile siteverify returned unparseable JSON', { error: error.message });
    return { success: false, reason: 'verification_unavailable' };
  }

  if (result.success === true) {
    return { success: true };
  }

  const codes = Array.isArray(result['error-codes']) ? result['error-codes'] : [];
  logger.securityLog('Turnstile verification rejected', { codes });

  return { success: false, reason: 'rejected', codes };
}

module.exports = { verifyTurnstileToken, TOKEN_FIELD };
