const express = require('express');
const tls = require('tls');
const net = require('net');
const { URL } = require('url');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');
const { checkPublicHostname, pinnedLookup, GENERIC_PRIVATE_ERROR } = require('../utils/ssrfGuard');
const { enhancedSecurityWithRateLimit } = require('../middleware/enhancedSecurity');

const router = express.Router();

/**
 * Helper function to get SSL certificate information
 */
async function getSSLCertificate(hostname, port = 443, timeout = 10000, pinnedAddress = null) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: port,
      servername: hostname,
      rejectUnauthorized: false, // We want to check even invalid certificates
      timeout: timeout,
      // Dial the exact address the SSRF guard already screened. servername
      // stays the hostname so SNI and cert validation are unaffected.
      // See pinnedLookup in utils/ssrfGuard for the dual-callback contract.
      ...(pinnedAddress ? { lookup: pinnedLookup(pinnedAddress.address) } : {}),
    });

    const timeoutId = setTimeout(() => {
      socket.destroy();
      reject(new Error('Connection timeout'));
    }, timeout);

    socket.on('secureConnect', () => {
      clearTimeout(timeoutId);
      
      try {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        // rejectUnauthorized:false lets the handshake finish so the certificate
        // can be inspected, but Node still runs full chain verification against
        // its CA store and records the outcome here. It must be read: without
        // it a self-signed or untrusted-root certificate looked "valid".
        const authorized = socket.authorized === true;
        const authorizationError = socket.authorizationError
          ? String(socket.authorizationError.code || socket.authorizationError)
          : null;
        
        socket.destroy();
        
        if (!cert || !cert.subject) {
          reject(new Error('No certificate found'));
          return;
        }

        resolve({
          certificate: cert,
          protocol: protocol,
          cipher: cipher,
          authorized,
          authorizationError
        });
      } catch (error) {
        socket.destroy();
        reject(error);
      }
    });

    socket.on('error', (error) => {
      clearTimeout(timeoutId);
      socket.destroy();
      reject(error);
    });

    socket.on('timeout', () => {
      clearTimeout(timeoutId);
      socket.destroy();
      reject(new Error('Connection timeout'));
    });
  });
}

/**
 * Helper function to parse certificate chain
 */
function parseCertificateChain(cert, depth = 0, maxDepth = 10) {
  const certificates = [];
  let currentCert = cert;
  let currentDepth = 0;

  while (currentCert && currentDepth < maxDepth) {
    certificates.push({
      subject: currentCert.subject?.CN || 'Unknown',
      issuer: currentCert.issuer?.CN || 'Unknown',
      valid: !currentCert.valid_from || !currentCert.valid_to ? false : 
             new Date() >= new Date(currentCert.valid_from) && 
             new Date() <= new Date(currentCert.valid_to),
      serialNumber: currentCert.serialNumber,
      fingerprint: currentCert.fingerprint,
      algorithm: currentCert.sigalg
    });

    // Move to issuer certificate if available
    if (currentCert.issuerCertificate && 
        currentCert.issuerCertificate !== currentCert && 
        currentCert.issuerCertificate.subject) {
      currentCert = currentCert.issuerCertificate;
    } else {
      break;
    }
    currentDepth++;
  }

  return certificates;
}

/**
 * Human-readable explanations for OpenSSL chain-verification codes. Node
 * reports only the first failure it hits, walking up from the leaf.
 */
const TRUST_ERROR_MESSAGES = {
  DEPTH_ZERO_SELF_SIGNED_CERT: 'Certificate is self-signed (not issued by a trusted certificate authority)',
  SELF_SIGNED_CERT_IN_CHAIN: 'Certificate chain ends in an untrusted root (self-signed root not in the trusted CA store)',
  UNABLE_TO_GET_ISSUER_CERT_LOCALLY: 'Certificate chain could not be verified: the issuer is not a trusted certificate authority, or the server did not send its intermediate certificate',
  UNABLE_TO_GET_ISSUER_CERT: 'Certificate chain could not be verified: issuer certificate not found',
  UNABLE_TO_VERIFY_LEAF_SIGNATURE: 'Incomplete certificate chain: the server did not send the intermediate certificate needed to reach a trusted root',
  CERT_HAS_EXPIRED: 'A certificate in the chain has expired',
  CERT_NOT_YET_VALID: 'A certificate in the chain is not yet valid',
  CERT_REVOKED: 'Certificate has been revoked',
  CERT_SIGNATURE_FAILURE: 'Certificate signature is invalid',
  CERT_UNTRUSTED: 'Certificate is not trusted',
  CERT_REJECTED: 'Certificate was rejected',
  INVALID_CA: 'A certificate in the chain is not a valid certificate authority',
  PATH_LENGTH_EXCEEDED: 'Certificate chain is longer than the issuer allows',
  INVALID_PURPOSE: 'Certificate is not valid for TLS server authentication',
  ERR_TLS_CERT_ALTNAME_INVALID: 'Certificate does not match the hostname',
};

/**
 * Classify chain trust from the TLS socket result.
 * Returns { trusted, code, reason, selfSigned }.
 */
function describeTrust(authorized, authorizationError) {
  // Node sets authorizationError to ERR_TLS_CERT_ALTNAME_INVALID when the
  // chain verified but the hostname did not match. That is a hostname
  // problem, reported separately, not a trust problem.
  if (authorized || authorizationError === 'ERR_TLS_CERT_ALTNAME_INVALID') {
    return { trusted: true, code: null, reason: null, selfSigned: false };
  }
  const code = authorizationError || 'UNKNOWN';
  return {
    trusted: false,
    code,
    reason: TRUST_ERROR_MESSAGES[code] || `Certificate chain is not trusted (${code})`,
    selfSigned: code === 'DEPTH_ZERO_SELF_SIGNED_CERT',
  };
}

/**
 * Check the certificate against the hostname the user asked about (SAN, with
 * CN fallback only when there is no SAN, wildcard rules per RFC 6125) using
 * the same function Node uses for HTTPS. Returns { matches, error }.
 */
function checkHostname(hostname, cert) {
  try {
    const err = tls.checkServerIdentity(hostname, cert);
    if (err) {
      return { matches: false, error: err.reason || err.message || 'Hostname does not match certificate' };
    }
    return { matches: true, error: null };
  } catch (error) {
    return { matches: false, error: error.message || 'Hostname check failed' };
  }
}

/**
 * Helper function to calculate days remaining
 */
function calculateDaysRemaining(validTo) {
  const now = new Date();
  const expiry = new Date(validTo);
  const diffTime = expiry - now;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  return diffDays;
}

/**
 * Helper function to extract alternative names
 */
function extractAltNames(cert) {
  const altNames = [];
  
  if (cert.subjectaltname) {
    const names = cert.subjectaltname.split(', ');
    names.forEach(name => {
      if (name.startsWith('DNS:')) {
        altNames.push(name.substring(4));
      }
    });
  }
  
  return altNames;
}

/**
 * POST /api/ssl/check
 * Check SSL certificate for a domain
 */
router.post('/check', enhancedSecurityWithRateLimit(basicRateLimit), async (req, res) => {
  try {
    const { domain } = req.body;

    if (!domain) {
      return sendError(res, 'Domain is required', 400);
    }

    // Clean and validate domain
    let cleanDomain = domain.trim().toLowerCase();
    
    // Remove protocol if present
    cleanDomain = cleanDomain.replace(/^https?:\/\//, '');
    
    // Remove path if present
    cleanDomain = cleanDomain.replace(/\/.*$/, '');
    
    // Remove port if present (we'll use 443 by default)
    cleanDomain = cleanDomain.replace(/:.*$/, '');

    // Basic domain validation
    const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?(\.[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]?)*$/;
    if (!domainRegex.test(cleanDomain)) {
      return sendError(res, 'Invalid domain format', 400);
    }

    // Screen the resolved address before opening a socket. The regex above only
    // proves the string looks like a domain — it says nothing about where that
    // domain points, so without this a name resolving to 127.0.0.1 or
    // 169.254.169.254 got a TLS connection and its certificate read back.
    const guard = await checkPublicHostname(cleanDomain);
    if (!guard.valid) {
      return sendError(res, guard.error, guard.error === GENERIC_PRIVATE_ERROR ? 403 : 400);
    }

    // Get SSL certificate information, pinned to the screened address.
    const pinned = { address: guard.addresses[0], family: net.isIP(guard.addresses[0]) };
    const sslInfo = await getSSLCertificate(cleanDomain, 443, 10000, pinned);
    const cert = sslInfo.certificate;
    
    // Calculate days remaining
    const now = new Date();
    const daysRemaining = calculateDaysRemaining(cert.valid_to);
    const isExpired = !cert.valid_to || now > new Date(cert.valid_to);
    const isNotYetValid = !!cert.valid_from && now < new Date(cert.valid_from);
    const isExpiringSoon = !isExpired && daysRemaining <= 30;
    const withinDates = !isExpired && !isNotYetValid;

    // Chain trust (from the handshake) and hostname match (checked here).
    const trust = describeTrust(sslInfo.authorized, sslInfo.authorizationError);
    const hostnameCheck = checkHostname(cleanDomain, cert);
    
    // Extract alternative names
    const altNames = extractAltNames(cert);
    
    // Parse certificate chain
    const certificateChain = parseCertificateChain(cert);
    
    // Generate warnings and errors
    const warnings = [];
    const errors = [];
    
    if (isExpiringSoon) {
      warnings.push(`Certificate expires in ${daysRemaining} days`);
    }
    
    if (isExpired) {
      errors.push('Certificate has expired');
    }

    if (isNotYetValid) {
      errors.push('Certificate is not valid yet (its start date is in the future)');
    }

    // Avoid repeating "expired" when the chain failure is just the leaf's expiry.
    if (!trust.trusted && !(trust.code === 'CERT_HAS_EXPIRED' && isExpired) &&
        !(trust.code === 'CERT_NOT_YET_VALID' && isNotYetValid)) {
      errors.push(trust.reason);
    }

    if (!hostnameCheck.matches) {
      errors.push(`Hostname mismatch: ${hostnameCheck.error}`);
    }
    
    // Check key size
    const keySize = cert.bits || 0;
    if (keySize < 2048 && keySize > 0) {
      warnings.push(`Key size (${keySize} bits) is below recommended 2048 bits`);
    }
    
    // Check signature algorithm
    if (cert.sigalg && cert.sigalg.includes('SHA1')) {
      warnings.push('Certificate uses SHA-1 signature algorithm (deprecated)');
    }
    
    // Build response
    const certificateInfo = {
      domain: cleanDomain,
      // Valid means what a browser would accept: a trusted chain, a
      // certificate issued for this hostname, and today within its dates.
      valid: trust.trusted && hostnameCheck.matches && withinDates,
      trust: {
        trusted: trust.trusted,
        selfSigned: trust.selfSigned,
        code: trust.code,
        reason: trust.reason
      },
      hostname: {
        checked: cleanDomain,
        matches: hostnameCheck.matches,
        error: hostnameCheck.error
      },
      issuer: {
        organization: cert.issuer?.O || cert.issuer?.organizationName,
        country: cert.issuer?.C || cert.issuer?.countryName,
        commonName: cert.issuer?.CN || cert.issuer?.commonName
      },
      subject: {
        commonName: cert.subject?.CN || cert.subject?.commonName,
        organization: cert.subject?.O || cert.subject?.organizationName,
        organizationalUnit: cert.subject?.OU || cert.subject?.organizationalUnitName,
        country: cert.subject?.C || cert.subject?.countryName,
        altNames: altNames
      },
      validity: {
        notBefore: cert.valid_from,
        notAfter: cert.valid_to,
        daysRemaining: daysRemaining,
        isExpired: isExpired,
        isNotYetValid: isNotYetValid,
        isExpiringSoon: isExpiringSoon
      },
      protocol: {
        version: sslInfo.protocol,
        cipher: sslInfo.cipher?.name,
        keyExchange: sslInfo.cipher?.version
      },
      chain: {
        depth: certificateChain.length,
        certificates: certificateChain
      },
      fingerprint: {
        sha1: cert.fingerprint,
        sha256: cert.fingerprint256
      },
      signatureAlgorithm: cert.sigalg,
      keySize: keySize,
      serialNumber: cert.serialNumber,
      warnings: warnings,
      errors: errors
    };

    sendSuccess(res, 'SSL certificate information retrieved successfully', certificateInfo);

  } catch (error) {
    console.error('SSL check error:', error);
    
    // Determine appropriate error message based on error type
    let errorMessage = 'Failed to check SSL certificate';
    let statusCode = 500;
    
    if (error.message.includes('timeout')) {
      errorMessage = 'Connection timeout - domain may be unreachable';
      statusCode = 408;
    } else if (error.message.includes('ENOTFOUND')) {
      errorMessage = 'Domain not found';
      statusCode = 404;
    } else if (error.message.includes('ECONNREFUSED')) {
      errorMessage = 'Connection refused - domain may not support HTTPS';
      statusCode = 503;
    } else if (error.message.includes('certificate')) {
      errorMessage = 'Certificate error - ' + error.message;
      statusCode = 422;
    }
    
    sendError(res, errorMessage, statusCode, {
      domain: req.body.domain,
      details: error.message
    });
  }
});

/**
 * GET /api/ssl/info
 * Get SSL checking service information
 */
router.get('/info', basicRateLimit, (req, res) => {
  const info = {
    service: 'SSL Certificate Checker',
    version: '1.0.0',
    description: 'Check SSL certificate details, expiration dates, and security status for any domain',
    features: [
      'Certificate expiration checking',
      'Certificate chain analysis',
      'Security warnings and recommendations',
      'Support for custom ports',
      'Detailed certificate information',
      'Alternative name extraction'
    ],
    limitations: [
      'Requires HTTPS connection on port 443',
      'Connection timeout after 10 seconds',
      'Rate limited to prevent abuse'
    ],
    usage: {
      endpoint: 'POST /api/ssl/check',
      required_fields: ['domain'],
      example_domain: 'google.com'
    }
  };

  sendSuccess(res, 'SSL service information', info);
});

module.exports = router;