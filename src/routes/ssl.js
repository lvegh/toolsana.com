const express = require('express');
const tls = require('tls');
const { URL } = require('url');
const { basicRateLimit } = require('../middleware/rateLimit');
const { sendSuccess, sendError } = require('../middleware/errorHandler');

const router = express.Router();

/**
 * Helper function to get SSL certificate information
 */
async function getSSLCertificate(hostname, port = 443, timeout = 10000) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port: port,
      servername: hostname,
      rejectUnauthorized: false, // We want to check even invalid certificates
      timeout: timeout
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
        
        socket.destroy();
        
        if (!cert || !cert.subject) {
          reject(new Error('No certificate found'));
          return;
        }

        resolve({
          certificate: cert,
          protocol: protocol,
          cipher: cipher
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
router.post('/check', basicRateLimit, async (req, res) => {
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

    // Get SSL certificate information
    const sslInfo = await getSSLCertificate(cleanDomain);
    const cert = sslInfo.certificate;
    
    // Calculate days remaining
    const daysRemaining = calculateDaysRemaining(cert.valid_to);
    const isExpired = daysRemaining < 0;
    const isExpiringSoon = daysRemaining <= 30 && daysRemaining > 0;
    
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
      valid: !isExpired && cert.valid_to && new Date() <= new Date(cert.valid_to),
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