const nodemailer = require('nodemailer');
const logger = require('./logger');

/**
 * Security Notification Service
 * Handles sending security alerts via email
 */
class SecurityNotifier {
  constructor() {
    this.securityEmail = process.env.SECURITY_EMAIL || 'security@toolzyhub.app';
    this.emailFrom = process.env.EMAIL_FROM || 'noreply@toolzyhub.app';
    this.transporter = null;
    this.lastEmailSent = new Map(); // Rate limiting for emails
    this.emailCooldown = 5 * 60 * 1000; // 5 minutes cooldown per IP
  }

  /**
   * Initialize email transporter
   */
  initializeTransporter() {
    if (this.transporter) {
      return this.transporter;
    }

    try {
      const smtpHost = process.env.SMTP_HOST;
      const smtpPort = process.env.SMTP_PORT;
      const smtpUser = process.env.SMTP_USER;
      const smtpPass = process.env.SMTP_PASS;

      if (!smtpHost || !smtpPort || !smtpUser || !smtpPass) {
        logger.error('SMTP configuration incomplete for security notifications');
        return null;
      }

      this.transporter = nodemailer.createTransporter({
        host: smtpHost,
        port: parseInt(smtpPort),
        secure: false,
        auth: {
          user: smtpUser,
          pass: smtpPass,
        },
      });

      logger.info('Security notification email transporter initialized');
      return this.transporter;
    } catch (error) {
      logger.error('Failed to initialize security email transporter', {
        error: error.message
      });
      return null;
    }
  }

  /**
   * Check if we should send email (rate limiting)
   */
  shouldSendEmail(ip) {
    const lastSent = this.lastEmailSent.get(ip);
    const now = Date.now();

    if (!lastSent || (now - lastSent) > this.emailCooldown) {
      this.lastEmailSent.set(ip, now);
      return true;
    }

    return false;
  }

  /**
   * Get IP geolocation info (basic implementation)
   */
  async getIPInfo(ip) {
    // Basic IP info - in production you might want to use a geolocation service
    const isPrivate = this.isPrivateIP(ip);
    
    return {
      ip,
      isPrivate,
      location: isPrivate ? 'Private Network' : 'Unknown Location',
      isp: 'Unknown ISP'
    };
  }

  /**
   * Check if IP is private/local
   */
  isPrivateIP(ip) {
    const privateRanges = [
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
      /^192\.168\./,
      /^127\./,
      /^::1$/,
      /^fc00:/,
      /^fe80:/
    ];

    return privateRanges.some(range => range.test(ip));
  }

  /**
   * Format ban duration for email
   */
  formatBanDuration(hours) {
    if (hours < 24) {
      return `${hours} hour${hours !== 1 ? 's' : ''}`;
    } else {
      const days = Math.floor(hours / 24);
      const remainingHours = hours % 24;
      let result = `${days} day${days !== 1 ? 's' : ''}`;
      if (remainingHours > 0) {
        result += ` and ${remainingHours} hour${remainingHours !== 1 ? 's' : ''}`;
      }
      return result;
    }
  }

  /**
   * Generate security alert email HTML
   */
  generateSecurityAlertHTML(banData, ipInfo) {
    const banDuration = this.formatBanDuration(banData.banDurationHours);
    const bannedAt = new Date(banData.bannedAt).toLocaleString();
    const expiresAt = new Date(banData.expiresAt).toLocaleString();

    return `
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Alert - IP Address Banned</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px; }
        .header { background-color: #dc3545; color: white; padding: 20px; border-radius: 5px 5px 0 0; text-align: center; }
        .content { background-color: #f8f9fa; padding: 20px; border: 1px solid #dee2e6; }
        .footer { background-color: #6c757d; color: white; padding: 15px; border-radius: 0 0 5px 5px; text-align: center; font-size: 12px; }
        .alert-box { background-color: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 5px; margin: 15px 0; }
        .info-table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        .info-table th, .info-table td { padding: 10px; text-align: left; border-bottom: 1px solid #dee2e6; }
        .info-table th { background-color: #e9ecef; font-weight: bold; }
        .critical { color: #dc3545; font-weight: bold; }
        .code { background-color: #f1f3f4; padding: 2px 4px; border-radius: 3px; font-family: monospace; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚨 Security Alert</h1>
        <h2>IP Address Banned</h2>
    </div>
    
    <div class="content">
        <div class="alert-box">
            <strong>⚠️ CRITICAL SECURITY EVENT</strong><br>
            An IP address has been automatically banned due to multiple failed authentication attempts.
        </div>
        
        <h3>Ban Details</h3>
        <table class="info-table">
            <tr>
                <th>IP Address</th>
                <td class="critical code">${banData.ip}</td>
            </tr>
            <tr>
                <th>Location</th>
                <td>${ipInfo.location}</td>
            </tr>
            <tr>
                <th>ISP</th>
                <td>${ipInfo.isp}</td>
            </tr>
            <tr>
                <th>Ban Reason</th>
                <td>${banData.reason}</td>
            </tr>
            <tr>
                <th>Failed Attempts</th>
                <td class="critical">${banData.requestInfo.failedAttempts || 'Unknown'}</td>
            </tr>
            <tr>
                <th>Banned At</th>
                <td>${bannedAt}</td>
            </tr>
            <tr>
                <th>Ban Duration</th>
                <td class="critical">${banDuration}</td>
            </tr>
            <tr>
                <th>Ban Expires</th>
                <td>${expiresAt}</td>
            </tr>
        </table>
        
        <h3>Request Information</h3>
        <table class="info-table">
            <tr>
                <th>Last Endpoint</th>
                <td class="code">${banData.requestInfo.endpoint || 'Unknown'}</td>
            </tr>
            <tr>
                <th>User Agent</th>
                <td class="code">${banData.requestInfo.userAgent || 'Unknown'}</td>
            </tr>
            <tr>
                <th>Network Type</th>
                <td>${ipInfo.isPrivate ? 'Private/Internal' : 'Public/External'}</td>
            </tr>
        </table>
        
        <div class="alert-box">
            <strong>📋 Recommended Actions:</strong>
            <ul>
                <li>Review server logs for additional suspicious activity</li>
                <li>Check if this IP should be whitelisted (if it's a legitimate service)</li>
                <li>Monitor for similar attack patterns from other IPs</li>
                <li>Consider implementing additional security measures if attacks persist</li>
            </ul>
        </div>
        
        <h3>System Information</h3>
        <table class="info-table">
            <tr>
                <th>Server</th>
                <td>ToolzyHub API (api.toolzyhub.app)</td>
            </tr>
            <tr>
                <th>Environment</th>
                <td>${process.env.NODE_ENV || 'Unknown'}</td>
            </tr>
            <tr>
                <th>Alert Generated</th>
                <td>${new Date().toLocaleString()}</td>
            </tr>
        </table>
    </div>
    
    <div class="footer">
        <p>This is an automated security alert from ToolzyHub API Security System</p>
        <p>If you believe this is a false positive, please investigate immediately</p>
    </div>
</body>
</html>`;
  }

  /**
   * Generate plain text version of security alert
   */
  generateSecurityAlertText(banData, ipInfo) {
    const banDuration = this.formatBanDuration(banData.banDurationHours);
    const bannedAt = new Date(banData.bannedAt).toLocaleString();
    const expiresAt = new Date(banData.expiresAt).toLocaleString();

    return `
SECURITY ALERT - IP ADDRESS BANNED
==================================

CRITICAL SECURITY EVENT: An IP address has been automatically banned due to multiple failed authentication attempts.

BAN DETAILS:
- IP Address: ${banData.ip}
- Location: ${ipInfo.location}
- ISP: ${ipInfo.isp}
- Ban Reason: ${banData.reason}
- Failed Attempts: ${banData.requestInfo.failedAttempts || 'Unknown'}
- Banned At: ${bannedAt}
- Ban Duration: ${banDuration}
- Ban Expires: ${expiresAt}

REQUEST INFORMATION:
- Last Endpoint: ${banData.requestInfo.endpoint || 'Unknown'}
- User Agent: ${banData.requestInfo.userAgent || 'Unknown'}
- Network Type: ${ipInfo.isPrivate ? 'Private/Internal' : 'Public/External'}

RECOMMENDED ACTIONS:
- Review server logs for additional suspicious activity
- Check if this IP should be whitelisted (if it's a legitimate service)
- Monitor for similar attack patterns from other IPs
- Consider implementing additional security measures if attacks persist

SYSTEM INFORMATION:
- Server: ToolzyHub API (api.toolzyhub.app)
- Environment: ${process.env.NODE_ENV || 'Unknown'}
- Alert Generated: ${new Date().toLocaleString()}

This is an automated security alert from ToolzyHub API Security System.
If you believe this is a false positive, please investigate immediately.
`;
  }

  /**
   * Send IP ban notification email
   */
  async sendIPBanAlert(banData) {
    try {
      // Check rate limiting
      if (!this.shouldSendEmail(banData.ip)) {
        logger.info('Security email rate limited', {
          ip: banData.ip,
          cooldownMinutes: this.emailCooldown / (60 * 1000)
        });
        return false;
      }

      const transporter = this.initializeTransporter();
      if (!transporter) {
        logger.error('Cannot send security alert - email transporter not available');
        return false;
      }

      // Get IP information
      const ipInfo = await this.getIPInfo(banData.ip);

      // Generate email content
      const htmlContent = this.generateSecurityAlertHTML(banData, ipInfo);
      const textContent = this.generateSecurityAlertText(banData, ipInfo);

      const mailOptions = {
        from: this.emailFrom,
        to: this.securityEmail,
        subject: `🚨 SECURITY ALERT: IP ${banData.ip} Banned - ToolzyHub API`,
        html: htmlContent,
        text: textContent,
        priority: 'high',
        headers: {
          'X-Priority': '1',
          'X-MSMail-Priority': 'High',
          'Importance': 'high'
        }
      };

      // Send email
      const info = await transporter.sendMail(mailOptions);

      logger.info('Security alert email sent successfully', {
        ip: banData.ip,
        to: this.securityEmail,
        messageId: info.messageId,
        bannedAt: banData.bannedAt,
        banDuration: banData.banDurationHours
      });

      return true;
    } catch (error) {
      logger.error('Failed to send security alert email', {
        error: error.message,
        stack: error.stack,
        ip: banData.ip,
        to: this.securityEmail
      });
      return false;
    }
  }

  /**
   * Send test security alert (for testing purposes)
   */
  async sendTestAlert() {
    const testBanData = {
      ip: '192.168.1.100',
      reason: 'Test security alert',
      bannedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
      banDurationHours: 24,
      requestInfo: {
        userAgent: 'Test User Agent',
        endpoint: '/api/test',
        failedAttempts: 5
      }
    };

    return await this.sendIPBanAlert(testBanData);
  }

  /**
   * Clean up old rate limiting entries
   */
  cleanupRateLimiting() {
    const now = Date.now();
    for (const [ip, timestamp] of this.lastEmailSent.entries()) {
      if ((now - timestamp) > this.emailCooldown) {
        this.lastEmailSent.delete(ip);
      }
    }
  }
}

// Export singleton instance
module.exports = new SecurityNotifier();
