/**
 * Sentinel Audit — SSL/TLS Scanner
 * Checks SSL certificate validity, cipher suites, and HTTPS enforcement.
 */

const tls = require('tls');
const axios = require('axios');

const TIMEOUT_MS = 10000;

// Weak/insecure cipher suites to flag
const WEAK_CIPHERS = [
  /^TLS_RSA_/, // RSA key exchange is weak
  /^TLS_.*_RC4/, // RC4 is broken
  /^TLS_.*_DES/, // DES is broken
  /^TLS_.*_3DES/, // 3DES is weak
  /^TLS_.*_MD5/, // MD5 is broken
  /^SSL_/, // SSLv2/v3 are deprecated
  /_EXPORT_/, // Export ciphers are weak
  /NULL/i, // NULL ciphers
  /anon/i, // Anonymous key exchange
];

// Minimum TLS version to be considered acceptable
const MIN_TLS_VERSION = 'TLSv1.2';

/**
 * Check if a cipher suite is considered weak.
 */
function isWeakCipher(cipher) {
  if (!cipher) return false;
  return WEAK_CIPHERS.some((re) => re.test(cipher));
}

/**
 * Get TLS certificate info from a host.
 */
function getCertInfo(host, port) {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host,
        port: port || 443,
        servername: host,
        rejectUnauthorized: false, // we want to check even invalid certs
        timeout: TIMEOUT_MS,
      },
      () => {
        const cert = socket.getPeerCertificate();
        const cipher = socket.getCipher();
        socket.destroy();
        resolve({ cert, cipher, success: true });
      }
    );

    socket.on('error', (err) => {
      resolve({ cert: null, cipher: null, success: false, error: err.message });
    });

    socket.on('timeout', () => {
      socket.destroy();
      resolve({ cert: null, cipher: null, success: false, error: 'Connection timeout' });
    });
  });
}

/**
 * Extract host from URL or use directly.
 */
function extractHost(target) {
  if (!target) return null;
  try {
    const url = new URL(target.startsWith('http') ? target : 'https://' + target);
    return url.hostname;
  } catch {
    return target;
  }
}

/**
 * Check days until certificate expiry.
 */
function daysUntilExpiry(cert) {
  if (!cert || !cert.valid_to) return null;
  const expiry = new Date(cert.valid_to);
  const now = new Date();
  return Math.ceil((expiry - now) / (1000 * 60 * 60 * 24));
}

/**
 * Scan target for SSL/TLS issues.
 * @param {string} target - URL or hostname
 * @param {object} config - Scanner config
 * @returns {Promise<Array>} Array of finding objects
 */
async function scan(target, config) {
  const findings = [];

  const host = extractHost(target);
  if (!host) {
    findings.push({
      severity: 'INFO',
      title: 'SSL Scan Skipped',
      description: 'No valid target hostname provided.',
      remediation: 'Provide a valid URL or hostname with --target flag.',
      cwe: 'N/A',
    });
    return findings;
  }

  // Check HTTP→HTTPS redirect
  let httpUrl = target;
  if (!target.startsWith('http://') && !target.startsWith('https://')) {
    httpUrl = 'http://' + target;
  }

  try {
    const httpRes = await axios.get(httpUrl, {
      timeout: TIMEOUT_MS,
      validateStatus: () => true,
      maxRedirects: 0, // don't follow redirects — we want to see if it redirects
    });
    if (httpRes.status >= 300 && httpRes.status < 400) {
      const location = httpRes.headers['location'] || '';
      if (!location.startsWith('https://')) {
        findings.push({
          severity: 'HIGH',
          title: 'HTTP Does Not Redirect to HTTPS',
          description: `HTTP on port 80 responds with ${httpRes.status} but redirects to "${location}" instead of HTTPS. Users may remain on unencrypted connections.`,
          remediation: 'Configure HTTP (port 80) to redirect all traffic to HTTPS (https://).',
          cwe: 'CWE-319',
        });
      }
    } else if (httpRes.status === 200) {
      findings.push({
        severity: 'HIGH',
        title: 'HTTP Available on Port 80 (No Redirect to HTTPS)',
        description: `HTTP on port 80 serves content over unencrypted HTTP without redirecting to HTTPS.`,
        remediation: 'Configure HTTP (port 80) to 301-redirect all requests to HTTPS.',
        cwe: 'CWE-319',
      });
    }
  } catch {
    // HTTP redirect check failed — that's informational only
  }

  // Now check HTTPS/TLS
  const { cert, cipher, success, error } = await getCertInfo(host, 443);

  if (!success) {
    findings.push({
      severity: 'CRITICAL',
      title: 'TLS Connection Failed',
      description: `Could not establish TLS connection to ${host}:443 — ${error}`,
      remediation: 'Verify port 443 is open and a valid TLS server is running. Check for self-signed certificates, expired certificates, or firewall blocking.',
      cwe: 'CWE-295',
    });
    return findings;
  }

  if (!cert || Object.keys(cert).length === 0) {
    findings.push({
      severity: 'CRITICAL',
      title: 'No TLS Certificate Detected',
      description: `Could not retrieve certificate from ${host}:443`,
      remediation: 'Ensure the server has a valid TLS certificate installed.',
      cwe: 'CWE-295',
    });
    return findings;
  }

  // Check certificate expiry
  const daysLeft = daysUntilExpiry(cert);
  if (daysLeft !== null) {
    if (daysLeft < 0) {
      findings.push({
        severity: 'CRITICAL',
        title: 'TLS Certificate Expired',
        description: `Certificate for ${host} expired ${Math.abs(daysLeft)} days ago (${cert.valid_to}). All TLS connections are insecure.`,
        remediation: `Renew the TLS certificate immediately. Expired certificates break TLS entirely.`,
        cwe: 'CWE-295',
      });
    } else if (daysLeft <= 7) {
      findings.push({
        severity: 'CRITICAL',
        title: 'TLS Certificate Expiring Soon',
        description: `Certificate for ${host} expires in ${daysLeft} days (${cert.valid_to}). Renewal must be scheduled immediately.`,
        remediation: `Schedule TLS certificate renewal before expiry to avoid service interruption.`,
        cwe: 'CWE-295',
      });
    } else if (daysLeft <= 30) {
      findings.push({
        severity: 'HIGH',
        title: 'TLS Certificate Expiring Soon',
        description: `Certificate for ${host} expires in ${daysLeft} days (${cert.valid_to}).`,
        remediation: `Plan to renew the TLS certificate before it expires.`,
        cwe: 'CWE-295',
      });
    }
  }

  // Check self-signed certificate
  if (cert.issuer === cert.subject) {
    findings.push({
      severity: 'MEDIUM',
      title: 'Self-Signed TLS Certificate',
      description: `Certificate for ${host} is self-signed. Browsers will show a security warning.`,
      remediation: 'Replace the self-signed certificate with a certificate from a trusted CA (Let\'s Encrypt, DigiCert, etc.).',
      cwe: 'CWE-295',
    });
  }

  // Check certificate subject
  if (cert.subject) {
    const cn = cert.subject.CN || '';
    if (cn && cn !== host && !cn.startsWith('*')) {
      findings.push({
        severity: 'MEDIUM',
        title: 'TLS Certificate Hostname Mismatch',
        description: `Certificate CN "${cn}" does not match hostname "${host}". This can cause browser warnings or rejection.`,
        remediation: `Obtain a certificate valid for the hostname "${host}" or use a wildcard certificate.`,
        cwe: 'CWE-295',
      });
    }
  }

  // Check weak ciphers
  if (cipher && isWeakCipher(cipher.name)) {
    findings.push({
      severity: 'HIGH',
      title: `Weak TLS Cipher Suite: ${cipher.name}`,
      description: `Server supports cipher "${cipher.name}" which is considered weak or deprecated.`,
      remediation: 'Disable weak cipher suites on the server. Configure TLS 1.2+ only and use strong ciphers (e.g., TLS_AES_256_GCM_SHA384).',
      cwe: 'CWE-327',
    });
  }

  // Check TLS version (via cipher object)
  if (cipher && cipher.version) {
    if (cipher.version === 'TLS 1.0' || cipher.version === 'TLS 1.1' || cipher.version === 'SSL') {
      findings.push({
        severity: 'CRITICAL',
        title: `Deprecated TLS Version: ${cipher.version}`,
        description: `Server supports ${cipher.version} which is deprecated (PCI DSS 3.2 prohibits TLS 1.0/1.1).`,
        remediation: 'Disable TLS 1.0 and TLS 1.1. Configure minimum TLS version to TLS 1.2 (TLS 1.3 preferred).',
        cwe: 'CWE-326',
      });
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'INFO',
      title: 'TLS/SSL Configuration OK',
      description: `Certificate for ${host} is valid, not expired, and uses appropriate cipher suites.`,
      remediation: 'Continue monitoring certificate expiry and TLS configuration.',
      cwe: 'N/A',
    });
  }

  return findings;
}

module.exports = { scan };
