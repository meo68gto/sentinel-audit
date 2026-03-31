/**
 * Sentinel Audit — SSL/TLS Scanner
 * Validates SSL/TLS certificate and configuration
 * Checks: certificate expiry, weak ciphers, hostname mismatch, protocol versions
 */

const tls = require('tls');
const { URL } = require('url');
const { createFinding } = require('../core/findings');
const { normalizeSeverity } = require('../core/severity');

const SCANNER_ID = 'ssl';
const SCANNER_NAME = 'SSL/TLS Certificate Scanner';

let findingCounter = 0;
function nextId() {
  findingCounter++;
  return `SENTINEL-SSL-${String(findingCounter).padStart(3, '0')}`;
}

// Weak/insecure cipher suites — anything using RC4, 3DES, NULL, orEXPORT
const WEAK_CIPHERS = /^(TLS_RSA_|_EXPORT|RC4|MD5|SHA1$|NULL|aNULL)/i;

// TLS 1.0 and 1.1 are deprecated (PCI DSS 3.2.1 as of 2018, removal required)
const DEPRECATED_PROTOCOLS = ['TLSv1', 'TLSv1.1'];
const BAD_PROTOCOLS = ['SSLv2', 'SSLv3'];

/**
 * Fetch certificate info from a TLS server
 * @param {string} hostname
 * @param {number} port
 * @returns {Promise<Object>}
 */
function fetchCertificate(hostname, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect(port, hostname, {
      rejectUnauthorized: false, // We want the cert even if invalid
      servername: hostname, // SNI
    }, () => {
      const cert = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      socket.destroy();
      resolve({ cert, cipher, protocol, success: true });
    });

    socket.on('error', (err) => {
      resolve({ cert: null, cipher: null, protocol: null, success: false, error: err.message });
    });

    socket.setTimeout(10000, () => {
      socket.destroy();
      resolve({ cert: null, success: false, error: 'Connection timeout' });
    });
  });
}

/**
 * Parse certificate expiry and days until expiration
 * @param {Object} cert
 * @returns {{ validFrom: Date, validTo: Date, daysUntilExpiry: number, expired: boolean }}
 */
function parseCertExpiry(cert) {
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const now = new Date();
  const daysUntilExpiry = Math.floor((validTo - now) / (1000 * 60 * 60 * 24));
  return { validFrom, validTo, daysUntilExpiry, expired: daysUntilExpiry < 0 };
}

/**
 * Check if certificate has weak key
 * @param {Object} cert
 * @returns {{ weak: boolean, detail: string }}
 */
function checkWeakKey(cert) {
  if (!cert || !cert.pubkey) return { weak: false };

  const keySize = cert.pubkey?.length || 0;
  const keyType = cert.pubkey?.type || '';

  if (keyType === 'RSA') {
    if (keySize < 2048) {
      return { weak: true, detail: `RSA key size ${keySize} bits — must be at least 2048 bits` };
    }
  }
  if (keyType === 'EC') {
    if (keySize < 256) {
      return { weak: true, detail: `EC key size ${keySize} bits — must be at least 256 bits` };
    }
  }

  return { weak: false };
}

/**
 * Main scan function
 * @param {Object} context
 * @param {Object} config
 * @returns {Promise<Array>}
 */
async function run(context, config) {
  const { targetUrl } = context;
  if (!targetUrl) return [];

  const findings = [];

  let hostname, port;
  try {
    const url = new URL(targetUrl);
    hostname = url.hostname;
    port = url.port || (url.protocol === 'https:' ? 443 : 80);
  } catch {
    return [];
  }

  // Only check SSL/TLS for HTTPS targets
  if (port !== 443 && !targetUrl.startsWith('https')) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'medium',
      title: 'Non-HTTPS URL — SSL/TLS check not applicable',
      description: `Scanning ${targetUrl} which is not HTTPS. SSL scanner skipped.`,
      target: targetUrl,
      remediation: 'Ensure the target uses HTTPS for all communications.'
    }));
    return findings;
  }

  const { cert, cipher, protocol, success, error } = await fetchCertificate(hostname, 443);

  if (!success) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'high',
      title: 'Cannot establish SSL/TLS connection',
      description: `SSL connection to ${hostname}:443 failed: ${error}`,
      cwe: 'CWE-295',
      target: targetUrl,
      evidence: { hostname, error },
      remediation: 'Verify the server is running and accepts HTTPS connections on port 443.'
    }));
    return findings;
  }

  if (!cert || Object.keys(cert).length === 0) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'high',
      title: 'No certificate returned',
      description: `Server ${hostname}:443 did not return a certificate.`,
      cwe: 'CWE-295',
      target: targetUrl,
      remediation: 'Configure a valid TLS certificate on the server.'
    }));
    return findings;
  }

  const { validFrom, validTo, daysUntilExpiry, expired } = parseCertExpiry(cert);

  // Check expired certificate
  if (expired) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'high',
      title: 'SSL certificate has expired',
      description: `Certificate expired on ${validTo.toISOString()}. Browsers will reject connections to this server.`,
      cwe: 'CWE-295',
      cvss: 7.5,
      target: targetUrl,
      evidence: { expired: true, validTo: validTo.toISOString(), daysAgo: Math.abs(daysUntilExpiry) },
      remediation: `Renew the SSL certificate immediately. Expired since ${validTo.toLocaleDateString()}.`
    }));
  } else if (daysUntilExpiry < 30) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'medium',
      title: `SSL certificate expires soon (${daysUntilExpiry} days)`,
      description: `Certificate expires on ${validTo.toLocaleDateString()}. Expired certificates break browser connections and cause service disruption.`,
      cwe: 'CWE-295',
      cvss: 5.3,
      target: targetUrl,
      evidence: { validTo: validTo.toISOString(), daysUntilExpiry },
      remediation: `Renew the SSL certificate before ${validTo.toLocaleDateString()} to avoid service disruption.`
    }));
  }

  // Check certificate not yet valid
  if (validFrom > new Date()) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'high',
      title: 'SSL certificate not yet valid',
      description: `Certificate validity period starts ${validFrom.toLocaleDateString()} — in the future. Connections will fail.`,
      cwe: 'CWE-295',
      target: targetUrl,
      evidence: { validFrom: validFrom.toISOString() },
      remediation: 'Check server clock and certificate validity dates.'
    }));
  }

  // Check hostname mismatch
  if (cert.subject && cert.subject.CN) {
    const certCN = cert.subject.CN.toLowerCase();
    const targetHost = hostname.toLowerCase();
    const sans = (cert.subjectaltname || '').toLowerCase();

    // Check CN match
    if (certCN !== targetHost && !sans.includes(targetHost) && !sans.includes(`*.${certCN.replace(/^\*\./, '')}`)) {
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: 'medium',
        title: 'SSL certificate hostname mismatch',
        description: `Certificate CN "${certCN}" does not match target hostname "${hostname}".`,
        cwe: 'CWE-295',
        cvss: 5.3,
        target: targetUrl,
        evidence: { certCN, hostname, subjectAltNames: cert.subjectaltname },
        remediation: `Reissue the certificate with the correct hostname (${hostname}) in the CN or Subject Alternative Names (SAN).`
      }));
    }
  }

  // Check weak key
  const { weak: weakKey, detail: keyDetail } = checkWeakKey(cert);
  if (weakKey) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'high',
      title: `Weak certificate key: ${keyDetail}`,
      description: keyDetail,
      cwe: 'CWE-295',
      cvss: 7.4,
      target: targetUrl,
      evidence: { pubkey: cert.pubkey },
      remediation: 'Regenerate the certificate with a key size of at least 2048 bits (RSA) or 256 bits (EC).'
    }));
  }

  // Check deprecated protocol versions
  if (BAD_PROTOCOLS.includes(protocol)) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'critical',
      title: `Dangerous protocol in use: ${protocol}`,
      description: `Server supports ${protocol}, which has known critical vulnerabilities (POODLE, BEAST, etc.).`,
      cwe: 'CWE-295',
      cvss: 9.8,
      target: targetUrl,
      evidence: { protocol, cipher: cipher?.name },
      remediation: `Disable ${protocol} immediately. Use TLS 1.2 or TLS 1.3 only.`
    }));
  } else if (DEPRECATED_PROTOCOLS.includes(protocol)) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'high',
      title: `Deprecated TLS protocol: ${protocol}`,
      description: `TLS 1.0 and 1.1 are deprecated (PCI DSS 3.2.1, TLS 1.3 is current).`,
      cwe: 'CWE-295',
      cvss: 7.4,
      target: targetUrl,
      evidence: { protocol, cipher: cipher?.name },
      remediation: 'Disable TLS 1.0 and 1.1. Configure server to use TLS 1.2 minimum (TLS 1.3 preferred).'
    }));
  }

  // Check weak cipher
  if (cipher && WEAK_CIPHERS.test(cipher.name)) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'high',
      title: `Weak cipher suite: ${cipher.name}`,
      description: `Cipher ${cipher.name} is considered weak or deprecated.`,
      cwe: 'CWE-295',
      cvss: 7.4,
      target: targetUrl,
      evidence: { cipher: cipher.name, protocol },
      remediation: `Configure server to disable weak ciphers. Use TLS 1.3 ciphers only: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384.`
    }));
  }

  // Check self-signed certificate
  if (cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN && cert.issuer.CN === cert.subject.O) {
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'medium',
      title: 'Self-signed certificate',
      description: 'Certificate is self-signed and not from a trusted CA. Browsers will show security warnings.',
      cwe: 'CWE-295',
      cvss: 5.3,
      target: targetUrl,
      evidence: { issuer: cert.issuer, subject: cert.subject },
      remediation: 'Replace self-signed certificate with one from a trusted Certificate Authority (Let\'s Encrypt is free).'
    }));
  }

  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Validates SSL/TLS certificate: expiry, weak ciphers, hostname mismatch, deprecated protocols', run, defaultTimeout: 30000 };
