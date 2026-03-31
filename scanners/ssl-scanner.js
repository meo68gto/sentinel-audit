/**
 * Sentinel Audit — SSL/TLS Certificate Scanner
 * Validates SSL/TLS certificate and configuration
 */

const tls = require('tls');
const { URL } = require('url');
const { createFinding } = require('../core/findings');
const { normalizeSeverity } = require('../core/severity');

const SCANNER_ID = 'ssl';
const SCANNER_NAME = 'SSL/TLS Certificate Scanner';

const WEAK_CIPHERS = /^(TLS_RSA_|_EXPORT|RC4|MD5|SHA1$|NULL|aNULL)/i;
const DEPRECATED = ['TLSv1', 'TLSv1.1'];
const BAD = ['SSLv2', 'SSLv3'];

function fetchCertificate(hostname, port = 443) {
  return new Promise((resolve) => {
    const socket = tls.connect(port, hostname, { rejectUnauthorized: false, servername: hostname }, () => {
      const cert = socket.getPeerCertificate();
      const cipher = socket.getCipher();
      const protocol = socket.getProtocol();
      socket.destroy();
      resolve({ cert, cipher, protocol, success: true });
    });
    socket.on('error', (err) => { resolve({ cert: null, cipher: null, protocol: null, success: false, error: err.message }); });
    socket.setTimeout(10000, () => { socket.destroy(); resolve({ cert: null, success: false, error: 'Connection timeout' }); });
  });
}

async function run(context) {
  const { targetUrl } = context;
  if (!targetUrl) return [];
  const findings = [];
  let hostname, port;
  try {
    const url = new URL(targetUrl);
    hostname = url.hostname;
    port = url.port || (url.protocol === 'https:' ? 443 : 80);
  } catch { return []; }
  if (port !== 443) {
    return [createFinding({ scanner: SCANNER_ID, severity: 'info', title: 'Non-HTTPS URL — SSL check not applicable',
      description: `Target uses port ${port}, not 443. SSL scanner skipped.`,
      target: targetUrl, remediation: 'Ensure the target uses HTTPS.' })];
  }
  const { cert, cipher, protocol, success, error } = await fetchCertificate(hostname, 443);
  if (!success) {
    return [createFinding({ scanner: SCANNER_ID, severity: 'high', title: 'Cannot establish SSL/TLS connection',
      description: `SSL connection failed: ${error}`, cwe: 'CWE-295', target: targetUrl,
      remediation: 'Verify the server accepts HTTPS connections on port 443.' })];
  }
  if (!cert || Object.keys(cert).length === 0) {
    return [createFinding({ scanner: SCANNER_ID, severity: 'high', title: 'No certificate returned',
      description: `Server ${hostname}:443 did not return a certificate.`, cwe: 'CWE-295', target: targetUrl,
      remediation: 'Configure a valid TLS certificate on the server.' })];
  }
  const validFrom = new Date(cert.valid_from);
  const validTo = new Date(cert.valid_to);
  const daysUntil = Math.floor((validTo - new Date()) / (1000 * 60 * 60 * 24));
  const expired = daysUntil < 0;
  if (expired) {
    findings.push(createFinding({ scanner: SCANNER_ID, severity: 'high', title: 'SSL certificate has expired',
      description: `Certificate expired on ${validTo.toLocaleDateString()}. Browsers reject connections.`,
      cwe: 'CWE-295', cvss: 7.5, target: targetUrl,
      evidence: { validTo: validTo.toISOString(), daysAgo: Math.abs(daysUntil) },
      remediation: `Renew the SSL certificate immediately. Expired since ${validTo.toLocaleDateString()}.`
    }));
  } else if (daysUntil < 30) {
    findings.push(createFinding({ scanner: SCANNER_ID, severity: 'medium', title: `SSL certificate expires soon (${daysUntil} days)`,
      description: `Certificate expires on ${validTo.toLocaleDateString()}. Expired certs break browser connections.`,
      cwe: 'CWE-295', cvss: 5.3, target: targetUrl,
      evidence: { validTo: validTo.toISOString(), daysUntilExpiry: daysUntil },
      remediation: `Renew the SSL certificate before ${validTo.toLocaleDateString()}.`
    }));
  }
  if (validFrom > new Date()) {
    findings.push(createFinding({ scanner: SCANNER_ID, severity: 'high', title: 'SSL certificate not yet valid',
      description: `Certificate validity starts ${validFrom.toLocaleDateString()} — in the future.`,
      cwe: 'CWE-295', target: targetUrl,
      evidence: { validFrom: validFrom.toISOString() },
      remediation: 'Check server clock and certificate validity dates.'
    }));
  }
  if (cert.subject && cert.subject.CN) {
    const certCN = cert.subject.CN.toLowerCase();
    const targetHost = hostname.toLowerCase();
    const sans = (cert.subjectaltname || '').toLowerCase();
    if (certCN !== targetHost && !sans.includes(targetHost) && !sans.includes(`*.${certCN.replace(/^\*\./, '')}`)) {
      findings.push(createFinding({ scanner: SCANNER_ID, severity: 'medium', title: 'SSL certificate hostname mismatch',
        description: `Certificate CN "${certCN}" does not match target hostname "${hostname}".`,
        cwe: 'CWE-295', cvss: 5.3, target: targetUrl,
        evidence: { certCN, hostname, subjectAltNames: cert.subjectaltname },
        remediation: `Reissue the certificate with ${hostname} in the CN or SAN.`
      }));
    }
  }
  if (BAD.includes(protocol)) {
    findings.push(createFinding({ scanner: SCANNER_ID, severity: 'critical', title: `Dangerous protocol: ${protocol}`,
      description: `Server supports ${protocol}, which has critical known vulnerabilities (POODLE, BEAST, etc.).`,
      cwe: 'CWE-295', cvss: 9.8, target: targetUrl,
      evidence: { protocol, cipher: cipher?.name },
      remediation: `Disable ${protocol} immediately. Use TLS 1.2 or TLS 1.3 only.`
    }));
  } else if (DEPRECATED.includes(protocol)) {
    findings.push(createFinding({ scanner: SCANNER_ID, severity: 'high', title: `Deprecated TLS protocol: ${protocol}`,
      description: 'TLS 1.0 and 1.1 are deprecated. PCI DSS 3.2.1 requires TLS 1.2+.',
      cwe: 'CWE-295', cvss: 7.4, target: targetUrl,
      evidence: { protocol, cipher: cipher?.name },
      remediation: 'Disable TLS 1.0 and 1.1. Configure TLS 1.2 minimum (TLS 1.3 preferred).'
    }));
  }
  if (cipher && WEAK_CIPHERS.test(cipher.name)) {
    findings.push(createFinding({ scanner: SCANNER_ID, severity: 'high', title: `Weak cipher suite: ${cipher.name}`,
      description: `Cipher ${cipher.name} is considered weak or deprecated.`,
      cwe: 'CWE-295', cvss: 7.4, target: targetUrl,
      evidence: { cipher: cipher.name, protocol },
      remediation: 'Configure server to use TLS 1.3 ciphers only: TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384.'
    }));
  }
  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Validates SSL/TLS certificate: expiry, weak ciphers, hostname mismatch, deprecated TLS', run, defaultTimeout: 30000 };
