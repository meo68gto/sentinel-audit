/**
 * Sentinel Audit — HTTP Security Headers Scanner
 * Checks a target URL for missing or misconfigured security headers.
 */

const axios = require('axios');

// Security headers to check
const SECURITY_HEADERS = [
  {
    name: 'Content-Security-Policy',
    severity: 'HIGH',
    cwe: 'CWE-693',
    description: 'Content-Security-Policy (CSP) header is missing. CSP helps prevent XSS and data injection attacks.',
    remediation: "Add a strict Content-Security-Policy header, e.g.: Content-Security-Policy: default-src 'self'; script-src 'self'",
  },
  {
    name: 'Strict-Transport-Security',
    severity: 'HIGH',
    cwe: 'CWE-311',
    description: 'Strict-Transport-Security (HSTS) header is missing. Without HSTS, browsers may communicate over unencrypted HTTP.',
    remediation: 'Add Strict-Transport-Security header, e.g.: Strict-Transport-Security: max-age=31536000; includeSubDomains',
  },
  {
    name: 'X-Frame-Options',
    severity: 'MEDIUM',
    cwe: 'CWE-1021',
    description: 'X-Frame-Options header is missing. This leaves the site vulnerable to clickjacking attacks.',
    remediation: "Add X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN to prevent framing",
  },
  {
    name: 'X-Content-Type-Options',
    severity: 'MEDIUM',
    cwe: 'CWE-693',
    description: 'X-Content-Type-Options header is missing. Without it, browsers may MIME-sniff and execute content as script.',
    remediation: "Add X-Content-Type-Options: nosniff",
  },
  {
    name: 'Referrer-Policy',
    severity: 'LOW',
    cwe: 'CWE-200',
    description: 'Referrer-Policy header is missing. Without it, sensitive URL information may leak via the Referer header.',
    remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin or Referrer-Policy: no-referrer',
  },
  {
    name: 'Permissions-Policy',
    severity: 'LOW',
    cwe: 'CWE-693',
    description: 'Permissions-Policy (Feature-Policy) header is missing. Controls which browser features can be used.',
    remediation: "Add Permissions-Policy header to disable unnecessary browser features, e.g.: Permissions-Policy: geolocation=(), microphone=()",
  },
  {
    name: 'X-XSS-Protection',
    severity: 'INFO',
    cwe: 'CWE-79',
    description: 'X-XSS-Protection header is present but deprecated. Modern browsers rely on CSP instead.',
    remediation: 'Consider removing X-XSS-Protection and relying on Content-Security-Policy for XSS protection.',
  },
];

/**
 * Check a URL for security headers.
 * @param {string} targetUrl - URL to scan (http or https)
 * @param {object} config - Scanner config
 * @returns {Promise<Array>} Array of finding objects
 */
async function scan(targetUrl, config) {
  const findings = [];

  if (!targetUrl) {
    findings.push({
      severity: 'INFO',
      title: 'Headers Scan Skipped',
      description: 'No target URL provided.',
      remediation: 'Provide a valid URL with --target flag.',
      cwe: 'N/A',
    });
    return findings;
  }

  let normalizedUrl = targetUrl;
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    normalizedUrl = 'https://' + targetUrl;
  }

  try {
    const response = await axios.get(normalizedUrl, {
      timeout: 10000,
      validateStatus: () => true, // accept any status
      maxRedirects: 5,
    });

    const headers = response.headers || {};
    const headerKeys = Object.keys(headers).reduce((acc, key) => {
      acc[key.toLowerCase()] = headers[key];
      return acc;
    }, {});

    // Check for missing headers
    for (const headerDef of SECURITY_HEADERS) {
      const headerKey = headerDef.name.toLowerCase();
      if (!headerKeys[headerKey]) {
        findings.push({
          severity: headerDef.severity,
          title: `Missing Security Header: ${headerDef.name}`,
          description: headerDef.description,
          remediation: headerDef.remediation,
          cwe: headerDef.cwe,
        });
      }
    }

    // Check for HTTPS usage
    if (normalizedUrl.startsWith('http://')) {
      findings.push({
        severity: 'HIGH',
        title: 'Insecure HTTP Transport',
        description: 'Target URL uses HTTP instead of HTTPS. Data in transit is not encrypted.',
        remediation: 'Use https:// instead of http:// for all endpoints.',
        cwe: 'CWE-319',
      });
    }

    // Check for Cache-Control on sensitive endpoints
    if (response.status >= 200 && response.status < 400) {
      if (!headerKeys['cache-control'] && normalizedUrl.includes('api')) {
        findings.push({
          severity: 'LOW',
          title: 'Missing Cache-Control on API Endpoint',
          description: 'No Cache-Control header on API response. Sensitive data may be cached by browsers or proxies.',
          remediation: 'Add Cache-Control: no-store, no-cache, must-revalidate for sensitive API responses.',
          cwe: 'CWE-524',
        });
      }
    }

    // Check for Server header (information disclosure)
    if (headerKeys['server']) {
      findings.push({
        severity: 'INFO',
        title: 'Server Header Exposes Version Information',
        description: `Server header reveals: "${headerKeys['server']}". Attackers can use this to target known vulnerabilities.`,
        remediation: 'Suppress or genericize the Server header, e.g., Server: nginx or Server: Apache.',
        cwe: 'CWE-200',
      });
    }

    if (findings.length === 0) {
      findings.push({
        severity: 'INFO',
        title: 'Security Headers OK',
        description: 'All checked security headers are present and correctly configured.',
        remediation: 'Continue monitoring and updating security headers as standards evolve.',
        cwe: 'N/A',
      });
    }
  } catch (err) {
    findings.push({
      severity: 'HIGH',
      title: 'Headers Scan Error',
      description: `Failed to connect to ${normalizedUrl}: ${err.message}`,
      remediation: 'Verify the target URL is reachable and publicly accessible.',
      cwe: 'N/A',
    });
  }

  return findings;
}

module.exports = { scan };
