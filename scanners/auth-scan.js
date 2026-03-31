/**
 * Sentinel Audit — Authentication Scanner
 * Checks for missing or misconfigured authentication-related headers.
 */

const axios = require('axios');

const AUTH_HEADERS = [
  {
    name: 'WWW-Authenticate',
    check: (headers) => !headers['www-authenticate'],
    severity: 'INFO',
    cwe: 'N/A',
    title: 'WWW-Authenticate Header Not Present',
    description: 'WWW-Authenticate header is not present. This is informational — it is only needed for realm-based HTTP Basic/Digest auth.',
    remediation: 'No action required unless implementing HTTP Basic/Digest authentication.',
  },
];

/**
 * Check a URL for authentication-related issues.
 * @param {string} targetUrl - URL to scan
 * @param {object} config - Scanner config
 * @returns {Promise<Array>} Array of finding objects
 */
async function scan(targetUrl, config) {
  const findings = [];

  if (!targetUrl) {
    findings.push({
      severity: 'INFO',
      title: 'Auth Scan Skipped',
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
      validateStatus: () => true,
      maxRedirects: 5,
    });

    const headers = response.headers || {};
    const headerKeys = Object.keys(headers).reduce((acc, key) => {
      acc[key.toLowerCase()] = headers[key];
      return acc;
    }, {});

    // Check for Basic Auth over HTTP
    if (normalizedUrl.startsWith('http://') && headerKeys['authorization']) {
      const authHeader = headerKeys['authorization'];
      if (authHeader.toLowerCase().startsWith('basic ')) {
        findings.push({
          severity: 'CRITICAL',
          title: 'Basic Authentication Over HTTP',
          description: 'Authorization header with Basic auth is sent over unencrypted HTTP. Credentials are transmitted in base64 (easily decoded).',
          remediation: 'Never use Basic Authentication over HTTP. Switch to HTTPS and use Bearer tokens or OAuth 2.0.',
          cwe: 'CWE-319',
        });
      }
    }

    // Check for Bearer token in URL (also check for token in Referer leak)
    if (normalizedUrl.startsWith('http://')) {
      const authHeader = headerKeys['authorization'];
      if (authHeader && authHeader.toLowerCase().startsWith('bearer ')) {
        findings.push({
          severity: 'HIGH',
          title: 'Bearer Token Over HTTP',
          description: 'Bearer token is sent over unencrypted HTTP. Tokens can be intercepted and stolen via man-in-the-middle attacks.',
          remediation: 'Use HTTPS exclusively when transmitting Bearer tokens. Configure HSTS to enforce HTTPS.',
          cwe: 'CWE-319',
        });
      }
    }

    // Check for tokens in URL query strings (security smell)
    try {
      const urlObj = new URL(normalizedUrl);
      const queryTokenParams = ['token', 'key', 'api_key', 'apikey', 'access_token', 'auth', 'secret', 'password', 'pwd'];
      for (const [key, value] of urlObj.searchParams) {
        if (queryTokenParams.includes(key.toLowerCase()) && value.length > 5) {
          findings.push({
            severity: 'HIGH',
            title: `Authentication Token in URL Query Parameter`,
            description: `Parameter "${key}" in the URL query string appears to be an authentication token. Tokens in URLs leak via server logs, browser history, and Referer headers.`,
            remediation: `Move authentication tokens from URL query strings to request headers (Authorization: Bearer <token>) or request bodies.`,
            cwe: 'CWE-598',
          });
        }
      }
    } catch {}

    // Check for missing X-Content-Type-Options (relevant for auth)
    if (!headerKeys['x-content-type-options']) {
      findings.push({
        severity: 'LOW',
        title: 'Missing X-Content-Type-Options',
        description: 'Without this header, browsers may MIME-sniff responses and execute content as script, potentially bypassing auth-related protections.',
        remediation: "Add X-Content-Type-Options: nosniff",
        cwe: 'CWE-693',
      });
    }

    // Check for secure cookie flags (Set-Cookie)
    const setCookieHeaders = Array.isArray(headerKeys['set-cookie'])
      ? headerKeys['set-cookie']
      : headerKeys['set-cookie']
        ? [headerKeys['set-cookie']]
        : [];

    for (const cookie of setCookieHeaders) {
      if (!cookie.toLowerCase().includes('secure')) {
        findings.push({
          severity: 'MEDIUM',
          title: 'Cookie Missing Secure Flag',
          description: `Set-Cookie header does not include the Secure attribute: "${cookie.substring(0, 80)}...". Cookie can be sent over unencrypted connections.`,
          remediation: 'Add the Secure attribute to all Set-Cookie headers so cookies are only sent over HTTPS.',
          cwe: 'CWE-614',
        });
      }
      if (!cookie.toLowerCase().includes('httponly')) {
        findings.push({
          severity: 'MEDIUM',
          title: 'Cookie Missing HttpOnly Flag',
          description: `Set-Cookie header does not include the HttpOnly attribute. Cookie can be accessed via JavaScript (XSS risk).`,
          remediation: 'Add the HttpOnly attribute to prevent JavaScript access to cookies.',
          cwe: 'CWE-1004',
        });
      }
      if (!cookie.toLowerCase().includes('samesite')) {
        findings.push({
          severity: 'LOW',
          title: 'Cookie Missing SameSite Attribute',
          description: `Set-Cookie header does not specify SameSite. This can lead to CSRF vulnerabilities.`,
          remediation: 'Add SameSite=Strict or SameSite=Lax to Set-Cookie headers.',
          cwe: 'CWE-308',
        });
      }
    }

    // Check 401/403 responses for proper WWW-Authenticate
    if (response.status === 401) {
      if (!headerKeys['www-authenticate']) {
        findings.push({
          severity: 'MEDIUM',
          title: '401 Response Missing WWW-Authenticate Header',
          description: 'A 401 response does not include WWW-Authenticate header, making it unclear what authentication scheme is expected.',
          remediation: 'Add WWW-Authenticate header to 401 responses to indicate the expected auth scheme (e.g., Bearer, Basic realm="...").',
          cwe: 'CWE-287',
        });
      }
    }

    if (response.status === 403) {
      findings.push({
        severity: 'INFO',
        title: 'Access Forbidden (403)',
        description: `Target returned 403 Forbidden. Authentication/authorization may be in place, but the reason for denial is not clear.`,
        remediation: 'Verify that 403 responses distinguish between "not authenticated" (401) and "authenticated but not authorized" (403).',
        cwe: 'CWE-287',
      });
    }

    if (findings.length === 0) {
      findings.push({
        severity: 'INFO',
        title: 'Authentication Checks Passed',
        description: 'No authentication misconfigurations detected.',
        remediation: 'Continue monitoring auth-related headers and token handling practices.',
        cwe: 'N/A',
      });
    }
  } catch (err) {
    findings.push({
      severity: 'HIGH',
      title: 'Auth Scan Error',
      description: `Failed to connect to ${normalizedUrl}: ${err.message}`,
      remediation: 'Verify the target URL is reachable and publicly accessible.',
      cwe: 'N/A',
    });
  }

  return findings;
}

module.exports = { scan };
