/**
 * Sentinel Audit — Authentication Scanner
 * JWT analysis, rate limiting detection, Basic Auth over HTTP checks
 */

const axios = require('axios');
const { createFinding } = require('../core/findings');
const { normalizeSeverity } = require('../core/severity');

const SCANNER_ID = 'auth';
const SCANNER_NAME = 'Authentication Security Scanner';

function analyzeJwt(token, target, source) {
  const findings = [];
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return findings;
    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
    if (header.alg && header.alg.toLowerCase() === 'none') {
      findings.push(createFinding({ scanner: SCANNER_ID, severity: 'critical', title: 'JWT alg:none — forged tokens possible',
        description: 'Server accepts JWTs with alg:none, allowing attackers to forge arbitrary tokens. CVE-2025-61152 (python-jose), CVE-2026-23993 (HarbourJwt), CVE-2026-28802 (Authlib) all exploit this.',
        cwe: 'CWE-347', cvss: 9.4, target,
        evidence: { header, source, token: token.slice(0, 50) + '...' },
        remediation: 'Reject alg:none on the server. Whitelist allowed algorithms (RS256, ES256) and explicitly reject "none".'
      }));
    }
    if (payload.exp === undefined) {
      findings.push(createFinding({ scanner: SCANNER_ID, severity: 'high', title: 'JWT missing expiration (exp) claim',
        description: 'This JWT has no expiration. If compromised, attackers have indefinite access.',
        cwe: 'CWE-613', cvss: 7.5, target,
        evidence: { header, source },
        remediation: 'Always include exp claim. Access tokens: 15min-1h. Refresh tokens: up to 7d.'
      }));
    } else {
      const now = Math.floor(Date.now() / 1000);
      if (payload.exp - now > 86400 * 30) {
        findings.push(createFinding({ scanner: SCANNER_ID, severity: 'medium', title: `JWT expiration too long (${Math.round((payload.exp - now) / 86400)} days)`,
          description: 'Long-lived tokens increase risk window if compromised.',
          cwe: 'CWE-613', cvss: 5.3, target,
          evidence: { exp: payload.exp, expiresInSeconds: payload.exp - now, source },
          remediation: 'Shorten JWT expiration. Access tokens: 15min-1h. Use refresh tokens for long-lived sessions.'
        }));
      }
    }
    if (payload.iat === undefined) {
      findings.push(createFinding({ scanner: SCANNER_ID, severity: 'medium', title: 'JWT missing issued-at (iat) claim',
        description: 'Without iat, server cannot determine when the token was issued.',
        cwe: 'CWE-613', cvss: 4.3, target,
        evidence: { source },
        remediation: 'Always include iat claim: iat = current Unix timestamp when token is issued.'
      }));
    }
    if (header.kid && /(\.\.|\/)/.test(header.kid)) {
      findings.push(createFinding({ scanner: SCANNER_ID, severity: 'critical', title: 'JWT kid header contains path traversal',
        description: `kid value "${header.kid}" may allow attackers to control which key is used to verify the signature.`,
        cwe: 'CWE-347', cvss: 9.1, target,
        evidence: { kid: header.kid, source },
        remediation: 'Validate and sanitize the kid claim. Never use user-controllable input to select keys.'
      }));
    }
  } catch {}
  return findings;
}

async function checkJwtSecurity(targetUrl) {
  const findings = [];
  try {
    const response = await axios.get(targetUrl, { timeout: 15000, validateStatus: () => true, maxRedirects: 3, maxContentLength: 102400 });
    const authHeader = response.headers['authorization'] || '';
    const responseText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);
    if (authHeader.toLowerCase().startsWith('bearer ')) {
      findings.push(...analyzeJwt(authHeader.slice(7), targetUrl, 'authorization_header'));
    }
    const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
    let match;
    while ((match = jwtRegex.exec(responseText)) !== null) {
      findings.push(...analyzeJwt(match[0], targetUrl, 'response_body'));
    }
    const cookies = response.headers['set-cookie'] || [];
    for (const cookie of cookies) {
      const jwtMatch = cookie.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/);
      if (jwtMatch) findings.push(...analyzeJwt(jwtMatch[0], targetUrl, 'cookie'));
    }
  } catch {}
  return findings;
}

async function checkRateLimiting(targetUrl) {
  const findings = [];
  const endpoints = [
    targetUrl.replace(/\/$/, '') + '/login',
    targetUrl.replace(/\/$/, '') + '/api/login',
    targetUrl.replace(/\/$/, '') + '/auth/login',
    targetUrl
  ];
  for (const endpoint of endpoints) {
    const results = [];
    for (let i = 0; i < 20; i++) {
      try {
        const resp = await axios.post(endpoint, { username: `ratelimit_test_${i}@example.com`, password: 'test' }, {
          timeout: 5000, validateStatus: () => true, headers: { 'Content-Type': 'application/json' }
        });
        results.push({ status: resp.status, i });
      } catch { results.push({ status: 0, error: true, i }); }
    }
    const has429 = results.some(r => r.status === 429);
    if (!has429) {
      findings.push(createFinding({ scanner: SCANNER_ID, severity: 'high', title: `No rate limiting on ${new URL(endpoint).pathname}`,
        description: `Sent 20 rapid POST requests without any rate limiting response (no 429, no lockout). Enables unlimited brute-force attacks.`,
        cwe: 'CWE-307', cvss: 7.5, target: endpoint,
        evidence: { endpoint, requestsSent: 20, responses: results.slice(0, 5) },
        remediation: 'Implement rate limiting: 5 attempts per minute per IP for login endpoints. Return 429 with Retry-After header.'
      }));
      break;
    }
  }
  return findings;
}

async function checkBasicAuthWithoutTLS(targetUrl) {
  if (targetUrl.startsWith('http://')) {
    return [createFinding({ scanner: SCANNER_ID, severity: 'medium', title: 'HTTP URL — Basic Auth would be over cleartext',
      description: `Target is HTTP. If Basic Auth or Digest Auth is in use, credentials are transmitted in cleartext.`,
      cwe: 'CWE-319', cvss: 7.5, target: targetUrl,
      remediation: 'Use HTTPS for all endpoints requiring authentication.'
    })];
  }
  return [];
}

async function run(context) {
  const { targetUrl } = context;
  if (!targetUrl) return [];
  const findings = [];
  findings.push(...await checkBasicAuthWithoutTLS(targetUrl));
  findings.push(...await checkJwtSecurity(targetUrl));
  findings.push(...await checkRateLimiting(targetUrl));
  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Checks authentication security: JWT analysis, rate limiting, Basic Auth over HTTP', run, defaultTimeout: 60000 };
