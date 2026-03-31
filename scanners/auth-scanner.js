/**
 * Sentinel Audit — Authentication Scanner
 * Checks for authentication-related security issues:
 * - Missing WWW-Authenticate header
 * - JWT token analysis (alg:none, weak secrets, missing expiry)
 * - Basic Auth on APIs without TLS
 * - Missing rate limiting on auth endpoints
 */

const axios = require('axios');
const { createFinding } = require('../core/findings');
const { normalizeSeverity } = require('../core/severity');

const SCANNER_ID = 'auth';
const SCANNER_NAME = 'Authentication Security Scanner';

let findingCounter = 0;
function nextId() {
  findingCounter++;
  return `SENTINEL-AUTH-${String(findingCounter).padStart(3, '0')}`;
}

/**
 * Check WWW-Authenticate header presence
 * @param {string} targetUrl
 * @returns {Promise<Array>}
 */
async function checkWwwAuthenticate(targetUrl) {
  const findings = [];
  try {
    const response = await axios.head(targetUrl, { timeout: 10000, validateStatus: () => true });
    const wwwAuth = response.headers['www-authenticate'];

    if (!wwwAuth && response.status === 401) {
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: 'low',
        title: '401 response without WWW-Authenticate header',
        description: 'An unauthenticated request returned 401 but did not specify the authentication scheme, making it harder for legitimate clients to authenticate.',
        cwe: 'CWE-287',
        target: targetUrl,
        evidence: { statusCode: 401, wwwAuthenticate: null },
        remediation: 'Include WWW-Authenticate header on 401 responses, e.g., WWW-Authenticate: Bearer realm="api"'
      }));
    }
  } catch {}
  return findings;
}

/**
 * Check for Basic Auth without TLS
 * @param {string} targetUrl
 * @returns {Promise<Array>}
 */
async function checkBasicAuthWithoutTLS(targetUrl) {
  const findings = [];
  if (targetUrl.startsWith('http://')) {
    // Check if Basic Auth might be in use (not definitive — just a signal)
    try {
      const response = await axios.head(targetUrl, { timeout: 10000 });
      const authHeader = response.request?.socket?.getProtocol?.() || 'http';
      if (authHeader === 'http') {
        findings.push(createFinding({
          scanner: SCANNER_ID,
          severity: 'medium',
          title: 'Possible Basic/Digest Auth over HTTP',
          description: 'Target is accessible over HTTP. If Basic Auth or Digest Auth is in use, credentials are transmitted in cleartext.',
          cwe: 'CWE-319',
          target: targetUrl,
          evidence: { protocol: 'HTTP', url: targetUrl },
          remediation: 'Use HTTPS for all endpoints requiring authentication. Redirect HTTP → HTTPS.'
        }));
      }
    } catch {}
  }
  return findings;
}

/**
 * Detect JWT tokens in response bodies and headers
 * @param {string} targetUrl
 * @returns {Promise<Array>}
 */
async function checkJwtSecurity(targetUrl) {
  const findings = [];

  try {
    // Try to fetch a login/auth endpoint
    const response = await axios.get(targetUrl, {
      timeout: 15000,
      validateStatus: () => true,
      maxRedirects: 3,
      maxContentLength: 1024 * 100
    });

    const authHeader = response.headers['authorization'] || '';
    const responseText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data);

    // Check Authorization header for JWT
    if (authHeader.toLowerCase().startsWith('bearer ')) {
      const token = authHeader.slice(7);
      findings.push(...analyzeJwt(token, targetUrl, 'authorization_header'));
    }

    // Check response body for JWT tokens
    const jwtRegex = /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g;
    let match;
    while ((match = jwtRegex.exec(responseText)) !== null) {
      const token = match[0];
      findings.push(...analyzeJwt(token, targetUrl, 'response_body'));
    }

    // Check cookies for JWT
    const cookies = response.headers['set-cookie'] || [];
    for (const cookie of cookies) {
      const jwtMatch = cookie.match(/eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/);
      if (jwtMatch) {
        findings.push(...analyzeJwt(jwtMatch[0], targetUrl, 'cookie'));
      }
    }
  } catch {}

  return findings;
}

/**
 * Analyze a JWT token for security issues
 * @param {string} token
 * @param {string} target
 * @param {string} source
 * @returns {Array}
 */
function analyzeJwt(token, target, source) {
  const findings = [];
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return findings;

    const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));

    // Check alg: none
    if (header.alg && header.alg.toLowerCase() === 'none') {
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: 'critical',
        title: 'JWT alg:none vulnerability — forged tokens possible',
        description: 'The server accepts JWTs with alg:none, allowing attackers to forge arbitrary tokens and impersonate any user. CVE-2025-61152 (python-jose), CVE-2026-23993 (HarbourJwt), CVE-2026-28802 (Authlib) all exploit this.',
        cwe: 'CWE-347',
        cvss: 9.4,
        target: target,
        evidence: { header, source, token: token.slice(0, 50) + '...' },
        remediation: 'Reject alg:none on the server: set allowed algorithms (e.g., RS256, ES256) and explicitly reject "none".'
      }));
    }

    // Check missing exp
    if (payload.exp === undefined) {
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: 'high',
        title: 'JWT missing expiration (exp) claim — token never expires',
        description: 'This JWT has no expiration time. If the token is compromised, attackers have indefinite access.',
        cwe: 'CWE-613', // Insufficient Session Expiration
        cvss: 7.5,
        target: target,
        evidence: { header, source, token: token.slice(0, 50) + '...' },
        remediation: 'Always include exp claim in JWTs: exp should be set to a reasonable duration (e.g., 15min for access tokens, 7d for refresh tokens).'
      }));
    } else {
      // Check if exp is too far in the future
      const now = Math.floor(Date.now() / 1000);
      const expiresIn = payload.exp - now;
      if (expiresIn > 86400 * 30) { // > 30 days
        findings.push(createFinding({
          scanner: SCANNER_ID,
          severity: 'medium',
          title: `JWT expiration too long (${Math.round(expiresIn / 86400)} days)`,
          description: 'Long-lived tokens increase risk window if token is compromised.',
          cwe: 'CWE-613',
          cvss: 5.3,
          target: target,
          evidence: { exp: payload.exp, issuedAt: payload.iat, expiresInSeconds: expiresIn, source },
          remediation: 'Shorten JWT expiration: access tokens should expire in 15min-1h. Use refresh tokens for long-lived sessions.'
        }));
      }
    }

    // Check missing iat (issued at)
    if (payload.iat === undefined) {
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: 'medium',
        title: 'JWT missing issued-at (iat) claim',
        description: 'Without iat, the server cannot determine when the token was issued or detect replay of old tokens.',
        cwe: 'CWE-613',
        cvss: 4.3,
        target: target,
        evidence: { source },
        remediation: 'Always include iat claim: iat should be set to current Unix timestamp when token is issued.'
      }));
    }

    // Check for RS256 vs HS256 (HS256 = symmetric, risk of key disclosure)
    if (header.alg === 'HS256') {
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: 'info',
        title: 'JWT using HS256 (symmetric) algorithm',
        description: 'HS256 uses a shared secret. RS256 (asymmetric) is preferred — server keeps private key, clients only need public key.',
        cwe: 'CWE-347',
        cvss: 3.7,
        target: target,
        evidence: { alg: header.alg, source },
        remediation: 'Prefer RS256 or ES256 over HS256. If HS256 is required, ensure the secret is stored securely and rotated.'
      }));
    }

    // Check kid for path traversal
    if (header.kid && /(\.\.|\/)/.test(header.kid)) {
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: 'critical',
        title: 'JWT kid header contains path traversal — key injection possible',
        description: `kid value "${header.kid}" contains path traversal characters. Attackers may be able to control which key is used to verify the signature.`,
        cwe: 'CWE-347',
        cvss: 9.1,
        target: target,
        evidence: { kid: header.kid, source },
        remediation: 'Validate and sanitize the kid claim. Never use user-controllable input to select keys without validation.'
      }));
    }

    // Check for excessive permissions (scope/role)
    if (payload.scope || payload.scopes || payload.role || payload.roles) {
      const roles = payload.scope || payload.scopes || payload.role || payload.roles;
      if (Array.isArray(roles) && roles.includes('admin')) {
        findings.push(createFinding({
          scanner: SCANNER_ID,
          severity: 'info',
          title: 'JWT contains admin role — verify this is necessary',
          description: 'Tokens with admin roles are high-value targets. Ensure JWTs are stored securely and transmitted over HTTPS only.',
          cwe: 'CWE-287',
          cvss: 5.0,
          target: target,
          evidence: { roles, source }
        }));
      }
    }
  } catch {}
  return findings;
}

/**
 * Check for missing rate limiting on auth endpoints
 * @param {string} targetUrl
 * @returns {Promise<Array>}
 */
async function checkRateLimiting(targetUrl) {
  const findings = [];

  try {
    // Try login/auth endpoints that might be rate-limited
    const authEndpoints = [
      targetUrl.replace(/\/$/, '') + '/login',
      targetUrl.replace(/\/$/, '') + '/api/login',
      targetUrl.replace(/\/$/, '') + '/auth/login',
      targetUrl.replace(/\/$/, '') + '/api/auth',
      targetUrl
    ];

    for (const endpoint of authEndpoints) {
      const results = [];
      const TEST_COUNT = 20;

      // Send rapid requests
      for (let i = 0; i < TEST_COUNT; i++) {
        try {
          const resp = await axios.post(endpoint, {
            username: `ratelimit_test_${i}@example.com`,
            password: 'test_password_ratelimit_check'
          }, {
            timeout: 5000,
            validateStatus: () => true,
            headers: { 'Content-Type': 'application/json' }
          });
          results.push({ status: resp.status, i });
        } catch {
          results.push({ status: 0, error: true, i });
        }
      }

      const has429 = results.some(r => r.status === 429);
      const allSuccess = results.every(r => r.status >= 200 && r.status < 500);

      if (!has429 && allSuccess) {
        findings.push(createFinding({
          scanner: SCANNER_ID,
          severity: 'high',
          title: `No rate limiting on ${new URL(endpoint).pathname}`,
          description: `Sent ${TEST_COUNT} rapid POST requests to ${new URL(endpoint).pathname} without any rate limiting response (no 429, no lockout). This enables unlimited brute-force attacks.`,
          cwe: 'CWE-307',
          cvss: 7.5,
          target: endpoint,
          evidence: { endpoint, requestsSent: TEST_COUNT, responses: results.slice(0, 5) },
          remediation: 'Implement rate limiting: 5 attempts per minute per IP for login endpoints. Return 429 Too Many Requests with Retry-After header.'
        }));
        break; // Only test one endpoint
      }
    }
  } catch {}

  return findings;
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

  findings.push(...await checkWwwAuthenticate(targetUrl));
  findings.push(...await checkBasicAuthWithoutTLS(targetUrl));
  findings.push(...await checkJwtSecurity(targetUrl));
  findings.push(...await checkRateLimiting(targetUrl));

  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Checks authentication security: JWT analysis, rate limiting, Basic Auth over HTTP, missing WWW-Authenticate', run, defaultTimeout: 60000 };
