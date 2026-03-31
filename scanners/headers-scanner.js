/**
 * Sentinel Audit — Security Headers Scanner
 * Checks for the presence and correctness of HTTP security headers
 * Targets: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy
 */

const axios = require('axios');
const { createFinding } = require('../core/findings');
const { normalizeSeverity } = require('../core/severity');

const SCANNER_ID = 'headers';
const SCANNER_NAME = 'Security Headers Scanner';

let findingCounter = 0;
function nextId() {
  findingCounter++;
  return `SENTINEL-HEAD-${String(findingCounter).padStart(3, '0')}`;
}

// Security headers to check, with expected values and severity if missing/wrong
const HEADER_CHECKS = [
  {
    name: 'Strict-Transport-Security',
    key: 'strict-transport-security',
    severity: 'high',
    cwe: 'CWE-523',
    check: (val) => {
      if (!val) return { ok: false, detail: 'Header missing — HTTPS downgrades possible' };
      if (!val.includes('max-age=')) return { ok: false, detail: 'max-age directive missing' };
      const maxAge = parseInt(val.match(/max-age=(\d+)/)?.[1] || '0');
      if (maxAge < 31536000) return { ok: false, detail: `max-age too low (${maxAge}s, should be >= 31536000)` };
      if (!val.includes('includeSubDomains')) return { ok: false, detail: 'includeSubDomains directive missing' };
      return { ok: true };
    },
    remediation: 'Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
  },
  {
    name: 'X-Frame-Options',
    key: 'x-frame-options',
    severity: 'medium',
    cwe: 'CWE-346',
    check: (val) => {
      if (!val) return { ok: false, detail: 'Header missing — clickjacking possible' };
      const upper = val.toUpperCase();
      if (upper !== 'DENY' && upper !== 'SAMEORIGIN') {
        return { ok: false, detail: `Invalid value "${val}" — should be DENY or SAMEORIGIN` };
      }
      return { ok: true };
    },
    remediation: 'Set: X-Frame-Options: DENY (or SAMEORIGIN if iframes are needed)'
  },
  {
    name: 'Content-Security-Policy',
    key: 'content-security-policy',
    severity: 'high',
    cwe: 'CWE-346',
    check: (val) => {
      if (!val) return { ok: false, detail: 'CSP missing — XSS and data injection possible' };
      if (val.includes("'unsafe-inline'") || val.includes("'unsafe-eval'")) {
        return { ok: false, detail: 'CSP contains unsafe-inline or unsafe-eval — weakens protection' };
      }
      return { ok: true };
    },
    remediation: 'Define a strict CSP: default-src \'self\'; script-src \'self\'; object-src \'none\'; frame-ancestors \'none\''
  },
  {
    name: 'X-Content-Type-Options',
    key: 'x-content-type-options',
    severity: 'low',
    cwe: 'CWE-693',
    check: (val) => {
      if (!val || val.toLowerCase() !== 'nosniff') {
        return { ok: false, detail: `Invalid value "${val}" — must be "nosniff"` };
      }
      return { ok: true };
    },
    remediation: 'Set: X-Content-Type-Options: nosniff'
  },
  {
    name: 'Referrer-Policy',
    key: 'referrer-policy',
    severity: 'low',
    cwe: 'CWE-688',
    check: (val) => {
      if (!val) return { ok: false, detail: 'Referrer-Policy missing — referrer leaks possible' };
      const valid = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
      if (!valid.includes(val.toLowerCase())) {
        return { ok: false, detail: `Invalid Referrer-Policy "${val}"` };
      }
      return { ok: true };
    },
    remediation: 'Set: Referrer-Policy: strict-origin-when-cross-origin (or stricter)'
  },
  {
    name: 'Permissions-Policy',
    key: 'permissions-policy',
    severity: 'low',
    cwe: 'CWE-693',
    check: (val) => {
      if (!val) return { ok: false, detail: 'Permissions-Policy missing — unused browser features accessible' };
      return { ok: true };
    },
    remediation: 'Set Permissions-Policy to disable unused features: geolocation=(), camera=(), microphone=()'
  }
];

/**
 * Check information disclosure headers
 * @param {Object} headers
 * @returns {Array}
 */
function checkInfoDisclosure(headers) {
  const findings = [];
  const headerNames = Object.keys(headers).map(k => k.toLowerCase());

  // Check for X-Powered-By (ASP.NET, Express default)
  if (headerNames.includes('x-powered-by')) {
    const val = headers['x-powered-by'] || headers['X-Powered-By'] || '';
    findings.push(createFinding({
      scanner: SCANNER_ID,
      severity: 'low',
      title: 'X-Powered-By header exposed',
      description: `Server technology disclosed: "${val}". Attackers use this to fingerprint and target known vulnerabilities for ${val}.`,
      cwe: 'CWE-200',
      evidence: { header: 'X-Powered-By', value: val },
      remediation: 'Remove X-Powered-By header: Express: app.disable("x-powered-by"); ASP.NET: remove via web.config'
    }));
  }

  // Check for Server header (often discloses Apache, nginx, IIS version)
  if (headerNames.includes('server')) {
    const val = headers['server'] || '';
    if (/\d+\.\d+/.test(val) || /apache|nginx|iis|tomcat/i.test(val)) {
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: 'low',
        title: 'Server header exposes version information',
        description: `Server header discloses: "${val}". Fingerprinting enables targeted attacks.`,
        cwe: 'CWE-200',
        evidence: { header: 'Server', value: val },
        remediation: 'Suppress or genericize Server header: Express: use helmet with hidePoweredBy; nginx: server_tokens off; Apache: ServerTokens Prod'
      }));
    }
  }

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
  let response;

  try {
    response = await axios.head(targetUrl, {
      timeout: 15000,
      validateStatus: () => true, // Accept any status
      maxRedirects: 5
    });
  } catch (err) {
    // Try GET if HEAD fails (some servers don't support HEAD)
    try {
      response = await axios.get(targetUrl, {
        timeout: 15000,
        validateStatus: () => true,
        maxRedirects: 5,
        maxContentLength: 1024 * 100 // Only first 100KB
      });
    } catch (e) {
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: 'high',
        title: 'Cannot connect to target',
        description: `Failed to fetch target URL: ${err.message}`,
        target: targetUrl,
        remediation: 'Verify the target URL is reachable and running.'
      }));
      return findings;
    }
  }

  const headers = {};
  for (const [key, value] of Object.entries(response.headers)) {
    headers[key.toLowerCase()] = value;
  }

  // Check each required security header
  for (const check of HEADER_CHECKS) {
    const rawValue = headers[check.key];
    const result = check.check(rawValue);

    if (!result.ok) {
      const { cvss } = normalizeSeverity(check.severity);
      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity: check.severity,
        title: `${check.name} header: ${result.detail}`,
        description: result.detail,
        cwe: check.cwe,
        cvss,
        target: targetUrl,
        evidence: {
          header: check.name,
          actualValue: rawValue || '(not set)',
          requiredCheck: check.key
        },
        remediation: check.remediation
      }));
    }
  }

  // Check info disclosure headers
  findings.push(...checkInfoDisclosure(headers));

  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Audits HTTP security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy', run, defaultTimeout: 30000 };
