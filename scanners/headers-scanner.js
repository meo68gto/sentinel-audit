/**
 * Sentinel Audit — Security Headers Scanner
 * Checks for HTTP security headers: CSP, HSTS, X-Frame-Options, etc.
 */

const axios = require('axios');
const { createFinding } = require('../core/findings');
const { normalizeSeverity } = require('../core/severity');

const SCANNER_ID = 'headers';
const SCANNER_NAME = 'Security Headers Scanner';

const HEADER_CHECKS = [
  { name: 'Strict-Transport-Security', key: 'strict-transport-security', severity: 'high', cwe: 'CWE-523',
    check: (v) => {
      if (!v) return { ok: false, detail: 'Header missing — HTTPS downgrades possible' };
      if (!v.includes('max-age=')) return { ok: false, detail: 'max-age directive missing' };
      const maxAge = parseInt(v.match(/max-age=(\d+)/)?.[1] || '0');
      if (maxAge < 31536000) return { ok: false, detail: `max-age too low (${maxAge}s, should be >= 31536000)` };
      if (!v.includes('includeSubDomains')) return { ok: false, detail: 'includeSubDomains missing' };
      return { ok: true };
    },
    remediation: 'Set: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
  },
  { name: 'X-Frame-Options', key: 'x-frame-options', severity: 'medium', cwe: 'CWE-346',
    check: (v) => {
      if (!v) return { ok: false, detail: 'Header missing — clickjacking possible' };
      if (v.toUpperCase() !== 'DENY' && v.toUpperCase() !== 'SAMEORIGIN') return { ok: false, detail: `Invalid value "${v}" — should be DENY or SAMEORIGIN` };
      return { ok: true };
    },
    remediation: 'Set: X-Frame-Options: DENY'
  },
  { name: 'Content-Security-Policy', key: 'content-security-policy', severity: 'high', cwe: 'CWE-346',
    check: (v) => {
      if (!v) return { ok: false, detail: 'CSP missing — XSS and data injection possible' };
      if (v.includes("'unsafe-inline'") || v.includes("unsafe-inline") || v.includes("'unsafe-eval'") || v.includes("unsafe-eval")) return { ok: false, detail: 'CSP contains unsafe-inline or unsafe-eval' };
      return { ok: true };
    },
    remediation: "Define strict CSP: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
  },
  { name: 'X-Content-Type-Options', key: 'x-content-type-options', severity: 'low', cwe: 'CWE-693',
    check: (v) => (!v || v.toLowerCase() !== 'nosniff') ? { ok: false, detail: `Invalid value "${v}" — must be "nosniff"` } : { ok: true },
    remediation: 'Set: X-Content-Type-Options: nosniff'
  },
  { name: 'Referrer-Policy', key: 'referrer-policy', severity: 'low', cwe: 'CWE-688',
    check: (v) => {
      if (!v) return { ok: false, detail: 'Referrer-Policy missing — referrer leaks possible' };
      const valid = ['no-referrer', 'no-referrer-when-downgrade', 'origin', 'origin-when-cross-origin', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'];
      if (!valid.includes(v.toLowerCase())) return { ok: false, detail: `Invalid Referrer-Policy "${v}"` };
      return { ok: true };
    },
    remediation: 'Set: Referrer-Policy: strict-origin-when-cross-origin'
  },
  { name: 'Permissions-Policy', key: 'permissions-policy', severity: 'low', cwe: 'CWE-693',
    check: (v) => !v ? { ok: false, detail: 'Permissions-Policy missing — unused browser features accessible' } : { ok: true },
    remediation: 'Set Permissions-Policy to disable unused features: geolocation=(), camera=(), microphone=()'
  }
];

function checkInfoDisclosure(headers) {
  const findings = [];
  const names = Object.keys(headers).map(k => k.toLowerCase());
  if (names.includes('x-powered-by')) {
    const val = headers['x-powered-by'] || headers['X-Powered-By'] || '';
    findings.push(createFinding({ scanner: SCANNER_ID, severity: 'low', title: 'X-Powered-By header exposed',
      description: `Server technology disclosed: "${val}". Attackers use this to fingerprint and target known vulnerabilities.`,
      cwe: 'CWE-200', evidence: { header: 'X-Powered-By', value: val },
      remediation: 'Remove X-Powered-By: Express: app.disable("x-powered-by")' }));
  }
  if (names.includes('server')) {
    const val = headers['server'] || '';
    if (/\d+\.\d+/.test(val) || /apache|nginx|iis|tomcat/i.test(val)) {
      findings.push(createFinding({ scanner: SCANNER_ID, severity: 'low', title: 'Server header exposes version',
        description: `Server header discloses: "${val}". Fingerprinting enables targeted attacks.`,
        cwe: 'CWE-200', evidence: { header: 'Server', value: val },
        remediation: 'Suppress/genericize Server header: nginx: server_tokens off; Apache: ServerTokens Prod' }));
    }
  }
  return findings;
}

async function run(context) {
  const { targetUrl } = context;
  if (!targetUrl) return [];
  const findings = [];
  let response;
  try {
    response = await axios.head(targetUrl, { timeout: 15000, validateStatus: () => true, maxRedirects: 5 });
  } catch {
    try {
      response = await axios.get(targetUrl, { timeout: 15000, validateStatus: () => true, maxRedirects: 5, maxContentLength: 102400 });
    } catch (e) {
      return [createFinding({ scanner: SCANNER_ID, severity: 'high', title: 'Cannot connect to target',
        description: `Failed to fetch target URL: ${e.message}`, target: targetUrl,
        remediation: 'Verify the target URL is reachable.' })];
    }
  }
  const headers = {};
  for (const [key, value] of Object.entries(response.headers)) headers[key.toLowerCase()] = value;
  for (const check of HEADER_CHECKS) {
    const rawValue = headers[check.key];
    const result = check.check(rawValue);
    if (!result.ok) {
      const { cvss } = normalizeSeverity(check.severity);
      findings.push(createFinding({ scanner: SCANNER_ID, severity: check.severity, title: `${check.name}: ${result.detail}`,
        description: result.detail, cwe: check.cwe, cvss, target: targetUrl,
        evidence: { header: check.name, actualValue: rawValue || '(not set)' },
        remediation: check.remediation }));
    }
  }
  findings.push(...checkInfoDisclosure(headers));
  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Audits HTTP security headers: CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy', run, defaultTimeout: 30000 };
