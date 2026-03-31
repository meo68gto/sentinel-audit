/**
 * Sentinel Audit — Severity Scorer
 * Maps raw scan output to severity levels and CVSS scores
 */

const CWE_CVSS_MAP = {
  // Use of Hard-coded Credentials
  'CWE-798': { cvss: 8.9, severity: 'high' },
  // Use of Hard-coded Credentials
  'CWE-259': { cvss: 7.5, severity: 'high' },
  // Missing Encryption of Sensitive Data
  'CWE-311': { cvss: 9.1, severity: 'critical' },
  // SQL Injection
  'CWE-89': { cvss: 9.8, severity: 'critical' },
  // OS Command Injection
  'CWE-78': { cvss: 9.8, severity: 'critical' },
  // Exposure of Private Personal Information
  'CWE-359': { cvss: 7.5, severity: 'high' },
  // Missing Authentication for Critical Function
  'CWE-306': { cvss: 9.8, severity: 'critical' },
  // Broken Authentication
  'CWE-287': { cvss: 9.1, severity: 'critical' },
  // Sensitive Cookie Without 'HttpOnly' Flag
  'CWE-1004': { cvss: 6.5, severity: 'medium' },
  // Sensitive Server Endpoint Without Authentication
  'CWE-306': { cvss: 8.6, severity: 'high' },
  // Missing Rate Limiting
  'CWE-307': { cvss: 7.5, severity: 'high' },
  // Cleartext Transmission of Sensitive Data
  'CWE-319': { cvss: 9.1, severity: 'critical' },
  // Use of Spreadsheet Document Without Agent and Integrity Check
  'CWE-295': { cvss: 8.0, severity: 'high' },
  // Cleartext Storage of Sensitive Information in a Cookie
  'CWE-315': { cvss: 8.1, severity: 'high' },
  // Creation of Texture Image File With Detectable Metadata
  'CWE-685': { cvss: 3.7, severity: 'low' },
  // Cross-Site Scripting (XSS)
  'CWE-79': { cvss: 6.1, severity: 'medium' },
  // Open Redirect
  'CWE-601': { cvss: 8.3, severity: 'high' },
  // Directory Traversal
  'CWE-22': { cvss: 8.6, severity: 'high' },
  // URL Redirection to Untrusted Site
  'CWE-601': { cvss: 8.3, severity: 'high' },
  // Exposure of Version-Control Repository to Unauthorized Agents
  'CWE-540': { cvss: 8.0, severity: 'high' },
  // Information Exposure Through Error Messages
  'CWE-209': { cvss: 4.3, severity: 'medium' },
  // Information Exposure Through Directory Listing
  'CWE-548': { cvss: 5.3, severity: 'medium' },
  // Exposure of Sensitive Information Through Debug Information
  'CWE-11': { cvss: 5.3, severity: 'medium' },
  // Expired Certificate
  'CWE-295': { cvss: 5.3, severity: 'medium' },
  // Weak Cryptographic Hash
  'CWE-328': { cvss: 7.5, severity: 'high' },
  // JWtalg None Vulnerability
  'CWE-347': { cvss: 9.4, severity: 'critical' },
  // Insufficiently Protected Credentials
  'CWE-311': { cvss: 8.2, severity: 'high' }
};

/**
 * @param {string|number} input - CVSS score, severity string, or CWE code
 * @returns {{ severity: string, cvss: number }}
 */
function normalizeSeverity(input) {
  if (typeof input === 'string') {
    const lower = input.toLowerCase();
    if (['critical', 'high', 'medium', 'low', 'info'].includes(lower)) {
      const cvssMap = {
        critical: 10.0,
        high: 8.9,
        medium: 6.9,
        low: 3.9,
        info: 0.0
      };
      return { severity: lower, cvss: cvssMap[lower] };
    }
    // CWE code like "CWE-798"
    if (lower.startsWith('cwe-')) {
      const mapped = CWE_CVSS_MAP[lower.toUpperCase()];
      if (mapped) return mapped;
    }
  }

  if (typeof input === 'number') {
    if (input >= 9.0) return { severity: 'critical', cvss: input };
    if (input >= 7.0) return { severity: 'high', cvss: input };
    if (input >= 4.0) return { severity: 'medium', cvss: input };
    if (input > 0) return { severity: 'low', cvss: input };
    return { severity: 'info', cvss: input };
  }

  return { severity: 'info', cvss: 0.0 };
}

/**
 * @param {string} npmSeverity - Severity string from npm audit
 * @returns {string} - Normalized severity
 */
function npmSeverityToLevel(npmSev) {
  const map = {
    critical: 'critical',
    high: 'high',
    moderate: 'medium',
    low: 'low',
    info: 'info'
  };
  return map[npmSev?.toLowerCase()] || 'info';
}

module.exports = {
  normalizeSeverity,
  npmSeverityToLevel,
  CWE_CVSS_MAP
};
