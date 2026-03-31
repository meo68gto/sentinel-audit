/**
 * Sentinel Audit — Severity Scorer
 * Maps raw scan output to severity levels and CVSS scores
 */

const CWE_CVSS_MAP = {
  'CWE-798': { cvss: 8.9, severity: 'high' },
  'CWE-259': { cvss: 7.5, severity: 'high' },
  'CWE-311': { cvss: 9.1, severity: 'critical' },
  'CWE-89': { cvss: 9.8, severity: 'critical' },
  'CWE-78': { cvss: 9.8, severity: 'critical' },
  'CWE-306': { cvss: 9.8, severity: 'critical' },
  'CWE-287': { cvss: 9.1, severity: 'critical' },
  'CWE-307': { cvss: 7.5, severity: 'high' },
  'CWE-319': { cvss: 9.1, severity: 'critical' },
  'CWE-295': { cvss: 8.0, severity: 'high' },
  'CWE-79': { cvss: 6.1, severity: 'medium' },
  'CWE-601': { cvss: 8.3, severity: 'high' },
  'CWE-22': { cvss: 8.6, severity: 'high' },
  'CWE-540': { cvss: 8.0, severity: 'high' },
  'CWE-209': { cvss: 4.3, severity: 'medium' },
  'CWE-548': { cvss: 5.3, severity: 'medium' },
  'CWE-200': { cvss: 5.3, severity: 'medium' },
  'CWE-328': { cvss: 7.5, severity: 'high' },
  'CWE-347': { cvss: 9.4, severity: 'critical' },
  'CWE-523': { cvss: 7.5, severity: 'high' },
  'CWE-346': { cvss: 6.5, severity: 'medium' },
  'CWE-693': { cvss: 3.8, severity: 'low' },
  'CWE-688': { cvss: 4.3, severity: 'medium' },
  'CWE-613': { cvss: 7.5, severity: 'high' },
  'CWE-1104': { cvss: 7.5, severity: 'high' }
};

function normalizeSeverity(input) {
  if (typeof input === 'string') {
    const lower = input.toLowerCase();
    if (['critical', 'high', 'medium', 'low', 'info'].includes(lower)) {
      const cvssMap = { critical: 10.0, high: 8.9, medium: 6.9, low: 3.9, info: 0.0 };
      return { severity: lower, cvss: cvssMap[lower] };
    }
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

function npmSeverityToLevel(npmSev) {
  const map = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'info' };
  return map[npmSev?.toLowerCase()] || 'info';
}

module.exports = { normalizeSeverity, npmSeverityToLevel, CWE_CVSS_MAP };
