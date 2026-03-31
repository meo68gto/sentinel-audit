/**
 * Sentinel Audit — Findings Aggregator
 * Collects, deduplicates, scores, and summarizes findings from all scanners
 */

const { SEVERITY_WEIGHTS } = require('./types');
const { normalizeSeverity } = require('./severity');

let findingCounter = 0;

/**
 * @returns {string} - Next finding ID like "SENTINEL-001"
 */
function nextId() {
  findingCounter++;
  return `SENTINEL-${String(findingCounter).padStart(3, '0')}`;
}

/**
 * @typedef {import('./types').Finding} Finding
 */

/**
 * Create a standardized finding object
 * @param {Object} opts
 * @returns {Finding}
 */
function createFinding({
  scanner,
  severity,
  title,
  description,
  cwe,
  cvss,
  target,
  evidence,
  filePath,
  lineNumber,
  remediation
}) {
  const { severity: normSev, cvss: normCvss } = normalizeSeverity(cvss || severity);
  return {
    id: nextId(),
    scanner,
    severity: normSev,
    title,
    description: description || '',
    cwe: cwe || null,
    cvss: normCvss,
    target: target || '',
    evidence: evidence || {},
    filePath: filePath || null,
    lineNumber: lineNumber || null,
    remediation: remediation || ''
  };
}

/**
 * Deduplicate findings by comparing title + scanner + target + filePath
 * @param {Finding[]} findings
 * @returns {Finding[]}
 */
function deduplicate(findings) {
  const seen = new Map();
  for (const f of findings) {
    const key = `${f.scanner}|${f.title}|${f.target}|${f.filePath || ''}|${f.lineNumber || ''}`;
    if (!seen.has(key)) {
      seen.set(key, f);
    }
  }
  return Array.from(seen.values());
}

/**
 * Sort findings by severity (critical first)
 * @param {Finding[]} findings
 * @returns {Finding[]}
 */
function sortBySeverity(findings) {
  return [...findings].sort((a, b) => {
    const weightA = SEVERITY_WEIGHTS[a.severity] || 0;
    const weightB = SEVERITY_WEIGHTS[b.severity] || 0;
    if (weightB !== weightA) return weightB - weightA;
    return (b.cvss || 0) - (a.cvss || 0);
  });
}

/**
 * Filter findings by minimum severity
 * @param {Finding[]} findings
 * @param {string} minSeverity
 * @returns {Finding[]}
 */
function filterByMinSeverity(findings, minSeverity = 'info') {
  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const minIdx = levels.indexOf(minSeverity);
  return findings.filter(f => {
    const fIdx = levels.indexOf(f.severity);
    return fIdx >= minIdx;
  });
}

/**
 * Build summary object from findings
 * @param {Finding[]} findings
 * @returns {Object}
 */
function buildSummary(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (summary[f.severity] !== undefined) {
      summary[f.severity]++;
    }
  }
  return summary;
}

/**
 * Calculate overall risk score (0-100)
 * @param {Finding[]} findings
 * @returns {number}
 */
function riskScore(findings) {
  let score = 0;
  for (const f of findings) {
    switch (f.severity) {
      case 'critical': score += 25; break;
      case 'high':     score += 10; break;
      case 'medium':   score += 4;  break;
      case 'low':      score += 1;  break;
    }
  }
  return Math.min(score, 100);
}

module.exports = {
  createFinding,
  deduplicate,
  sortBySeverity,
  filterByMinSeverity,
  buildSummary,
  riskScore
};
