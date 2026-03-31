/**
 * Sentinel Audit — Findings Aggregator
 */

const { SEVERITY_WEIGHTS } = require('./types');

let findingCounter = 0;

function nextId() {
  findingCounter++;
  return `SENTINEL-${String(findingCounter).padStart(3, '0')}`;
}

function createFinding({
  scanner, severity, title, description = '',
  cwe = null, cvss, target = '', evidence = {},
  filePath = null, lineNumber = null, remediation = ''
}) {
  const { normalizeSeverity: norm } = require('./severity');
  const { severity: normSev, cvss: normCvss } = norm(cvss || severity);
  return {
    id: nextId(), scanner, severity: normSev, title, description,
    cwe, cvss: normCvss, target, evidence, filePath, lineNumber, remediation
  };
}

function deduplicate(findings) {
  const seen = new Map();
  for (const f of findings) {
    const key = `${f.scanner}|${f.title}|${f.target}|${f.filePath || ''}|${f.lineNumber || ''}`;
    if (!seen.has(key)) seen.set(key, f);
  }
  return Array.from(seen.values());
}

function sortBySeverity(findings) {
  return [...findings].sort((a, b) => {
    const wA = SEVERITY_WEIGHTS[a.severity] || 0;
    const wB = SEVERITY_WEIGHTS[b.severity] || 0;
    if (wB !== wA) return wB - wA;
    return (b.cvss || 0) - (a.cvss || 0);
  });
}

function filterByMinSeverity(findings, minSeverity = 'info') {
  const levels = ['info', 'low', 'medium', 'high', 'critical'];
  const minIdx = levels.indexOf(minSeverity);
  return findings.filter(f => levels.indexOf(f.severity) >= minIdx);
}

function buildSummary(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    if (summary[f.severity] !== undefined) summary[f.severity]++;
  }
  return summary;
}

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
  createFinding, deduplicate, sortBySeverity,
  filterByMinSeverity, buildSummary, riskScore
};
