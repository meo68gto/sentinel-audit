/**
 * Sentinel Audit — JSON Reporter
 * Outputs a structured JSON report.
 */

const fs = require('fs');
const path = require('path');

const SEVERITY_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

/**
 * Summarize findings by severity.
 */
function summarize(findings) {
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const key = f.severity.toLowerCase();
    if (summary[key] !== undefined) summary[key]++;
  }
  return summary;
}

/**
 * Sort findings by severity.
 */
function sortFindings(findings) {
  return [...findings].sort((a, b) => {
    const ai = SEVERITY_ORDER.indexOf(a.severity);
    const bi = SEVERITY_ORDER.indexOf(b.severity);
    return ai - bi;
  });
}

/**
 * Generate a JSON report from scan findings.
 * @param {object} params - { target, findings, scanDate, outputPath }
 * @returns {string} JSON report string
 */
function generate(params) {
  const { target, findings, scanDate, outputPath } = params;
  const sortedFindings = sortFindings(findings);
  const summary = summarize(sortedFindings);

  const report = {
    scanDate: scanDate ? new Date(scanDate).toISOString() : new Date().toISOString(),
    target,
    totalFindings: findings.length,
    summary,
    findings: sortedFindings.map((f, i) => ({
      id: i + 1,
      severity: f.severity,
      title: f.title,
      description: f.description,
      remediation: f.remediation,
      cwe: f.cwe,
    })),
  };

  const json = JSON.stringify(report, null, 2);

  if (outputPath) {
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(outputPath, json, 'utf-8');
  }

  return json;
}

module.exports = { generate };
