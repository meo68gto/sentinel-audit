/**
 * Sentinel Audit — JSON Reporter
 * Outputs scan results as formatted JSON
 */

const fs = require('fs-extra');
const path = require('path');

class JsonReporter {
  /**
   * Write scan result to a JSON file
   * @param {Object} result - ScanResult
   * @param {string} outputPath
   */
  async write(result, outputPath) {
    await fs.ensureDir(path.dirname(outputPath));

    const output = {
      version: '1.0.0',
      scanId: result.scanId,
      target: result.target,
      targetType: result.targetType,
      timestamp: result.completedAt?.toISOString() || new Date().toISOString(),
      durationMs: result.durationMs,
      summary: result.summary,
      riskScore: result.riskScore,
      findings: result.findings.map(f => ({
        id: f.id,
        scanner: f.scanner,
        severity: f.severity,
        title: f.title,
        description: f.description,
        cwe: f.cwe,
        cvss: f.cvss,
        target: f.target,
        filePath: f.filePath,
        lineNumber: f.lineNumber,
        evidence: f.evidence,
        remediation: f.remediation
      })),
      scannerResults: result.scannerResults
    };

    await fs.writeFile(outputPath, JSON.stringify(output, null, 2), 'utf8');
  }
}

module.exports = JsonReporter;
