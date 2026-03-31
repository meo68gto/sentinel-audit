/**
 * Sentinel Audit — JSON Reporter
 * Outputs scan results as structured JSON
 */

const fs = require('fs-extra');
const path = require('path');

class JsonReporter {
  async write(result, outputPath) {
    await fs.ensureDir(path.dirname(outputPath));
    const output = {
      version: '1.0.0',
      scanId: result.scanId,
      target: result.target,
      targetType: result.targetType,
      timestamp: result.completedAt?.toISOString() || new Date().toISOString(),
      durationMs: result.durationMs,
      riskScore: result.riskScore,
      summary: result.summary,
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
      scannerResults: result.scannerResults.map(r => ({
        id: r.id,
        name: r.name,
        status: r.status,
        durationMs: r.durationMs,
        error: r.error,
        findingCount: r.findingCount
      }))
    };
    await fs.writeFile(outputPath, JSON.stringify(output, null, 2), 'utf8');
  }
}

module.exports = JsonReporter;
