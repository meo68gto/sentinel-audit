/**
 * Sentinel Audit — Scanner Engine
 * Discovers and runs all enabled scanners in parallel
 */

const path = require('path');
const { createFinding, deduplicate, sortBySeverity, filterByMinSeverity, buildSummary, riskScore } = require('./findings');

const SCANNER_DIR = path.join(__dirname, '..', 'scanners');

function loadScanners() {
  const scanners = new Map();
  try {
    const files = require('fs').readdirSync(SCANNER_DIR);
    for (const file of files) {
      if (!file.endsWith('-scanner.js')) continue;
      try {
        const scanner = require(path.join(SCANNER_DIR, file));
        if (scanner && scanner.id && scanner.run) {
          scanners.set(scanner.id, scanner);
        }
      } catch (e) {
        console.warn(`[sentinel-audit] Failed to load scanner ${file}: ${e.message}`);
      }
    }
  } catch (e) {
    console.error(`[sentinel-audit] Failed to read scanners directory: ${e.message}`);
  }
  return scanners;
}

async function runScanner(scanner, context, config) {
  const timeout = (config.scanners?.[scanner.id]?.timeout) || scanner.defaultTimeout || 60000;
  const result = { id: scanner.id, name: scanner.name, status: 'pending', startedAt: null, completedAt: null, durationMs: 0, findings: [], error: null };
  try {
    result.startedAt = new Date();
    let timedOut = false;
    const timer = setTimeout(() => { timedOut = true; throw new Error(`Scanner ${scanner.id} exceeded timeout of ${timeout}ms`); }, timeout);
    const findings = await scanner.run(context, config);
    clearTimeout(timer);
    if (timedOut) throw new Error('Timeout');
    result.findings = Array.isArray(findings) ? findings : [];
    result.status = 'complete';
  } catch (err) {
    result.status = 'error';
    result.error = err.message;
    console.error(`[sentinel-audit] Scanner ${scanner.id} error: ${err.message}`);
  }
  result.completedAt = new Date();
  result.durationMs = result.completedAt - result.startedAt;
  return result;
}

async function runScan({ target, targetDir, targetUrl, scopes, config }) {
  const scanId = `scan_${new Date().toISOString().replace(/[-:T]/g, '').slice(0, 14)}`;
  const startedAt = new Date();
  const context = {
    target,
    targetDir: targetDir || null,
    targetUrl: targetUrl || (target.startsWith('http') ? target : null),
    scanId,
    config
  };
  const allScanners = loadScanners();
  const scopeList = scopes ? scopes.split(',').map(s => s.trim()) : null;
  const runnable = Array.from(allScanners.values()).filter(s => !scopeList || scopeList.includes(s.id));
  const scannerResults = [];
  const promises = runnable.map(scanner => runScanner(scanner, context, config));
  const settled = await Promise.allSettled(promises);
  for (const result of settled) {
    if (result.status === 'fulfilled') scannerResults.push(result.value);
    else console.error(`[sentinel-audit] Scanner promise rejected: ${result.reason.message}`);
  }
  const allFindings = scannerResults.map(r => r.findings || []).flat().map(f => ({ ...f, scanId }));
  const completedAt = new Date();
  const dedupedFindings = deduplicate(allFindings);
  const sortedFindings = sortBySeverity(dedupedFindings);
  return {
    scanId, target,
    targetType: targetDir ? 'directory' : target.startsWith('http') ? 'url' : 'host',
    startedAt, completedAt, durationMs: completedAt - startedAt,
    findings: sortedFindings,
    summary: buildSummary(sortedFindings),
    riskScore: riskScore(sortedFindings),
    scannerResults: scannerResults.map(r => ({
      id: r.id, name: r.name, status: r.status, durationMs: r.durationMs, error: r.error, findingCount: r.findings ? r.findings.length : 0
    }))
  };
}

module.exports = { runScan, loadScanners };
