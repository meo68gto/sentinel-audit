/**
 * Sentinel Audit — Scanner Engine
 * Discovers, validates, and runs all enabled scanners in parallel
 */

const path = require('path');
const { EventEmitter } = require('events');
const { createFinding, deduplicate, sortBySeverity, filterByMinSeverity, buildSummary, riskScore } = require('./findings');
const { normalizeSeverity } = require('./severity');

const SCANNER_DIR = path.join(__dirname, '..', 'scanners');

/**
 * Load all scanner modules from the scanners/ directory
 * @returns {Map<string, Object>}
 */
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

/**
 * Execute a single scanner with timeout
 * @param {Object} scanner
 * @param {Object} context
 * @param {Object} config
 * @returns {Promise<Object>}
 */
async function runScanner(scanner, context, config) {
  const timeout = (config.scanners?.[scanner.id]?.timeout) || scanner.defaultTimeout || 60000;
  const scannerConfig = config.scanners?.[scanner.id] || {};

  const result = {
    id: scanner.id,
    name: scanner.name,
    status: 'pending',
    startedAt: null,
    completedAt: null,
    durationMs: 0,
    findings: [],
    error: null
  };

  try {
    result.startedAt = new Date();
    const timer = setTimeout(() => {
      throw new Error(`Scanner ${scanner.id} exceeded timeout of ${timeout}ms`);
    }, timeout);

    const findings = await scanner.run(context, scannerConfig);
    clearTimeout(timer);

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

/**
 * Determine which scanners to run based on context and config
 * @param {Map} scanners
 * @param {Object} context
 * @param {Object} config
 * @returns {Array}
 */
function selectScanners(scanners, context, config) {
  const enabled = [];
  const targetType = context.targetType;

  for (const [id, scanner] of scanners) {
    const scannerConfig = config.scanners?.[id];

    // Check if explicitly disabled
    if (scannerConfig?.enabled === false) continue;

    // For directory targets, skip network-only scanners unless they are explicitly needed
    if (targetType === 'directory' && scanner.id === 'ports') {
      // Ports scanner needs network — check if directory also has a URL
      if (!context.targetUrl) continue;
    }

    // For URL targets, skip file-only scanners
    if (targetType === 'url' && scanner.id === 'dependency') {
      // Dependency scanner needs a filesystem path
      if (!context.targetDir) continue;
    }

    // For host targets, skip auth scanner if no URL
    if (targetType === 'host' && scanner.id === 'auth') {
      if (!context.targetUrl) continue;
    }

    enabled.push(scanner);
  }

  return enabled;
}

/**
 * Run all enabled scanners against a target
 * @param {Object} options
 * @param {string} options.target - URL, directory path, or host
 * @param {string} [options.targetDir] - Directory path (for dependency scans)
 * @param {string} [options.targetUrl] - Full URL (for web scanners)
 * @param {string} [options.scopes] - Comma-separated scanner IDs to run (or 'all')
 * @param {Object} options.config - Full config object
 * @returns {Promise<Object>} - ScanResult
 */
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
  const scannerResults = [];

  // Run all registered scanners in parallel
  const runnable = Array.from(allScanners.values());
  const promises = runnable.map(scanner => {
    // Filter by scope if specified
    if (scopeList && !scopeList.includes(scanner.id)) {
      return Promise.resolve({ id: scanner.id, name: scanner.name, status: 'skipped', findings: [] });
    }
    return runScanner(scanner, context, config);
  });

  const settled = await Promise.allSettled(promises);

  for (const result of settled) {
    if (result.status === 'fulfilled') {
      scannerResults.push(result.value);
    } else {
      console.error(`[sentinel-audit] Scanner promise rejected: ${result.reason.message}`);
    }
  }

  const allFindings = scannerResults
    .filter(r => r.findings)
    .flat()
    .map(f => {
      // Ensure all findings have the scanId attached
      return { ...f, scanId };
    });

  const completedAt = new Date();
  const dedupedFindings = deduplicate(allFindings);
  const sortedFindings = sortBySeverity(dedupedFindings);
  const summary = buildSummary(sortedFindings);

  return {
    scanId,
    target,
    targetType: targetDir ? 'directory' : target.startsWith('http') ? 'url' : 'host',
    startedAt,
    completedAt,
    durationMs: completedAt - startedAt,
    findings: sortedFindings,
    summary,
    riskScore: riskScore(sortedFindings),
    scannerResults: scannerResults.map(r => ({
      id: r.id,
      name: r.name,
      status: r.status,
      durationMs: r.durationMs,
      error: r.error,
      findingCount: r.findings ? r.findings.length : 0
    }))
  };
}

module.exports = { runScan, loadScanners };
