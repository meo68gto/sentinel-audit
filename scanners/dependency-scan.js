/**
 * Sentinel Audit — Dependency Scanner
 * Runs `npm audit --json` against a local codebase and surfaces findings.
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

/**
 * Run npm audit on the target directory and parse results.
 * @param {string} targetDir - Absolute path to the codebase to scan
 * @param {object} config - Scanner config
 * @returns {Promise<Array>} Array of finding objects
 */
async function scan(targetDir, config) {
  const findings = [];

  if (!targetDir || !fs.existsSync(targetDir)) {
    findings.push({
      severity: 'INFO',
      title: 'Dependency Scan Skipped',
      description: `Target directory "${targetDir}" does not exist or is not accessible.`,
      remediation: 'Provide a valid local directory path containing a package.json file.',
      cwe: 'N/A',
    });
    return findings;
  }

  const packageJsonPath = path.join(targetDir, 'package.json');
  if (!fs.existsSync(packageJsonPath)) {
    findings.push({
      severity: 'INFO',
      title: 'No package.json Found',
      description: `No package.json found in "${targetDir}". Skipping dependency audit.`,
      remediation: 'Ensure the target directory contains a Node.js project with package.json.',
      cwe: 'N/A',
    });
    return findings;
  }

  try {
    let raw;
    try {
      raw = execSync('npm audit --json', {
        cwd: targetDir,
        encoding: 'utf-8',
        timeout: 60000,
        maxBuffer: 10 * 1024 * 1024,
      });
    } catch (err) {
      // npm audit exits non-zero when vulnerabilities found — still parse stdout
      raw = err.stdout || '';
    }

    if (!raw) {
      findings.push({
        severity: 'INFO',
        title: 'No Vulnerabilities Found',
        description: 'npm audit returned no output — dependencies appear clean.',
        remediation: 'Continue monitoring with `npm audit` regularly.',
        cwe: 'N/A',
      });
      return findings;
    }

    const result = JSON.parse(raw);
    const vulnerabilities = result.vulnerabilities || {};

    if (Object.keys(vulnerabilities).length === 0) {
      findings.push({
        severity: 'INFO',
        title: 'No Vulnerabilities Found',
        description: 'npm audit found no known vulnerabilities in dependencies.',
        remediation: 'Continue monitoring with `npm audit` regularly.',
        cwe: 'N/A',
      });
      return findings;
    }

    for (const [pkg, info] of Object.entries(vulnerabilities)) {
      const severity = mapSeverity(info.severity);
      const via = Array.isArray(info.via) ? info.via : Object.values(info.via || {});

      for (const v of via) {
        if (typeof v === 'object' && v && v.title) {
          findings.push({
            severity,
            title: `Vulnerable Dependency: ${pkg}`,
            description: `${pkg}@${info.name || 'unknown'} — ${v.title}${v.url ? ` (${v.url})` : ''}`,
            remediation: `Update ${pkg} to a patched version. Run: npm update ${pkg} or npm audit fix`,
            cwe: mapCWE(v.title),
          });
        } else if (typeof v === 'string') {
          findings.push({
            severity,
            title: `Vulnerable Dependency: ${pkg}`,
            description: `${pkg} — ${v}`,
            remediation: `Update ${pkg} to a patched version. Run: npm update ${pkg} or npm audit fix`,
            cwe: 'CWE-1025',
          });
        }
      }
    }
  } catch (err) {
    findings.push({
      severity: 'HIGH',
      title: 'Dependency Scan Error',
      description: `Failed to run npm audit: ${err.message}`,
      remediation: 'Ensure npm is installed and the target directory contains package.json.',
      cwe: 'N/A',
    });
  }

  return findings;
}

function mapSeverity(npmSeverity) {
  const map = { critical: 'CRITICAL', high: 'HIGH', moderate: 'MEDIUM', low: 'LOW' };
  return map[npmSeverity] || 'MEDIUM';
}

function mapCWE(title) {
  const l = title.toLowerCase();
  if (l.includes('prototype pollution')) return 'CWE-1321';
  if (l.includes('command injection') || l.includes('os command')) return 'CWE-78';
  if (l.includes('xss') || l.includes('cross-site')) return 'CWE-79';
  if (l.includes('sql injection')) return 'CWE-89';
  if (l.includes('path traversal')) return 'CWE-22';
  if (l.includes('denial')) return 'CWE-400';
  if (l.includes('sensitive data') || l.includes('credentials')) return 'CWE-200';
  return 'CWE-1035';
}

module.exports = { scan };
