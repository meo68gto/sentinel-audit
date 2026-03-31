/**
 * Sentinel Audit — Dependency CVE Scanner
 * Runs npm audit / pip audit against a target directory
 * Detects known vulnerabilities in npm and Python packages
 */

const { spawn } = require('child_process');
const { createFinding } = require('../core/findings');
const { normalizeSeverity, npmSeverityToLevel } = require('../core/severity');
const path = require('path');

const SCANNER_ID = 'dependency';
const SCANNER_NAME = 'Dependency CVE Scanner';

let findingCounter = 0;
function nextId() {
  findingCounter++;
  return `SENTINEL-DEP-${String(findingCounter).padStart(3, '0')}`;
}

/**
 * Run npm audit and parse results
 * @param {string} dir
 * @returns {Promise<Array>}
 */
async function runNpmAudit(dir) {
  return new Promise((resolve) => {
    const findings = [];
    const npm = spawn('npm', ['audit', '--json'], { cwd: dir, timeout: 90000 });

    let stdout = '';
    let stderr = '';

    npm.stdout.on('data', d => stdout += d);
    npm.stderr.on('data', d => stderr += d);

    npm.on('close', (code) => {
      if (stdout) {
        try {
          const result = JSON.parse(stdout);
          const vulnerabilities = result.vulnerabilities || {};
          for (const [pkg, vuln] of Object.entries(vulnerabilities)) {
            const severity = npmSeverityToLevel(vuln.severity);
            const { cvss } = normalizeSeverity(severity);
            findings.push(createFinding({
              scanner: SCANNER_ID,
              severity,
              title: `Vulnerable package: ${pkg}`,
              description: `${vuln.title || 'Known vulnerability in ' + pkg}\nVia: ${vuln.range}`,
              cwe: 'CWE-1104', // Use of Unmaintained Third-Party Component
              cvss,
              target: dir,
              evidence: {
                package: pkg,
                severity: vuln.severity,
                url: `https://www.npmjs.com/advisories/${Object.keys(vuln.advisory || {})[0] || 'unknown'}`
              },
              remediation: `Update ${pkg}: npm install ${pkg}@latest`
            }));
          }
        } catch (e) {
          // JSON parse failed — may be empty or too large
        }
      }
      resolve(findings);
    });

    npm.on('error', () => resolve(findings));
  });
}

/**
 * Run pip audit and parse results
 * @param {string} dir
 * @returns {Promise<Array>}
 */
async function runPipAudit(dir) {
  return new Promise((resolve) => {
    const findings = [];
    const pip = spawn('pip', ['audit', '--json'], { cwd: dir, timeout: 90000 });

    let stdout = '';

    pip.stdout.on('data', d => stdout += d);
    pip.on('close', () => {
      if (stdout) {
        try {
          const result = JSON.parse(stdout);
          for (const vuln of (result.vulnerabilities || [])) {
            const { cvss } = normalizeSeverity(vuln.vulns?.[0]?.cvss_v3?.score || 'medium');
            findings.push(createFinding({
              scanner: SCANNER_ID,
              severity: vuln.vulns?.[0]?.cvss_v3?.score?.toLowerCase() || 'medium',
              title: `Vulnerable Python package: ${vuln.name}`,
              description: `${vuln.name}==${vuln.version} has known vulnerabilities.\nIDs: ${(vuln.vulns || []).map(v => v.id).join(', ')}`,
              cwe: 'CWE-1104',
              cvss,
              target: dir,
              evidence: {
                package: vuln.name,
                version: vuln.version,
                vulnerabilities: vuln.vulns
              },
              remediation: `Update ${vuln.name}: pip install --upgrade ${vuln.name}`
            }));
          }
        } catch (e) {
          // JSON parse failed
        }
      }
      resolve(findings);
    });

    pip.on('error', () => resolve(findings));
  });
}

/**
 * Main scan function — detects package manager and runs appropriate audit
 * @param {Object} context
 * @param {Object} config
 * @returns {Promise<Array>}
 */
async function run(context, config) {
  const { targetDir } = context;
  if (!targetDir) return [];

  const findings = [];

  // Detect package manager from lockfile
  const lockfileNpm = path.join(targetDir, 'package-lock.json');
  const lockfilePip = path.join(targetDir, 'requirements.txt');

  const hasNpm = require('fs').existsSync(lockfileNpm);
  const hasPip = require('fs').existsSync(lockfilePip);

  if (hasNpm) {
    findings.push(...await runNpmAudit(targetDir));
  }

  if (hasPip) {
    findings.push(...await runPipAudit(targetDir));
  }

  // If no lockfiles found, try to detect from package.json
  if (!hasNpm && !hasPip) {
    const pkgJson = path.join(targetDir, 'package.json');
    if (require('fs').existsSync(pkgJson)) {
      findings.push(...await runNpmAudit(targetDir));
    }
  }

  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Scans dependencies for known CVEs via npm/pip audit', run, defaultTimeout: 90000 };
