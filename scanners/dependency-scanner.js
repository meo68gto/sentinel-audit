/**
 * Sentinel Audit — Dependency CVE Scanner
 * Runs npm audit / pip audit against a target directory
 */

const { spawn } = require('child_process');
const { createFinding } = require('../core/findings');
const { normalizeSeverity, npmSeverityToLevel } = require('../core/severity');
const path = require('path');
const fs = require('fs');

const SCANNER_ID = 'dependency';
const SCANNER_NAME = 'Dependency CVE Scanner';

async function runNpmAudit(dir) {
  return new Promise((resolve) => {
    const findings = [];
    const npm = spawn('npm', ['audit', '--json'], { cwd: dir, timeout: 90000 });
    let stdout = '';
    npm.stdout.on('data', d => { stdout += d; });
    npm.on('close', () => {
      if (stdout) {
        try {
          const result = JSON.parse(stdout);
          const vulnerabilities = result.vulnerabilities || {};
          for (const [pkg, vuln] of Object.entries(vulnerabilities)) {
            const severity = npmSeverityToLevel(vuln.severity);
            const { cvss } = normalizeSeverity(severity);
            findings.push(createFinding({
              scanner: SCANNER_ID, severity, title: `Vulnerable npm package: ${pkg}`,
              description: `${vuln.title || 'Known vulnerability in ' + pkg}\nRange: ${vuln.range}`,
              cwe: 'CWE-1104', cvss, target: dir,
              evidence: { package: pkg, severity: vuln.severity, range: vuln.range },
              remediation: `Update ${pkg}: npm install ${pkg}@latest`
            }));
          }
        } catch {}
      }
      resolve(findings);
    });
    npm.on('error', () => resolve(findings));
  });
}

async function runPipAudit(dir) {
  return new Promise((resolve) => {
    const findings = [];
    const pip = spawn('pip', ['audit', '--json'], { cwd: dir, timeout: 90000 });
    let stdout = '';
    pip.stdout.on('data', d => { stdout += d; });
    pip.on('close', () => {
      if (stdout) {
        try {
          const result = JSON.parse(stdout);
          for (const vuln of (result.vulnerabilities || [])) {
            const sev = vuln.vulns?.[0]?.cvss_v3?.score?.toLowerCase() || 'medium';
            const { cvss } = normalizeSeverity(sev);
            findings.push(createFinding({
              scanner: SCANNER_ID, severity: sev, title: `Vulnerable Python package: ${vuln.name}`,
              description: `${vuln.name}==${vuln.version} has known vulnerabilities.\nIDs: ${(vuln.vulns || []).map(v => v.id).join(', ')}`,
              cwe: 'CWE-1104', cvss, target: dir,
              evidence: { package: vuln.name, version: vuln.version },
              remediation: `Update ${vuln.name}: pip install --upgrade ${vuln.name}`
            }));
          }
        } catch {}
      }
      resolve(findings);
    });
    pip.on('error', () => resolve(findings));
  });
}

async function run(context) {
  const { targetDir } = context;
  if (!targetDir) return [];
  const findings = [];
  const hasNpm = fs.existsSync(path.join(targetDir, 'package-lock.json'));
  const hasPip = fs.existsSync(path.join(targetDir, 'requirements.txt'));
  const hasPackageJson = fs.existsSync(path.join(targetDir, 'package.json'));
  if (hasNpm || hasPackageJson) findings.push(...await runNpmAudit(targetDir));
  if (hasPip) findings.push(...await runPipAudit(targetDir));
  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Scans dependencies for known CVEs via npm/pip audit', run, defaultTimeout: 90000 };
