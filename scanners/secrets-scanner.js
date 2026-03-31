/**
 * Sentinel Audit — Secrets Scanner
 * Detects hardcoded credentials, API keys, tokens, and secrets
 * in source code using gitleaks patterns + custom regex
 */

const { spawn } = require('child_process');
const { createFinding } = require('../core/findings');
const { normalizeSeverity } = require('../core/severity');
const path = require('path');
const fs = require('fs');

const SCANNER_ID = 'secrets';
const SCANNER_NAME = 'Secrets & Credential Scanner';

let findingCounter = 0;
function nextId() {
  findingCounter++;
  return `SENTINEL-SEC-${String(findingCounter).padStart(3, '0')}`;
}

// High-confidence secret patterns derived from gitleaks ruleset
const SECRET_PATTERNS = [
  { pattern: /(?i)(api[_-]?key|apikey)\s*[=:]\s*['"]?([a-z0-9_\-]{20,})['"]?/g, type: 'API Key', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /(?i)(aws[_-]?(access[_-]?key[_-]?id|secret[_-]?access[_-]?key))\s*[=:]\s*['"]?[A-Z0-9]{20,}['"]?/g, type: 'AWS Key', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /(?i)github[_\-]?(token|pat|personal[_\-]?access[_\-]?token)\s*[=:]\s*['"]?[a-z0-9_\-]{20,}['"]?/g, type: 'GitHub Token', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /(?i)(private[_\-]?key|priv[_\-]?key)\s*[=:]\s*['"]?-----BEGIN[ A-Z]+-----/g, type: 'Private Key', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /(?i)(stripe[_\-]?(api[_\-]?key|secret[_\-]?key))\s*[=:]\s*['"]?sk_[a-z0-9]{20,}/g, type: 'Stripe Key', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /(?i)(jwt|bearer|accesstoken|access[_\-]?token)\s*[=:]\s*['"]?[a-zA-Z0-9_\-\.]{20,}['"]?/g, type: 'Bearer Token', severity: 'high', cwe: 'CWE-347' },
  { pattern: /(?i)(slack[_\-]?token|slack[_\-]?webhook)\s*[=:]\s*['"]?[a-zA-Z0-9/\-]{20,}['"]?/g, type: 'Slack Token', severity: 'high', cwe: 'CWE-798' },
  { pattern: /(?i)(password|passwd|pwd)\s*[=:]\s*['"]?[a-zA-Z0-9_\-$!@#%]{6,}/g, type: 'Hardcoded Password', severity: 'critical', cwe: 'CWE-259' },
  { pattern: /(?i)(database|db[_\-]?conn|postgres|mysql|redis)\s*[=:]\s*['"]?[\w\-\.:\/@]{10,}['"]?/g, type: 'Database Connection String', severity: 'high', cwe: 'CWE-798' },
  { pattern: /(?i)twilio[_\-]?(api[_\-]?key|auth[_\-]?token)\s*[=:]\s*['"]?[a-z0-9]{20,}/g, type: 'Twilio Key', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /(?i)(sendgrid|mailgun|ses)[_\-]?(api[_\-]?key)\s*[=:]\s*['"]?[a-z0-9_\-]{10,}/g, type: 'Email Service Key', severity: 'high', cwe: 'CWE-798' },
  { pattern: /xox[baprs]-[0-9a-zA-Z]{10,}/g, type: 'Slack Token', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /sk_live_[a-zA-Z0-9]{20,}/g, type: 'Stripe Live Key', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /AKIA[0-9][A-Z0-9]{16}/g, type: 'AWS Access Key ID', severity: 'critical', cwe: 'CWE-798' },
];

/**
 * Scan a file for secret patterns
 * @param {string} filePath
 * @param {string} targetDir
 * @returns {Array}
 */
function scanFile(filePath, targetDir) {
  const findings = [];
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return findings;
  }

  for (const { pattern, type, severity, cwe } of SECRET_PATTERNS) {
    // Reset lastIndex each iteration
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(content)) !== null) {
      // Redact the actual secret value in the finding
      const raw = match[0];
      const redacted = raw.replace(/[a-zA-Z0-9_\-\.]{10,}$/, '***REDACTED***');
      const lineNum = content.slice(0, match.index).split('\n').length;

      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity,
        title: `Potential hardcoded secret: ${type}`,
        description: `Found ${type} pattern in source code. Secret must be rotated immediately and moved to environment variables or a secrets manager.`,
        cwe,
        target: targetDir,
        evidence: { file: filePath, line: lineNum, redactedMatch: redacted, pattern: type },
        filePath,
        lineNumber: lineNum,
        remediation: `Remove the hardcoded secret from source code. Use environment variables (process.env.SECRET_NAME) or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.`
      }));
    }
  }

  return findings;
}

/**
 * Recursively scan directory for source files
 * @param {string} dir
 * @param {string[]} extensions
 * @returns {string[]}
 */
function getSourceFiles(dir, extensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.rb', '.go', '.json', '.yaml', '.yml', '.env', '.sql']) {
  const files = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist' || entry.name === 'build' || entry.name === '__pycache__') continue;
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        files.push(...getSourceFiles(fullPath, extensions));
      } else if (extensions.some(ext => entry.name.endsWith(ext))) {
        files.push(fullPath);
      }
    }
  } catch {}
  return files;
}

/**
 * Try gitleaks if available, fall back to pattern scanning
 * @param {Object} context
 * @returns {Promise<Array>}
 */
async function runWithGitleaks(context) {
  return new Promise((resolve) => {
    const { targetDir } = context;
    const findings = [];
    const gitleaks = spawn('gitleaks', ['detect', '--source', targetDir, '--report-format', 'json', '--no-color'], { timeout: 120000 });

    let stdout = '';
    gitleaks.stdout.on('data', d => stdout += d);
    gitleaks.on('close', (code) => {
      if (stdout.trim()) {
        const lines = stdout.trim().split('\n');
        for (const line of lines) {
          try {
            const finding = JSON.parse(line);
            findings.push(createFinding({
              scanner: SCANNER_ID,
              severity: 'high',
              title: `Leaked secret detected: ${finding.RuleID || 'credential'}`,
              description: `Gitleaks detected a ${finding.RuleID || 'secret'} in ${finding.File || 'unknown file'}`,
              cwe: 'CWE-798',
              target: targetDir,
              evidence: { file: finding.File, line: finding.StartLine, secretType: finding.RuleID },
              filePath: finding.File,
              lineNumber: finding.StartLine,
              remediation: 'Rotate the exposed credential immediately. Remove from git history with git-filter-repo or BFG Repo-Cleaner.'
            }));
          } catch {}
        }
      }
      resolve(findings);
    });

    gitleaks.on('error', () => resolve([]));
  });
}

/**
 * Main scan function
 * @param {Object} context
 * @param {Object} config
 * @returns {Promise<Array>}
 */
async function run(context, config) {
  const { targetDir } = context;
  if (!targetDir) return [];

  // Try gitleaks first (preferred, scans git history)
  let findings = await runWithGitleaks(context);

  // Also run pattern scan on current files (catches things gitleaks might miss in unstaged)
  const files = getSourceFiles(targetDir);
  for (const file of files) {
    findings.push(...scanFile(file, targetDir));
  }

  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Detects hardcoded credentials, API keys, and tokens via gitleaks and regex patterns', run, defaultTimeout: 120000 };
