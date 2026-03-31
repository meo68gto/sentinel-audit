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

/**
 * High-confidence secret patterns.
 * All use explicit character ranges [Aa] instead of (?i) flag (Python syntax not supported in JS).
 * Patterns designed for low false-positive rate.
 */
const SECRET_PATTERNS = [
  // AWS Access Key ID (starts with AKIA, very distinctive)
  {
    pattern: /\bAKIA[0-9][A-Z0-9]{16}\b/g,
    type: 'AWS Access Key ID',
    severity: 'critical',
    cwe: 'CWE-798'
  },
  // AWS Secret Access Key (40-char alphanumeric, after AWS_SECRET_ACCESS_KEY or similar)
  {
    pattern: /\b[A-Za-z0-9/+=]{40}\b/g,
    type: 'Potential AWS Secret Key',
    severity: 'high',
    cwe: 'CWE-798'
  },
  // GitHub Personal Access Token
  {
    pattern: /\b(gho_|ghp_|github_pat_)[a-zA-Z0-9_]{20,}\b/g,
    type: 'GitHub Personal Access Token',
    severity: 'critical',
    cwe: 'CWE-798'
  },
  // Stripe keys (sk_live_, pk_live_)
  {
    pattern: /\b(sk_live_|pk_live_)[a-zA-Z0-9]{20,}\b/g,
    type: 'Stripe Live Key',
    severity: 'critical',
    cwe: 'CWE-798'
  },
  // Slack tokens (xox[baprs]-...)
  {
    pattern: /\bxox[baprs]-[a-zA-Z0-9]{10,}\b/g,
    type: 'Slack Token',
    severity: 'critical',
    cwe: 'CWE-798'
  },
  // Generic API key pattern (api_key = 'xxx' or apiKey: "xxx" where xxx is 20+ chars)
  {
    pattern: /[Aa][Pp][Ii][_\s-]?[Kk][Ee][Yy]\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]/g,
    type: 'Potential API Key',
    severity: 'high',
    cwe: 'CWE-798'
  },
  // Private key header
  {
    pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g,
    type: 'Private Key Header',
    severity: 'critical',
    cwe: 'CWE-798'
  },
  // JWT / Bearer token in header/assignment (eyJ... format)
  {
    pattern: /\b(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b/g,
    type: 'JWT Token',
    severity: 'high',
    cwe: 'CWE-347'
  },
  // Database connection string (postgres://, mysql://, mongodb://, redis://)
  {
    pattern: /\b((postgres|mysql|mongodb|redis|mssql):\/\/[^\s'"]+)/gi,
    type: 'Database Connection String',
    severity: 'high',
    cwe: 'CWE-798'
  },
  // Password assignment: password = '...' or "..." with 8+ chars
  {
    pattern: /[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[=:]\s*['"][a-zA-Z0-9_\-$!@#%]{8,}['"]/g,
    type: 'Hardcoded Password',
    severity: 'critical',
    cwe: 'CWE-259'
  },
  // Twilio API key
  {
    pattern: /\b[a-zA-Z0-9]{30,}\b/g,
    type: 'Potential Twilio Key',
    severity: 'high',
    cwe: 'CWE-798'
  },
  // SendGrid / Mailgun / generic email service key
  {
    pattern: /\bSG\.[a-zA-Z0-9_\-.]{30,}\b/g,
    type: 'SendGrid API Key',
    severity: 'critical',
    cwe: 'CWE-798'
  },
  // Generic long secret string in assignment (secret = 'xxx' or token: 'xxx')
  {
    pattern: /[Ss][Ee][Cc][Rr][Ee][Tt]\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]/g,
    type: 'Potential Secret Token',
    severity: 'high',
    cwe: 'CWE-798'
  },
  // Bearer token assignment
  {
    pattern: /[Bb][Ee][Aa][Rr][Ee][Rr]\s+[Tt][Oo][Kk][Ee][Nn]\s*[=:]\s*['"][a-zA-Z0-9_\-.]{20,}['"]/g,
    type: 'Bearer Token',
    severity: 'high',
    cwe: 'CWE-347'
  },
];

/**
 * Scan a single file for secret patterns
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

  // Skip binary/large files
  if (content.length > 5 * 1024 * 1024) return findings;

  // Skip common false-positive files
  const skipExtensions = ['.min.js', '.map', '.lock'];
  if (skipExtensions.some(ext => filePath.endsWith(ext))) return findings;
  const skipDirs = ['node_modules', '.git', 'dist', 'build', 'coverage', '__pycache__'];
  if (skipDirs.some(d => filePath.includes(path.sep + d + path.sep))) return findings;

  for (const { pattern, type, severity, cwe } of SECRET_PATTERNS) {
    // Reset lastIndex for each file (required for /g flag)
    pattern.lastIndex = 0;

    // Use matchAll for reliable global matching
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const raw = match[0];
      // Calculate line number
      const lineNum = content.slice(0, match.index).split('\n').length;

      findings.push(createFinding({
        scanner: SCANNER_ID,
        severity,
        title: `Potential hardcoded secret: ${type}`,
        description: `Detected a ${type} pattern in source code at line ${lineNum}. Secret must be rotated immediately and moved to environment variables.`,
        cwe,
        target: targetDir,
        evidence: { file: path.relative(targetDir, filePath), line: lineNum, type },
        filePath: path.relative(targetDir, filePath),
        lineNumber: lineNum,
        remediation: `Remove the hardcoded secret from source code. Use environment variables (process.env.SECRET_NAME) or a secrets manager (AWS Secrets Manager, HashiCorp Vault). Rotate the exposed credential immediately.`
      }));

      // Safety: break if lastIndex isn't advancing (stuck pattern)
      if (pattern.lastIndex === match.index) {
        pattern.lastIndex++;
      }
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
      const entryName = entry.name;
      if (entryName === 'node_modules' || entryName === '.git' || entryName === 'dist' || entryName === 'build' || entryName === '__pycache__' || entryName === '.next') continue;
      const fullPath = path.join(dir, entryName);
      if (entry.isDirectory()) {
        files.push(...getSourceFiles(fullPath, extensions));
      } else if (extensions.some(ext => entryName.endsWith(ext))) {
        files.push(fullPath);
      }
    }
  } catch {}
  return files;
}

/**
 * Run gitleaks if available (preferred — scans full git history)
 * Falls back to pattern scan if gitleaks is not installed
 * @param {Object} context
 * @returns {Promise<Array>}
 */
async function runWithGitleaks(context) {
  return new Promise((resolve) => {
    const { targetDir } = context;
    const findings = [];

    try {
      const gitleaks = spawn('gitleaks', ['detect', '--source', targetDir, '--report-format', 'json', '--no-color'], { timeout: 120000 });

      let stdout = '';
      gitleaks.stdout.on('data', d => { stdout += d; });
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
                evidence: { file: finding.File, line: finding.StartLine, ruleId: finding.RuleID },
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
    } catch {
      resolve([]);
    }
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

  // Try gitleaks first (preferred, scans git history including all branches)
  let findings = await runWithGitleaks(context);

  // Also run pattern scan on current files (catches things gitleaks might miss in unstaged)
  const files = getSourceFiles(targetDir);
  for (const file of files) {
    findings.push(...scanFile(file, targetDir));
  }

  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Detects hardcoded credentials, API keys, and tokens via gitleaks and regex patterns', run, defaultTimeout: 120000 };
