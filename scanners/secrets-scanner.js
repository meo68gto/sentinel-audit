/**
 * Sentinel Audit — Secrets Scanner
 * Detects hardcoded credentials, API keys, tokens via regex patterns
 */

const { spawn } = require('child_process');
const { createFinding } = require('../core/findings');
const path = require('path');
const fs = require('fs');

const SCANNER_ID = 'secrets';
const SCANNER_NAME = 'Secrets & Credential Scanner';

// All patterns use [Aa] instead of (?i) — JavaScript does not support inline (?i)
const SECRET_PATTERNS = [
  // AWS Access Key ID
  { pattern: /\bAKIA[0-9][A-Z0-9]{16}\b/g, type: 'AWS Access Key ID', severity: 'critical', cwe: 'CWE-798' },
  // GitHub Personal Access Token
  { pattern: /\b(gho_|ghp_|github_pat_)[a-zA-Z0-9_]{20,}\b/g, type: 'GitHub PAT', severity: 'critical', cwe: 'CWE-798' },
  // Stripe Live Key
  { pattern: /\b(sk_live_|pk_live_)[a-zA-Z0-9]{20,}\b/g, type: 'Stripe Key', severity: 'critical', cwe: 'CWE-798' },
  // Slack Token
  { pattern: /\bxox[baprs]-[a-zA-Z0-9]{10,}\b/g, type: 'Slack Token', severity: 'critical', cwe: 'CWE-798' },
  // JWT Token (eyJ...)
  { pattern: /\b(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b/g, type: 'JWT Token', severity: 'high', cwe: 'CWE-347' },
  // Database connection string
  { pattern: /\b((postgres|mysql|mongodb|redis|mssql):\/\/[^\s'"]+)/gi, type: 'Database Connection String', severity: 'high', cwe: 'CWE-798' },
  // Private key header
  { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g, type: 'Private Key', severity: 'critical', cwe: 'CWE-798' },
  // Hardcoded password assignment
  { pattern: /[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[=:]\s*['"][a-zA-Z0-9_\-$!@#%]{8,}['"]/g, type: 'Hardcoded Password', severity: 'critical', cwe: 'CWE-259' },
  // SendGrid API key
  { pattern: /\bSG\.[a-zA-Z0-9_\-.]{30,}\b/g, type: 'SendGrid Key', severity: 'critical', cwe: 'CWE-798' },
  // Bearer token assignment
  { pattern: /[Bb][Ee][Aa][Rr][Ee][Rr]\s+[Tt][Oo][Kk][Ee][Nn]\s*[=:]\s*['"][a-zA-Z0-9_\-.]{20,}['"]/g, type: 'Bearer Token', severity: 'high', cwe: 'CWE-347' },
  // Secret token assignment
  { pattern: /[Ss][Ee][Cc][Rr][Ee][Tt]\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]/g, type: 'Secret Token', severity: 'high', cwe: 'CWE-798' },
  // Generic API key
  { pattern: /[Aa][Pp][Ii][_\s-]?[Kk][Ee][Yy]\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]/g, type: 'API Key', severity: 'high', cwe: 'CWE-798' },
];

function scanFile(filePath, targetDir) {
  const findings = [];
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); } catch { return findings; }
  if (content.length > 5 * 1024 * 1024) return findings;
  if (/\.(min|map)\.js$|\.lock$/.test(filePath)) return findings;
  const skipDirs = ['node_modules', '.git', 'dist', 'build', 'coverage', '__pycache__', '.next'];
  if (skipDirs.some(d => filePath.includes(path.sep + d + path.sep))) return findings;
  for (const { pattern, type, severity, cwe } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const lineNum = content.slice(0, match.index).split('\n').length;
      findings.push(createFinding({
        scanner: SCANNER_ID, severity, title: `Hardcoded secret: ${type}`,
        description: `Detected a ${type} pattern in source code at line ${lineNum}.`,
        cwe, target: targetDir,
        evidence: { file: path.relative(targetDir, filePath), line: lineNum, type },
        filePath: path.relative(targetDir, filePath), lineNumber: lineNum,
        remediation: `Remove the hardcoded secret. Use environment variables or a secrets manager. Rotate the credential.`
      }));
      if (pattern.lastIndex === match.index) pattern.lastIndex++;
    }
  }
  return findings;
}

function getSourceFiles(dir) {
  const files = [];
  const exts = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.rb', '.go', '.json', '.yaml', '.yml', '.env', '.sql'];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const n = entry.name;
      if (['node_modules', '.git', 'dist', 'build', '__pycache__', '.next'].includes(n)) continue;
      const fp = path.join(dir, n);
      if (entry.isDirectory()) files.push(...getSourceFiles(fp));
      else if (exts.some(ext => n.endsWith(ext))) files.push(fp);
    }
  } catch {}
  return files;
}

async function runWithGitleaks(context) {
  return new Promise((resolve) => {
    const { targetDir } = context;
    const findings = [];
    try {
      const gl = spawn('gitleaks', ['detect', '--source', targetDir, '--report-format', 'json', '--no-color'], { timeout: 120000 });
      let stdout = '';
      gl.stdout.on('data', d => { stdout += d; });
      gl.on('close', () => {
        if (stdout.trim()) {
          for (const line of stdout.trim().split('\n')) {
            try {
              const f = JSON.parse(line);
              findings.push(createFinding({
                scanner: SCANNER_ID, severity: 'high', title: `Leaked secret: ${f.RuleID || 'credential'}`,
                description: `Gitleaks detected ${f.RuleID || 'secret'} in ${f.File || 'file'}`,
                cwe: 'CWE-798', target: targetDir,
                evidence: { file: f.File, line: f.StartLine, ruleId: f.RuleID },
                filePath: f.File, lineNumber: f.StartLine,
                remediation: 'Rotate credential immediately. Remove from git history with git-filter-repo.'
              }));
            } catch {}
          }
        }
        resolve(findings);
      });
      gl.on('error', () => resolve([]));
    } catch { resolve([]); }
  });
}

async function run(context) {
  const { targetDir } = context;
  if (!targetDir) return [];
  let findings = await runWithGitleaks(context);
  for (const file of getSourceFiles(targetDir)) findings.push(...scanFile(file, targetDir));
  return findings;
}

module.exports = { id: SCANNER_ID, name: SCANNER_NAME, description: 'Detects hardcoded credentials, API keys, and tokens via gitleaks and regex patterns', run, defaultTimeout: 120000 };
