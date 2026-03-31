/**
 * Sentinel Audit — Secrets Scanner
 * Detects hardcoded credentials, API keys, tokens via gitleaks + regex patterns
 */

const { spawn } = require('child_process');
const { createFinding } = require('../core/findings');
const path = require('path');
const fs = require('fs');

const SCANNER_ID = 'secrets';
const SCANNER_ID_FULL = 'Secrets & Credential Scanner';

const SECRET_PATTERNS = [
  { pattern: /\bAKIA[0-9][A-Z0-9]{16}\b/g, type: 'AWS Access Key ID', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /\b(gho_|ghp_|github_pat_)[a-zA-Z0-9_]{20,}\b/g, type: 'GitHub Personal Access Token', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /\b(sk_live_|pk_live_)[a-zA-Z0-9]{20,}\b/g, type: 'Stripe Live Key', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /\bxox[baprs]-[a-zA-Z0-9]{10,}\b/g, type: 'Slack Token', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /\b(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\b/g, type: 'JWT Token', severity: 'high', cwe: 'CWE-347' },
  { pattern: /\b((postgres|mysql|mongodb|redis|mssql):\/\/[^\s'"]+)/gi, type: 'Database Connection String', severity: 'high', cwe: 'CWE-798' },
  { pattern: /-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----/g, type: 'Private Key Header', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[=:]\s*['"][a-zA-Z0-9_\-$!@#%]{8,}['"]/g, type: 'Hardcoded Password', severity: 'critical', cwe: 'CWE-259' },
  { pattern: /\bSG\.[a-zA-Z0-9_\-.]{30,}\b/g, type: 'SendGrid API Key', severity: 'critical', cwe: 'CWE-798' },
  { pattern: /[Ss][Ee][Cc][Rr][Ee][Tt]\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]/g, type: 'Potential Secret Token', severity: 'high', cwe: 'CWE-798' },
  { pattern: /[Bb][Ee][Aa][Rr][Ee][Rr]\s+[Tt][Oo][Kk][Ee][Nn]\s*[=:]\s*['"][a-zA-Z0-9_\-.]{20,}['"]/g, type: 'Bearer Token', severity: 'high', cwe: 'CWE-347' },
  { pattern: /[Aa][Pp][Ii][_\s-]?[Kk][Ee][Yy]\s*[=:]\s*['"][a-zA-Z0-9_\-]{20,}['"]/g, type: 'Potential API Key', severity: 'high', cwe: 'CWE-798' },
];

function scanFile(filePath, targetDir) {
  const findings = [];
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); } catch { return findings; }
  if (content.length > 5 * 1024 * 1024) return findings;
  const skipExtensions = ['.min.js', '.map', '.lock'];
  if (skipExtensions.some(ext => filePath.endsWith(ext))) return findings;
  const skipDirs = ['node_modules', '.git', 'dist', 'build', 'coverage', '__pycache__', '.next'];
  if (skipDirs.some(d => filePath.includes(path.sep + d + path.sep))) return findings;
  for (const { pattern, type, severity, cwe } of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const lineNum = content.slice(0, match.index).split('\n').length;
      findings.push(createFinding({
        scanner: SCANNER_ID, severity, title: `Potential hardcoded secret: ${type}`,
        description: `Detected a ${type} pattern in source code at line ${lineNum}.`,
        cwe, target: targetDir,
        evidence: { file: path.relative(targetDir, filePath), line: lineNum, type },
        filePath: path.relative(targetDir, filePath), lineNumber: lineNum,
        remediation: `Remove the hardcoded secret. Use environment variables (process.env.SECRET_NAME) or a secrets manager. Rotate exposed credentials.`
      }));
      if (pattern.lastIndex === match.index) pattern.lastIndex++;
    }
  }
  return findings;
}

function getSourceFiles(dir, extensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.rb', '.go', '.json', '.yaml', '.yml', '.env', '.sql']) {
  const files = [];
  try {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const n = entry.name;
      if (n === 'node_modules' || n === '.git' || n === 'dist' || n === 'build' || n === '__pycache__' || n === '.next') continue;
      const fp = path.join(dir, n);
      if (entry.isDirectory()) files.push(...getSourceFiles(fp, extensions));
      else if (extensions.some(ext => n.endsWith(ext))) files.push(fp);
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
                description: `Gitleaks detected ${f.RuleID || 'secret'} in ${f.File || 'unknown file'}`,
                cwe: 'CWE-798', target: targetDir,
                evidence: { file: f.File, line: f.StartLine, ruleId: f.RuleID },
                filePath: f.File, lineNumber: f.StartLine,
                remediation: 'Rotate the exposed credential immediately. Remove from git history with git-filter-repo.'
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

module.exports = { id: SCANNER_ID, name: SCANNER_ID_FULL, description: 'Detects hardcoded credentials, API keys, and tokens via gitleaks and regex patterns', run, defaultTimeout: 120000 };
