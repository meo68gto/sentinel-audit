/**
 * Sentinel Audit — Secrets Scanner
 * Scans a local codebase for leaked secrets using gitleaks-style regex patterns.
 */

const fs = require('fs');
const path = require('path');

// Gitleaks-inspired regex patterns for common secret types
const SECRET_PATTERNS = [
  { name: 'AWS Access Key ID', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'AWS Secret Access Key', pattern: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Generic API Key', pattern: /(?i)(api[_-]?key|apikey)\s*[:=]\s*["']?[A-Za-z0-9_\-]{20,}["']?/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Private Key', pattern: /-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'GitHub Token', pattern: /ghp_[A-Za-z0-9]{36}/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'GitHub OAuth Token', pattern: /gho_[A-Za-z0-9]{36}/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'GitHub PAT', pattern: /github_pat_[A-Za-z0-9_]{22,}/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Slack Token', pattern: /xox[baprs]-[0-9]{10,13}-[0-9]{10,13}[A-Za-z0-9-]*/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Stripe Secret Key', pattern: /sk_live_[A-Za-z0-9]{24,}/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Stripe Publishable Key', pattern: /pk_live_[A-Za-z0-9]{24,}/g, severity: 'MEDIUM', cwe: 'CWE-798' },
  { name: 'Database Connection String', pattern: /(?i)(mysql|postgres|postgresql|mongodb|redis):\/\/[^\s'"`]{10,}/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'JWT Token', pattern: /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*/g, severity: 'HIGH', cwe: 'CWE-345' },
  { name: 'Hardcoded Password', pattern: /(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']/g, severity: 'HIGH', cwe: 'CWE-259' },
  { name: 'Hardcoded Secret', pattern: /(?i)(secret|token|auth)\s*[:=]\s*["'][A-Za-z0-9_\-]{10,}["']/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Twilio API Key', pattern: /SK[a-f0-9]{32}/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'Google API Key', pattern: /AIza[0-9A-Za-z_-]{35}/g, severity: 'HIGH', cwe: 'CWE-798' },
  { name: 'SendGrid API Key', pattern: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Discord Token', pattern: /[A-Za-z0-9]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}/g, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'PayPal Access Token', pattern: /access_token\$[A-Za-z0-9_-]+/, severity: 'CRITICAL', cwe: 'CWE-798' },
  { name: 'Basic Auth in URL', pattern: /https?:\/\/[^\s@]+:[^\s@]+@[^\s@]+/g, severity: 'HIGH', cwe: 'CWE-798' },
];

// Patterns for files/directories to skip
const SKIP_PATTERNS = [
  /node_modules/,
  /\.git\//,
  /\.DS_Store/,
  /dist\//,
  /build\//,
  /\.min\.(js|css)/,
  /package-lock\.json/,
  /yarn\.lock/,
  /pnpm-lock\.yaml/,
  /\.png|\.jpg|\.gif|\.ico|\.woff2?|\.ttf|\.eot/,
  /\.env\.example/,
  /\.md/,
];

const MAX_FILE_SIZE = 1024 * 1024; // 1MB

/**
 * Recursively collect all files in a directory, skipping node_modules etc.
 */
function collectFiles(dir, files = []) {
  if (!fs.existsSync(dir)) return files;
  const entries = fs.readdirSync(dir, { withFileTypes: true });
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      const shouldSkip = SKIP_PATTERNS.some((re) => re.test(fullPath));
      if (!shouldSkip) collectFiles(fullPath, files);
    } else {
      const shouldSkip = SKIP_PATTERNS.some((re) => re.test(fullPath));
      if (!shouldSkip) files.push(fullPath);
    }
  }
  return files;
}

/**
 * Scan a local codebase for secrets.
 * @param {string} targetDir - Absolute path to scan
 * @param {object} config - Scanner config
 * @returns {Promise<Array>} Array of finding objects
 */
async function scan(targetDir, config) {
  const findings = [];

  if (!targetDir || !fs.existsSync(targetDir)) {
    findings.push({
      severity: 'INFO',
      title: 'Secrets Scan Skipped',
      description: `Target directory "${targetDir}" does not exist.`,
      remediation: 'Provide a valid local directory path to scan for secrets.',
      cwe: 'N/A',
    });
    return findings;
  }

  const files = collectFiles(targetDir);
  if (files.length === 0) {
    findings.push({
      severity: 'INFO',
      title: 'No Files to Scan',
      description: 'No scannable files found in target directory.',
      remediation: 'Ensure the target directory contains source code files.',
      cwe: 'N/A',
    });
    return findings;
  }

  let filesScanned = 0;
  let secretsFound = 0;

  for (const filePath of files) {
    let content;
    try {
      const stat = fs.statSync(filePath);
      if (stat.size > MAX_FILE_SIZE) continue;
      content = fs.readFileSync(filePath, 'utf-8');
    } catch {
      continue;
    }

    filesScanned++;

    for (const rule of SECRET_PATTERNS) {
      rule.pattern.lastIndex = 0;
      let match;
      while ((match = rule.pattern.exec(content)) !== null) {
        secretsFound++;
        const lineNumber = content.substring(0, match.index).split('\n').length;
        const relPath = path.relative(targetDir, filePath);
        findings.push({
          severity: rule.severity,
          title: `Potential Secret Detected: ${rule.name}`,
          description: `Found ${rule.name} pattern in \`${relPath}\` (line ~${lineNumber}). Secret: \`${match[0].substring(0, 30)}...\``,
          remediation: `Remove or externalize the ${rule.name}. Use environment variables or a secrets manager (AWS Secrets Manager, HashiCorp Vault).`,
          cwe: rule.cwe,
        });
      }
    }
  }

  if (secretsFound === 0) {
    findings.push({
      severity: 'INFO',
      title: 'No Secrets Detected',
      description: `Scanned ${filesScanned} files — no gitleaks-pattern secrets found.`,
      remediation: 'Continue using a secrets manager and rotating credentials regularly.',
      cwe: 'N/A',
    });
  }

  return findings;
}

module.exports = { scan };
