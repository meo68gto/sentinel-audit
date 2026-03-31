/**
 * Sentinel Audit — Markdown Reporter
 * Outputs scan results as formatted Markdown
 */

const fs = require('fs-extra');
const path = require('path');
const chalk = require('chalk');

// Severity badges (no color for plain markdown)
const SEVERITY_BADGE = {
  critical: '[![CRITICAL](https://img.shields.io/badge/SEVERITY-CRITICAL-red)]',
  high:     '[![HIGH](https://img.shields.io/badge/SEVERITY-HIGH-orange)]',
  medium:   '[![MEDIUM](https://img.shields.io/badge/SEVERITY-MEDIUM-yellow)]',
  low:      '[![LOW](https://img.shields.io/badge/SEVERITY-LOW-green)]',
  info:     '[![INFO](https://img.shields.io/badge/SEVERITY-INFO-blue)]'
};

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info'];

function severityIndex(level) {
  return SEVERITY_ORDER.indexOf(level);
}

function escMd(str) {
  if (!str) return '';
  return String(str).replace(/[#*_`~]/g, '\\$&');
}

class MarkdownReporter {
  /**
   * Write scan result to a Markdown file
   * @param {Object} result - ScanResult
   * @param {string} outputPath
   */
  async write(result, outputPath) {
    await fs.ensureDir(path.dirname(outputPath));

    const lines = [];

    // Header
    lines.push(`# Sentinel Audit Report`);
    lines.push('');
    lines.push(`**Scan ID:** \`${result.scanId}\``);
    lines.push(`**Target:** ${result.target}`);
    lines.push(`**Type:** ${result.targetType}`);
    lines.push(`**Timestamp:** ${(result.completedAt || new Date()).toISOString()}`);
    lines.push(`**Duration:** ${(result.durationMs / 1000).toFixed(1)}s`);
    lines.push(`**Risk Score:** ${result.riskScore}/100`);
    lines.push('');

    // Executive Summary
    lines.push(`## Executive Summary`);
    lines.push('');
    lines.push(`| Severity | Count |`);
    lines.push(`|----------|-------|`);
    lines.push(`| 🔴 Critical | ${result.summary.critical} |`);
    lines.push(`| 🟠 High     | ${result.summary.high} |`);
    lines.push(`| 🟡 Medium   | ${result.summary.medium} |`);
    lines.push(`| 🟢 Low      | ${result.summary.low} |`);
    lines.push(`| 🔵 Info     | ${result.summary.info} |`);
    lines.push('');
    lines.push(`**Total Findings:** ${result.findings.length}`);
    lines.push('');

    // Risk interpretation
    const rs = result.riskScore;
    let riskLevel, riskAdvice;
    if (rs >= 50)      { riskLevel = '🔴 CRITICAL'; riskAdvice = 'Do not deploy. Remediate critical and high findings immediately.'; }
    else if (rs >= 25) { riskLevel = '🟠 HIGH';      riskAdvice = 'High risk. Block deployment until critical findings are resolved.'; }
    else if (rs >= 10) { riskLevel = '🟡 MEDIUM';   riskAdvice = 'Moderate risk. Address high-severity findings before deploying.'; }
    else if (rs >= 1)  { riskLevel = '🟢 LOW';       riskAdvice = 'Low risk. Fix findings in next sprint cycle.'; }
    else               { riskLevel = '✅ MINIMAL';    riskAdvice = 'No significant findings. Target appears secure.'; }

    lines.push(`**Risk Level:** ${riskLevel}`);
    lines.push(`**Advice:** ${riskAdvice}`);
    lines.push('');

    // Findings — grouped by severity
    lines.push(`---`);
    lines.push('');
    lines.push(`## Detailed Findings`);
    lines.push('');

    const sorted = [...result.findings].sort((a, b) => {
      return severityIndex(a.severity) - severityIndex(b.severity);
    });

    const bySeverity = {};
    for (const level of SEVERITY_ORDER) {
      bySeverity[level] = sorted.filter(f => f.severity === level);
    }

    for (const level of SEVERITY_ORDER) {
      const findings = bySeverity[level];
      if (findings.length === 0) continue;

      const emoji = { critical: '🔴', high: '🟠', medium: '🟡', low: '🟢', info: '🔵' }[level];
      lines.push(`### ${emoji} ${level.toUpperCase()} (${findings.length})`);
      lines.push('');

      for (const f of findings) {
        lines.push(`#### ${escMd(f.title)}`);
        lines.push('');
        lines.push(`| Field | Value |`);
        lines.push(`|-------|-------|`);
        lines.push(`| **ID** | \`${f.id}\` |`);
        lines.push(`| **Scanner** | ${f.scanner} |`);
        lines.push(`| **Severity** | ${level.toUpperCase()} |`);
        if (f.cwe) lines.push(`| **CWE** | ${f.cwe} |`);
        if (f.cvss) lines.push(`| **CVSS** | ${f.cvss} |`);
        if (f.target) lines.push(`| **Target** | ${escMd(f.target)} |`);
        if (f.filePath) lines.push(`| **File** | \`${escMd(f.filePath)}\` |`);
        if (f.lineNumber) lines.push(`| **Line** | ${f.lineNumber} |`);
        lines.push('');

        if (f.description) {
          lines.push(`**Description:**`);
          lines.push('');
          lines.push(`${escMd(f.description)}`);
          lines.push('');
        }

        if (f.evidence && Object.keys(f.evidence).length > 0) {
          lines.push(`**Evidence:**`);
          lines.push('');
          lines.push('```');
          lines.push(JSON.stringify(f.evidence, null, 2));
          lines.push('```');
          lines.push('');
        }

        if (f.remediation) {
          lines.push(`**Remediation:**`);
          lines.push('');
          lines.push(`${escMd(f.remediation)}`);
          lines.push('');
        }

        lines.push(`---`);
        lines.push('');
      }
    }

    // Scanner Results Summary
    lines.push('');
    lines.push(`## Scanner Execution Summary`);
    lines.push('');
    lines.push(`| Scanner | Status | Duration | Findings |`);
    lines.push(`|---------|--------|----------|----------|`);
    for (const sr of result.scannerResults) {
      const statusIcon = sr.status === 'complete' ? '✅' : sr.status === 'error' ? '❌' : '⏭';
      lines.push(`| ${sr.name} | ${statusIcon} ${sr.status} | ${(sr.durationMs / 1000).toFixed(1)}s | ${sr.findingCount} |`);
    }
    lines.push('');

    // Footer
    lines.push('---');
    lines.push('');
    lines.push(`*Generated by Sentinel Audit v1.0.0 — Batcave Security*`);
    lines.push(`*Report date: ${new Date().toISOString()}*`);

    await fs.writeFile(outputPath, lines.join('\n'), 'utf8');
  }
}

module.exports = MarkdownReporter;
