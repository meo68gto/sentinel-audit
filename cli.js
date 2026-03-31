#!/usr/bin/env node

/**
 * Sentinel Audit — CLI Entry Point
 * Usage: sentinel-audit scan --target <url|dir|host> [--dir <local-codebase>] [--format json|markdown] [--output <path>]
 */

const { Command } = require('commander');
const path = require('path');
const fs = require('fs');

// Scanner modules
const dependencyScanner = require('./scanners/dependency-scanner');
const secretsScanner = require('./scanners/secrets-scanner');
const headersScanner = require('./scanners/headers-scan');
const portsScanner = require('./scanners/ports-scan');
const authScanner = require('./scanners/auth-scan');
const sslScanner = require('./scanners/ssl-scan');

// Reporter modules
const { generate: generateJson } = require('./reporter/json-reporter');
const { generate: generateMarkdown } = require('./reporter/markdown-reporter');

// Output dir
const OUTPUT_DIR = path.join(__dirname, 'output');

const program = new Command();

program
  .name('sentinel-audit')
  .description('CLI pre-penetration-test security audit tool')
  .version('1.0.0');

program
  .command('scan')
  .description('Run a security audit scan against a target')
  .requiredOption('--target <value>', 'Target URL or hostname (required)')
  .option('--dir <path>', 'Local codebase directory (for dependency and secrets scanning)')
  .option('--format <format>', 'Output format: json or markdown (default: markdown)')
  .option('--output <path>', 'Output file path (default: output/<timestamp>.<format>)')
  .action(async (opts) => {
    await runScan(opts);
  });

/**
 * Run all scanners in parallel and aggregate findings.
 */
async function runScan(opts) {
  const target = opts.target;
  const format = opts.format || 'markdown';
  const localDir = opts.dir || null;
  const outputPath = opts.output || null;

  console.log('\n  Sentinel Audit  Pre-Pen-Test Security Scanner');
  console.log('  ' + '='.repeat(50));
  console.log('  Target:   ' + target);
  console.log('  Format:   ' + format);
  console.log('  Local:    ' + (localDir || 'none'));
  console.log('');

  // Resolve local dir to absolute
  let absLocalDir = null;
  if (localDir) {
    absLocalDir = path.resolve(localDir);
    if (!fs.existsSync(absLocalDir)) {
      console.error('  [ERROR] Local directory does not exist: ' + absLocalDir);
      process.exit(1);
    }
  }

  // Run all scanners in parallel
  const [
    headersResult,
    portsResult,
    authResult,
    sslResult,
    depResult,
    secretsResult,
  ] = await Promise.allSettled([
    headersScanner.scan(target, {}),
    portsScanner.scan(target, {}),
    authScanner.scan(target, {}),
    sslScanner.scan(target, {}),
    localDir ? dependencyScanner.scan(absLocalDir, {}) : Promise.resolve([]),
    localDir ? secretsScanner.scan(absLocalDir, {}) : Promise.resolve([]),
  ]);

  const allFindings = [];

  function collect(label, result) {
    if (result.status === 'fulfilled') {
      const count = result.value.length;
      console.log('  [OK]   ' + label + ': ' + count + ' finding(s)');
      allFindings.push(...result.value);
    } else {
      console.error('  [ERR]  ' + label + ': ' + (result.reason?.message || result.reason));
      allFindings.push({
        severity: 'HIGH',
        title: label + ' Error',
        description: 'Scanner failed: ' + (result.reason?.message || result.reason),
        remediation: 'Review scanner configuration and target accessibility.',
        cwe: 'N/A',
      });
    }
  }

  collect('Headers Scan', headersResult);
  collect('Ports Scan', portsResult);
  collect('Auth Scan', authResult);
  collect('SSL Scan', sslResult);
  if (localDir) {
    collect('Dependency Scan', depResult);
    collect('Secrets Scan', secretsResult);
  } else {
    console.log('  [--]   Dependency Scan: skipped (no --dir)');
    console.log('  [--]   Secrets Scan: skipped (no --dir)');
  }

  // Generate output path if not provided
  let finalOutputPath = outputPath;
  if (!finalOutputPath) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const ext = format === 'json' ? 'json' : 'md';
    finalOutputPath = path.join(OUTPUT_DIR, 'sentinel-audit-' + timestamp + '.' + ext);
  }

  // Ensure output directory exists
  const outDir = path.dirname(finalOutputPath);
  if (!fs.existsSync(outDir)) fs.mkdirSync(outDir, { recursive: true });

  // Generate report
  const params = {
    target,
    findings: allFindings,
    scanDate: new Date(),
    outputPath: finalOutputPath,
  };

  if (format === 'json') {
    const report = generateJson(params);
    console.log('\n  Report written to: ' + finalOutputPath);
    console.log(report);
  } else {
    const report = generateMarkdown(params);
    fs.writeFileSync(finalOutputPath, report, 'utf-8');
    console.log('\n  Report written to: ' + finalOutputPath);
    // Print summary
    const summary = summarize(allFindings);
    console.log('\n  Summary:');
    console.log('    CRITICAL: ' + summary.critical);
    console.log('    HIGH:     ' + summary.high);
    console.log('    MEDIUM:   ' + summary.medium);
    console.log('    LOW:      ' + summary.low);
    console.log('    INFO:     ' + summary.info);
    console.log('    Total:    ' + allFindings.length);
    if (summary.critical > 0) {
      console.log('\n  [!] Critical findings detected -- review immediately.');
    } else if (summary.high > 0) {
      console.log('\n  [!] High severity findings -- prioritize remediation.');
    } else {
      console.log('\n  [OK] No critical or high severity findings.');
    }
  }
  console.log('');
}

function summarize(findings) {
  const s = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const k = f.severity.toLowerCase();
    if (s[k] !== undefined) s[k]++;
  }
  return s;
}

program.parse(process.argv);
