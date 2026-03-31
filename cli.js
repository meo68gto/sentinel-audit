#!/usr/bin/env node

/**
 * Sentinel Audit — CLI Entry Point
 * Usage: sentinel-audit scan --target <url|dir> [--dir <local-codebase>] [--format json|markdown] [--output <path>]
 */

const { Command } = require('commander');
const path = require('path');
const fs = require('fs');

// Scanner modules
const dependencyScan = require('./scanners/dependency-scan');
const secretsScan = require('./scanners/secrets-scan');
const headersScan = require('./scanners/headers-scan');
const portsScan = require('./scanners/ports-scan');
const authScan = require('./scanners/auth-scan');
const sslScan = require('./scanners/ssl-scan');

// Reporter modules
const jsonReporter = require('./reporter/json-report');
const markdownReporter = require('./reporter/markdown-report');

// Config
const config = require('./config/default.json');

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

  console.log('\n🛡️  Sentinel Audit — Starting Scan');
  console.log(`   Target: ${target}`);
  console.log(`   Format: ${format}`);
  console.log(`   Local dir: ${localDir || 'none'}`);
  console.log('');

  // Resolve local dir to absolute
  let absLocalDir = null;
  if (localDir) {
    absLocalDir = path.resolve(localDir);
    if (!fs.existsSync(absLocalDir)) {
      console.error(`❌ Local directory does not exist: ${absLocalDir}`);
      process.exit(1);
    }
  }

  // Run all scanners in parallel
  const [
    headersResults,
    portsResults,
    authResults,
    sslResults,
    depResults,
    secretsResults,
  ] = await Promise.allSettled([
    headersScan.scan(target, config),
    portsScan.scan(target, config),
    authScan.scan(target, config),
    sslScan.scan(target, config),
    localDir ? dependencyScan.scan(absLocalDir, config) : Promise.resolve([]),
    localDir ? secretsScan.scan(absLocalDir, config) : Promise.resolve([]),
  ]);

  const allFindings = [];

  function collect(label, result) {
    if (result.status === 'fulfilled') {
      console.log(`✅ ${label}: ${result.value.length} finding(s)`);
      allFindings.push(...result.value);
    } else {
      console.error(`❌ ${label}: ${result.reason?.message || result.reason}`);
      allFindings.push({
        severity: 'HIGH',
        title: `${label} Scanner Error`,
        description: `Scanner failed: ${result.reason?.message || result.reason}`,
        remediation: 'Review scanner configuration and target accessibility.',
        cwe: 'N/A',
      });
    }
  }

  collect('Headers Scan', headersResults);
  collect('Ports Scan', portsResults);
  collect('Auth Scan', authResults);
  collect('SSL Scan', sslResults);
  if (localDir) {
    collect('Dependency Scan', depResults);
    collect('Secrets Scan', secretsResults);
  } else {
    console.log('⏭️  Dependency Scan: skipped (no --dir)');
    console.log('⏭️  Secrets Scan: skipped (no --dir)');
  }

  // Generate output path if not provided
  let finalOutputPath = outputPath;
  if (!finalOutputPath) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
    const ext = format === 'json' ? 'json' : 'md';
    finalOutputPath = path.join(OUTPUT_DIR, `sentinel-audit-${timestamp}.${ext}`);
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
    const report = jsonReporter.generate(params);
    console.log(`\n📄 JSON report written to: ${finalOutputPath}`);
    console.log(report);
  } else {
    const report = markdownReporter.generate(params);
    console.log(`\n📄 Markdown report written to: ${finalOutputPath}`);
    // Print a preview
    const lines = report.split('\n').slice(0, 30);
    console.log('\n--- Report Preview ---');
    console.log(lines.join('\n'));
    if (report.split('\n').length > 30) console.log('\n... (truncated)');
  }

  // Summary
  const summary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of allFindings) {
    const key = f.severity.toLowerCase();
    if (summary[key] !== undefined) summary[key]++;
  }

  console.log('\n📊 Scan Summary:');
  console.log(`   🔴 CRITICAL: ${summary.critical}`);
  console.log(`   🟠 HIGH:     ${summary.high}`);
  console.log(`   🟡 MEDIUM:   ${summary.medium}`);
  console.log(`   🔵 LOW:      ${summary.low}`);
  console.log(`   ⚪ INFO:     ${summary.info}`);
  console.log(`   Total:      ${allFindings.length}`);
  console.log('');

  if (summary.critical > 0) {
    console.error('⚠️  Critical findings detected! Review immediately.');
  } else if (summary.high > 0) {
    console.warn('⚠️  High severity findings detected. Prioritize remediation.');
  } else {
    console.log('✅ No critical or high severity findings.');
  }

  console.log(`\n🛡️  Scan complete. Report saved to: ${finalOutputPath}\n`);
}

program.parse(process.argv);
