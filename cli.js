#!/usr/bin/env node

/**
 * Sentinel Audit — CLI Entry Point
 * Usage: sentinel-audit scan --target <url|dir|host> [--format json|markdown] [--output path]
 */

const { program, Option } = require('commander');
const path = require('path');
const fs = require('fs-extra');
const chalk = require('chalk');

const { runScan } = require('./core/scanner-engine');
const { buildSummary, riskScore } = require('./core/findings');
const { loadScanners } = require('./core/scanner-engine');
const JsonReporter = require('./reporter/json-reporter');
const MarkdownReporter = require('./reporter/markdown-reporter');

// Load config
const CONFIG_PATH = path.join(__dirname, 'config', 'default.json');
let config = { scanners: {} };
try {
  config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
} catch {
  console.warn('[sentinel-audit] Warning: config/default.json not found, using defaults');
}

// Build version from package.json
let version = '1.0.0';
try {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, 'package.json'), 'utf8'));
  version = pkg.version;
} catch {}

// ─── Commands ────────────────────────────────────────────────────────────────

program
  .name('sentinel-audit')
  .description('Automated pre-penetration-test security audit tool')
  .version(version);

// scan command
program
  .command('scan')
  .description('Run a security audit scan')
  .requiredOption('-t, --target <value>', 'Scan target: URL, directory path, or host')
  .option('-d, --dir <path>', 'Directory to scan (for dependency/secrets scanners)')
  .option('-o, --output <path>', 'Output file path (default: ./output/<scanId>.<format>)')
  .option('-f, --format <type>', 'Output format: json or markdown (default: markdown)', 'markdown')
  .option('-s, --scopes <list>', 'Comma-separated scanner IDs to run (default: all)', null)
  .option('--no-color', 'Disable colored output')
  .option('--verbose', 'Show verbose scanner progress')
  .option('--min-severity <level>', 'Minimum severity to report: critical, high, medium, low, info', 'info')
  .action(async (opts) => {
    await runScanCommand(opts);
  });

// list command
program
  .command('list')
  .description('List all available scanners')
  .action(() => {
    const scanners = loadScanners();
    console.log(chalk.bold('\n🔍 Available Scanners:\n'));
    for (const [, scanner] of scanners) {
      const dot = scanner.defaultTimeout ? '' : '·';
      console.log(`  ${chalk.cyan(scanner.id.padEnd(16))} ${scanner.name}`);
      console.log(`  ${' '.repeat(20)}${scanner.description}\n`);
    }
    console.log(`Total: ${scanners.size} scanner${scanners.size !== 1 ? 's' : ''}\n`);
  });

// check command
program
  .command('check')
  .description('Check if Sentinel is properly installed')
  .action(() => {
    const scanners = loadScanners();
    const deps = ['npm', 'node'];
    console.log(chalk.bold('\n⚙️  Sentinel Audit Installation Check\n'));
    console.log(`  Node.js:  ${chalk.green('✓')} ${process.version}`);
    console.log(`  Scanners: ${chalk.green('✓')} ${scanners.size} loaded\n`);
    console.log('  Config:   ' + (fs.existsSync(CONFIG_PATH) ? chalk.green('✓') : chalk.red('✗')) + ' config/default.json\n');
  });

// ─── Scan Command Implementation ─────────────────────────────────────────────

async function runScanCommand(opts) {
  const { target, dir, output, format, scopes, noColor, verbose } = opts;

  // Validate target
  if (!target) {
    console.error(chalk.red('[sentinel-audit] Error: --target is required'));
    process.exit(1);
  }

  // Determine target type
  const targetType = target.startsWith('http') ? 'url' : fs.existsSync(target) ? 'directory' : 'host';

  // Resolve targetDir if --dir is provided
  const targetDir = dir || (targetType === 'directory' ? target : null);
  const targetUrl = targetType === 'url' ? target : null;

  console.log(chalk.bold('\n🦇 Sentinel Audit — Pre-Pen-Test Security Scanner\n'));
  console.log(`  Target:    ${chalk.cyan(target)}`);
  console.log(`  Type:      ${targetType}`);
  if (targetDir) console.log(`  Directory: ${chalk.cyan(targetDir)}`);
  if (scopes) console.log(`  Scopes:    ${chalk.cyan(scopes)}`);
  console.log(`  Format:    ${chalk.cyan(format)}`);
  console.log('');

  try {
    const result = await runScan({
      target,
      targetDir,
      targetUrl,
      scopes: scopes || null,
      config
    });

    // Filter by min severity
    const { filterByMinSeverity } = require('./core/findings');
    const filtered = filterByMinSeverity(result.findings, opts.minSeverity || 'info');
    result.findings = filtered;
    result.summary = buildSummary(filtered);

    // Print summary
    printSummary(result, noColor);

    // Generate output
    let outputPath;
    if (output) {
      outputPath = output;
    } else {
      const outDir = path.join(__dirname, 'output');
      fs.ensureDirSync(outDir);
      const ext = format === 'json' ? 'json' : 'md';
      outputPath = path.join(outDir, `${result.scanId}.${ext}`);
    }

    if (format === 'json') {
      const reporter = new JsonReporter();
      await reporter.write(result, outputPath);
    } else {
      const reporter = new MarkdownReporter();
      await reporter.write(result, outputPath);
    }

    console.log(chalk.green(`\n  Report: ${chalk.cyan(outputPath)}\n`));

    // Determine exit code based on severity thresholds
    const thresholds = config.thresholds || {};
    const critThresh = thresholds.critical || {};
    const highThresh = thresholds.high || {};

    if (result.summary.critical > 0 && critThresh.block) {
      console.log(chalk.red.bold('  ✖ CRITICAL findings detected — deploy BLOCKED\n'));
      process.exit(1);
    }
    if (result.summary.high > 0 && highThresh.block) {
      console.log(chalk.yellow.bold('  ⚠ HIGH findings detected — review required\n'));
      process.exit(1);
    }

    if (result.findings.length === 0) {
      console.log(chalk.green.bold('  ✓ No findings — target appears clean\n'));
      process.exit(0);
    }

    process.exit(0);

  } catch (err) {
    console.error(chalk.red(`\n[sentinel-audit] Scan failed: ${err.message}`));
    if (verbose) console.error(err.stack);
    process.exit(1);
  }
}

// ─── Console Summary ──────────────────────────────────────────────────────────

function printSummary(result, noColor) {
  const { summary, durationMs, riskScore: rs } = result;
  const pad = (s, n) => String(s).padStart(n);

  console.log(chalk.bold('  Scan Results:\n'));
  console.log(`  Duration: ${(durationMs / 1000).toFixed(1)}s`);
  console.log(`  Risk Score: ${rs}/100\n`);

  const levels = [
    ['critical', summary.critical, chalk.red],
    ['high',     summary.high,     chalk.yellow],
    ['medium',   summary.medium,   chalk.yellow],
    ['low',      summary.low,      chalk.green],
    ['info',     summary.info,      chalk.gray],
  ];

  let total = 0;
  for (const [level, count, colorFn] of levels) {
    if (count > 0) {
      const label = colorFn(`  ${count} ${level.toUpperCase()}`);
      console.log(`  ${label}`);
      total += count;
    }
  }
  console.log(`  ${chalk.bold('─'.repeat(36))}`);
  console.log(`  ${chalk.bold(`${total} total finding${total !== 1 ? 's' : ''}`)}`);
  console.log('');
}

program.parse(process.argv);
