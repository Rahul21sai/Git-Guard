#!/usr/bin/env node
'use strict';

/**
 * GitGuard CLI entry point
 * Usage:
 *   gitguard scan [path]
 *   gitguard fix
 *   gitguard install
 */

const path = require('path');
const fs   = require('fs');

const args    = process.argv.slice(2);
const command = args[0];

function printHelp() {
  console.log(`
  GitGuard — Prevent API keys and secrets from reaching GitHub

  Usage:
    gitguard scan [path]   Scan a file or directory for secrets
    gitguard fix           Launch the remediation wizard
    gitguard install       Install the pre-push Git hook globally

  Options:
    --help, -h             Show this help
    --version, -v          Show version
  `);
}

function printVersion() {
  const pkg = path.join(__dirname, '..', 'package.json');
  const { version } = JSON.parse(fs.readFileSync(pkg, 'utf8'));
  console.log(`gitguard v${version}`);
}

switch (command) {
  case 'scan': {
    const { scanFile, scanDiff, loadAllowlist, loadConfig } = require('./scan');
    const chalk = requireChalk();
    const target = args[1] || process.cwd();
    const allowlist = loadAllowlist();
    const config    = loadConfig();
    const opts = buildOpts(config, allowlist);

    let findings = [];
    if (fs.existsSync(target) && fs.statSync(target).isFile()) {
      findings = scanFile(target, opts);
    } else if (fs.existsSync(target) && fs.statSync(target).isDirectory()) {
      findings = scanDirectory(target, opts);
    } else {
      console.error(chalk.red(`Path not found: ${target}`));
      process.exit(1);
    }

    if (findings.length === 0) {
      console.log(chalk.green('🔒 GitGuard: No secrets detected.'));
    } else {
      printFindings(findings, chalk);
      process.exit(1);
    }
    break;
  }

  case 'fix':
    require('./remediate');
    break;

  case 'install': {
    const { execSync } = require('child_process');
    const scriptPath = path.join(__dirname, '..', 'scripts', 'install.sh');
    try {
      execSync(`bash "${scriptPath}"`, { stdio: 'inherit' });
    } catch {
      process.exit(1);
    }
    break;
  }

  case '--version':
  case '-v':
    printVersion();
    break;

  case '--help':
  case '-h':
  case undefined:
    printHelp();
    break;

  default:
    console.error(`Unknown command: ${command}`);
    printHelp();
    process.exit(1);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function requireChalk() {
  try {
    return require('chalk');
  } catch {
    // Minimal chalk shim if chalk is not installed
    const id = (s) => s;
    return new Proxy({}, { get: () => new Proxy(id, { get: () => id }) });
  }
}

function buildOpts(config, allowlist) {
  const scan   = config.scan   || {};
  const patterns = config.patterns || {};
  const ignore = config.ignore  || {};

  const customPatterns = (patterns.custom || []).map(({ name, regex }) => ({
    name,
    regex: new RegExp(regex),
  }));

  const extraAllowlist = (ignore.patterns || []).map((p) => {
    try { return new RegExp(p); } catch { return null; }
  }).filter(Boolean);

  return {
    allowlist: [...allowlist, ...extraAllowlist],
    customPatterns,
    entropyThreshold: scan.entropy_threshold || 4.5,
    minSecretLength:  scan.min_secret_length  || 20,
    ignoreFiles: ignore.files || [],
  };
}

function scanDirectory(dir, opts) {
  const { scanFile } = require('./scan');
  const results = [];
  const ignore  = opts.ignoreFiles || [];

  function walk(current) {
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const full = path.join(current, entry.name);
      const rel  = path.relative(process.cwd(), full);

      if (entry.name === '.git') continue;
      if (ignore.some((pat) => matchGlob(pat, rel))) continue;

      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.isFile()) {
        results.push(...scanFile(full, opts));
      }
    }
  }
  walk(dir);
  return results;
}

function matchGlob(pattern, filePath) {
  // Simple glob: convert ** and * to regex
  const re = pattern
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '.+')
    .replace(/\*/g, '[^/]+');
  return new RegExp(re).test(filePath);
}

function printFindings(findings, chalk) {
  console.log(chalk.red('\n🔴 GitGuard — secrets detected\n'));
  const col = [30, 6, 20, 16];
  const header = padRow(['File', 'Line', 'Type', 'Preview'], col);
  console.log(chalk.bold(header));
  console.log('─'.repeat(col.reduce((a, b) => a + b + 2, 0)));
  for (const f of findings) {
    console.log(padRow([f.file, String(f.lineNumber), f.type, f.preview], col));
  }
  console.log();
}

function padRow(cells, widths) {
  return cells.map((c, i) => c.slice(0, widths[i]).padEnd(widths[i])).join('  ');
}
