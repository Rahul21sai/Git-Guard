#!/usr/bin/env node
'use strict';

/**
 * GitGuard — Git pre-push hook
 *
 * Install:
 *   cp hooks/pre-push.js ~/.githooks/pre-push
 *   chmod +x ~/.githooks/pre-push
 *   git config --global core.hooksPath ~/.githooks
 *
 * The hook reads the staged diff and blocks the push if secrets are found.
 */

const { execSync } = require('child_process');
const path   = require('path');
const fs     = require('fs');

// Resolve the CLI modules — handle both global hook path and local dev path
function resolveModule(name) {
  // Try relative to this file first (local install)
  const local = path.join(__dirname, '..', 'cli', `${name}.js`);
  if (fs.existsSync(local)) return local;
  // Try resolving via require (global npm install)
  try {
    return require.resolve(`gitguard/cli/${name}`);
  } catch {
    return null;
  }
}

const scanMod    = resolveModule('scan');
const patternMod = resolveModule('patterns');

if (!scanMod || !patternMod) {
  // GitGuard not found — allow push (fail open)
  console.warn('⚠️  GitGuard hook: scan engine not found, skipping check.');
  process.exit(0);
}

const { scanDiff, loadAllowlist, loadConfig } = require(scanMod);
const { previewSecret } = require(patternMod);

// ---------------------------------------------------------------------------
// Attempt chalk — fall back to plain output gracefully
// ---------------------------------------------------------------------------
let chalk;
try { chalk = require('chalk'); } catch {
  const id = (s) => s;
  chalk = new Proxy({}, { get: () => new Proxy(id, { get: () => id }) });
}

// ---------------------------------------------------------------------------
// Read diff
// ---------------------------------------------------------------------------
let diff = '';
try {
  // Use @{upstream} to correctly reference whichever remote/branch is tracked
  diff = execSync('git diff @{upstream} HEAD --unified=0', {
    encoding: 'utf8',
    stdio: ['pipe', 'pipe', 'pipe'],
  });
} catch {
  // No upstream set yet (first push) — scan everything staged
  try {
    diff = execSync('git diff --cached --unified=0', {
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch {
    process.exit(0); // Can't diff — allow push
  }
}

if (!diff.trim()) {
  process.exit(0); // Nothing to scan
}

// ---------------------------------------------------------------------------
// Build scan options from project config
// ---------------------------------------------------------------------------
const allowlist = loadAllowlist();
const config    = loadConfig();
const scanCfg   = config.scan     || {};
const patterns  = config.patterns || {};
const ignore    = config.ignore   || {};

const customPatterns = (patterns.custom || []).map(({ name, regex }) => ({
  name,
  regex: new RegExp(regex),
}));

const extraAllowlist = (ignore.patterns || []).map((p) => {
  try { return new RegExp(p); } catch { return null; }
}).filter(Boolean);

const opts = {
  allowlist: [...allowlist, ...extraAllowlist],
  customPatterns,
  entropyThreshold: scanCfg.entropy_threshold || 4.5,
  minSecretLength:  scanCfg.min_secret_length  || 20,
};

// ---------------------------------------------------------------------------
// Scan
// ---------------------------------------------------------------------------
const findings = scanDiff(diff, opts);

if (findings.length === 0) {
  console.log(chalk.green('🔒 GitGuard: Clean — no secrets detected.'));
  process.exit(0);
}

// ---------------------------------------------------------------------------
// Print warning table and block push
// ---------------------------------------------------------------------------
console.log(chalk.red('\n🔴 GitGuard blocked this push — secrets detected\n'));

const col = [30, 6, 22, 16];
function padRow(cells) {
  return cells.map((c, i) => String(c).slice(0, col[i]).padEnd(col[i])).join('  ');
}

console.log(chalk.bold(padRow(['File', 'Line', 'Type', 'Preview'])));
console.log('─'.repeat(col.reduce((a, b) => a + b + 2, 0)));
for (const f of findings) {
  console.log(padRow([f.file, f.lineNumber, f.type, f.preview]));
}

console.log();
console.log(chalk.yellow('Run: ') + chalk.bold('gitguard fix') + '   to start the remediation wizard');
console.log(chalk.yellow('Run: ') + chalk.bold('git push --no-verify') + '   to bypass (NOT recommended)\n');

process.exit(1);
