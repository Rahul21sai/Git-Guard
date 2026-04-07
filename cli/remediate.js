#!/usr/bin/env node
'use strict';

/**
 * GitGuard — Remediation wizard
 * Run with: gitguard fix
 *
 * Steps:
 *  1. Scan full git history for leaked secrets
 *  2. Open revocation URL for each secret type
 *  3. Purge secrets from history using git-filter-repo (or BFG fallback)
 *  4. Force-push cleaned history
 *  5. Print post-remediation checklist
 */

const { execSync, spawnSync } = require('child_process');
const crypto = require('crypto');
const path   = require('path');
const fs     = require('fs');
const readline = require('readline');

const { scanDiff, loadAllowlist, loadConfig } = require('./scan');
const { previewSecret } = require('./patterns');

// ---------------------------------------------------------------------------
// Revocation URLs per secret type
// ---------------------------------------------------------------------------
const REVOKE_URLS = {
  'OpenAI API Key':    'https://platform.openai.com/account/api-keys',
  'AWS Access Key':    'https://console.aws.amazon.com/iam/home#/security_credentials',
  'AWS Secret Key':    'https://console.aws.amazon.com/iam/home#/security_credentials',
  'GitHub PAT':        'https://github.com/settings/tokens',
  'GitHub OAuth':      'https://github.com/settings/tokens',
  'Stripe Live Key':   'https://dashboard.stripe.com/apikeys',
  'Google API Key':    'https://console.cloud.google.com/apis/credentials',
  'Anthropic Key':     'https://console.anthropic.com/settings/keys',
  'Slack Bot Token':   'https://api.slack.com/apps',
  'HuggingFace Token': 'https://huggingface.co/settings/tokens',
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
let chalk;
try { chalk = require('chalk'); } catch {
  const id = (s) => s;
  chalk = new Proxy({}, { get: () => new Proxy(id, { get: () => id }) });
}

function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

function openBrowser(url) {
  const cmd = process.platform === 'darwin' ? 'open'
    : process.platform === 'win32'  ? 'start'
    : 'xdg-open';
  try { execSync(`${cmd} "${url}"`, { stdio: 'ignore' }); } catch { /* best effort */ }
}

function run(cmd, opts = {}) {
  return spawnSync('sh', ['-c', cmd], { encoding: 'utf8', ...opts });
}

function isAvailable(tool) {
  return run(`command -v ${tool}`).status === 0;
}

function padRow(cells, widths) {
  return cells.map((c, i) => String(c).slice(0, widths[i]).padEnd(widths[i])).join('  ');
}

// ---------------------------------------------------------------------------
// Step 1 — Scan git history
// ---------------------------------------------------------------------------
async function scanHistory() {
  console.log(chalk.cyan('\n📜 Step 1 — Scanning full git history…\n'));

  let historyDiff;
  try {
    historyDiff = execSync('git log -p --all --no-color', {
      encoding: 'utf8',
      maxBuffer: 100 * 1024 * 1024,
    });
  } catch (e) {
    console.error(chalk.red('Failed to read git history: ' + e.message));
    process.exit(1);
  }

  const allowlist = loadAllowlist();
  const config    = loadConfig();
  const scan      = config.scan || {};
  const opts = {
    allowlist,
    entropyThreshold: scan.entropy_threshold || 4.5,
    minSecretLength:  scan.min_secret_length  || 20,
  };

  const findings = scanDiff(historyDiff, opts);

  if (findings.length === 0) {
    console.log(chalk.green('✅ No secrets found in git history. Nothing to remediate.'));
    process.exit(0);
  }

  console.log(chalk.red(`⚠️  Found ${findings.length} potential secret(s) in history:\n`));
  const col = [42, 6, 22, 16];
  console.log(chalk.bold(padRow(['File', 'Line', 'Type', 'Preview'], col)));
  console.log('─'.repeat(col.reduce((a, b) => a + b + 2, 0)));
  for (const f of findings) {
    console.log(padRow([f.file, f.lineNumber, f.type, f.preview], col));
  }
  console.log();
  return findings;
}

// ---------------------------------------------------------------------------
// Step 2 — Revoke secrets
// ---------------------------------------------------------------------------
async function revokeSecrets(findings) {
  console.log(chalk.cyan('\n🔑 Step 2 — Revoking secrets\n'));

  const types = [...new Set(findings.map((f) => f.type))];

  for (const type of types) {
    const url = REVOKE_URLS[type];
    if (url) {
      console.log(chalk.yellow(`Secret type: ${type}`));
      console.log(`  Revocation page: ${chalk.underline(url)}`);
      openBrowser(url);
    } else {
      console.log(chalk.yellow(`Secret type: ${type} — no known revocation URL. Revoke manually.`));
    }

    let confirmed = '';
    while (confirmed.toLowerCase() !== 'y') {
      confirmed = await prompt(
        chalk.bold(`  Have you revoked all "${type}" keys? (y/n): `)
      );
      if (confirmed.toLowerCase() === 'n') {
        console.log(chalk.red('  Please revoke the key before continuing.'));
      }
    }
    console.log(chalk.green(`  ✅ Revocation confirmed for: ${type}\n`));
  }
}

// ---------------------------------------------------------------------------
// Step 3 — Purge from git history
// ---------------------------------------------------------------------------
async function purgeHistory(findings) {
  console.log(chalk.cyan('\n🧹 Step 3 — Purging secrets from git history\n'));

  const secretValues = [...new Set(findings.map((f) => f.match))];

  const answer = await prompt(
    chalk.bold(`This will rewrite git history for ${secretValues.length} secret(s). Proceed? (y/n): `)
  );
  if (answer.toLowerCase() !== 'y') {
    console.log(chalk.yellow('Skipping history purge. Re-run "gitguard fix" when ready.'));
    return false;
  }

  if (isAvailable('git-filter-repo')) {
    console.log(chalk.cyan('  Using git-filter-repo…'));
    for (const secret of secretValues) {
      const rand    = crypto.randomBytes(12).toString('hex');
      const tmpFile = path.join(require('os').tmpdir(), `gitguard-${rand}.txt`);
      fs.writeFileSync(tmpFile, `${secret}==>REDACTED_BY_GITGUARD\n`, { encoding: 'utf8', mode: 0o600 });
      const result = run(`git filter-repo --replace-text "${tmpFile}" --force`);
      fs.unlinkSync(tmpFile);
      if (result.status !== 0) {
        console.error(chalk.red('  git-filter-repo failed:\n' + result.stderr));
        return false;
      }
    }
    console.log(chalk.green('  ✅ History rewritten with git-filter-repo.'));
  } else if (isAvailable('java')) {
    // BFG fallback
    const bfgJar = path.join(__dirname, '..', 'tools', 'bfg.jar');
    if (!fs.existsSync(bfgJar)) {
      console.log(chalk.red(
        '  BFG jar not found. Please download from https://rtyley.github.io/bfg-repo-cleaner/ ' +
        `and place it at: ${bfgJar}`
      ));
      printManualPurgeInstructions(secretValues);
      return false;
    }
    const rand        = crypto.randomBytes(12).toString('hex');
    const secretsFile = path.join(require('os').tmpdir(), `gitguard-${rand}.txt`);
    fs.writeFileSync(secretsFile, secretValues.join('\n') + '\n', { encoding: 'utf8', mode: 0o600 });
    const result = run(`java -jar "${bfgJar}" --replace-text "${secretsFile}"`, { cwd: process.cwd() });
    fs.unlinkSync(secretsFile);
    if (result.status !== 0) {
      console.error(chalk.red('  BFG failed:\n' + result.stderr));
      return false;
    }
    run('git reflog expire --expire=now --all && git gc --prune=now --aggressive');
    console.log(chalk.green('  ✅ History rewritten with BFG.'));
  } else {
    console.log(chalk.red(
      '  Neither git-filter-repo nor Java/BFG is available.\n' +
      '  Install git-filter-repo: pip install git-filter-repo\n' +
      '  Or install Java for BFG support.'
    ));
    printManualPurgeInstructions(secretValues);
    return false;
  }

  // Verify purge
  console.log(chalk.cyan('\n  Verifying purge…'));
  const { execSync: ex } = require('child_process');
  let newHistory;
  try {
    newHistory = ex('git log -p --all --no-color', { encoding: 'utf8', maxBuffer: 100 * 1024 * 1024 });
  } catch { newHistory = ''; }

  const stillFound = secretValues.filter((s) => newHistory.includes(s));
  if (stillFound.length > 0) {
    console.log(chalk.red(`  ⚠️  ${stillFound.length} secret(s) still present after purge. Review manually.`));
    return false;
  }
  console.log(chalk.green('  ✅ Verification passed — secrets removed from history.'));
  return true;
}

function printManualPurgeInstructions(secrets) {
  console.log(chalk.yellow('\n  Manual purge instructions:'));
  for (const s of secrets) {
    console.log(`    git filter-repo --replace-text <(echo '${s}==>REDACTED')`);
  }
}

// ---------------------------------------------------------------------------
// Step 4 — Force push
// ---------------------------------------------------------------------------
async function forcePush() {
  console.log(chalk.cyan('\n🚀 Step 4 — Force-push cleaned history\n'));

  console.log(chalk.yellow('  Commands to be executed:'));
  console.log('    git push --force --all');
  console.log('    git push --force --tags\n');

  const answer = await prompt(
    chalk.bold('  Execute force push now? (y/n) — or run manually if you prefer: ')
  );
  if (answer.toLowerCase() !== 'y') {
    console.log(chalk.yellow('\n  Skipped. Run manually:'));
    console.log('    git push --force --all');
    console.log('    git push --force --tags\n');
    return;
  }

  const r1 = run('git push --force --all', { stdio: 'inherit' });
  const r2 = run('git push --force --tags', { stdio: 'inherit' });

  if (r1.status === 0 && r2.status === 0) {
    console.log(chalk.green('\n  ✅ Force push complete.'));
  } else {
    console.log(chalk.red('\n  ⚠️  Force push failed. Run manually.'));
  }
}

// ---------------------------------------------------------------------------
// Step 5 — Post-remediation checklist
// ---------------------------------------------------------------------------
function printChecklist() {
  console.log(chalk.cyan('\n📋 Step 5 — Post-remediation checklist\n'));
  console.log(chalk.green('✅ Remediation complete. Verify these manually:\n'));
  const items = [
    'New key generated and added to .env (not committed)',
    '.env added to .gitignore',
    'All team members notified to rotate their local credentials',
    'Check GitHub → Settings → Security → Secret scanning alerts',
    'Audit any services that may have used the exposed key (logs, billing)',
    'If on a public repo: assume the key was harvested. Treat as compromised.',
  ];
  for (const item of items) console.log(`  ☐  ${item}`);
  console.log();
  console.log(chalk.yellow(
    '⚠️  Note: GitHub caches commits by SHA for ~90 days even after force push.\n' +
    '   The key revocation in Step 2 is critical and non-negotiable.\n'
  ));
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
(async () => {
  console.log(chalk.bold.cyan('\n🛡️  GitGuard — Remediation Wizard\n'));

  const findings = await scanHistory();
  await revokeSecrets(findings);
  const purged  = await purgeHistory(findings);
  if (purged) await forcePush();
  printChecklist();
})().catch((err) => {
  console.error(err);
  process.exit(1);
});
