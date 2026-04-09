'use strict';

/**
 * GitGuard — Scan engine
 * Wraps patterns.js with file-level and diff-level scanning helpers.
 */

const fs   = require('fs');
const path = require('path');
const { scanLines, parseGitguardignore, previewSecret } = require('./patterns');

// ---------------------------------------------------------------------------
// Load .gitguardignore from repo root (or a given directory)
// ---------------------------------------------------------------------------
/**
 * @param {string} [rootDir]  Defaults to process.cwd()
 * @returns {RegExp[]}
 */
function loadAllowlist(rootDir = process.cwd()) {
  const file = path.join(rootDir, '.gitguardignore');
  if (fs.existsSync(file)) {
    return parseGitguardignore(fs.readFileSync(file, 'utf8'));
  }
  return [];
}

// ---------------------------------------------------------------------------
// Load .gitguard.yml config (optional dependency on js-yaml)
// ---------------------------------------------------------------------------
/**
 * @param {string} [rootDir]
 * @returns {object}
 */
function loadConfig(rootDir = process.cwd()) {
  const file = path.join(rootDir, '.gitguard.yml');
  if (!fs.existsSync(file)) return {};
  try {
    const yaml = require('js-yaml');
    return yaml.load(fs.readFileSync(file, 'utf8')) || {};
  } catch {
    return {};
  }
}

// ---------------------------------------------------------------------------
// Scan a single file's content
// ---------------------------------------------------------------------------
/**
 * @param {string} filePath   Absolute or relative path to the file
 * @param {object} [opts]
 * @returns {Array<{file, lineNumber, type, match, preview}>}
 */
function scanFile(filePath, opts = {}) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch {
    return [];
  }

  const fileName = path.relative(process.cwd(), filePath);
  const lines = content.split('\n').map((line, idx) => ({
    line,
    lineNumber: idx + 1,
    file: fileName,
  }));

  return scanLines(lines, opts).map((r) => ({
    ...r,
    preview: previewSecret(r.match),
  }));
}

// ---------------------------------------------------------------------------
// Scan a git diff (unified format) — only added lines (+)
// ---------------------------------------------------------------------------
/**
 * @param {string} diffText   Output of `git diff ...`
 * @param {object} [opts]
 * @returns {Array<{file, lineNumber, type, match, preview}>}
 */
function scanDiff(diffText, opts = {}) {
  const lines = [];
  let currentFile = '<unknown>';
  let lineNumber  = 0;

  for (const rawLine of diffText.split('\n')) {
    if (rawLine.startsWith('+++ b/')) {
      currentFile = rawLine.slice(6);
      lineNumber  = 0;
    } else if (rawLine.startsWith('@@ ')) {
      // @@ -old +new,count @@
      const m = rawLine.match(/\+(\d+)/);
      lineNumber = m ? parseInt(m[1], 10) - 1 : 0;
    } else if (rawLine.startsWith('+') && !rawLine.startsWith('+++')) {
      lineNumber++;
      lines.push({ line: rawLine.slice(1), lineNumber, file: currentFile });
    } else if (!rawLine.startsWith('-')) {
      lineNumber++;
    }
  }

  return scanLines(lines, opts).map((r) => ({
    ...r,
    preview: previewSecret(r.match),
  }));
}

module.exports = { loadAllowlist, loadConfig, scanFile, scanDiff };
