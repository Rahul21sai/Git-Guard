'use strict';

/**
 * GitGuard — Shared scan engine
 * Framework-agnostic: importable by the CLI hook and the VS Code extension.
 */

// ---------------------------------------------------------------------------
// Regex-based secret patterns
// ---------------------------------------------------------------------------
const PATTERNS = [
  { name: 'AWS Access Key',      regex: /AKIA[0-9A-Z]{16}/ },
  { name: 'AWS Secret Key',      regex: /aws_secret_access_key\s*=\s*[^\s]{40}/ },
  { name: 'OpenAI API Key',      regex: /sk-[a-zA-Z0-9]{48}/ },
  { name: 'GitHub PAT',          regex: /ghp_[a-zA-Z0-9]{36}/ },
  { name: 'GitHub OAuth',        regex: /gho_[a-zA-Z0-9]{36}/ },
  { name: 'Stripe Live Key',     regex: /sk_live_[0-9a-zA-Z]{24}/ },
  { name: 'Google API Key',      regex: /AIza[0-9A-Za-z\-_]{35}/ },
  { name: 'Slack Bot Token',     regex: /xoxb-[0-9]{11}-[0-9]{11}-[a-zA-Z0-9]{24}/ },
  { name: 'HuggingFace Token',   regex: /hf_[a-zA-Z0-9]{37}/ },
  { name: 'Anthropic Key',       regex: /sk-ant-[a-zA-Z0-9\-_]{93}/ },
  {
    name: 'Generic Secret',
    regex: /(api_key|api_secret|secret_key|access_token|auth_token|private_key)\s*[=:]\s*['"]?[a-zA-Z0-9\-_\.]{20,}['"]?/i,
  },
];

// ---------------------------------------------------------------------------
// Entropy analysis — variable names that warrant entropy checks
// ---------------------------------------------------------------------------
const SENSITIVE_VAR_NAMES = /key|secret|token|password|credential|auth|api/i;

const MIN_ENTROPY = 4.5;
const MIN_LENGTH  = 20;

/**
 * Calculate Shannon entropy of a string.
 * @param {string} str
 * @returns {number} bits per character
 */
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return Object.values(freq).reduce((h, count) => {
    const p = count / len;
    return h - p * Math.log2(p);
  }, 0);
}

// ---------------------------------------------------------------------------
// Allowlist — patterns that are always safe to ignore
// ---------------------------------------------------------------------------
const BUILTIN_ALLOWLIST = [
  /process\.env\.[A-Z_]+/,
  /os\.environ\.[A-Z_]+/i,
  /\$\{[^}]+\}/,
  /<%=.*?%>/,
];

/**
 * Parse a .gitguardignore file and return an array of RegExp patterns.
 * @param {string} content  Raw file content
 * @returns {RegExp[]}
 */
function parseGitguardignore(content) {
  return content
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !l.startsWith('#'))
    .map((l) => {
      try {
        return new RegExp(l);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

/**
 * Check whether a line is covered by the allowlist.
 * @param {string} line
 * @param {RegExp[]} extraAllowlist
 * @returns {boolean}
 */
function isAllowlisted(line, extraAllowlist = []) {
  const all = [...BUILTIN_ALLOWLIST, ...extraAllowlist];
  return all.some((re) => re.test(line));
}

// ---------------------------------------------------------------------------
// Core scan function
// ---------------------------------------------------------------------------

/**
 * Scan a single line for secrets.
 *
 * @param {string} line            The raw line text
 * @param {object} opts
 * @param {RegExp[]} [opts.allowlist]          Extra allowlist patterns
 * @param {object[]} [opts.customPatterns]     Extra {name, regex} patterns
 * @param {number}  [opts.entropyThreshold]    Override entropy threshold
 * @param {number}  [opts.minSecretLength]     Override minimum length
 * @returns {{ type: string, match: string }[]}  Array of findings
 */
function scanLine(line, opts = {}) {
  const {
    allowlist = [],
    customPatterns = [],
    entropyThreshold = MIN_ENTROPY,
    minSecretLength  = MIN_LENGTH,
  } = opts;

  if (isAllowlisted(line, allowlist)) return [];

  const findings = [];

  // Layer 1 — regex patterns
  for (const { name, regex } of [...PATTERNS, ...customPatterns]) {
    const m = line.match(regex);
    if (m) {
      findings.push({ type: name, match: m[0] });
    }
  }

  // Layer 2 — Shannon entropy on string values assigned to sensitive variables
  // Matches: varName = "value" or varName = 'value' or varName=value
  const assignmentRe = /([a-zA-Z_][a-zA-Z0-9_]*)\s*[=:]\s*['"]?([a-zA-Z0-9\-_\.\/+]{20,})['"]?/g;
  let m;
  while ((m = assignmentRe.exec(line)) !== null) {
    const varName = m[1];
    const value   = m[2];
    if (
      SENSITIVE_VAR_NAMES.test(varName) &&
      value.length >= minSecretLength &&
      shannonEntropy(value) > entropyThreshold
    ) {
      // Avoid duplicating a finding already caught by a regex
      const alreadyFound = findings.some((f) => f.match.includes(value));
      if (!alreadyFound) {
        findings.push({ type: 'High-Entropy Secret', match: value });
      }
    }
  }

  return findings;
}

/**
 * Scan an array of {line, lineNumber, file} objects.
 *
 * @param {Array<{line:string, lineNumber:number, file:string}>} lines
 * @param {object} opts   Same options as scanLine
 * @returns {Array<{file:string, lineNumber:number, type:string, match:string}>}
 */
function scanLines(lines, opts = {}) {
  const results = [];
  for (const { line, lineNumber, file } of lines) {
    for (const finding of scanLine(line, opts)) {
      results.push({ file, lineNumber, ...finding });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Preview helper — truncate a secret match for safe display
// ---------------------------------------------------------------------------
/**
 * Return a display-safe preview of a secret.
 * @param {string} secret
 * @returns {string}
 */
function previewSecret(secret) {
  if (secret.length <= 8) return secret.slice(0, 4) + '...';
  return secret.slice(0, 6) + '...' + secret.slice(-3);
}

module.exports = {
  PATTERNS,
  shannonEntropy,
  parseGitguardignore,
  isAllowlisted,
  scanLine,
  scanLines,
  previewSecret,
  MIN_ENTROPY,
  MIN_LENGTH,
};
