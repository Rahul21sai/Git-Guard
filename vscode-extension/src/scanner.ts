/**
 * GitGuard — VS Code scanner
 * Thin TypeScript wrapper around the shared JS scan engine.
 * This file re-exports the JS functions with proper types so the extension
 * can import them without a separate bundling step.
 */

// We import the plain-JS patterns module at runtime.
// In a packaged extension, webpack/esbuild bundles this automatically.
// eslint-disable-next-line @typescript-eslint/no-var-requires
const patternsModule = require('../../cli/patterns');

export interface ScanFinding {
  type: string;
  match: string;
}

export interface ScanOptions {
  allowlist?: RegExp[];
  customPatterns?: Array<{ name: string; regex: RegExp }>;
  entropyThreshold?: number;
  minSecretLength?: number;
}

/**
 * Scan a single line of text for secrets.
 */
export function scanLine(line: string, opts: ScanOptions = {}): ScanFinding[] {
  return patternsModule.scanLine(line, opts) as ScanFinding[];
}

/**
 * Parse a .gitguardignore file content into an array of RegExp patterns.
 */
export function parseGitguardignore(content: string): RegExp[] {
  return patternsModule.parseGitguardignore(content) as RegExp[];
}

/**
 * Return a display-safe preview of a secret value.
 */
export function previewSecret(secret: string): string {
  return patternsModule.previewSecret(secret) as string;
}
