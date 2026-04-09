# 🛡️ GitGuard

> **Stop API keys and secrets from ever reaching GitHub.**

GitGuard is a developer security toolkit that detects leaked secrets **before** they are pushed, and helps you **remediate** any secrets that have already been exposed. It works in three coordinated layers:

| Component | What it does |
|-----------|-------------|
| **Git pre-push hook** | Blocks every `git push` that contains a detected secret |
| **VS Code extension** | Shows inline warnings as you type, with one-click fixes |
| **Remediation CLI** | Guided wizard to purge secrets from git history and revoke keys |

---

## Table of Contents

1. [Why GitGuard?](#why-gitguard)
2. [Quick Start](#quick-start)
3. [Installation](#installation)
   - [Pre-push Hook](#1-pre-push-hook)
   - [VS Code Extension](#2-vs-code-extension)
4. [Usage](#usage)
   - [CLI Commands](#cli-commands)
   - [VS Code](#vs-code)
5. [Detection Capabilities](#detection-capabilities)
6. [Configuration](#configuration)
   - [.gitguard.yml](#gitguardyml)
   - [.gitguardignore](#gitguardignore)
7. [Remediation Wizard](#remediation-wizard-gitguard-fix)
8. [Project Structure](#project-structure)
9. [Contributing](#contributing)
10. [License](#license)

---

## Why GitGuard?

With the rise of AI-assisted ("vibe") coding, developers often paste real API keys directly into source code, accidentally commit them, and push to public repositories. Automated scanners harvest these keys within seconds of exposure. GitGuard sets a **barrier at the last safe moment** — the push — and helps you clean up if you're already past that point.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/Rahul21sai/Git-Guard.git
cd Git-Guard
npm install

# Install the global pre-push hook
bash scripts/install.sh

# Or use the CLI
npx gitguard install
```

From now on, every `git push` in any repository is automatically scanned for secrets.

---

## Installation

### 1. Pre-push Hook

The hook must be installed **once** and will then protect **all** your git repositories.

```bash
# Option A — using the install script (recommended)
bash scripts/install.sh

# Option B — manual
mkdir -p ~/.githooks
cp hooks/pre-push.js ~/.githooks/pre-push
chmod +x ~/.githooks/pre-push
git config --global core.hooksPath ~/.githooks
```

To uninstall:

```bash
bash scripts/uninstall.sh
```

### 2. VS Code Extension

```bash
cd vscode-extension
npm install
npm run build

# Install the packaged extension
vsce package          # produces gitguard-vscode-1.0.0.vsix
code --install-extension gitguard-vscode-1.0.0.vsix
```

> **Tip:** The extension automatically reuses the same detection engine (`cli/patterns.js`) as the CLI hook, so behavior is identical.

---

## Usage

### CLI Commands

```bash
# Scan a file or directory
gitguard scan src/config.js
gitguard scan .

# Launch the remediation wizard (if secrets already pushed)
gitguard fix

# Install the global pre-push hook
gitguard install

# Help
gitguard --help
```

### VS Code

Once the extension is installed:

- Open any file — secrets are highlighted with a ⚠️ warning immediately.
- Click the lightbulb (💡) on a flagged line to see quick fixes:
  - **Move to .env and replace with `process.env`** — moves the value to your `.env` file and updates the code to reference it.
  - **Add to .gitguardignore** — suppresses the warning for this specific pattern.
- The status bar (bottom-right) shows `🔒 GitGuard: Clean` or `⚠️ GitGuard: N secrets`.

---

## Detection Capabilities

### Layer 1 — Known secret formats (regex)

| Secret type | Pattern |
|-------------|---------|
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| AWS Secret Key | `aws_secret_access_key = ...` |
| OpenAI API Key | `sk-...` (48 chars) |
| GitHub PAT | `ghp_...` (36 chars) |
| GitHub OAuth | `gho_...` (36 chars) |
| Stripe Live Key | `sk_live_...` |
| Google API Key | `AIza...` |
| Slack Bot Token | `xoxb-...` |
| HuggingFace Token | `hf_...` |
| Anthropic Key | `sk-ant-...` |
| Generic Secret | Variable names containing `api_key`, `secret`, `token`, `password`, etc. with values ≥ 20 chars |

### Layer 2 — Shannon entropy analysis

For variables whose names contain `key`, `secret`, `token`, `password`, `credential`, `auth`, or `api`:

- Calculate the [Shannon entropy](https://en.wikipedia.org/wiki/Entropy_(information_theory)) of the assigned string value
- Flag if entropy > **4.5 bits/char** AND length > **20 characters**

This catches novel secret formats that regex patterns might miss.

### Built-in allowlist

These patterns are **always ignored** (never flagged):

- `process.env.*`
- `os.environ.*`
- `${...}` (template literals / shell variables)
- `<%=...%>` (template tags)

---

## Configuration

### `.gitguard.yml`

Copy `.gitguard.yml.example` to `.gitguard.yml` in your project root:

```yaml
version: 1

scan:
  entropy_threshold: 4.5
  min_secret_length: 20
  scan_binary_files: false

patterns:
  use_builtin: true
  custom:
    - name: "Internal Auth Token"
      regex: "MYAPP_[A-Z0-9]{32}"

ignore:
  files:
    - "**/*.test.js"
    - "**/fixtures/**"
  patterns:
    - "example_key_here"
    - "PLACEHOLDER"

notify:
  slack_webhook: ""
  email: ""
```

### `.gitguardignore`

Create a `.gitguardignore` file in your project root. Each line is a JavaScript-compatible regex pattern. Lines matching this file are never flagged:

```
# Ignore placeholder values
example_key_here
your_api_key_here
PLACEHOLDER

# Ignore test fixtures
test_secret_value
dummy_api_key
```

---

## Remediation Wizard (`gitguard fix`)

Run this wizard **after** a secret has been pushed. It walks you through five steps:

```
Step 1 — Scan full git history for leaked secrets
Step 2 — Open revocation URLs for each secret type (browser opens automatically)
Step 3 — Purge secrets from history (git-filter-repo or BFG)
Step 4 — Force-push cleaned history
Step 5 — Post-remediation checklist
```

> ⚠️ **Every destructive git command requires your explicit confirmation** — GitGuard never runs history-rewriting or force-push commands automatically.

### Requirements for Step 3

Install `git-filter-repo` (recommended):

```bash
pip install git-filter-repo
```

Or ensure Java is installed for BFG Repo Cleaner fallback (place `bfg.jar` in `tools/`).

---

## Project Structure

```
gitguard/
├── package.json                 Root package (CLI)
├── .gitguard.yml.example        Config template
├── .gitguardignore.example      Allowlist template
│
├── cli/
│   ├── index.js                 CLI entry point (gitguard command)
│   ├── patterns.js              ★ Shared scan engine (regex + entropy)
│   ├── scan.js                  File & diff scanning helpers
│   └── remediate.js             Remediation wizard
│
├── hooks/
│   └── pre-push.js              Git pre-push hook
│
├── vscode-extension/
│   ├── package.json             Extension manifest
│   ├── tsconfig.json
│   └── src/
│       ├── extension.ts         Activation + DiagnosticCollection
│       ├── scanner.ts           Thin wrapper around cli/patterns.js
│       ├── codeActions.ts       Quick-fix provider
│       └── statusBar.ts         Status bar item
│
└── scripts/
    ├── install.sh               Global hook installer
    └── uninstall.sh             Uninstaller
```

---

## Contributing

Pull requests are welcome! Please:

1. Fork the repository and create a feature branch.
2. Add or update tests in `tests/`.
3. Run `npm test` before submitting.

---

## License

MIT © GitGuard Contributors