# Git-Guard 🛡️

**Git-Guard** is a lightweight, zero-dependency Python tool that scans your
repository for leaked API keys and secrets **before they reach GitHub**.

It works as a **git pre-push hook** — the moment you run `git push`, Git-Guard
silently inspects your files. If a secret is detected the push is **blocked**,
giving you time to revoke the key and clean your history.

---

## Why Git-Guard?

"Vibe coding" and AI-assisted development make it easy to accidentally
hard-code credentials. Once a secret reaches a public repository it can be
harvested within seconds by automated scanners. Git-Guard sets a barrier at the
last moment before the push leaves your machine.

---

## What it detects

| Category | Examples |
|---|---|
| **AWS** | Access Key IDs (`AKIA…`), Secret Access Keys |
| **GitHub** | Personal Access Tokens (`ghp_…`), Fine-Grained PATs, OAuth / App tokens |
| **Google** | API keys (`AIza…`), OAuth tokens |
| **Slack** | Bot tokens (`xoxb-…`), user tokens, webhooks |
| **Stripe** | Live & test secret/public keys |
| **Twilio** | API keys, Account SIDs |
| **SendGrid** | API keys (`SG.…`) |
| **GitLab** | Personal Access Tokens (`glpat-…`) |
| **NPM** | Auth tokens (`npm_…`) |
| **Crypto** | JWT tokens, RSA/EC/OpenSSH private key blocks |
| **Generic** | `api_key = …`, `secret_key = …`, `access_token = …` (high-entropy only) |
| **URLs** | Credentials embedded in connection strings (`postgres://user:pass@host`) |

Shannon-entropy analysis is applied to *generic* patterns to suppress
low-entropy placeholders (e.g. `api_key = YOUR_KEY_HERE`).

---

## Installation

### From source (recommended during development)

```bash
git clone https://github.com/Rahul21sai/Git-Guard.git
cd Git-Guard
pip install -e .
```

### From PyPI (once published)

```bash
pip install gitguard
```

---

## Quick start

### 1 — Install the pre-push hook in your project

```bash
cd /path/to/your-project
gitguard install-hook
```

That's it. From now on every `git push` in that repository will be scanned
automatically.

### 2 — Scan manually at any time

```bash
# Scan current directory
gitguard scan

# Scan a specific directory
gitguard scan /path/to/your-project

# Scan a single file
gitguard scan src/config.py
```

### 3 — Remove the hook when no longer needed

```bash
gitguard uninstall-hook
```

---

## Suppressing false positives

Create a `.gitguardignore` file in the root of your repository. Each non-comment
line is treated as a Python regular expression matched against the finding's
matched text or file path.

```text
# .gitguardignore

# Suppress a known placeholder in docs
AKIAIOSFODNN7EXAMPLE

# Suppress all findings inside test fixtures
tests/fixtures/

# Suppress a specific JWT used in documentation
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
```

See [`.gitguardignore.example`](.gitguardignore.example) for a fully-annotated
template.

---

## What to do if a secret is detected

### If the push was **blocked** (secret not yet on GitHub)

1. **Remove the secret** from your source file.
2. **Use an environment variable or secret manager** instead:

   ```python
   # ❌ Bad
   api_key = "AIzaSyD-9tSrke72..."

   # ✅ Good
   import os
   api_key = os.environ["GOOGLE_API_KEY"]
   ```

3. Re-run `gitguard scan` to confirm no further issues, then push.

### If the secret **already reached GitHub** (or another remote)

> **Assume it is compromised — act immediately.**

#### Step 1 — Revoke the key right now

| Provider | Revocation URL |
|---|---|
| AWS | https://console.aws.amazon.com/iam/home#/security_credentials |
| GitHub | https://github.com/settings/tokens |
| Google | https://console.cloud.google.com/apis/credentials |
| Slack | https://api.slack.com/apps → select app → Revoke |
| Stripe | https://dashboard.stripe.com/apikeys |
| Twilio | https://www.twilio.com/console/account/keys |
| SendGrid | https://app.sendgrid.com/settings/api_keys |

#### Step 2 — Remove the secret from git history

Even after deleting the file the secret may still exist in previous commits.
Use **BFG Repo Cleaner** or **git-filter-repo** to purge it:

**Option A — BFG Repo Cleaner** (simpler)

```bash
# 1. Create a file listing strings to replace
echo "YOUR_LEAKED_KEY" > secrets.txt

# 2. Run BFG on a bare clone of your repo
git clone --mirror https://github.com/you/your-repo.git
java -jar bfg.jar --replace-text secrets.txt your-repo.git

# 3. Push the cleaned history
cd your-repo.git
git reflog expire --expire=now --all
git gc --prune=now --aggressive
git push --force
```

**Option B — git-filter-repo** (modern, pure Python)

```bash
pip install git-filter-repo

# Create replacements file: literal:REPLACEMENT
printf 'literal:YOUR_LEAKED_KEY==>REMOVED\n' > replacements.txt
git filter-repo --replace-text replacements.txt
git push origin --force --all --tags
```

#### Step 3 — Rotate all dependent credentials

Revoked keys may have been cached or copied. Rotate **every** downstream
credential that could have been derived from the exposed one (e.g. session
tokens, refresh tokens, OAuth clients).

#### Step 4 — Store secrets safely going forward

| Method | Notes |
|---|---|
| `.env` file + `.gitignore` | Simple; use `python-dotenv` or similar to load |
| CI/CD secrets | GitHub Secrets, GitLab CI Variables, CircleCI Contexts |
| Cloud secret managers | AWS Secrets Manager, GCP Secret Manager, Azure Key Vault |
| HashiCorp Vault | Self-hosted, open-source |

---

## Project structure

```
Git-Guard/
├── gitguard/
│   ├── __init__.py        # Package version
│   ├── __main__.py        # python -m gitguard entry-point
│   ├── scanner.py         # Core scanning engine (patterns + entropy)
│   ├── cli.py             # CLI (scan / install-hook / uninstall-hook)
│   └── hooks.py           # Git hook install / uninstall logic
├── hooks/
│   └── pre-push           # Standalone hook script (copy to .git/hooks/)
├── tests/
│   └── test_scanner.py    # Pytest test-suite (51 tests)
├── .gitguardignore.example
├── pyproject.toml
├── requirements-dev.txt
└── README.md
```

---

## Running the tests

```bash
pip install -e ".[dev]"   # or: pip install pytest
pytest
```

---

## Contributing

Pull requests are welcome! Please open an issue first to discuss significant
changes.

---

## License

MIT © Rahul21sai
