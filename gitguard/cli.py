"""
CLI interface for Git-Guard.

Usage:
    gitguard scan [PATH]           Scan a directory (default: current dir)
    gitguard install-hook [PATH]   Install the pre-push hook in a git repo
    gitguard uninstall-hook [PATH] Remove the pre-push hook
    gitguard --help
"""

import sys
from pathlib import Path

from gitguard.scanner import Finding, load_allowlist, scan_directory, scan_files
from gitguard.hooks import install_hook, uninstall_hook, HookError


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_findings(findings: list[Finding]) -> None:
    print(f"\n{'='*60}")
    print(f"  Git-Guard found {len(findings)} potential secret(s)!")
    print(f"{'='*60}\n")
    for finding in findings:
        print(finding)
        print()


def _print_remediation() -> None:
    print("=" * 60)
    print("  HOW TO REMEDIATE")
    print("=" * 60)
    print(
        """
1. DO NOT PUSH — Stop the push immediately (or revert if already pushed).

2. REVOKE THE KEY — Invalidate the exposed credential immediately:
   • AWS        → https://console.aws.amazon.com/iam/home#/security_credentials
   • GitHub PAT → https://github.com/settings/tokens
   • Google     → https://console.cloud.google.com/apis/credentials
   • Slack      → https://api.slack.com/apps  (Revoke / Regenerate)
   • Stripe     → https://dashboard.stripe.com/apikeys
   • Twilio     → https://www.twilio.com/console/account/keys
   • SendGrid   → https://app.sendgrid.com/settings/api_keys

3. REMOVE FROM HISTORY — Even after removal the key may live in git history.
   Use BFG Repo Cleaner or git-filter-repo to purge it:
     # With BFG:
     bfg --replace-text secrets.txt
     git reflog expire --expire=now --all && git gc --prune=now --aggressive
     git push origin --force --all

     # With git-filter-repo:
     git filter-repo --replace-text secrets.txt

4. USE ENVIRONMENT VARIABLES — Never hard-code secrets. Store them in:
   • .env files (add .env to .gitignore)
   • CI/CD secret stores (GitHub Secrets, GitLab CI Variables, etc.)
   • Cloud secret managers (AWS Secrets Manager, HashiCorp Vault, etc.)

5. ADD TO .gitguardignore — If a match is a false positive, add a pattern
   to .gitguardignore at the root of your repository to suppress it.
"""
    )


# ---------------------------------------------------------------------------
# Sub-commands
# ---------------------------------------------------------------------------

def cmd_scan(args: list[str]) -> int:
    """Scan a directory for secrets. Returns exit-code."""
    root = Path(args[0]) if args else Path.cwd()
    if not root.exists():
        print(f"Error: path '{root}' does not exist.", file=sys.stderr)
        return 2

    print(f"Scanning '{root}' for secrets …")
    allowlist = load_allowlist(root)
    if root.is_file():
        findings = scan_files([root], allowlist)
    else:
        findings = scan_directory(root, allowlist)

    if findings:
        _print_findings(findings)
        _print_remediation()
        return 1

    print("✔  No secrets detected.")
    return 0


def cmd_install(args: list[str]) -> int:
    """Install the git pre-push hook. Returns exit-code."""
    repo_path = Path(args[0]) if args else Path.cwd()
    try:
        install_hook(repo_path)
        print(f"✔  Git-Guard pre-push hook installed in '{repo_path}'.")
        return 0
    except HookError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


def cmd_uninstall(args: list[str]) -> int:
    """Remove the git pre-push hook. Returns exit-code."""
    repo_path = Path(args[0]) if args else Path.cwd()
    try:
        uninstall_hook(repo_path)
        print(f"✔  Git-Guard pre-push hook removed from '{repo_path}'.")
        return 0
    except HookError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


# ---------------------------------------------------------------------------
# Entry-point
# ---------------------------------------------------------------------------

USAGE = """\
Git-Guard — API key & secret scanner for git repositories

Usage:
  gitguard scan [PATH]             Scan PATH (default: current directory)
  gitguard install-hook [PATH]     Install pre-push hook in git repo at PATH
  gitguard uninstall-hook [PATH]   Remove the pre-push hook
  gitguard --help                  Show this message

Examples:
  gitguard scan .
  gitguard scan /home/user/my-project
  gitguard install-hook
  gitguard install-hook /home/user/my-project
"""


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return 0

    sub = argv[0]
    rest = argv[1:]

    if sub == "scan":
        return cmd_scan(rest)
    if sub == "install-hook":
        return cmd_install(rest)
    if sub == "uninstall-hook":
        return cmd_uninstall(rest)

    print(f"Unknown command: '{sub}'\n", file=sys.stderr)
    print(USAGE, file=sys.stderr)
    return 2


def run() -> None:
    sys.exit(main())


if __name__ == "__main__":
    run()
