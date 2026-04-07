"""Tests for gitguard — scanner, hooks, and CLI."""

import stat
import textwrap
from pathlib import Path

import pytest

from gitguard.scanner import (
    Finding,
    _shannon_entropy,
    load_allowlist,
    scan_directory,
    scan_file,
    scan_files,
    ALLOWLIST_FILENAME,
)
from gitguard.hooks import HookError, install_hook, uninstall_hook, _MARKER
from gitguard.cli import main


# ===========================================================================
# Helpers
# ===========================================================================

def write(tmp_path: Path, filename: str, content: str) -> Path:
    """Write *content* to *tmp_path/filename* and return the Path."""
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ===========================================================================
# Shannon entropy
# ===========================================================================

class TestShannonEntropy:
    def test_empty_string(self):
        assert _shannon_entropy("") == 0.0

    def test_single_char_repeated(self):
        # All same characters → entropy = 0
        assert _shannon_entropy("aaaa") == pytest.approx(0.0)

    def test_known_high_entropy(self):
        # Random-looking string should have high entropy
        value = "a1B2c3D4e5F6g7H8i9J0"
        assert _shannon_entropy(value) > 3.0

    def test_low_entropy_placeholder(self):
        # "YOUR_API_KEY_HERE" — all same-ish characters → low entropy
        value = "AAAAAAAAAAAAAAAA"
        assert _shannon_entropy(value) == pytest.approx(0.0)


# ===========================================================================
# scan_file — specific pattern tests
# ===========================================================================

class TestScanFilePatterns:
    """Each test writes a file containing a known-bad pattern and asserts
    that scan_file returns at least one finding with the right pattern name."""

    def _scan(self, tmp_path, filename, content):
        p = write(tmp_path, filename, content)
        return scan_file(p)

    # ── AWS ─────────────────────────────────────────────────────────────

    def test_aws_access_key(self, tmp_path):
        findings = self._scan(
            tmp_path, "config.py",
            'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
        )
        assert any(f.pattern_name == "AWS Access Key ID" for f in findings)

    # ── GitHub tokens ────────────────────────────────────────────────────

    def test_github_personal_token(self, tmp_path):
        token = "ghp_" + "A" * 36
        findings = self._scan(
            tmp_path, "deploy.sh",
            f"GITHUB_TOKEN={token}\n",
        )
        assert any(f.pattern_name == "GitHub Personal Token" for f in findings)

    def test_github_fine_grained_pat(self, tmp_path):
        token = "github_pat_" + "B" * 82
        findings = self._scan(
            tmp_path, "ci.yml",
            f"token: {token}\n",
        )
        assert any(f.pattern_name == "GitHub Fine-Grained PAT" for f in findings)

    # ── Google ───────────────────────────────────────────────────────────

    def test_google_api_key(self, tmp_path):
        key = "AIza" + "T" * 35
        findings = self._scan(
            tmp_path, "app.js",
            f"const apiKey = '{key}';\n",
        )
        assert any(f.pattern_name == "Google API Key" for f in findings)

    # ── Slack ────────────────────────────────────────────────────────────

    def test_slack_bot_token(self, tmp_path):
        token = "xoxb-1234567890-1234567890-" + "A" * 24
        findings = self._scan(
            tmp_path, "bot.py",
            f'SLACK_TOKEN = "{token}"\n',
        )
        assert any(f.pattern_name == "Slack Bot Token" for f in findings)

    # ── Stripe ───────────────────────────────────────────────────────────

    def test_stripe_live_secret(self, tmp_path):
        key = "sk_live_" + "x" * 24
        findings = self._scan(
            tmp_path, "payment.py",
            f'stripe.api_key = "{key}"\n',
        )
        assert any(f.pattern_name == "Stripe Live Secret Key" for f in findings)

    def test_stripe_test_secret(self, tmp_path):
        key = "sk_test_" + "y" * 24
        findings = self._scan(
            tmp_path, "test_payment.py",
            f'stripe.api_key = "{key}"\n',
        )
        assert any(f.pattern_name == "Stripe Test Secret Key" for f in findings)

    # ── SendGrid ─────────────────────────────────────────────────────────

    def test_sendgrid_key(self, tmp_path):
        key = "SG." + "A" * 22 + "." + "B" * 43
        findings = self._scan(
            tmp_path, "mail.py",
            f'SENDGRID_API_KEY = "{key}"\n',
        )
        assert any(f.pattern_name == "SendGrid API Key" for f in findings)

    # ── JWT ──────────────────────────────────────────────────────────────

    def test_jwt_token(self, tmp_path):
        jwt = (
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
            ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
            ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        )
        findings = self._scan(
            tmp_path, "auth.js",
            f"const token = '{jwt}';\n",
        )
        assert any(f.pattern_name == "JWT Token" for f in findings)

    # ── Private key block ────────────────────────────────────────────────

    def test_private_key_block(self, tmp_path):
        findings = self._scan(
            tmp_path, "key.pem",
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----\n",
        )
        assert any(f.pattern_name == "Private Key Block" for f in findings)

    # ── Password in URL ──────────────────────────────────────────────────

    def test_password_in_url(self, tmp_path):
        findings = self._scan(
            tmp_path, "db.py",
            'DATABASE_URL = "postgresql://admin:s3cr3tP@ss@db.example.com/mydb"\n',
        )
        assert any(f.pattern_name == "Password in URL" for f in findings)

    # ── NPM token ────────────────────────────────────────────────────────

    def test_npm_auth_token(self, tmp_path):
        token = "npm_" + "A" * 36
        findings = self._scan(
            tmp_path, ".npmrc",
            f"//registry.npmjs.org/:_authToken={token}\n",
        )
        assert any(f.pattern_name == "NPM Auth Token" for f in findings)

    # ── Generic patterns ─────────────────────────────────────────────────

    def test_generic_api_key_high_entropy(self, tmp_path):
        # High entropy value → should be flagged
        findings = self._scan(
            tmp_path, "config.env",
            "API_KEY=aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1v\n",
        )
        assert any("Generic" in f.pattern_name for f in findings)

    def test_generic_api_key_low_entropy_skipped(self, tmp_path):
        # Low-entropy placeholder → should NOT be flagged
        findings = self._scan(
            tmp_path, "example.env",
            "api_key=AAAAAAAAAAAAAAAAAAAAAA\n",
        )
        generic = [f for f in findings if "Generic" in f.pattern_name]
        assert len(generic) == 0

    # ── Clean file ───────────────────────────────────────────────────────

    def test_clean_file_no_findings(self, tmp_path):
        findings = self._scan(
            tmp_path, "hello.py",
            'def hello():\n    print("hello world")\n',
        )
        assert findings == []

    # ── Skipped extensions ───────────────────────────────────────────────

    def test_binary_extension_skipped(self, tmp_path):
        p = tmp_path / "image.png"
        p.write_bytes(b"AKIAIOSFODNN7EXAMPLE")  # fake binary with key bytes
        findings = scan_file(p)
        assert findings == []

    # ── Finding fields ───────────────────────────────────────────────────

    def test_finding_fields(self, tmp_path):
        p = write(
            tmp_path, "creds.py",
            'key = "AKIAIOSFODNN7EXAMPLE"\n',
        )
        findings = scan_file(p)
        assert len(findings) >= 1
        f = findings[0]
        assert f.file == str(p)
        assert f.line_number == 1
        assert "AKIAIOSFODNN7EXAMPLE" in f.matched_text

    def test_finding_str_representation(self, tmp_path):
        p = write(
            tmp_path, "creds.py",
            'key = "AKIAIOSFODNN7EXAMPLE"\n',
        )
        findings = scan_file(p)
        assert findings
        text = str(findings[0])
        assert "AWS Access Key ID" in text
        assert "Line" in text


# ===========================================================================
# Allowlist
# ===========================================================================

class TestAllowlist:
    def test_allowlist_suppresses_finding(self, tmp_path):
        # Write an allowlist that suppresses the AWS key pattern
        (tmp_path / ALLOWLIST_FILENAME).write_text(
            "AKIAIOSFODNN7EXAMPLE\n", encoding="utf-8"
        )
        p = write(
            tmp_path, "config.py",
            'key = "AKIAIOSFODNN7EXAMPLE"\n',
        )
        allowlist = load_allowlist(tmp_path)
        findings = scan_file(p, allowlist)
        assert findings == []

    def test_allowlist_skips_comments(self, tmp_path):
        (tmp_path / ALLOWLIST_FILENAME).write_text(
            "# this is a comment\n", encoding="utf-8"
        )
        allowlist = load_allowlist(tmp_path)
        assert len(allowlist) == 0

    def test_no_allowlist_file(self, tmp_path):
        allowlist = load_allowlist(tmp_path)
        assert allowlist == []

    def test_allowlist_invalid_regex_skipped(self, tmp_path):
        (tmp_path / ALLOWLIST_FILENAME).write_text(
            "[invalid(\n", encoding="utf-8"
        )
        # Should not raise; invalid patterns are silently skipped
        allowlist = load_allowlist(tmp_path)
        assert len(allowlist) == 0


# ===========================================================================
# scan_directory
# ===========================================================================

class TestScanDirectory:
    def test_detects_secret_in_nested_file(self, tmp_path):
        subdir = tmp_path / "src" / "auth"
        subdir.mkdir(parents=True)
        (subdir / "creds.py").write_text(
            'SECRET = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
        )
        findings = scan_directory(tmp_path)
        assert any(f.pattern_name == "AWS Access Key ID" for f in findings)

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "some-pkg"
        nm.mkdir(parents=True)
        (nm / "config.js").write_text(
            'const key = "AKIAIOSFODNN7EXAMPLE";\n', encoding="utf-8"
        )
        findings = scan_directory(tmp_path)
        assert findings == []

    def test_skips_git_dir(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text(
            'token = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
        )
        findings = scan_directory(tmp_path)
        assert findings == []

    def test_clean_directory(self, tmp_path):
        (tmp_path / "main.py").write_text('print("hello")\n', encoding="utf-8")
        findings = scan_directory(tmp_path)
        assert findings == []


# ===========================================================================
# scan_files
# ===========================================================================

class TestScanFiles:
    def test_scans_provided_list(self, tmp_path):
        p1 = write(tmp_path, "a.py", 'key = "AKIAIOSFODNN7EXAMPLE"\n')
        p2 = write(tmp_path, "b.py", 'print("clean")\n')
        findings = scan_files([p1, p2])
        assert any(f.pattern_name == "AWS Access Key ID" for f in findings)
        # b.py has no findings
        assert not any(f.file == str(p2) for f in findings)

    def test_nonexistent_file_skipped(self, tmp_path):
        findings = scan_files([tmp_path / "does_not_exist.py"])
        assert findings == []


# ===========================================================================
# Hook management
# ===========================================================================

class TestHookManagement:
    def _make_repo(self, tmp_path: Path) -> Path:
        """Create a minimal fake git repository."""
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        return tmp_path

    def test_install_creates_hook(self, tmp_path):
        repo = self._make_repo(tmp_path)
        install_hook(repo)
        hook = repo / ".git" / "hooks" / "pre-push"
        assert hook.exists()
        assert _MARKER in hook.read_text(encoding="utf-8")

    def test_installed_hook_is_executable(self, tmp_path):
        repo = self._make_repo(tmp_path)
        install_hook(repo)
        hook = repo / ".git" / "hooks" / "pre-push"
        mode = hook.stat().st_mode
        assert mode & stat.S_IXUSR, "Hook must be executable by owner"

    def test_install_over_existing_managed_hook(self, tmp_path):
        """Re-installing over an existing managed hook should succeed."""
        repo = self._make_repo(tmp_path)
        install_hook(repo)
        # Should not raise on second install
        install_hook(repo)

    def test_install_refuses_existing_foreign_hook(self, tmp_path):
        repo = self._make_repo(tmp_path)
        hook = repo / ".git" / "hooks" / "pre-push"
        hook.write_text("#!/bin/bash\necho custom hook\n", encoding="utf-8")
        with pytest.raises(HookError, match="already exists"):
            install_hook(repo)

    def test_install_non_repo_raises(self, tmp_path):
        with pytest.raises(HookError, match="not a git repository"):
            install_hook(tmp_path)

    def test_uninstall_removes_hook(self, tmp_path):
        repo = self._make_repo(tmp_path)
        install_hook(repo)
        uninstall_hook(repo)
        hook = repo / ".git" / "hooks" / "pre-push"
        assert not hook.exists()

    def test_uninstall_refuses_foreign_hook(self, tmp_path):
        repo = self._make_repo(tmp_path)
        hook = repo / ".git" / "hooks" / "pre-push"
        hook.write_text("#!/bin/bash\necho custom hook\n", encoding="utf-8")
        with pytest.raises(HookError, match="not installed by Git-Guard"):
            uninstall_hook(repo)

    def test_uninstall_no_hook_raises(self, tmp_path):
        repo = self._make_repo(tmp_path)
        with pytest.raises(HookError, match="No pre-push hook found"):
            uninstall_hook(repo)


# ===========================================================================
# CLI
# ===========================================================================

class TestCLI:
    def test_help_returns_zero(self):
        assert main(["--help"]) == 0

    def test_no_args_returns_zero(self):
        assert main([]) == 0

    def test_unknown_command_returns_nonzero(self):
        assert main(["bogus-command"]) == 2

    def test_scan_clean_directory(self, tmp_path):
        (tmp_path / "clean.py").write_text('x = 1\n', encoding="utf-8")
        assert main(["scan", str(tmp_path)]) == 0

    def test_scan_dirty_directory(self, tmp_path):
        (tmp_path / "secrets.py").write_text(
            'key = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
        )
        assert main(["scan", str(tmp_path)]) == 1

    def test_scan_nonexistent_path(self, tmp_path):
        assert main(["scan", str(tmp_path / "no_such_dir")]) == 2

    def test_scan_single_file_with_secret(self, tmp_path):
        p = tmp_path / "creds.py"
        p.write_text('key = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
        assert main(["scan", str(p)]) == 1

    def test_install_hook_cli(self, tmp_path):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        assert main(["install-hook", str(tmp_path)]) == 0
        assert (tmp_path / ".git" / "hooks" / "pre-push").exists()

    def test_uninstall_hook_cli(self, tmp_path):
        (tmp_path / ".git" / "hooks").mkdir(parents=True)
        main(["install-hook", str(tmp_path)])
        assert main(["uninstall-hook", str(tmp_path)]) == 0
        assert not (tmp_path / ".git" / "hooks" / "pre-push").exists()

    def test_install_hook_non_repo(self, tmp_path):
        assert main(["install-hook", str(tmp_path)]) == 1

    def test_uninstall_hook_non_repo(self, tmp_path):
        assert main(["uninstall-hook", str(tmp_path)]) == 1
