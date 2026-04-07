"""
Core scanning engine for Git-Guard.

Detects API keys, tokens, and secrets in source files using
regex patterns and Shannon entropy analysis.
"""

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Generator, Optional

# ---------------------------------------------------------------------------
# Detection patterns
# ---------------------------------------------------------------------------

# Each entry: (label, compiled pattern)
PATTERNS: list[tuple[str, re.Pattern]] = [
    # ── Cloud providers ──────────────────────────────────────────────────
    ("AWS Access Key ID",       re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS Secret Access Key",   re.compile(
        r"(?i)aws.{0,20}['\"\s][0-9a-zA-Z\/+]{40}['\"\s]"
    )),
    # ── Version-control platforms ────────────────────────────────────────
    ("GitHub Personal Token",   re.compile(
        r"ghp_[A-Za-z0-9]{36}"
    )),
    ("GitHub Fine-Grained PAT", re.compile(
        r"github_pat_[A-Za-z0-9_]{82}"
    )),
    ("GitHub OAuth Token",      re.compile(r"gho_[A-Za-z0-9]{36}")),
    ("GitHub App Token",        re.compile(r"ghs_[A-Za-z0-9]{36}")),
    ("GitLab Token",            re.compile(r"glpat-[A-Za-z0-9\-_]{20}")),
    # ── Google ───────────────────────────────────────────────────────────
    ("Google API Key",          re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("Google OAuth Token",      re.compile(r"ya29\.[0-9A-Za-z\-_]+")),
    # ── Communication / SaaS ─────────────────────────────────────────────
    ("Slack Bot Token",         re.compile(
        r"xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}"
    )),
    ("Slack User Token",        re.compile(r"xoxp-[0-9A-Za-z\-]+")),
    ("Slack Webhook",           re.compile(
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]{8}/B[A-Za-z0-9_]{8}/[A-Za-z0-9_]{24}"
    )),
    # ── Payments ─────────────────────────────────────────────────────────
    ("Stripe Live Secret Key",  re.compile(r"sk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Live Public Key",  re.compile(r"pk_live_[0-9a-zA-Z]{24,}")),
    ("Stripe Test Secret Key",  re.compile(r"sk_test_[0-9a-zA-Z]{24,}")),
    # ── Telephony ────────────────────────────────────────────────────────
    ("Twilio API Key",          re.compile(r"SK[0-9a-fA-F]{32}")),
    ("Twilio Account SID",      re.compile(r"AC[a-z0-9]{32}")),
    # ── Email / messaging ────────────────────────────────────────────────
    ("SendGrid API Key",        re.compile(
        r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"
    )),
    ("Mailgun API Key",         re.compile(r"key-[0-9a-zA-Z]{32}")),
    # ── Crypto / auth ────────────────────────────────────────────────────
    ("JWT Token",               re.compile(
        r"ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"
    )),
    ("Private Key Block",       re.compile(
        r"-----BEGIN\s+(RSA|DSA|EC|PGP|OPENSSH)\s+PRIVATE\s+KEY-----"
    )),
    # ── NPM ──────────────────────────────────────────────────────────────
    ("NPM Auth Token",          re.compile(r"npm_[A-Za-z0-9]{36}")),
    # ── Generic high-confidence patterns ─────────────────────────────────
    ("Generic API Key",         re.compile(
        r"(?i)(api[_\-]?key|apikey)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"
    )),
    ("Generic Secret",          re.compile(
        r"(?i)(secret[_\-]?key|client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"
    )),
    ("Generic Access Token",    re.compile(
        r"(?i)(access[_\-]?token|auth[_\-]?token)\s*[=:]\s*['\"]?([A-Za-z0-9\-_]{20,})['\"]?"
    )),
    ("Password in URL",         re.compile(
        r"[a-zA-Z][a-zA-Z0-9+\-.]*://[^:@\s]+:[^@\s]+@"
    )),
]

# ---------------------------------------------------------------------------
# Files / paths to skip (binary, vendored, etc.)
# ---------------------------------------------------------------------------

SKIP_EXTENSIONS: frozenset[str] = frozenset(
    {
        ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".svg",
        ".pdf", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z",
        ".exe", ".dll", ".so", ".dylib", ".wasm",
        ".pyc", ".pyo", ".class", ".o", ".a",
        ".mp3", ".mp4", ".wav", ".avi", ".mov",
        ".ttf", ".woff", ".woff2", ".eot",
        ".lock",          # package-lock.json etc. contain many hashes
        ".sum",           # go.sum
    }
)

SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git", "node_modules", ".venv", "venv", "__pycache__",
        ".tox", "dist", "build", "vendor", ".idea", ".vscode",
        "coverage", ".mypy_cache", ".pytest_cache",
    }
)


# ---------------------------------------------------------------------------
# Allowlist helpers
# ---------------------------------------------------------------------------

ALLOWLIST_FILENAME = ".gitguardignore"


def load_allowlist(root: Path) -> list[re.Pattern]:
    """
    Read ``.gitguardignore`` from *root* and compile each non-comment line
    as a regex pattern used to skip matching findings.
    """
    allowlist_path = root / ALLOWLIST_FILENAME
    patterns: list[re.Pattern] = []
    if allowlist_path.is_file():
        for line in allowlist_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                try:
                    patterns.append(re.compile(line))
                except re.error:
                    pass
    return patterns


# ---------------------------------------------------------------------------
# Finding dataclass
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    """A single detected secret."""

    file: str
    line_number: int
    line_content: str
    pattern_name: str
    matched_text: str

    def __str__(self) -> str:
        # Truncate very long lines for readability
        snippet = self.line_content.strip()
        if len(snippet) > 120:
            snippet = snippet[:117] + "..."
        return (
            f"  [{self.pattern_name}]\n"
            f"    File : {self.file}\n"
            f"    Line : {self.line_number}\n"
            f"    Match: {self.matched_text}\n"
            f"    Code : {snippet}"
        )


# ---------------------------------------------------------------------------
# Entropy helper
# ---------------------------------------------------------------------------

def _shannon_entropy(data: str) -> float:
    """Return the Shannon entropy (bits per character) of *data*."""
    if not data:
        return 0.0
    freq: dict[str, int] = {}
    for ch in data:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(data)
    return -sum(
        (count / length) * math.log2(count / length)
        for count in freq.values()
    )


# ---------------------------------------------------------------------------
# Low-entropy allowlist (reduce false positives for generic patterns)
# ---------------------------------------------------------------------------

# Generic patterns that capture a value group — we only flag them when the
# captured value has high entropy (likely a real secret).
_GENERIC_PATTERN_NAMES: frozenset[str] = frozenset(
    {"Generic API Key", "Generic Secret", "Generic Access Token"}
)

_MIN_ENTROPY_FOR_GENERIC = 3.2  # bits/char


def _is_high_entropy(match: re.Match, pattern_name: str) -> bool:
    """
    For generic patterns that capture a value group, return False if the
    captured value has suspiciously low entropy (e.g., placeholder text).
    """
    if pattern_name not in _GENERIC_PATTERN_NAMES:
        return True
    # Group 2 holds the captured value for generic patterns
    groups = match.groups()
    value = groups[-1] if groups else match.group(0)
    return _shannon_entropy(value) >= _MIN_ENTROPY_FOR_GENERIC


# ---------------------------------------------------------------------------
# File scanning
# ---------------------------------------------------------------------------

def scan_file(
    filepath: Path,
    allowlist: Optional[list[re.Pattern]] = None,
) -> list[Finding]:
    """
    Scan a single file and return a list of :class:`Finding` objects.

    Binary files and files with a skipped extension are silently ignored.
    """
    findings: list[Finding] = []

    if filepath.suffix.lower() in SKIP_EXTENSIONS:
        return findings

    try:
        text = filepath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    lines = text.splitlines()
    for line_no, line in enumerate(lines, start=1):
        for pattern_name, pattern in PATTERNS:
            match = pattern.search(line)
            if match is None:
                continue
            if not _is_high_entropy(match, pattern_name):
                continue
            matched_text = match.group(0)
            # Check against allowlist
            if allowlist and any(
                al.search(matched_text) or al.search(str(filepath))
                for al in allowlist
            ):
                continue
            findings.append(
                Finding(
                    file=str(filepath),
                    line_number=line_no,
                    line_content=line,
                    pattern_name=pattern_name,
                    matched_text=matched_text,
                )
            )
    return findings


# ---------------------------------------------------------------------------
# Directory / staged-file scanning
# ---------------------------------------------------------------------------

def _iter_files(root: Path) -> Generator[Path, None, None]:
    """Walk *root* recursively, yielding scannable files."""
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skipped directories in-place so os.walk won't descend
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            yield Path(dirpath) / filename


def scan_directory(
    root: Path,
    allowlist: Optional[list[re.Pattern]] = None,
) -> list[Finding]:
    """
    Recursively scan all files under *root* and return all findings.
    """
    findings: list[Finding] = []
    for filepath in _iter_files(root):
        findings.extend(scan_file(filepath, allowlist))
    return findings


def scan_files(
    file_paths: list[Path],
    allowlist: Optional[list[re.Pattern]] = None,
) -> list[Finding]:
    """
    Scan a specific list of files (e.g., staged files) and return findings.
    """
    findings: list[Finding] = []
    for filepath in file_paths:
        if filepath.exists():
            findings.extend(scan_file(filepath, allowlist))
    return findings
