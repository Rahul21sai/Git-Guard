"""
Git hook management for Git-Guard.

Provides :func:`install_hook` and :func:`uninstall_hook` to add or remove
the Git-Guard pre-push hook from a local git repository.
"""

import os
import stat
from pathlib import Path

# Marker written inside the hook so we can identify and safely remove it later.
_MARKER = "# git-guard-managed"

# The hook script installed into .git/hooks/pre-push
_HOOK_SCRIPT = """\
#!/usr/bin/env bash
# git-guard-managed
#
# Git-Guard pre-push hook
# Scans staged/committed files for secrets before they reach the remote.
# Installed by: gitguard install-hook
# Remove with:  gitguard uninstall-hook

set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)

# Prefer the locally installed gitguard command; fall back to python -m
if command -v gitguard &>/dev/null; then
    SCANNER="gitguard scan"
else
    SCANNER="python3 -m gitguard.cli scan"
fi

echo "[Git-Guard] Scanning repository for secrets ..."
if $SCANNER "$REPO_ROOT"; then
    echo "[Git-Guard] ✔ No secrets detected. Proceeding with push."
    exit 0
else
    echo ""
    echo "[Git-Guard] ✖ Push BLOCKED — secrets detected in the repository."
    echo "[Git-Guard] Review the findings above, revoke any exposed keys,"
    echo "[Git-Guard] and remove the secrets before pushing."
    echo ""
    exit 1
fi
"""


class HookError(RuntimeError):
    """Raised when a hook operation fails."""


def _hooks_dir(repo_path: Path) -> Path:
    git_dir = repo_path / ".git"
    if not git_dir.is_dir():
        raise HookError(
            f"'{repo_path}' is not a git repository (no .git directory found)."
        )
    return git_dir / "hooks"


def install_hook(repo_path: Path) -> None:
    """
    Install the Git-Guard pre-push hook in the git repository at *repo_path*.

    If a pre-push hook already exists and was **not** installed by Git-Guard,
    a :class:`HookError` is raised to avoid overwriting user content.
    """
    hooks_dir = _hooks_dir(repo_path)
    hooks_dir.mkdir(exist_ok=True)

    hook_file = hooks_dir / "pre-push"

    if hook_file.exists():
        existing = hook_file.read_text(encoding="utf-8")
        if _MARKER not in existing:
            raise HookError(
                f"A pre-push hook already exists at '{hook_file}' and was not "
                "installed by Git-Guard. Remove it manually before installing "
                "the Git-Guard hook."
            )

    hook_file.write_text(_HOOK_SCRIPT, encoding="utf-8")
    # Make the hook executable
    current = hook_file.stat().st_mode
    hook_file.chmod(current | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def uninstall_hook(repo_path: Path) -> None:
    """
    Remove the Git-Guard pre-push hook from the git repository at *repo_path*.

    Only removes the hook if it was previously installed by Git-Guard (i.e.,
    contains the managed marker). Raises :class:`HookError` otherwise.
    """
    hooks_dir = _hooks_dir(repo_path)
    hook_file = hooks_dir / "pre-push"

    if not hook_file.exists():
        raise HookError(
            f"No pre-push hook found at '{hook_file}'. Nothing to remove."
        )

    existing = hook_file.read_text(encoding="utf-8")
    if _MARKER not in existing:
        raise HookError(
            f"The pre-push hook at '{hook_file}' was not installed by "
            "Git-Guard. Refusing to remove it automatically."
        )

    hook_file.unlink()
