#!/usr/bin/env bash
# GitGuard — Uninstaller
set -euo pipefail

HOOK_DIR="$HOME/.githooks"
HOOK_DEST="$HOOK_DIR/pre-push"

if [ -f "$HOOK_DEST" ]; then
  rm -f "$HOOK_DEST"
  echo "✅ Removed GitGuard pre-push hook: $HOOK_DEST"
else
  echo "ℹ️  No GitGuard hook found at: $HOOK_DEST"
fi

# Reset global hooksPath only if it still points to our directory
CURRENT_HOOKS=$(git config --global core.hooksPath 2>/dev/null || true)
if [ "$CURRENT_HOOKS" = "$HOOK_DIR" ]; then
  git config --global --unset core.hooksPath
  echo "✅ Reset git global core.hooksPath"
fi

echo "✅ GitGuard uninstalled."
