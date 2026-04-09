#!/usr/bin/env bash
# GitGuard — Global pre-push hook installer
set -euo pipefail

HOOK_DIR="$HOME/.githooks"
HOOK_SRC="$(cd "$(dirname "$0")/.." && pwd)/hooks/pre-push.js"
HOOK_DEST="$HOOK_DIR/pre-push"

mkdir -p "$HOOK_DIR"

if [ ! -f "$HOOK_SRC" ]; then
  echo "❌ Hook source not found at: $HOOK_SRC"
  echo "   Make sure you are running this script from the gitguard project root."
  exit 1
fi

cp "$HOOK_SRC" "$HOOK_DEST"
chmod +x "$HOOK_DEST"

git config --global core.hooksPath "$HOOK_DIR"

echo "✅ GitGuard pre-push hook installed globally"
echo "   Hook path : $HOOK_DEST"
echo "   Git config: core.hooksPath = $HOOK_DIR"
