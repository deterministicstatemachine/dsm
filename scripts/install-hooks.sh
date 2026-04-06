#!/usr/bin/env bash
# scripts/install-hooks.sh
# Wire the version-controlled hooks in .githooks/ into the local git config.
# Run once after cloning:
#
#   bash scripts/install-hooks.sh
#
set -euo pipefail

REPO_ROOT="$(git -C "$(dirname "$0")" rev-parse --show-toplevel)"
cd "$REPO_ROOT"

git config core.hooksPath .githooks
chmod +x .githooks/pre-commit .githooks/pre-push

echo "Git hooks installed — .githooks/ is now active."
echo "  pre-commit : fmt, protocol purity, forbidden symbols, bilateral gates"
echo "  pre-push   : clippy, tests, codegen enforcement, proto guards, Android NDK build (when NDK is configured)"
