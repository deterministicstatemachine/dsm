#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A built dsm-app-host as the release archive install.sh downloads:
#
#   <out>/dsm-app-host-<version>-<platform>.tar.gz
#     dsm-app-host-<version>-<platform>/dsm-app-host
#     dsm-app-host-<version>-<platform>/LICENSE-MIT, LICENSE-APACHE
#
# <platform> is linux-x86_64, linux-arm64, macos-arm64 or macos-x86_64.
#
# usage: scripts/release/package_app_host.sh <dsm-app-host> <version> <platform> <out-dir>

set -euo pipefail

BIN="$1"
VERSION="$2"
PLATFORM="$3"
OUT="$4"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

case "$PLATFORM" in
    linux-x86_64 | linux-arm64 | macos-arm64 | macos-x86_64) ;;
    *) echo "unknown platform $PLATFORM" >&2; exit 2 ;;
esac

NAME="dsm-app-host-$VERSION-$PLATFORM"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/$NAME" "$OUT"
cp "$BIN" "$STAGE/$NAME/dsm-app-host"
chmod 755 "$STAGE/$NAME/dsm-app-host"
cp "$REPO/LICENSE-MIT" "$REPO/LICENSE-APACHE" "$STAGE/$NAME/"
# Every file is recorded as root's, by number: the archive names no account
# of the machine that built it, so one unpacked as root hands nothing to
# whichever local account happens to have the builder's id.
case "$(tar --version 2>/dev/null)" in
    *GNU*) set -- --owner=0 --group=0 --numeric-owner ;;
    *) set -- --uid 0 --gid 0 --numeric-owner ;;
esac
tar "$@" -C "$STAGE" -cf - "$NAME" | gzip -n -9 >"$OUT/$NAME.tar.gz"
echo "[package] $OUT/$NAME.tar.gz"
