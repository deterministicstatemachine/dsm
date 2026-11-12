#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# The developer half of a release, finished: scripts/install.sh copied in
# beside the archives, after checking that it installs this version, and
# SHA256SUMS written over every archive and the script. install.sh reads
# SHA256SUMS before it unpacks anything.
#
# usage: scripts/release/checksums.sh <dir> <version>

set -euo pipefail

DIR="$1"
VERSION="$2"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

pinned="$(sed -n 's/^DSM_VERSION="\(.*\)"$/\1/p' "$REPO/scripts/install.sh")"
[ "$pinned" = "$VERSION" ] || { echo "scripts/install.sh installs $pinned, not $VERSION" >&2; exit 1; }
cp "$REPO/scripts/install.sh" "$DIR/install.sh"

cd "$DIR"
want=(install.sh "dsm-developer-$VERSION.tar.gz")
for platform in linux-x86_64 linux-arm64 macos-arm64 macos-x86_64; do
    want+=("dsm-app-host-$VERSION-$platform.tar.gz")
done
present=()
for f in "${want[@]}"; do
    if [ -f "$f" ]; then
        present+=("$f")
    elif [ -z "${CHECKSUMS_PARTIAL:-}" ]; then
        echo "$DIR has no $f" >&2
        exit 1
    fi
done
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${present[@]}" >SHA256SUMS
else
    shasum -a 256 "${present[@]}" >SHA256SUMS
fi
cat SHA256SUMS
