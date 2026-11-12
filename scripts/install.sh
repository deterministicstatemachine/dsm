#!/bin/sh
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# Install what you need to plug an app into DSM, from a DSM release, with no
# Rust, no protobuf compiler and no copy of the DSM repo:
#
#   dsm-app-host          your app's own DSM account (a prebuilt binary for this machine)
#   dsm-app               your app's account from the terminal: up, id, owned, offer, send, ...
#   dsm-dev-wallet        a player's wallet in the terminal, to test with no phone
#   dsm-connect-starter   the starter app, on http://127.0.0.1:3000
#   the TypeScript and Python clients, as packages to install into your app
#
# Every file is checked against the release's SHA256SUMS before anything is
# unpacked or run; a file that is missing from it, or does not match, stops
# the install and nothing is changed.
#
#   sh install.sh
#
# Linux (x86-64, ARM64; on Windows, WSL2) and macOS (Apple silicon, Intel).
# The commands need Node.js 20 or later.
#
# Optional:
#   DSM_PREFIX=DIR        install under DIR (default ~/.local): DIR/bin and DIR/share/dsm
#   DSM_RELEASE_URL=URL   fetch from URL instead of the release's own page (a mirror, or a
#                         directory of a build: file:///path/to/dist)

set -eu

# This script installs the release it is part of.
DSM_VERSION="0.1.0-beta.4"

BASE="${DSM_RELEASE_URL:-https://github.com/deterministicstatemachine/dsm/releases/download/v$DSM_VERSION}"
PREFIX="${DSM_PREFIX:-$HOME/.local}"

say() { printf '%s\n' "$*"; }
# A path as shown: under your home directory, as ~/...
shown() { case "$1" in "$HOME"/*) printf '~/%s' "${1#"$HOME"/}" ;; *) printf '%s' "$1" ;; esac; }
fail() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64 | Linux-amd64) PLATFORM=linux-x86_64 ;;
    Linux-aarch64 | Linux-arm64) PLATFORM=linux-arm64 ;;
    Darwin-arm64) PLATFORM=macos-arm64 ;;
    Darwin-x86_64) PLATFORM=macos-x86_64 ;;
    *) fail "no dsm-app-host is built for $(uname -s) $(uname -m): Linux x86-64 or ARM64 (Windows: WSL2), macOS" ;;
esac

command -v curl >/dev/null 2>&1 || fail "curl is needed to download the release"
if command -v sha256sum >/dev/null 2>&1; then
    sha256() { sha256sum "$1" | cut -d' ' -f1; }
elif command -v shasum >/dev/null 2>&1; then
    sha256() { shasum -a 256 "$1" | cut -d' ' -f1; }
else
    fail "sha256sum or shasum is needed to check the downloads"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

fetch() {
    curl --proto '=https,file' --tlsv1.2 -fsSL -o "$WORK/$1" "$BASE/$1" || fail "could not download $BASE/$1"
}

# The release's checksums, then each file, checked before it is used.
fetch SHA256SUMS
check() {
    want="$(awk -v f="$1" '$2 == f || $2 == "*" f { print $1 }' "$WORK/SHA256SUMS")"
    [ -n "$want" ] || fail "$1 is not in the release's SHA256SUMS; nothing was installed"
    got="$(sha256 "$WORK/$1")"
    [ "$got" = "$want" ] || fail "$1 does not match the release's SHA256SUMS (expected $want, got $got); nothing was installed"
    say "  verified  $1  sha256 $got"
}

HOST="dsm-app-host-$DSM_VERSION-$PLATFORM"
TOOLS="dsm-developer-$DSM_VERSION"
say "DSM $DSM_VERSION for $PLATFORM, from $BASE"
fetch "$HOST.tar.gz"
fetch "$TOOLS.tar.gz"
check "$HOST.tar.gz"
check "$TOOLS.tar.gz"

mkdir -p "$WORK/host" "$WORK/tools"
tar -C "$WORK/host" -xzf "$WORK/$HOST.tar.gz"
tar -C "$WORK/tools" -xzf "$WORK/$TOOLS.tar.gz"
[ -x "$WORK/host/$HOST/dsm-app-host" ] || fail "$HOST.tar.gz holds no dsm-app-host"
[ -d "$WORK/tools/$TOOLS/dsm-app-client" ] || fail "$TOOLS.tar.gz holds no dsm-app-client"

BIN="$PREFIX/bin"
SHARE="$PREFIX/share/dsm"
mkdir -p "$BIN" "$PREFIX/share"
cp "$WORK/host/$HOST/dsm-app-host" "$BIN/dsm-app-host.new"
chmod 755 "$BIN/dsm-app-host.new"
mv -f "$BIN/dsm-app-host.new" "$BIN/dsm-app-host"
rm -rf "$SHARE.new"
mv "$WORK/tools/$TOOLS" "$SHARE.new"
echo "$DSM_VERSION" >"$SHARE.new/VERSION"
rm -rf "$SHARE"
mv "$SHARE.new" "$SHARE"

launcher() {
    cat >"$BIN/$1" <<EOF
#!/bin/sh
# DSM $DSM_VERSION, installed by install.sh
exec node "$SHARE/$2" "\$@"
EOF
    chmod 755 "$BIN/$1"
}
launcher dsm-app dsm-app-client/dist/app-cli.js
launcher dsm-dev-wallet dsm-app-client/dist/dev-wallet.js
launcher dsm-connect-starter connect-starter/dist/server.js

say ""
say "installed:"
say "  $(shown "$BIN")/dsm-app-host        $("$BIN/dsm-app-host" --version)"
say "  $(shown "$BIN")/dsm-app"
say "  $(shown "$BIN")/dsm-dev-wallet"
say "  $(shown "$BIN")/dsm-connect-starter"
say "  the clients, to install into your app:"
for f in "$SHARE"/clients/*; do say "    $(shown "$f")"; done

if command -v node >/dev/null 2>&1; then
    major="$(node -p 'process.versions.node.split(".")[0]')"
    [ "$major" -ge 20 ] || say "note: node is $(node --version); dsm-app and the clients need Node.js 20 or later"
else
    say "note: no node here; dsm-app, dsm-dev-wallet and the TypeScript client need Node.js 20 or later"
fi
case ":$PATH:" in
    *":$BIN:"*) ;;
    *) case "$BIN" in
           "$HOME"/*) on_path="\$HOME/${BIN#"$HOME"/}" ;;
           *) on_path="$BIN" ;;
       esac
       say "note: $(shown "$BIN") is not on your PATH; add it (and the same line to your shell's profile):"
       say "  export PATH=\"$on_path:\$PATH\"" ;;
esac
