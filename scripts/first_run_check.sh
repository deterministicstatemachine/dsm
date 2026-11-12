#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A newcomer's first run, proven: a clean Ubuntu (in Docker) with nothing on
# it but what the guide's setup page says to install (guide/src/setup.md:
# Node.js, Python's venv, curl; no git, no Rust, no protobuf compiler), no
# copy of the DSM repo, and BUILDING_APPS.md's commands alone, in the docs'
# order, in TypeScript and in Python, each to a wallet connected and a payment
# received. The accounts go on the beta network, the hosted storage set, so
# the machine runs no node and no PostgreSQL, and the run needs outbound HTTPS
# to the fleet, npm's registry and PyPI.
#
# What it installs is a release's own files, the way a developer installs a
# release: install.sh, SHA256SUMS, the host archive for the machine and the
# developer archive.
#   FIRST_RUN_RELEASE=DIR   those files, already built (a release passes the
#                           ones it publishes, from app-host-binaries.yml)
#   otherwise               they are built here from this commit (committed
#                           files only): dsm-app-host for Linux in a Rust
#                           container, smoke-tested there, then packaged with
#                           scripts/release/ as CI packages them. Needs Node.js
#                           20+ and Python 3.10+ here.
# The one thing the newcomer types that differs: the guide downloads
# install.sh from the release's page; here it is the release directory's copy,
# and install.sh reads that directory (DSM_RELEASE_URL=file://...).
#
# Nothing here knows more than the docs:
#   - the Linux prerequisites are read out of guide/src/setup.md (the bash
#     block under "Ubuntu or Debian") and run as written;
#   - every command the newcomer types is checked to be one BUILDING_APPS.md
#     shows, before anything runs.
# So the docs cannot drift from what works. `make first-run` runs this; so
# does a release.
#
# What the newcomer does, in order:
#   sh install.sh; put ~/.local/bin on PATH; make a folder for the app;
#   dsm-app up; npm install the TypeScript client into it; dsm-connect-starter;
#   open http://127.0.0.1:3000 in a browser and press "Show the connect code";
#   dsm-dev-wallet up; dsm-dev-wallet connect <code>; on the page, ask the
#   connected wallet to send 0.05 ERA and watch that request's row show the
#   fact `received`. The browser is real: headless Chromium presses the page's
#   own buttons and reads its table (scripts/first_run_page.mjs), so the page
#   is proven, not its HTTP alone. Then Python: the virtual environment and pip
#   install the guide shows, first_payment.py, a second wallet (a wallet
#   connects to an app once, and the first is still connected to the starter)
#   connected to the code it prints, and its own request `received`.
#
# Needs Docker. Logs under .dsm-dev/first-run/. FIRST_RUN_IMAGE_ONLY=1 builds
# the clean machine and stops.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
OUT="$REPO/.dsm-dev/first-run"
IMAGE="dsm-first-run-machine"
mkdir -p "$OUT"
VERSION="$(sed -n 's/^DSM_VERSION="\(.*\)"$/\1/p' scripts/install.sh)"
PY_VERSION="$(echo "$VERSION" | sed -e 's/-beta\./b/' -e 's/-alpha\./a/' -e 's/-rc\./rc/')"
TS_CLIENT="~/.local/share/dsm/clients/dsm-app-client-$VERSION.tgz"
PY_CLIENT="~/.local/share/dsm/clients/dsm_app_client-$PY_VERSION-py3-none-any.whl"

# ---- the commands the newcomer types, each one the guide shows -------------
TYPED=(
    "releases/download/v$VERSION/install.sh"
    "sh install.sh"
    'export PATH="$HOME/.local/bin:$PATH"'
    "mkdir my-app && cd my-app"
    "dsm-app up"
    "npm init -y"
    "npm install $TS_CLIENT"
    "dsm-connect-starter"
    "dsm-dev-wallet up"
    "dsm-dev-wallet connect "
    "python3 -m venv .venv && . .venv/bin/activate"
    "pip install $PY_CLIENT"
    "python3 ~/.local/share/dsm/examples/first_payment.py"
    "DSM_WALLET_NAME=wallet2 dsm-dev-wallet up"
    "DSM_WALLET_NAME=wallet2 dsm-dev-wallet connect "
    "dsm-app down"
)
for cmd in "${TYPED[@]}"; do
    if ! grep -qF -- "$cmd" BUILDING_APPS.md; then
        echo "[first-run] BUILDING_APPS.md no longer shows: $cmd" >&2
        exit 1
    fi
done

# ---- the docs' Linux prerequisites, verbatim --------------------------------
awk '
    /^## 1\. Install the prerequisites/ { sec = 1; next }
    sec && /^## /                     { exit }
    sec && /^\*\*Ubuntu or Debian/    { linux = 1; next }
    sec && linux && /^```bash/        { block = 1; next }
    sec && block && /^```/            { exit }
    sec && block                      { print }
' guide/src/setup.md >"$OUT/prerequisites.sh"
if ! grep -q 'apt install' "$OUT/prerequisites.sh"; then
    echo "[first-run] guide/src/setup.md's prerequisites have no Ubuntu apt lines" >&2
    exit 1
fi
echo "[first-run] the prerequisites, from guide/src/setup.md:"
sed 's/^/    /' "$OUT/prerequisites.sh"

# ---- the release's files -----------------------------------------------------
docker_arch="$(docker info --format '{{.Architecture}}')"
case "$docker_arch" in
    x86_64 | amd64) PLATFORM=linux-x86_64 ;;
    aarch64 | arm64) PLATFORM=linux-arm64 ;;
    *) echo "[first-run] no dsm-app-host is built for Docker's $docker_arch" >&2; exit 1 ;;
esac
RELEASE="$OUT/release"
if [ -n "${FIRST_RUN_RELEASE:-}" ]; then
    rm -rf "$RELEASE"
    cp -R "$FIRST_RUN_RELEASE" "$RELEASE"
    echo "[first-run] the release's files: $FIRST_RUN_RELEASE"
else
    echo "[first-run] building the release's files from this commit ($(git rev-parse --short HEAD), committed files only)"
    if [ -n "$(git status --porcelain)" ]; then
        echo "[first-run] note: uncommitted changes here are not in what the newcomer installs" >&2
    fi
    rm -rf "$OUT/src" "$RELEASE"
    mkdir -p "$OUT/src" "$OUT/build" "$RELEASE"
    git archive HEAD | tar -x -C "$OUT/src"
    # dsm-app-host for this Docker's Linux, built and smoke-tested in a Rust
    # container (the cargo cache and target stay in Docker volumes).
    docker run --rm \
        -v "$OUT/src:/src:ro" -v "$OUT/build:/out" \
        -v dsm-first-run-cargo:/usr/local/cargo/registry -v dsm-first-run-target:/target \
        -e CARGO_TARGET_DIR=/target -e VERSION="$VERSION" \
        rust:1.98.0-bookworm bash -c '
            set -euo pipefail
            apt-get update -qq && apt-get install -y -qq protobuf-compiler >/dev/null
            cd /src
            cargo build --locked --release -p dsm-app-host
            bash scripts/release/smoke_app_host.sh /target/release/dsm-app-host "$VERSION"
            cp /target/release/dsm-app-host /out/dsm-app-host
        ' >"$OUT/build.log" 2>&1 || {
        tail -40 "$OUT/build.log" >&2
        echo "[first-run] dsm-app-host did not build for $PLATFORM" >&2
        exit 1
    }
    grep '^\[smoke\]' "$OUT/build.log" | sed 's/^/    /'
    bash "$OUT/src/scripts/release/package_app_host.sh" "$OUT/build/dsm-app-host" "$VERSION" "$PLATFORM" "$RELEASE"
    bash "$OUT/src/scripts/release/package_developer.sh" "$VERSION" "$RELEASE" >"$OUT/developer.log" 2>&1 || {
        tail -40 "$OUT/developer.log" >&2
        exit 1
    }
    CHECKSUMS_PARTIAL=1 bash "$OUT/src/scripts/release/checksums.sh" "$RELEASE" "$VERSION" >/dev/null
fi
for f in install.sh SHA256SUMS "dsm-app-host-$VERSION-$PLATFORM.tar.gz" "dsm-developer-$VERSION.tar.gz"; do
    [ -f "$RELEASE/$f" ] || { echo "[first-run] the release's files have no $f" >&2; exit 1; }
done
echo "[first-run] SHA256SUMS:"
sed 's/^/    /' "$RELEASE/SHA256SUMS"

# ---- the clean machine -------------------------------------------------------
cat >"$OUT/Dockerfile" <<'EOF'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends sudo ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash newcomer \
    && echo 'newcomer ALL=(ALL) NOPASSWD:ALL' >/etc/sudoers.d/newcomer
USER newcomer
WORKDIR /home/newcomer
SHELL ["/bin/bash", "-lc"]
# guide/src/setup.md, Ubuntu or Debian: as written.
COPY --chown=newcomer prerequisites.sh /first-run/prerequisites.sh
RUN set -e; . /first-run/prerequisites.sh
# The tester's hand, not the newcomer's machine: a browser to press the page's
# buttons with (scripts/first_run_page.mjs). It lives here, off PATH, and
# nothing the newcomer types uses it. (--with-deps adds Chromium's own shared
# libraries and fonts; none is anything DSM uses.)
ENV FIRST_RUN_HAND=/home/newcomer/.first-run-hand
RUN mkdir -p "$FIRST_RUN_HAND" && cd "$FIRST_RUN_HAND" \
    && echo '{ "name": "first-run-hand", "private": true }' >package.json \
    && npm install --no-audit --no-fund playwright@1.65.0 \
    && npx playwright install --with-deps chromium
EOF
cp "$REPO/scripts/first_run_page.mjs" "$OUT/first_run_page.mjs"
echo "[first-run] building the clean machine ($IMAGE)"
docker build --progress=plain -t "$IMAGE" "$OUT" >"$OUT/image.log" 2>&1 || {
    tail -60 "$OUT/image.log" >&2
    echo "[first-run] the clean machine did not build: the prerequisites above do not install" >&2
    exit 1
}
if [ -n "${FIRST_RUN_IMAGE_ONLY:-}" ]; then exit 0; fi

# ---- what the newcomer does --------------------------------------------------
cat >"$OUT/newcomer.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail
VERSION="$VERSION"
TS_CLIENT=$TS_CLIENT
PY_CLIENT=$PY_CLIENT
EOF
cat >>"$OUT/newcomer.sh" <<'EOF'
step() { printf '\n==== [%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
json() { node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const v=JSON.parse(d);console.log($1)})"; }
starter() { curl -fsS --max-time 10 "$@"; }
page() { node /first-run/first_run_page.mjs "$@"; }   # the tester's hand on the page: a real browser

step "the machine: node $(node --version), $(python3 --version); no git, no Rust, no protoc, no PostgreSQL, no storage node"
for tool in git cargo rustc protoc psql; do
    if command -v "$tool" >/dev/null 2>&1; then echo "$tool is installed: the prerequisites changed under this check"; exit 1; fi
done

step "curl -fsSLO https://github.com/deterministicstatemachine/dsm/releases/download/v$VERSION/install.sh   (here: the release directory's copy)"
cp /first-run/release/install.sh install.sh

step "sh install.sh   (DSM_RELEASE_URL=file:///first-run/release: this build's release files)"
DSM_RELEASE_URL=file:///first-run/release sh install.sh

step 'export PATH="$HOME/.local/bin:$PATH"'
export PATH="$HOME/.local/bin:$PATH"
dsm-app-host --version

step "mkdir my-app && cd my-app"
mkdir my-app && cd my-app

step "dsm-app up"
dsm-app up

step "npm init -y; npm install $TS_CLIENT"
npm init -y >/dev/null
eval "npm install --no-audit --no-fund $TS_CLIENT"
node --input-type=module -e 'import { localAccount } from "dsm-app-client"; const app = await localAccount("app"); console.log("connections:", JSON.stringify(await app.connections()));'

step "dsm-connect-starter   (in the background; the docs: open http://127.0.0.1:3000)"
(dsm-connect-starter >~/starter.log 2>&1 &)
for _ in $(seq 1 120); do starter http://127.0.0.1:3000/api/state >/dev/null 2>&1 && break; sleep 1; done
starter http://127.0.0.1:3000/api/state >/dev/null || { echo "the starter never answered:"; tail -20 ~/starter.log; exit 1; }
echo "your account owns: $(starter http://127.0.0.1:3000/api/state | json 'v.owned.map(o=>o.symbol+" "+o.amount).join(", ")')"

step "open http://127.0.0.1:3000 in a browser and press Show the connect code"
CODE=$(page offer)
echo "${CODE:0:48}..."

step "dsm-dev-wallet up"
dsm-dev-wallet up

step "dsm-dev-wallet connect dsm:connect/v1:..."
dsm-dev-wallet connect "$CODE"

step "on the page: ask the connected wallet to send 0.05 ERA, and watch that request's row"
page send 0.05
echo "TYPESCRIPT: a wallet connected, 0.05 ERA received"

step "python3 -m venv .venv && . .venv/bin/activate"
python3 -m venv .venv && . .venv/bin/activate

step "pip install $PY_CLIENT"
eval "pip install --quiet $PY_CLIENT"

step "python3 ~/.local/share/dsm/examples/first_payment.py   (in the background; then a wallet connects to its code)"
python3 ~/.local/share/dsm/examples/first_payment.py >~/first_payment.log 2>&1 &
PY=$!
for _ in $(seq 1 120); do
    grep -q '^connect code: ' ~/first_payment.log && break
    kill -0 "$PY" 2>/dev/null || { cat ~/first_payment.log; exit 1; }
    sleep 1
done
PYCODE=$(sed -n 's/^connect code: //p' ~/first_payment.log | head -1)
[ -n "$PYCODE" ] || { echo "first_payment.py printed no connect code:"; cat ~/first_payment.log; exit 1; }

step "DSM_WALLET_NAME=wallet2 dsm-dev-wallet up   (a second player's wallet: a wallet connects to an app once, and the first is connected to the starter)"
DSM_WALLET_NAME=wallet2 dsm-dev-wallet up

step "DSM_WALLET_NAME=wallet2 dsm-dev-wallet connect dsm:connect/v1:..."
DSM_WALLET_NAME=wallet2 dsm-dev-wallet connect "$PYCODE"
if wait "$PY"; then
    cat ~/first_payment.log
    echo "PYTHON: a wallet connected, 0.05 ERA received"
else
    cat ~/first_payment.log
    echo "PYTHON: first_payment.py failed"
    exit 1
fi

step "dsm-dev-wallet down; DSM_WALLET_NAME=wallet2 dsm-dev-wallet down; dsm-app down"
dsm-dev-wallet down
DSM_WALLET_NAME=wallet2 dsm-dev-wallet down
dsm-app down
step "FIRST RUN: no clone, no Rust; both paths reached a payment received"
EOF
chmod +x "$OUT/newcomer.sh"

echo "[first-run] the newcomer's run (log: $OUT/newcomer.log)"
docker rm -f dsm-first-run >/dev/null 2>&1 || :
set +e
docker run --name dsm-first-run -v "$OUT/newcomer.sh:/first-run/newcomer.sh:ro" \
    -v "$OUT/first_run_page.mjs:/first-run/first_run_page.mjs:ro" -v "$RELEASE:/first-run/release:ro" \
    "$IMAGE" bash -lc /first-run/newcomer.sh 2>&1 | tee "$OUT/newcomer.log"
code=${PIPESTATUS[0]}
set -e
docker rm -f dsm-first-run >/dev/null 2>&1 || :
if [ "$code" != 0 ]; then
    echo "[first-run] FAILED (exit $code): a newcomer following the docs stalls where the log above stops" >&2
    exit "$code"
fi
echo "[first-run] passed: a clean machine, no clone and no Rust, the docs alone, TypeScript and Python each to a payment received"
