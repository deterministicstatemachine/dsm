#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
#
# A newcomer's first run, proven: a clean Ubuntu (in Docker) with nothing on
# it but what QUICKSTART.md's prerequisites say to install, a fresh clone of
# this commit, and BUILDING_APPS.md's commands alone, in the docs' order, in
# TypeScript and in Python, each to a wallet connected and a payment received.
#
# Nothing here knows more than the docs:
#   - the Linux prerequisites are read out of QUICKSTART.md's "Prerequisites"
#     section (every bash block under a "Linux" label) and run as written;
#   - every `make ...` and `python3 ...` command the newcomer types is checked
#     to be one BUILDING_APPS.md shows, before anything runs.
# So the docs cannot drift from what works. `make first-run` runs this; so
# does a release.
#
# What the newcomer does, in order:
#   make app-dev; make starter; press "Show the connect code" (the starter's
#   POST /api/offer, which is what the button sends); make dev-wallet;
#   make dev-wallet-connect CODE=...; ask the wallet to send 0.05 ERA (the
#   page's button: POST /api/ask) and watch the fact become `received`.
#   Then Python: the virtual environment and pip install the guide shows,
#   clients/python/examples/first_payment.py, the wallet connected to the
#   code it prints, and its fact `received`.
#
# Needs Docker. Logs under .dsm-dev/first-run/. FIRST_RUN_IMAGE_ONLY=1 builds
# the clean machine and stops.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO"
OUT="$REPO/.dsm-dev/first-run"
IMAGE="dsm-first-run-machine"
mkdir -p "$OUT"

# ---- the commands the newcomer types, each one the guide shows -------------
TYPED=(
    "make app-dev"
    "make starter"
    "make dev-wallet"
    "make dev-wallet-connect CODE="
    "python3 -m venv .venv && . .venv/bin/activate"
    "pip install -e clients/python"
    "python3 clients/python/examples/first_payment.py"
    "make dev-down"
)
for cmd in "${TYPED[@]}"; do
    if ! grep -qF -- "$cmd" BUILDING_APPS.md; then
        echo "[first-run] BUILDING_APPS.md no longer shows: $cmd" >&2
        exit 1
    fi
done

# ---- the docs' Linux prerequisites, verbatim --------------------------------
awk '
    /^## Prerequisites/ { sec = 1; next }
    sec && /^## /       { exit }
    sec && /^### /      { next }
    sec && /^Linux/     { linux = 1; next }
    sec && /^(macOS|All platforms|Windows)/ { linux = 0 }
    sec && linux && /^```bash/ { block = 1; next }
    sec && block && /^```/     { block = 0; next }
    sec && block               { print }
' QUICKSTART.md >"$OUT/prerequisites.sh"
if ! grep -q 'apt install' "$OUT/prerequisites.sh"; then
    echo "[first-run] QUICKSTART.md's Prerequisites have no Linux apt lines" >&2
    exit 1
fi
echo "[first-run] the prerequisites, from QUICKSTART.md:"
sed 's/^/    /' "$OUT/prerequisites.sh"

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
# QUICKSTART.md, Prerequisites, Linux: as written.
COPY --chown=newcomer prerequisites.sh /first-run/prerequisites.sh
RUN set -e; . /first-run/prerequisites.sh
# QUICKSTART.md, All platforms: "Rust via rustup.rs", which says to run this.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --no-modify-path
ENV PATH="/home/newcomer/.cargo/bin:${PATH}"
EOF
echo "[first-run] building the clean machine ($IMAGE)"
docker build -q -t "$IMAGE" "$OUT" >"$OUT/image.log" 2>&1 || {
    cat "$OUT/image.log" >&2
    echo "[first-run] the clean machine did not build: the prerequisites above do not install" >&2
    exit 1
}
if [ -n "${FIRST_RUN_IMAGE_ONLY:-}" ]; then exit 0; fi

# ---- this commit, as a clone -------------------------------------------------
git bundle create "$OUT/dsm.bundle" HEAD >/dev/null 2>&1
if [ -n "$(git status --porcelain)" ]; then
    echo "[first-run] note: uncommitted changes here are not in the clone the newcomer gets" >&2
fi

# ---- what the newcomer does --------------------------------------------------
cat >"$OUT/newcomer.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
step() { printf '\n==== [%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
json() { node -e "let d='';process.stdin.on('data',c=>d+=c).on('end',()=>{const v=JSON.parse(d);console.log($1)})"; }
starter() { curl -fsS --max-time 10 "$@"; }

step "the machine: node $(node --version), $(protoc --version), $(cargo --version | cut -d' ' -f1-2), $(psql --version), $(python3 --version)"
sudo service postgresql start >/dev/null   # the machine booted: its server is up

step "git clone (the docs: git clone https://github.com/deterministicstatemachine/dsm.git; here, this commit)"
git -c advice.detachedHead=false clone -q /first-run/dsm.bundle dsm && cd dsm

step "make app-dev"
make app-dev

step "make starter   (in the background; the docs: open http://127.0.0.1:3000)"
(make starter >~/starter.log 2>&1 &)
for _ in $(seq 1 300); do starter http://127.0.0.1:3000/api/state >/dev/null 2>&1 && break; sleep 1; done
starter http://127.0.0.1:3000/api/state >/dev/null || { echo "the starter never answered:"; tail -20 ~/starter.log; exit 1; }
echo "your account owns: $(starter http://127.0.0.1:3000/api/state | json 'v.owned.map(o=>o.symbol+" "+o.amount).join(", ")')"

step "press Show the connect code   (the button's call: POST /api/offer)"
CODE=$(starter -X POST -H 'content-type: application/json' -d '{}' http://127.0.0.1:3000/api/offer | json 'v.code')
echo "${CODE:0:48}..."

step "make dev-wallet"
make dev-wallet

step "make dev-wallet-connect CODE=..."
make dev-wallet-connect CODE="$CODE"

step "ask the connected wallet to send 0.05 ERA   (the button's call: POST /api/ask)"
CONNECTION=$(starter http://127.0.0.1:3000/api/state | json 'v.connections.filter(c=>c.connected)[0].id')
starter -X POST -H 'content-type: application/json' \
    -d "{\"connection\":\"$CONNECTION\",\"ask\":{\"kind\":\"send\",\"object\":\"ERA\",\"amount\":\"0.05\"}}" \
    http://127.0.0.1:3000/api/ask >/dev/null
REQUESTS=""
for _ in $(seq 1 240); do
    REQUESTS=$(starter http://127.0.0.1:3000/api/state | json 'v.requests.map(r=>r.outcome+"/"+r.fact+(r.error?" error: "+r.error:"")).join("; ")')
    case "$REQUESTS" in *received*) break ;; esac
    sleep 1
done
echo "the request: $REQUESTS"
case "$REQUESTS" in
    *received*) echo "TYPESCRIPT: a wallet connected, 0.05 ERA received" ;;
    *) echo "TYPESCRIPT: the fact never became received"; exit 1 ;;
esac

step "python3 -m venv .venv && . .venv/bin/activate"
python3 -m venv .venv && . .venv/bin/activate

step "pip install -e clients/python"
pip install --quiet -e clients/python

step "python3 clients/python/examples/first_payment.py   (in the background; then the wallet connects to its code)"
python3 clients/python/examples/first_payment.py >~/first_payment.log 2>&1 &
PY=$!
for _ in $(seq 1 120); do
    grep -q '^connect code: ' ~/first_payment.log && break
    kill -0 "$PY" 2>/dev/null || { cat ~/first_payment.log; exit 1; }
    sleep 1
done
PYCODE=$(sed -n 's/^connect code: //p' ~/first_payment.log | head -1)
[ -n "$PYCODE" ] || { echo "first_payment.py printed no connect code:"; cat ~/first_payment.log; exit 1; }
make dev-wallet-connect CODE="$PYCODE"
if wait "$PY"; then
    cat ~/first_payment.log
    echo "PYTHON: a wallet connected, 0.05 ERA received"
else
    cat ~/first_payment.log
    echo "PYTHON: first_payment.py failed"
    exit 1
fi

step "make dev-down"
make dev-down >/dev/null
step "FIRST RUN: both paths reached a payment received"
EOF
chmod +x "$OUT/newcomer.sh"

echo "[first-run] the newcomer's run (log: $OUT/newcomer.log)"
docker rm -f dsm-first-run >/dev/null 2>&1 || :
set +e
docker run --name dsm-first-run -v "$OUT:/first-run:ro" "$IMAGE" bash -lc /first-run/newcomer.sh 2>&1 | tee "$OUT/newcomer.log"
code=${PIPESTATUS[0]}
set -e
docker rm -f dsm-first-run >/dev/null 2>&1 || :
if [ "$code" != 0 ]; then
    echo "[first-run] FAILED (exit $code): a newcomer following the docs stalls where the log above stops" >&2
    exit "$code"
fi
echo "[first-run] passed: a clean machine, the docs alone, TypeScript and Python each to a payment received"
