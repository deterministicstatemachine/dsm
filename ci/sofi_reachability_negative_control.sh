#!/usr/bin/env bash
# The negative control of Gate G1 (MR-SOFI-0273): on a tree whose one public
# function under Core's SoFi module has no production caller,
# ci/sofi_reachability.py fails and names it; once production code calls it,
# the gate passes. The gate and its helper are copied, unchanged, into a
# scratch tree with the workspace's layout, so what runs here is what runs on
# the real tree.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

core="$tmp/dsm_client/deterministic_state_machine/dsm/src"
sdk="$tmp/dsm_client/deterministic_state_machine/dsm_sdk/src"
mkdir -p "$tmp/ci" "$core/sofi" "$sdk" "$tmp/dsm_storage_node/src"
cp "$here/ci/sofi_reachability.py" "$here/ci/production_text.py" "$tmp/ci/"
cat > "$core/sofi/probe.rs" <<'RUST'
pub fn uncalled_probe() -> u8 {
    7
}
RUST
cat > "$sdk/lib.rs" <<'RUST'
pub fn caller() -> u8 {
    3
}
RUST

cd "$tmp"
if out="$(python3 ci/sofi_reachability.py 2>&1)"; then
    echo "[FAIL] G1 passed a tree whose public SoFi function has no caller"
    exit 1
fi
if ! grep -q "no production caller: .*/sofi/probe.rs uncalled_probe" <<<"$out"; then
    echo "[FAIL] G1 failed without naming the uncalled function:"
    echo "$out"
    exit 1
fi

cat > "$sdk/lib.rs" <<'RUST'
use dsm::sofi::probe::uncalled_probe;

pub fn caller() -> u8 {
    uncalled_probe()
}
RUST
if ! out="$(python3 ci/sofi_reachability.py 2>&1)"; then
    echo "[FAIL] G1 refused a public SoFi function production code calls:"
    echo "$out"
    exit 1
fi
echo "G1 negative control: an uncalled public SoFi function fails and is named; a called one passes"
