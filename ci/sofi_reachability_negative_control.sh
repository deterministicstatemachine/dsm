#!/usr/bin/env bash
# The negative control of Gate G1 (MR-SOFI-0273, and rule T1, MR-SOFI-0268):
# on a workspace whose public SoFi method has no production caller, and whose
# public SoFi type nothing uses, ci/sofi_reachability.py fails and names
# both; once production code calls the one and uses the other, it passes. The SDK
# beside it holds a method of the same name on a type of its own, called
# from production: a gate that matched names would count that call and
# pass. The gate and its helper are copied, unchanged, into a scratch
# workspace with the real one's layout, so what runs here is what runs on
# the real tree, rust-analyzer's index included.
set -euo pipefail

here="$(cd "$(dirname "$0")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

ws="$tmp/dsm_client/deterministic_state_machine"
mkdir -p "$tmp/ci" "$ws/dsm/src/sofi" "$ws/dsm_sdk/src" "$tmp/dsm_storage_node/src"
cp "$here/ci/sofi_reachability.py" "$here/ci/production_text.py" "$tmp/ci/"
cat > "$ws/Cargo.toml" <<'TOML'
[workspace]
members = ["dsm", "dsm_sdk"]
resolver = "2"
TOML
cat > "$ws/dsm/Cargo.toml" <<'TOML'
[package]
name = "dsm"
version = "0.1.0"
edition = "2021"
TOML
cat > "$ws/dsm_sdk/Cargo.toml" <<'TOML'
[package]
name = "dsm_sdk"
version = "0.1.0"
edition = "2021"

[dependencies]
dsm = { path = "../dsm" }

[features]
jni = []
bluetooth = []
TOML
echo 'pub mod sofi;' > "$ws/dsm/src/lib.rs"
echo 'pub mod probe;' > "$ws/dsm/src/sofi/mod.rs"
cat > "$ws/dsm/src/sofi/probe.rs" <<'RUST'
pub struct Probe;

pub struct Orphan;

impl Orphan {
    fn make() -> Self {
        Orphan
    }
}

impl Probe {
    pub fn uncalled_probe(&self) -> u8 {
        7
    }

    pub fn called_probe(&self) -> u8 {
        3
    }
}
RUST
write_sdk() {
    cat > "$ws/dsm_sdk/src/lib.rs" <<RUST
use dsm::sofi::probe::Probe;

pub struct Decoy;

impl Decoy {
    pub fn uncalled_probe(&self) -> u8 {
        5
    }
}

$2

pub fn caller() -> u8 {
    $1
}
RUST
}

cd "$tmp"
write_sdk 'Probe.called_probe() + Decoy.uncalled_probe()' ''
if out="$(python3 ci/sofi_reachability.py 2>&1)"; then
    echo "[FAIL] G1 passed a workspace whose public SoFi method has no caller"
    exit 1
fi
if ! grep -q "no production caller: .*/sofi/probe.rs Probe::uncalled_probe" <<<"$out"; then
    echo "[FAIL] G1 failed without naming the uncalled method:"
    echo "$out"
    exit 1
fi
if ! grep -q "no production caller: .*/sofi/probe.rs struct Orphan" <<<"$out"; then
    echo "[FAIL] G1 failed without naming the unused type:"
    echo "$out"
    exit 1
fi

write_sdk 'Probe.called_probe() + Probe.uncalled_probe() + held(dsm::sofi::probe::Orphan)' \
    'fn held(_orphan: dsm::sofi::probe::Orphan) -> u8 { 1 }'
if ! out="$(python3 ci/sofi_reachability.py 2>&1)"; then
    echo "[FAIL] G1 refused a public SoFi method production code calls:"
    echo "$out"
    exit 1
fi
echo "G1 negative control: an uncalled public SoFi method and an unused public SoFi type fail and are named, beside a called method of the same name on another type; called and used, they pass"
