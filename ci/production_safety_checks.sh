#!/usr/bin/env bash
# DSM Production Safety Checks
# Enforces production-ready code standards via clippy lints and formal verification

set -euo pipefail

echo "=== DSM Production Safety Checks ==="
echo ""

# ONE normative Rust version, mechanically proven — floating selection, drifted
# workflow mirror, or running under an undeclared toolchain all fail here.
bash ci/check_toolchain_consistency.sh
echo ""

# Run clippy with production safety lints.
#
# NO `+toolchain` OVERRIDE. This deliberately runs whatever rust-toolchain.toml
# declares, so this gate and `make lint` and ordinary CI are the same version.
#
# This line previously read `cargo +stable clippy`. The comment said it was to
# dodge a nightly Clippy ICE, but `+stable` also escaped the repository's pin:
# CI installed 1.96.0 and then this script asked for whatever `stable` happened
# to be that day. A clippy release could therefore fail CI on untouched code,
# and it did. The ICE it was avoiding is a NIGHTLY problem; the pin is not
# nightly, so plain `cargo` is both safe and correct here.
echo "Running clippy with production safety lints..."
cargo clippy --workspace --all-features -- \
  -W clippy::unwrap_used \
  -W clippy::expect_used \
  -W clippy::panic \
  -W clippy::unwrap_in_result \
  -D warnings

echo ""
echo "✓ Clippy production safety checks passed!"

# Run TLA+ model checking for formal verification
echo "Running TLA+ formal verification..."
cd tla
if [[ ! -f "tla2tools.jar" ]]; then
  echo "INFO: tla2tools.jar not found — skipping TLA+ formal verification."
  echo "To enable: download https://github.com/tlaplus/tlaplus/releases/download/v1.8.0/tla2tools.jar into tla/"
  cd ..
else
  # Run the tiny model check (terminating, fast)
  echo "Checking DSM_tiny.cfg model..."
  java -cp "tla2tools.jar" tlc2.TLC -config DSM_tiny.cfg DSM.tla -workers 1

  if [[ $? -ne 0 ]]; then
    echo "ERROR: TLA+ model checking failed!"
    exit 1
  fi

  echo ""
  echo "✓ TLA+ formal verification passed!"
  cd ..
fi

echo ""
echo "✓ All production safety checks passed!"
