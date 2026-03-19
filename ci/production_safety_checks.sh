#!/usr/bin/env bash
# DSM Production Safety Checks
# Enforces production-ready code standards via clippy lints and formal verification

set -euo pipefail

echo "=== DSM Production Safety Checks ==="
echo ""

# Run clippy with production safety lints
# NOTE: Use stable explicitly to avoid a known nightly Clippy ICE on repr attributes.
echo "Running clippy with production safety lints..."
cargo +stable clippy --workspace --all-features -- \
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
