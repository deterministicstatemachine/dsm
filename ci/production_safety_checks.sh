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
echo ""

# The persistent DLV tree trusts its builder: nothing outside `tree::apply` may
# assemble a commit input. Field visibility and a cfg gate have no runtime
# behaviour, so this is proven against the artifact, not by a test.
bash ci/sofi_shadow_nonforgeable.sh
echo ""

# A validated economic root is verifier-derived; its two deliberate punctures
# stay where the conjunctions that earn them are written.
bash ci/sofi_validated_root_constructors.sh

# A vault genesis must not be consumable from a PRESENTED creation operation.
# The funding pair is stated by a signed operation, never asserted, and F10
# still owes the binding from that operation to the accepted owner transition.
bash ci/sofi_genesis_acceptance_binding.sh

# Only an ordinary single-root lineage can become an eligible peer debit
# (P15-9). The discriminant is worthless if a caller can attach it, and
# variant-field visibility changes no runtime behaviour.
bash ci/peer_debit_lineage_authoritative.sh

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
