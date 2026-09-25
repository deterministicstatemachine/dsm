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
echo ""

# A validated economic root is verifier-derived; its two deliberate punctures
# stay where the conjunctions that earn them are written.
bash ci/sofi_validated_root_constructors.sh

# Gate G1 (SoFi §37): every pub fn under CORE/sofi has a production caller.
# The baseline lists what the rebuild (R1..R14) has not wired yet and only
# ever shrinks; R14 deletes it.
python3 ci/sofi_reachability.py
echo ""

# A vault genesis must not be consumable from a PRESENTED creation operation.
# The funding pair is stated by a signed operation, never asserted, and F10
# still owes the binding from that operation to the accepted owner transition.
bash ci/sofi_genesis_acceptance_binding.sh
bash ci/sofi_relay_is_party_neutral.sh

# Only an ordinary single-root lineage can become an eligible peer debit
# (P15-9). The discriminant is worthless if a caller can attach it, and
# variant-field visibility changes no runtime behaviour.
bash ci/peer_debit_lineage_authoritative.sh

# The descendant fence cannot fire until E2/E3 writes conditional admitted
# rows, so a descendant path added without it would be invisible today and a
# live hole the day that writer lands. Only a static check holds this.
bash ci/admitted_predecessor_readers_fenced.sh

# The storage node holds bytes and knows nothing about SoFi.
bash ci/storage_is_dumb.sh

# Requirement status is derived from evidence: pins, counts, and every named
# code item and test exist (specs/requirements/CONFORMANCE_GAPS.md §2 rule 6).
python3 ci/conformance_evidence.py

# Gate G2 (spec §37): SoFi evidence is fetched, never defaulted.
bash ci/sofi_no_default_evidence.sh

# TLA+ model checking is the Formal Validation job's (ci.yml,
# `dsm_vertical_validation tla-check`), not this script's.

echo ""
echo "✓ All production safety checks passed!"
