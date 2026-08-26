#!/usr/bin/env bash
# Proves the repository has exactly ONE normative Rust version.
#
#     rust-toolchain.toml   = the sole normative declaration
#     ci.yml / release.yml  = MIRRORS, mechanically proven equal here
#     CodeQL's 1.94 sysroot = explicit extractor-only exception (see below)
#
# GitHub Actions cannot read rust-toolchain.toml to select `uses:`, so the
# workflow pins must be written out. That makes them mirrors, not independent
# pins — and an unchecked mirror is just a second declaration that has not
# drifted YET. This script is what makes the difference real.
#
# It exists because the repository once carried four different answers to "the
# CI Rust toolchain": this file at 1.96.0, ci.yml at 1.96.0, release.yml
# floating on `stable`, and production_safety_checks.sh escaping to
# `cargo +stable`. The last one silently defeated the pin, so a clippy release
# failed CI on code nobody had touched — and because the cache key was computed
# from the DECLARED toolchain while a different one actually ran, whether the
# gate examined a crate at all could vary with cache warmth.
set -euo pipefail

CANONICAL="$(awk -F'"' '/^channel/{print $2}' rust-toolchain.toml)"
if [[ -z "$CANONICAL" ]]; then
  echo "ERROR: could not read channel from rust-toolchain.toml" >&2
  exit 1
fi
fail=0

# 1. No floating selection in any verification or build path. Comment lines are
#    skipped so prose describing the forbidden pattern does not trip its own gate.
floating="$(grep -rnE 'cargo \+(stable|nightly|beta)|rust-toolchain@(stable|nightly|beta)' \
    ci .github/workflows Makefile 2>/dev/null \
  | grep -vE '^[^:]+:[0-9]+: *#' || true)"
if [[ -n "$floating" ]]; then
  echo "ERROR: floating Rust toolchain selection — the shipped artifact must be built" >&2
  echo "       under the version this repository declares, not whatever is current:" >&2
  echo "$floating" >&2
  fail=1
fi

# 2. Every workflow mirror equals the canonical declaration.
mirrors="$(grep -rhoE 'dtolnay/rust-toolchain@[0-9]+\.[0-9]+\.[0-9]+' .github/workflows \
  | sed 's/.*@//' | sort -u)"
if [[ -z "$mirrors" ]]; then
  echo "ERROR: no toolchain mirrors found in .github/workflows — did the pin format change?" >&2
  fail=1
fi
for m in $mirrors; do
  if [[ "$m" != "$CANONICAL" ]]; then
    echo "ERROR: workflow mirror $m != rust-toolchain.toml $CANONICAL" >&2
    grep -rn "dtolnay/rust-toolchain@$m" .github/workflows >&2
    fail=1
  fi
done

# 3. The version actually running is the declared one.
#
#    NOTE for callers: `rustup run <tc> bash -c '... cargo ...'` does NOT
#    guarantee the pinned cargo. The nested shell re-sources profile files and
#    another cargo earlier on PATH (Homebrew's, typically) wins. Prepend the
#    toolchain's bin directory instead — `rustup which --toolchain <tc> cargo`.
#    This check caught exactly that mistake in the Makefile that invokes it. Without this, a gate can
#    lint under a version nobody declared and report green.
ACTUAL="$(cargo --version | awk '{print $2}')"
if [[ "$ACTUAL" != "$CANONICAL" ]]; then
  echo "ERROR: toolchain drift — rust-toolchain.toml declares $CANONICAL, cargo is $ACTUAL" >&2
  echo "       A verification gate must run the version the repository declares." >&2
  echo "       rustup toolchain install $CANONICAL --profile minimal --component rustfmt --component clippy" >&2
  fail=1
fi

# NOT checked, deliberately: .github/workflows/codeql.yml installs 1.94.0 to pin
# the SYSROOT the CodeQL extractor reads, working around a rust-analyzer
# incompatibility documented at length in that file. It selects no compiler for
# building or linting this repository, so it is not a mirror of the pin.

[[ $fail -eq 0 ]] || exit 1
echo "Toolchain: $ACTUAL — canonical, and every workflow mirror agrees."
