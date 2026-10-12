#!/usr/bin/env bash
set -euo pipefail

# Gate G2 (spec §37): no default evidence.
#
# `sofi::validation::Evidence` derives `Default` only under `cfg(test)`, and
# production code builds it only from fetched bytes (`Evidence::acquired`, at
# the end of `sdk::sofi_evidence::acquire_evidence`). A verifier that ran with
# evidence it never fetched would answer Unavailable for everything it should
# have fetched — or, worse, Valid over nothing — and a producer building on
# that would publish an operation nothing validates. Production code is every
# `.rs` file under CORE, SDK and NODE, excluding `tests/` directories and every
# `#[cfg(test)]`-attributed item (ci/production_text.py).

echo "=== SoFi evidence: never defaulted ==="

roots=(
  dsm_client/deterministic_state_machine/dsm/src
  dsm_client/deterministic_state_machine/dsm_sdk/src
  dsm_storage_node/src
)
validation=dsm_client/deterministic_state_machine/dsm/src/sofi/validation.rs
[[ -f "$validation" ]] || { echo "[FAIL] $validation is not where this gate expects it"; exit 1; }

# 1. `Default` on `Evidence` is test-only.
if ! grep -B2 '^pub struct Evidence {' "$validation" | grep -q '#\[cfg_attr(test, derive(Default))\]'; then
  echo "[FAIL] Evidence must derive Default only under cfg(test): #[cfg_attr(test, derive(Default))]"
  exit 1
fi
if grep -B2 '^pub struct Evidence {' "$validation" | grep -E '^#\[derive\(' | grep -q 'Default'; then
  echo "[FAIL] Evidence derives Default unconditionally"
  exit 1
fi
echo "  ✓ Evidence derives Default only under cfg(test)"

# 2. No production code constructs one by default.
fail=0
while IFS= read -r f; do
  prod=$(python3 ci/production_text.py "$f")
  if grep -nq 'Evidence::default()' <<<"$prod"; then
    echo "[FAIL] Evidence::default() in production code: $f"
    grep -n 'Evidence::default()' <<<"$prod"
    fail=1
  fi
done < <(find "${roots[@]}" -name '*.rs' -not -path '*/tests/*' -not -name '*_tests.rs')
[[ $fail -eq 0 ]] || exit 1
echo "  ✓ no Evidence::default() outside test code"
