#!/usr/bin/env bash
set -euo pipefail

# CI gate: no production build can fabricate a commit input for the persistent
# DLV tree (dsm/src/sofi/smt).
#
# The tree's canonicality rests entirely on `tree::apply` being the only
# producer of a `Shadow`: existence and height checks cannot establish it for a
# public node graph, because `Single(h)` and an `Internal(h)` over `Single(h-1)`
# plus a default share a Merkle value, and a valid stored subtree can be grafted
# under the wrong prefix. So `Shadow`'s fields are private and the only
# fabricating constructor is gated to test builds.
#
# A private field turned public, or a `pub(crate)` helper compiled into
# production, changes NO runtime behaviour, so no runtime test can catch it.
# This gate is therefore two source checks and one artifact check: the artifact
# check is the load-bearing one, because it asks the compiler rather than the
# text.

echo "=== SoFi persistent DLV tree: commit input non-forgeability ==="

core=dsm_client/deterministic_state_machine
tree="$core/dsm/src/sofi/smt/tree.rs"
forge=forge_for_tests
gate='#\[cfg\(any\(test, feature = "testing"\)\)\]'

[[ -f "$tree" ]] || { echo "[FAIL] $tree not found"; exit 1; }

# 1. Every field of Shadow is private.
echo "[1/3] Shadow's fields are private..."
body=$(awk '/^pub struct Shadow \{/{f=1} f{print} f&&/^\}/{exit}' "$tree")
[[ -n "$body" ]] || { echo "[FAIL] could not find 'pub struct Shadow' in $tree"; exit 1; }
if grep -qE '^\s+pub(\(| )' <<<"$body"; then
  echo "[FAIL] Shadow has a public field — a caller could then assemble a commit input:"
  grep -nE '^\s+pub(\(| )' <<<"$body"
  exit 1
fi
echo "  ✓ no public field"

# 2. The fabricating constructor carries the test gate on the line above it.
echo "[2/3] $forge is gated to test builds..."
if ! grep -q "fn $forge" "$tree"; then
  echo "[FAIL] $forge is not declared in $tree — this gate has lost its subject"
  exit 1
fi
while IFS=: read -r line _; do
  prev=$(sed -n "$((line - 1))p" "$tree")
  if ! grep -qE "$gate" <<<"$prev"; then
    echo "[FAIL] $tree:$line declares $forge without the test gate on the line above"
    echo "       expected: #[cfg(any(test, feature = \"testing\"))]"
    echo "       found:   $prev"
    exit 1
  fi
done < <(grep -n "fn $forge" "$tree")
echo "  ✓ gated"

# 3. No production artifact contains it. This is the real proof: a default
#    `cargo build` resolves no dev-dependencies, so the `testing` feature is
#    off, and the public item's name is absent from the rlib's metadata.
echo "[3/3] the default-feature rlib does not contain it..."
if ! command -v cargo &>/dev/null; then
  echo "[FAIL] cargo not available; cannot prove the production artifact"
  exit 1
fi
rlibs=$(cd "$core" && cargo build -p dsm --message-format=json 2>/dev/null |
  python3 -c '
import json, sys
for line in sys.stdin:
    try:
        m = json.loads(line)
    except ValueError:
        continue
    if m.get("reason") == "compiler-artifact" and m.get("target", {}).get("name") == "dsm":
        for f in m.get("filenames", []):
            if f.endswith(".rlib"):
                print(f)
')
if [[ -z "$rlibs" ]]; then
  echo "[FAIL] no dsm rlib was reported by cargo; cannot prove the production artifact"
  exit 1
fi
for rlib in $rlibs; do
  if grep -aq "$forge" "$rlib"; then
    echo "[FAIL] $forge is present in a default-feature artifact: $rlib"
    echo "       a production caller can fabricate a commit input"
    exit 1
  fi
done
echo "  ✓ absent from $(wc -w <<<"$rlibs" | tr -d ' ') default-feature artifact(s)"

echo "✓ commit inputs cannot be forged in a production build"
