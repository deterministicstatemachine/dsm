#!/bin/bash
set -euo pipefail

echo "🚀 Running DSM SDK Performance CI"

# Run the ignored perf test with release optimizations
RUSTFLAGS="-C opt-level=3 -C lto=fat -C target-cpu=native" \
cargo test -p dsm_sdk --release -q -- --ignored perf-ci --nocapture 2>&1 | tee perf.out

echo "📊 Parsing performance results..."

# Extract key metrics from PERF lines
OPS=$(awk -F'ops_sec=' '/^PERF:iters/{split($2,a," "); print a[1]}' perf.out | tail -1)
VER_US=$(awk -F'verify_us=' '/^PERF:iters/{split($2,a," "); print a[2]}' perf.out | tail -1)

echo "📈 Performance Results:"
echo "   Operations/sec: $OPS"
echo "   Verify time (µs): $VER_US"

# Calculate verify-bound (1M / verify_us * 1.05)
python3 - <<EOF
import sys
ops = float("$OPS")
ver_us = float("$VER_US")
bound = (1_000_000.0 / ver_us) * 1.05

print(f"   Verify-bound: {bound:.0f} ops/sec")

# Enforce performance gates
if ops < 1000:
    print(f"❌ FAIL: ops/sec {ops} below floor 1000", file=sys.stderr)
    sys.exit(1)

if ops > bound:
    print(f"❌ FAIL: ops/sec {ops} exceeds verify-bound {bound:.0f}", file=sys.stderr)
    sys.exit(1)

print("✅ PERF CI OK: Performance within acceptable bounds")
EOF

echo "🎉 Performance CI completed successfully"