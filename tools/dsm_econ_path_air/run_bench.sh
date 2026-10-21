#!/bin/sh
# Build the spike with the repository's pinned toolchain and prove 1, 2 and 4
# economic SMT paths, printing each run's cost. Usage: ./run_bench.sh [log]
set -eu
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"
LOG="${1:-/tmp/dsm_econ_path_air_bench.log}"
{
  echo "== host: $(uname -m) $(uname -s), $(sysctl -n hw.ncpu 2>/dev/null || nproc) cores"
  echo "== toolchain: $(cargo --version)"
  cargo build --release 2>&1 | tail -3
  cargo test --release 2>&1 | grep -E "^test |test result" || true
  for n in 1 2 4; do
    echo "== paths=$n"
    ./target/release/dsm_econ_path_air --paths "$n"
  done
  echo "BENCH_DONE"
} > "$LOG" 2>&1
