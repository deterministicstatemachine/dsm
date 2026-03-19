#!/usr/bin/env bash
# Reset and (optionally) restart the local DSM storage dev nodes.
#
# What it does safely:
# - Stops any running dev nodes by pid files (dev-node*.pid in repo root)
# - Cleans stale pid/log files
# - Optionally restarts the 5 dev nodes (ports 8080..8084)
# - Health-checks HTTP ports
#
# Usage:
#   ./scripts/dev_nodes_reset.sh            # stop + clean only
#   ./scripts/dev_nodes_reset.sh --start    # stop + clean + start + health check
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

log() { printf "[dev-nodes] %s\n" "$*"; }
warn() { printf "[dev-nodes][WARN] %s\n" "$*"; }

die() { printf "[dev-nodes][ERROR] %s\n" "$*"; exit 1; }

# 1) Stop nodes from pid files if present
stop_nodes() {
  shopt -s nullglob || true
  local pids=(dev-node*.pid)
  if [[ ${#pids[@]} -eq 0 ]]; then
    log "No dev-node pid files found; nothing to stop."
    return 0
  fi
  for pf in "${pids[@]}"; do
    local pid
    pid=$(cat "$pf" 2>/dev/null || true)
    if [[ -n "${pid:-}" ]] && kill -0 "$pid" 2>/dev/null; then
      log "Stopping node pid=$pid (from $pf)"
      kill "$pid" || true
      # give it a moment, then force if needed
      sleep 0.5
      if kill -0 "$pid" 2>/dev/null; then
        warn "pid $pid still running; sending SIGKILL"
        kill -9 "$pid" || true
      fi
    else
      warn "Stale pid file $pf (no running process)."
    fi
    rm -f "$pf"
  done
}

# 2) Clean logs
clean_logs() {
  rm -f storage_nodes.log storage_node.log || true
  find dsm_storage_node -maxdepth 1 -type f -name "*.log" -print -delete || true
  log "Cleaned node logs."
}

# 3) Start dev nodes if requested
start_nodes() {
  if [[ ! -x "dsm_storage_node/start_dev_nodes.sh" ]]; then
    die "dsm_storage_node/start_dev_nodes.sh not found or not executable."
  fi
  log "Starting 5 storage dev nodes (8080..8084)"
  (cd dsm_storage_node && ./start_dev_nodes.sh)
}

# 4) Health check
health_check() {
  local ports=(8080 8081 8082 8083 8084)
  for p in "${ports[@]}"; do
    local ok=0
    for i in {1..10}; do
      if curl -fsS "http://127.0.0.1:$p/health" >/dev/null 2>&1; then
        log "Node on :$p healthy."
        ok=1; break
      fi
      sleep 0.3
    done
    if [[ $ok -eq 0 ]]; then
      warn "No /health response on :$p — this may be fine if your node API differs."
    fi
  done
}

main() {
  local do_start=0
  if [[ ${1:-} == "--start" ]]; then
    do_start=1
  fi

  stop_nodes
  clean_logs

  if [[ $do_start -eq 1 ]]; then
    start_nodes
    health_check
  else
    log "Stopped nodes and cleaned logs. Use --start to relaunch the dev nodes."
  fi
}

main "$@"
