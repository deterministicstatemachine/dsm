#!/bin/bash
# Stop all dev storage nodes

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Stopping DSM storage dev nodes..."

cd "$NODE_DIR"

# Stop all nodes by PID files
for i in 1 2 3 4 5; do
  PID_FILE="dev-node${i}.pid"
  if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if kill -0 "$PID" 2>/dev/null; then
      echo "  Stopping node $i (PID $PID)..."
      kill "$PID"
      rm "$PID_FILE"
    else
      echo "  Node $i (PID $PID) not running, removing stale PID file"
      rm "$PID_FILE"
    fi
  else
    echo "  Node $i: no PID file found"
  fi
done

echo "All nodes stopped"
