#!/bin/bash

# DSM Storage Node - Development Node Launcher
# Starts 5 independent storage nodes on localhost for development testing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$NODE_DIR"

echo "Starting DSM storage dev nodes..."

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Function to check if storage node API is responding
# Accepts: port, optional config file path. If config enables TLS, uses https -k.
check_api_responding() {
    local port=$1
    local cfg=${2:-}
    local proto="http"
    # If a config file is provided and contains a '[tls]' section with 'enabled = true', use https
    if [ -n "$cfg" ] && [ -f "$cfg" ]; then
        # crude but reliable parse: find [tls] section then look for enabled = true
        if awk '/^\s*\[tls\]/ { in_tls=1; next } /^\s*\[/ { in_tls=0 } in_tls && /^\s*enabled\s*=/' "$cfg" | grep -Eiq 'enabled\s*=\s*true'; then
            proto="https"
        fi
    fi

    local url="${proto}://127.0.0.1:${port}/api/v2/health"

    if [ "$proto" = "https" ]; then
        if curl -s -k --connect-timeout 2 --max-time 5 "$url" >/dev/null 2>&1; then
            return 0
        fi
    else
        if curl -s --connect-timeout 2 --max-time 5 "$url" >/dev/null 2>&1; then
            return 0
        fi
    fi
    return 1
}

# Function to start a node
start_node() {
    local node_num=$1
    local config_file="config/dev/node${node_num}.toml"
    local port=$((8079 + node_num))
    local log_file="logs/dev-node${node_num}.log"
    
    echo -e "${BLUE}Starting Node ${node_num} on port ${port}...${NC}"
    echo "PWD=$(pwd)"; echo "Looking for storage_node at: $(cd .. && pwd)/target/release/storage_node"
    
    # Check if storage node API is already responding (pass config path so TLS can be detected)
    if check_api_responding $port "$config_file"; then
        echo -e "${GREEN}✓ Node ${node_num} already running and responding on port ${port}${NC}"
        return 0
    fi
    
    # If port is in use but API not responding, there might be a dead process
    if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
        echo -e "${YELLOW}⚠ Port ${port} in use but API not responding - attempting to clear${NC}"
        # Kill any process using this port
        local existing_pid=$(lsof -ti:$port 2>/dev/null)
        if [ -n "$existing_pid" ]; then
            echo "Killing existing process on port ${port}: $existing_pid"
            kill -9 $existing_pid 2>/dev/null || true
            sleep 1
        fi
    fi
    
    # Create log directory if it doesn't exist
    mkdir -p logs
    mkdir -p keys
    mkdir -p "data-dev-node${node_num}"
    
    # Start the node in background (detached). Use nohup to avoid SIGHUP when caller shell exits.
    # Use absolute path to avoid cwd surprises
    BIN_PATH="$(cd .. && pwd)/target/release/storage_node"
    if [ ! -x "$BIN_PATH" ]; then
        echo -e "${YELLOW}Release binary not found at $BIN_PATH, attempting to build...${NC}"
        (cd .. && cargo build --release -p dsm_storage_node --locked --all-features) || true
    fi

    # Fall back to debug binary if release build refuses to run with dev config
    if [ ! -x "$BIN_PATH" ]; then
        echo -e "${YELLOW}Release binary unavailable; trying debug binary...${NC}"
        BIN_PATH="$(cd .. && pwd)/target/debug/storage_node"
        if [ ! -x "$BIN_PATH" ]; then
            echo -e "${YELLOW}Debug binary not found at $BIN_PATH, attempting to build debug...${NC}"
            (cd .. && cargo build -p dsm_storage_node --locked --all-features) || true
        fi
    fi

    if [ ! -x "$BIN_PATH" ]; then
        echo -e "${RED}✗ Could not find storage_node binary (release or debug). Aborting node start.${NC}"
        return 1
    fi

    # Build benchmark flag if BENCHMARK_MODE is set
    local bench_flag=""
    if [ "${BENCHMARK_MODE:-}" = "1" ]; then
        bench_flag="--benchmark-mode"
    fi

    # Enable verbose logging for diagnostics and detach from terminal
    nohup env RUST_LOG=info "$BIN_PATH" --config "$config_file" --verbose $bench_flag > "$log_file" 2>&1 &
    local pid=$!
    
    echo "Node ${node_num} PID: $pid"
    echo "$pid" > "dev-node${node_num}.pid"
    
    # Wait for startup and check if API responds
    echo "Waiting for Node ${node_num} API to respond..."
    for attempt in {1..20}; do
        sleep 1
        if check_api_responding $port "$config_file"; then
            echo -e "${GREEN}✓ Node ${node_num} started successfully and API responding${NC}"
            return 0
        fi
        echo -n "."
    done
    
    echo ""
    # Check if process is still running
    if kill -0 "$pid" 2>/dev/null; then
        echo -e "${YELLOW}⚠ Node ${node_num} process running but API not responding yet${NC}"
        return 1
    else
        # If release binary exited immediately (e.g., refused due to dev config), attempt debug fallback once
        if echo "$BIN_PATH" | grep -q "/target/release/" ; then
            echo -e "${YELLOW}Release binary exited; attempting to start debug binary as fallback...${NC}"
            BIN_PATH="$(cd .. && pwd)/target/debug/storage_node"
            if [ ! -x "$BIN_PATH" ]; then
                echo -e "${YELLOW}Debug binary missing, building debug...${NC}"
                (cd .. && cargo build -p dsm_storage_node --locked --all-features) || true
            fi
            if [ ! -x "$BIN_PATH" ]; then
                echo -e "${RED}✗ Debug binary not found; cannot start node${NC}"
                return 1
            fi
            nohup env RUST_LOG=info "$BIN_PATH" --config "$config_file" --verbose $bench_flag > "$log_file" 2>&1 &
            pid=$!
            echo "Node ${node_num} fallback PID: $pid"
            echo "$pid" > "dev-node${node_num}.pid"
            echo "Waiting for Node ${node_num} API to respond (debug fallback)..."
            for attempt in {1..20}; do
                sleep 1
                if check_api_responding $port; then
                    echo -e "${GREEN}✓ Node ${node_num} started successfully and API responding (debug)${NC}"
                    return 0
                fi
                echo -n "."
            done
            echo ""
            if kill -0 "$pid" 2>/dev/null; then
                echo -e "${YELLOW}⚠ Node ${node_num} debug process running but API not responding${NC}"
                return 1
            else
                echo -e "${RED}✗ Node ${node_num} debug fallback failed to start${NC}"
                return 1
            fi
        fi
        echo -e "${RED}✗ Node ${node_num} failed to start${NC}"
        return 1
    fi
}

# Function to stop all nodes
stop_nodes() {
    echo -e "${YELLOW}Stopping all development nodes...${NC}"
    
    for i in {1..5}; do
        local port=$((8079 + i))
        echo "Stopping Node ${i} on port ${port}..."
        
        # Check if PID file exists
        if [ -f "dev-node${i}.pid" ]; then
            local pid=$(cat "dev-node${i}.pid")
            if kill -0 "$pid" 2>/dev/null; then
                echo "  Stopping Node ${i} using PID file (PID: $pid)"
                kill -TERM "$pid" 2>/dev/null || true
                sleep 1
                # Force kill if still running
                if kill -0 "$pid" 2>/dev/null; then
                    echo "  Force killing PID $pid"
                    kill -9 "$pid" 2>/dev/null || true
                fi
            fi
            rm -f "dev-node${i}.pid"
        fi
        
        # Also check for processes using the port (multiple times to be thorough)
        for attempt in {1..3}; do
            local port_pids=$(lsof -ti:$port 2>/dev/null)
            if [ -n "$port_pids" ]; then
                echo "  Found processes using port ${port}: $port_pids"
                echo "$port_pids" | xargs kill -TERM 2>/dev/null || true
                sleep 1
                # Force kill if still running
                echo "$port_pids" | while read pid; do
                    if kill -0 "$pid" 2>/dev/null; then
                        echo "  Force killing process $pid on port $port"
                        kill -9 "$pid" 2>/dev/null || true
                    fi
                done
            else
                break
            fi
        done
        
        # Also look for storage_node processes by name and port
        local dsm_pids=$(pgrep -f "storage_node.*$port" 2>/dev/null || true)
        if [ -n "$dsm_pids" ]; then
            echo "  Found storage_node processes for port $port: $dsm_pids"
            echo "$dsm_pids" | xargs kill -TERM 2>/dev/null || true
            sleep 1
            # Force kill remaining processes
            echo "$dsm_pids" | while read pid; do
                if kill -0 "$pid" 2>/dev/null; then
                    echo "  Force killing storage_node process $pid"
                    kill -9 "$pid" 2>/dev/null || true
                fi
            done
        fi
    done
    
    # Final cleanup - kill any remaining storage_node processes
    local remaining_pids=$(pgrep -f "storage_node" 2>/dev/null || true)
    if [ -n "$remaining_pids" ]; then
        echo "Cleaning up remaining storage_node processes: $remaining_pids"
        echo "$remaining_pids" | xargs kill -TERM 2>/dev/null || true
        sleep 2
        echo "$remaining_pids" | xargs kill -9 2>/dev/null || true
    fi
    
    echo -e "${GREEN}All nodes stopped${NC}"
}

# Function to show status
show_status() {
    echo -e "${BLUE}Dev Node Status:${NC}"
    for i in {1..5}; do
        local port=$((8079 + i))
        if lsof -Pi :$port -sTCP:LISTEN -t >/dev/null 2>&1; then
            echo -e "${GREEN}✓ Node ${i} - Running on port ${port}${NC}"
        else
            echo -e "${RED}✗ Node ${i} - Not running on port ${port}${NC}"
        fi
    done
}

# Function to check API endpoints
check_endpoints() {
    echo -e "${BLUE}Checking API endpoints...${NC}"
    for i in {1..5}; do
        local port=$((8079 + i))
        local config_file="config/dev/node${i}.toml"
        local proto="http"
        # Detect TLS and check with https -k when necessary
        if [ -f "$config_file" ] && awk '/^\s*\[tls\]/ { in_tls=1; next } /^\s*\[/ { in_tls=0 } in_tls && /^\s*enabled\s*=/' "$config_file" | grep -Eiq 'enabled\s*=\s*true'; then
            proto="https"
        fi
        local url="${proto}://127.0.0.1:${port}/api/v2/health"
        
        if check_api_responding $port "$config_file"; then
            echo -e "${GREEN}✓ Node ${i} API responding at ${url}${NC}"
        else
            echo -e "${YELLOW}⚠ Node ${i} API not responding at ${url}${NC}"
        fi
    done
}

# Main script logic
case "${1:-start}" in
    "start")
        echo -e "${BLUE}Starting dev nodes...${NC}"
        success_count=0
        
        for i in {1..5}; do
            if start_node $i; then
                ((success_count++))
            fi
        done
        
        echo ""
        echo "Started $success_count/5 nodes"
        
        if [ $success_count -gt 0 ]; then
            echo -e "${GREEN}Dev nodes are starting up...${NC}"
            echo "Wait a few seconds for full initialization, then run:"
            echo "  $0 status    - Check node status"
            echo "  $0 check     - Check API endpoints"
            echo "  $0 stop      - Stop all nodes"
            echo "  $0 logs      - Show recent logs"
        fi
        ;;
        
    "stop")
        stop_nodes
        ;;
        
    "status")
        show_status
        ;;
        
    "check")
        check_endpoints
        ;;
        
    "logs")
        echo -e "${BLUE}Recent logs from all nodes:${NC}"
        for i in {1..5}; do
            echo -e "${YELLOW}=== Node ${i} ===${NC}"
            if [ -f "logs/dev-node${i}.log" ]; then
                tail -5 "logs/dev-node${i}.log"
            else
                echo "No log file found"
            fi
            echo ""
        done
        ;;
        
    "restart")
        stop_nodes
        sleep 3
        "${BASH_SOURCE[0]}" start
        ;;
        
    *)
        echo "Usage: $0 {start|stop|status|check|logs|restart}"
        echo ""
        echo "Commands:"
        echo "  start   - Start all development nodes"
        echo "  stop    - Stop all development nodes"
        echo "  status  - Show node status"
        echo "  check   - Check API endpoints"
        echo "  logs    - Show recent logs"
        echo "  restart - Restart all nodes"
    exit 1
    ;;
esac