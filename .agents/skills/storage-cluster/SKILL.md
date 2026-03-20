---
name: storage-cluster
description: Start, stop, or check the local 5-node DSM storage cluster (ports 8080-8084)
disable-model-invocation: true
---

# Storage Cluster Management

Manage the local 5-node DSM storage cluster used for development and testing. Nodes run on ports 8080-8084.

The user may say "start", "stop", or "check" (default: check).

## Steps

### 1. Check cluster status

```bash
echo "Checking storage cluster status..."
for PORT in 8080 8081 8082 8083 8084; do
  if curl -sf -o /dev/null --max-time 2 "http://localhost:$PORT/health" 2>/dev/null; then
    echo "  Node :$PORT — UP"
  else
    echo "  Node :$PORT — DOWN"
  fi
done
```

### 2. Start cluster (if user says "start")

Build and start the storage node binary, then launch 5 instances:

```bash
cd /Users/cryptskii/Desktop/claude_workspace/dsm/dsm_client/deterministic_state_machine && \
cargo build --package dsm_storage_node --release 2>&1 | tail -5

for PORT in 8080 8081 8082 8083 8084; do
  STORAGE_DIR="/tmp/dsm_storage_$PORT"
  mkdir -p "$STORAGE_DIR"
  ./target/release/dsm_storage_node --port $PORT --storage-dir "$STORAGE_DIR" &
  echo "Started node on :$PORT (PID $!)"
done

sleep 2
echo "Cluster started. Verifying..."
for PORT in 8080 8081 8082 8083 8084; do
  curl -sf -o /dev/null --max-time 2 "http://localhost:$PORT/health" && echo "  :$PORT OK" || echo "  :$PORT FAILED"
done
```

### 3. Stop cluster (if user says "stop")

```bash
echo "Stopping storage cluster..."
pkill -f dsm_storage_node || true
sleep 1
echo "Cluster stopped."
```

### 4. Set up ADB reverse port forwarding (for device testing)

```bash
for DEVICE in $(adb devices | awk '/\tdevice$/{print $1}'); do
  for PORT in 8080 8081 8082 8083 8084; do
    adb -s "$DEVICE" reverse tcp:$PORT tcp:$PORT
  done
  echo "Port forwarding set for $DEVICE"
done
```

### 5. Report summary

Report:
- Which nodes are running
- Whether ADB port forwarding was set up
- Any errors
