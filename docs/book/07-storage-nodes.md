# Chapter 7 — Storage Nodes

Production AWS cluster, API reference, configuration, and optional local development.

---

## What Storage Nodes Do

Storage nodes are **dumb persistence servers**. They store and retrieve encrypted state blobs on behalf of clients. They:

- **Never sign** protocol messages
- **Never validate** protocol rules or balances
- **Never gate acceptance** of state transitions
- **Never affect** unlock predicates or transaction logic

All business logic runs on-device. Storage nodes are an index layer for state anchoring and replication.

---

## Architecture

```
Client (Android / Web)
  │
  │  HTTP + protobuf (Envelope v3)
  ▼
Storage Node (Rust / Axum)
  ├── Genesis anchoring
  ├── ByteCommit mirroring
  ├── DLV slot management
  ├── Unilateral b0x transport
  ├── Recovery capsule storage
  ├── Identity + Device Tree indexing
  └── Inter-node gossip (state sync, not consensus)
       │
       ▼
  PostgreSQL (per-node persistence)
```

### Design Properties

- **Clockless** — no wall-clock time in any protocol-relevant path
- **Signature-free** — nodes never produce cryptographic signatures
- **Protobuf-only** — all operational endpoints accept/return protobuf
- **No consensus** — no Byzantine agreement, Raft, Paxos, or leader election

### Replication Parameters

| Parameter | Value | Description                     |
| --------- | ----- | ------------------------------- |
| N         | 6     | Total replica count             |
| K         | 3     | Minimum replicas for durability |
| U_up      | 0.85  | Upscale utilization threshold   |
| U_down    | 0.35  | Downscale utilization threshold |

Replica placement uses keyed Fisher-Yates shuffle (deterministic, no coordination required).

---

## Production Cluster (AWS)

The default app configuration connects to 6 production storage nodes across 3 AWS regions:

| Node       | Region         | IP             | Endpoint                      |
| ---------- | -------------- | -------------- | ----------------------------- |
| dsm-node-1 | us-east-1      | 13.218.83.69   | `https://13.218.83.69:8080`   |
| dsm-node-2 | us-east-1      | 44.223.31.184  | `https://44.223.31.184:8080`  |
| dsm-node-3 | eu-west-1      | 54.74.145.172  | `https://54.74.145.172:8080`  |
| dsm-node-4 | eu-west-1      | 3.249.79.215   | `https://3.249.79.215:8080`   |
| dsm-node-5 | ap-southeast-1 | 18.141.56.252  | `https://18.141.56.252:8080`  |
| dsm-node-6 | ap-southeast-1 | 13.215.175.231 | `https://13.215.175.231:8080` |

The config file (`dsm_env_config.toml`) ships with these nodes. With outbound internet access, no local setup, PostgreSQL, or port forwarding is required.

---

## Local Multi-Node Development (Optional)

For offline development or testing against local nodes (not required for normal use — the default config uses AWS).

### Prerequisites

- Rust stable
- PostgreSQL installed and running

### Start the Local Development Nodes

```bash
# 1. Create dev databases (one-time)
cd dsm_storage_node
./scripts/setup_dev_db.sh

# 2. Start 5 local storage nodes
./scripts/dev/start_dev_nodes.sh

# 3. Verify all nodes
for port in 8080 8081 8082 8083 8084; do
  curl -s http://localhost:$port/api/v2/health | grep -q ok \
    && echo "Node $port: OK" \
    || echo "Node $port: NOT RUNNING"
done
```

PIDs are saved in `dev-node*.pid`, logs in `logs/`.

### Stop the Local Development Nodes

```bash
./scripts/dev/stop_dev_nodes.sh
```

### Using Makefile

```bash
make nodes-up      # start local storage nodes
make nodes-down    # stop local storage nodes
make nodes-status  # check local node health
make nodes-reset   # stop nodes and clean logs/pids
```

### Connect Phone to Local Storage Nodes

First push a localhost config override so the app talks to local nodes instead of AWS:

```bash
scripts/push_env_override.sh --local
```

Then forward ports via adb so the phone can reach `127.0.0.1:808x`:

```bash
adb reverse tcp:8080 tcp:8080
adb reverse tcp:8081 tcp:8081
adb reverse tcp:8082 tcp:8082
adb reverse tcp:8083 tcp:8083
adb reverse tcp:8084 tcp:8084
```

To switch back to AWS nodes, remove the override:

```bash
adb shell run-as com.dsm.wallet rm files/dsm_env_config.override.toml
```

---

## API Endpoints

All operational endpoints use protobuf encoding (`application/octet-stream`). The health endpoint is a lightweight plain-text check outside the protobuf data path.

### Health

```
GET /api/v2/health
```

Returns: `ok`

### Operational (protobuf-only)

| Endpoint                   | Method   | Purpose                             |
| -------------------------- | -------- | ----------------------------------- |
| `/api/v2/envelope`         | POST     | Submit Envelope v3 (protobuf bytes) |
| `/api/v2/genesis/entropy`  | GET/POST | Genesis entropy contribution        |
| `/api/v2/bytecommit`       | POST     | ByteCommit anchoring                |
| `/api/v2/dlv/slot`         | POST     | DLV slot management                 |
| `/api/v2/unilateral`       | POST     | Unilateral (b0x) transport          |
| `/api/v2/recovery/capsule` | POST     | Recovery capsule storage            |
| `/api/v2/identity`         | GET/POST | Identity and Device Tree queries    |
| `/api/v2/gossip`           | POST     | Inter-node state sync               |

---

## Source Layout

```
dsm_storage_node/src/
├── main.rs              # Axum server, TLS, CLI args
├── lib.rs               # AppState, shared types
├── api/
│   ├── genesis.rs       # Genesis entropy endpoints
│   ├── bytecommit.rs    # ByteCommit mirroring
│   ├── dlv_slot.rs      # DLV vault slot management
│   ├── gossip.rs        # Inter-node gossip
│   ├── device_api.rs    # Device registration/lookup
│   ├── identity_tips.rs # Identity tip queries
│   ├── identity_devtree.rs # Device tree endpoints
│   ├── object_store.rs  # Generic object storage
│   ├── unilateral_api.rs # b0x unilateral transport
│   ├── recovery_capsule.rs # Recovery capsule CRUD
│   ├── rate_limit.rs    # Transport-layer rate limiting
│   ├── hardening.rs     # Request validation, size limits
│   └── network_config.rs # Network topology auto-detection
├── auth/                # Token-based gossip auth
├── db/                  # PostgreSQL schema, migrations, queries
├── replication.rs       # Replica placement (Fisher-Yates)
├── partitioning.rs      # Deterministic shard assignment
└── operational.rs       # Operational metrics
```

---

## Configuration

Nodes accept TOML config files or CLI arguments:

```bash
# Run a single node with config file
cargo run --release -- --config config.toml

# Run with auto-detection
cargo run --release -- --auto-detect --node-index 0
```

### Build

```bash
cd dsm_storage_node
cargo build --release
# Binary: target/release/dsm_storage_node
```

---

## AWS Cloud Deployment

Deploy a 6-node storage-node replica set across 3 AWS regions from a single machine.

### Cloud Prerequisites

| Tool      | Version           | Install                                                       |
| --------- | ----------------- | ------------------------------------------------------------- |
| Terraform | >= 1.5            | `brew install terraform`                                      |
| AWS CLI   | v2                | `brew install awscli`                                         |
| Docker    | Desktop or Engine | [docker.com](https://www.docker.com/products/docker-desktop/) |

### AWS Account Setup

1. Create an AWS account
2. Create an IAM user with **AmazonEC2FullAccess** policy
3. Configure credentials: `aws configure`

### SSH Key

```bash
ssh-keygen -t ed25519 -f ~/.ssh/dsm-deploy -N ""
```

### Deploy

```bash
cd dsm_storage_node
bash deploy/provision_aws.sh --ssh-key ~/.ssh/dsm-deploy
```

This single command:

1. Provisions 6 EC2 instances across 3 regions via Terraform
2. Waits for SSH readiness (~2-3 minutes)
3. Generates per-node TLS certificates and configs
4. Builds the Docker image (cross-compiled for x86_64)
5. Uploads and starts services on all 6 nodes
6. Runs a health check

Total time: ~30-45 minutes (mostly the Rust release build).

### Cloud Architecture

```
┌───────────────────────────────────────────────────────┐
│                 Your Local Machine                      │
│  provision_aws.sh                                       │
│    ├── terraform apply (6 EC2 across 3 regions)         │
│    ├── generate_node_configs.sh (TLS certs + configs)        │
│    └── push_and_start.sh (docker build + scp + start)   │
└───────────────────────────────────────────────────────┘
       │              │              │
  ┌────▼────┐   ┌────▼────┐   ┌────▼────┐
  │us-east-1│   │eu-west-1│   │ap-se-1  │
  │ node-1  │   │ node-3  │   │ node-5  │
  │ node-2  │   │ node-4  │   │ node-6  │
  └─────────┘   └─────────┘   └─────────┘

Each node runs:
  ┌─────────────────────────────┐
  │  Docker Compose             │
  │  ├── storage-node (Rust)    │  port 8080 (API), 9090 (metrics)
  │  └── postgres:15-alpine     │  internal only
  └─────────────────────────────┘
```

### Estimated Cost

| Resource        | Spec                | Monthly        |
| --------------- | ------------------- | -------------- |
| 6x EC2 t3.small | 2 vCPU, 2GB RAM     | ~$75           |
| 6x 20GB gp3 EBS | SSD storage         | ~$10           |
| Data transfer   | Inter-region gossip | ~$5            |
| **Total**       |                     | **~$90/month** |

### Cloud Commands

```bash
# Re-deploy (skip Terraform)
bash deploy/provision_aws.sh --ssh-key ~/.ssh/dsm-deploy --skip-terraform

# Skip Docker build too
bash deploy/provision_aws.sh --ssh-key ~/.ssh/dsm-deploy --skip-terraform --skip-build

# Health check
bash deploy/check_nodes.sh <IP1> <IP2> <IP3> <IP4> <IP5> <IP6>

# SSH into a node
ssh -i ~/.ssh/dsm-deploy ubuntu@<NODE_IP>

# View logs
ssh -i ~/.ssh/dsm-deploy ubuntu@<NODE_IP> \
  "cd /opt/dsm-storage && docker compose -f docker-compose.node.yml logs -f storage-node"

# Tear down (stop billing)
bash deploy/teardown_aws.sh --ssh-key ~/.ssh/dsm-deploy
```

### Changing Regions

Edit `terraform/main.tf`:

```hcl
module "us_east_1"      { ... node_count = 2; global_node_offset = 0; }
module "eu_west_1"      { ... node_count = 2; global_node_offset = 2; }
module "ap_southeast_1" { ... node_count = 2; global_node_offset = 4; }
```

---

## Troubleshooting

See [Chapter 13 — Troubleshooting](13-troubleshooting.md) for the full troubleshooting guide. Quick fixes:

| Problem                    | Fix                                                                |
| -------------------------- | ------------------------------------------------------------------ |
| Database connection failed | Start PostgreSQL: `brew services start postgresql@15`              |
| Port already in use        | `./scripts/dev/stop_dev_nodes.sh && rm -f dev-node*.pid`           |
| Schema drift               | `./scripts/setup_dev_db.sh` (recreates databases)                  |
| Docker platform mismatch   | Script uses `--platform linux/amd64` for EC2                       |
| SSH timeout on deploy      | Instances take 1-3 minutes; check `/var/log/cloud-init-output.log` |

---

Next: [Chapter 8 — Bitcoin and dBTC](08-bitcoin-dbtc.md)
