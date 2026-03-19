# DSM Storage Node

Index-only, clockless, signature-free storage node for the DSM network.

## What Storage Nodes Do

Storage nodes are **dumb persistence servers**. They store and retrieve encrypted state blobs on behalf of clients. They:

- **Never sign** protocol messages
- **Never validate** protocol rules or balances
- **Never gate acceptance** of state transitions
- **Never affect** unlock predicates or transaction logic

All business logic runs on-device. Storage nodes are simply an index layer for state anchoring and replication.

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

### Key Design Properties

- **Clockless** — no wall-clock time in any protocol-relevant path. Ordering uses logical ticks derived from hash chain adjacency.
- **Signature-free** — storage nodes never produce cryptographic signatures. They are pure index/store services.
- **Protobuf-only** — all operational endpoints accept and return protobuf (`application/octet-stream`). JSON is banned from the protocol layer.
- **No consensus** — there is no Byzantine agreement, Raft, Paxos, or leader election. Nodes use simple gossip for state propagation.

### Replication Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| N | 6 | Total replica count |
| K | 3 | Minimum replicas for durability |
| U_up | 0.85 | Upscale utilization threshold |
| U_down | 0.35 | Downscale utilization threshold |

Replica placement uses keyed Fisher-Yates shuffle (deterministic, no coordination required).

## Production Cluster (AWS)

The default app config (`dsm_env_config.toml`) connects to 6 production storage nodes on AWS:

| Node | Region | IP | Endpoint |
|------|--------|----|----------|
| dsm-node-1 | us-east-1 | 13.218.83.69 | `https://13.218.83.69:8080` |
| dsm-node-2 | us-east-1 | 44.223.31.184 | `https://44.223.31.184:8080` |
| dsm-node-3 | eu-west-1 | 54.74.145.172 | `https://54.74.145.172:8080` |
| dsm-node-4 | eu-west-1 | 3.249.79.215 | `https://3.249.79.215:8080` |
| dsm-node-5 | ap-southeast-1 | 18.141.56.252 | `https://18.141.56.252:8080` |
| dsm-node-6 | ap-southeast-1 | 13.215.175.231 | `https://13.215.175.231:8080` |

No local setup, PostgreSQL, or port forwarding is required. The app works out of the box.

## Local Multi-Node Development (Optional)

For offline development or testing against local nodes (not required for normal use).

### Prerequisites

- Rust stable (`rustup`)
- PostgreSQL installed and running

### Setup and Run

```bash
cd dsm_storage_node

# 1. Create dev databases (one-time)
./scripts/setup_dev_db.sh

# 2. Start 5 local dev nodes
./start_dev_nodes.sh

# 3. Verify all nodes are healthy
for port in 8080 8081 8082 8083 8084; do
  curl -s http://localhost:$port/api/v2/health | grep -q ok \
    && echo "Node $port: OK" \
    || echo "Node $port: NOT RUNNING"
done
```

PIDs saved in `dev-node*.pid`, logs in `logs/`.

### Stop

```bash
./scripts/stop_dev_nodes.sh
```

### Connect Phone to Local Nodes

Push a localhost config override so the app talks to local nodes instead of AWS:

```bash
scripts/push_env_override.sh --local
```

Forward ports via adb:

```bash
adb reverse tcp:8080 tcp:8080
adb reverse tcp:8081 tcp:8081
adb reverse tcp:8082 tcp:8082
adb reverse tcp:8083 tcp:8083
adb reverse tcp:8084 tcp:8084
```

To switch back to AWS nodes:

```bash
adb shell run-as com.dsm.wallet rm files/dsm_env_config.override.toml
```

## API Endpoints

All operational endpoints use protobuf encoding. The health endpoint is a lightweight plain-text check outside the protobuf data path.

### Health

```
GET /api/v2/health
```

### Operational (protobuf-only)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v2/envelope` | POST | Submit Envelope v3 (protobuf bytes) |
| `/api/v2/genesis/entropy` | GET/POST | Genesis entropy contribution |
| `/api/v2/bytecommit` | POST | ByteCommit anchoring |
| `/api/v2/dlv/slot` | POST | DLV slot management |
| `/api/v2/unilateral` | POST | Unilateral (b0x) transport |
| `/api/v2/recovery/capsule` | POST | Recovery capsule storage |
| `/api/v2/identity` | GET/POST | Identity and Device Tree queries |
| `/api/v2/gossip` | POST | Inter-node state sync |

## Source Layout

```
src/
├── main.rs              # Axum server, TLS, CLI args
├── lib.rs               # AppState, shared types
├── api/
│   ├── genesis.rs       # Genesis entropy endpoints
│   ├── bytecommit.rs    # ByteCommit mirroring
│   ├── dlv_slot.rs      # DLV vault slot management
│   ├── gossip.rs        # Inter-node gossip (state sync)
│   ├── device_api.rs    # Device registration/lookup
│   ├── identity_tips.rs # Identity tip queries
│   ├── identity_devtree.rs # Device tree endpoints
│   ├── object_store.rs  # Generic object storage
│   ├── unilateral_api.rs # b0x unilateral transport
│   ├── recovery_capsule.rs # Recovery capsule CRUD
│   ├── rate_limit.rs    # Transport-layer rate limiting
│   ├── hardening.rs     # Request validation, size limits
│   └── network_config.rs # Auto-detection of network topology
├── auth/                # Token-based gossip auth
├── db/                  # PostgreSQL schema, migrations, queries
├── replication.rs       # Replica placement (Fisher-Yates)
├── partitioning.rs      # Deterministic shard assignment
└── operational.rs       # Operational metrics
```

## Configuration

Nodes are configured via TOML files or CLI arguments:

```bash
# Run a single node with config file
cargo run --release -- --config config.toml

# Run with auto-detection
cargo run --release -- --auto-detect --node-index 0
```

## Build

```bash
cd dsm_storage_node
cargo build --release
# Binary: target/release/dsm_storage_node
```

## Cryptographic Stack

Storage nodes use the same post-quantum primitives as the rest of DSM:

| Primitive | Algorithm | Usage |
|-----------|-----------|-------|
| Hashing | BLAKE3-256 | Domain-separated, all hashing |
| Key Exchange | ML-KEM-768 | Post-quantum key encapsulation (TLS) |
| Signatures | SPHINCS+ | Post-quantum signatures (client-side only) |
| Encryption | ChaCha20-Poly1305 | At-rest encryption |

Storage nodes themselves never sign anything. The crypto stack is used for TLS transport and verifying client-provided proofs.

## Troubleshooting

**"Database connection failed"**
```bash
# Check PostgreSQL is running
brew services list | grep postgresql   # macOS
sudo systemctl status postgresql       # Linux

# Re-run setup
./scripts/setup_dev_db.sh
```

**"Port already in use"**
```bash
./scripts/stop_dev_nodes.sh
rm -f dev-node*.pid
```

**Schema drift errors**
```bash
# Drop and recreate dev databases
./scripts/stop_dev_nodes.sh
./scripts/setup_dev_db.sh
./start_dev_nodes.sh
```

## AWS Cloud Deployment

Deploy 6 independent storage nodes across 3 AWS regions (us-east-1, eu-west-1, ap-southeast-1) from a single machine.

### Cloud Prerequisites

| Tool | Version | Install |
|------|---------|---------|
| Terraform | >= 1.5 | `brew install terraform` |
| AWS CLI | v2 | `brew install awscli` |
| Docker | Desktop or Engine | [docker.com](https://www.docker.com/products/docker-desktop/) |

### AWS Account Setup

1. Create an AWS account at [aws.amazon.com](https://aws.amazon.com)
2. Create an IAM user with **AmazonEC2FullAccess** policy:
   - AWS Console > IAM > Users > Create user
   - Attach policy: `AmazonEC2FullAccess`
   - Create access key (CLI use case)
3. Configure credentials locally:
   ```bash
   aws configure
   # Enter: Access Key ID, Secret Access Key, default region (us-east-1), output format (json)
   ```

### SSH Key

Generate a dedicated SSH key pair:

```bash
ssh-keygen -t ed25519 -f ~/.ssh/dsm-deploy -N ""
```

### Deploy

```bash
cd dsm_storage_node

# Full deploy (Terraform + Docker build + push to 6 nodes)
bash deploy/provision_aws.sh --ssh-key ~/.ssh/dsm-deploy
```

This single command:
1. Provisions 6 EC2 instances across 3 AWS regions via Terraform
2. Waits for all instances to be SSH-ready (~2-3 minutes)
3. Generates per-node TLS certificates and configs
4. Builds the Docker image (cross-compiled for x86_64 if on Apple Silicon)
5. Uploads and starts services on all 6 nodes
6. Runs a health check

Total time: ~30-45 minutes (bulk is the Rust release build).

### Cloud Architecture

```
┌──────────────────────────────────────────────────────────┐
│                   Your Local Machine                      │
│  provision_aws.sh                                         │
│    ├── terraform apply (creates 6 EC2 across 3 regions)   │
│    ├── generate_node_configs.sh (TLS certs + configs)      │
│    └── push_and_start.sh (docker build + scp + start)     │
└──────────────────────────────────────────────────────────┘
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

### Cost

| Resource | Spec | Monthly Cost |
|----------|------|-------------|
| 6x EC2 t3.small | 2 vCPU, 2GB RAM | ~$75 |
| 6x 20GB gp3 EBS | SSD storage | ~$10 |
| Data transfer | Inter-region gossip | ~$5 |
| **Total** | | **~$90/month** |

### Cloud Commands

```bash
# Skip Terraform (re-deploy to existing instances)
bash deploy/provision_aws.sh --ssh-key ~/.ssh/dsm-deploy --skip-terraform

# Skip Docker build (use previously built image)
bash deploy/provision_aws.sh --ssh-key ~/.ssh/dsm-deploy --skip-terraform --skip-build

# Health check all nodes
bash deploy/check_nodes.sh <IP1> <IP2> <IP3> <IP4> <IP5> <IP6>

# SSH into a node
ssh -i ~/.ssh/dsm-deploy ubuntu@<NODE_IP>

# View logs on a node
ssh -i ~/.ssh/dsm-deploy ubuntu@<NODE_IP> \
  "cd /opt/dsm-storage && docker compose -f docker-compose.node.yml logs -f storage-node"

# Tear down (stop billing)
bash deploy/teardown_aws.sh --ssh-key ~/.ssh/dsm-deploy
```

### Changing Regions

The 3 regions and node counts are configured in `terraform/main.tf`:

```hcl
module "us_east_1"      { ... node_count = 2; global_node_offset = 0; }
module "eu_west_1"      { ... node_count = 2; global_node_offset = 2; }
module "ap_southeast_1" { ... node_count = 2; global_node_offset = 4; }
```

Edit these module blocks to change regions or distribution.

### Terraform Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `instance_type` | `t3.small` | EC2 instance type |
| `volume_size_gb` | `20` | Root EBS volume (GB) |
| `ssh_public_key` | *(required)* | SSH public key content |
| `allowed_ssh_cidr` | `0.0.0.0/0` | CIDR for SSH access (restrict to your IP) |
| `project_tag` | `dsm-storage` | AWS resource tag for cost tracking |

### Cloud File Structure

```
dsm_storage_node/
├── Dockerfile.cloud              # Multi-stage build (Rust builder + Debian runtime)
├── config/
│   └── production.toml           # Node config template
├── deploy/
│   ├── provision_aws.sh          # Main deploy orchestrator
│   ├── generate_node_configs.sh   # Per-node TLS certs + configs
│   ├── push_and_start.sh         # Docker build + push + start
│   ├── check_nodes.sh            # Health check all nodes
│   ├── teardown_aws.sh           # Destroy all AWS resources
│   ├── docker-compose.node.yml   # Per-node compose file
│   └── nodes/                    # Generated bundles (gitignored)
└── terraform/
    ├── main.tf                   # 3 region providers + module calls
    ├── variables.tf              # Instance type, SSH key, etc.
    ├── outputs.tf                # Node IPs, helper commands
    ├── user_data.sh              # EC2 bootstrap (Docker CE install)
    └── modules/region/           # Per-region Terraform module
        ├── main.tf
        ├── variables.tf
        └── outputs.tf
```

### Cloud Troubleshooting

**Docker platform mismatch** — If you see `platform (linux/arm64) does not match the detected host platform (linux/amd64)`, the image was built for the wrong architecture. The deploy script uses `--platform linux/amd64` to cross-compile for x86_64 EC2 instances.

**SSH timeout** — Instances take 1-3 minutes to bootstrap. The script waits up to 300 seconds. If it times out, SSH in and check `/var/log/cloud-init-output.log`.

**Health check fails** — Nodes take 10-30 seconds to start after deploy. Wait and retry:
```bash
sleep 30 && bash deploy/check_nodes.sh <IPs>
```

**IAM permissions** — If Terraform fails with authorization errors, ensure your IAM user has the `AmazonEC2FullAccess` managed policy attached.

### Security Notes

- TLS certificates are self-signed, generated fresh per deployment
- SSH is key-based only; restrict `allowed_ssh_cidr` to your IP for production
- Security groups allow only ports 8080 (API), 9090 (metrics), 22 (SSH)
- PostgreSQL is internal-only (Docker bridge network), random 32-char password
- No secrets are committed to the repository

## License

Licensed under either of [Apache License, Version 2.0](../LICENSE-APACHE) or [MIT License](../LICENSE-MIT) at your option.

---

(c) 2025 Irrefutable Labs
