# dsm_storage_node/scripts/

Helper scripts for the local storage-node dev cluster and end-to-end binding-chain tests.
Production deployment is handled by [`dsm_storage_node/deploy/`](../deploy/) (Terraform + `provision_gcp.sh` + `push_and_start.sh` + `Dockerfile.cloud`).

## Layout

- **`dev/`** — local 5-node dev cluster (ports 8080–8084)
  - `start_dev_nodes.sh` — launch the cluster (uses `config/dev/node{1..5}.toml`)
  - `stop_dev_nodes.sh` — stop all dev nodes
  - `check_node_status.sh` — port + `/api/v2/health` status report
- **`tests/`** — end-to-end binding-chain integration tests
  - `test_hashchain_binding_chain.sh`
  - `test_protocol_metrics_binding_chain.sh`

All scripts are designed to be run from any working directory — they anchor
themselves via `SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)`.
