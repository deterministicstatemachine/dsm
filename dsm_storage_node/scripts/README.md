# dsm_storage_node/scripts/

Helper scripts for storage node lifecycle, security setup, and integration testing.

## Layout

- **`dev/`** — local 5-node dev cluster (ports 8080–8084)
  - `start_dev_nodes.sh` — launch the cluster (uses `config/dev/node{1..5}.toml`)
  - `stop_dev_nodes.sh` — stop all dev nodes
  - `check_node_status.sh` — port + `/api/v2/health` status report
- **`tests/`** — end-to-end binding-chain integration tests
  - `test_hashchain_binding_chain.sh`
  - `test_protocol_metrics_binding_chain.sh`
- **Top level** — production hardening (TLS, firewall, monitoring, prod startup).
  These scripts cross-generate one another via heredocs at fixed `./scripts/*.sh`
  paths, so they intentionally remain co-located:
  - `production_security_setup.sh` — orchestrates the full hardening pass
  - `start_production.sh` — secure production startup
  - `generate_tls_certificates.sh`, `quick_tls_setup.sh`
  - `setup_firewall.sh`, `setup_firewall_macos.sh`, `monitor_firewall.sh`, `reset_firewall.sh`
  - `setup_monitoring.sh`

All scripts are designed to be run from any working directory — they anchor
themselves via `SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)`.
