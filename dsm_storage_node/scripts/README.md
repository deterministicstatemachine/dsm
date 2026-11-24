# dsm_storage_node/scripts/

This directory holds two client binding-chain checks, not storage-node
scripts:

- **`tests/`**
  - `test_hashchain_binding_chain.sh`
  - `test_protocol_metrics_binding_chain.sh`

Both anchor themselves via `SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)`
and can be run from any working directory.

For storage nodes:

- A local storage set is `make nodes-up` (and `nodes-down`, `nodes-status`,
  `nodes-reset`) from the repository root, which runs `scripts/dev_net.sh` and
  `crates/dsm-dev-net`. See [the storage node README](../README.md).
- Deployment is [`dsm_storage_node/deploy/`](../deploy/): `provision_ovh.sh`
  or `provision_aws.sh`, then `assemble_storage_set.sh`.
