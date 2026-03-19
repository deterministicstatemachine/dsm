# Chapter 8 — Bitcoin and dBTC

dBTC is DSM's Bitcoin bridge — a deterministic, post-quantum wrapped Bitcoin built on HTLC deep-anchoring and CPTA fungibility manifolds.

---

## Network Configuration

All dBTC flows use Bitcoin signet. The default config (`dsm_env_config.toml`) ships with:

```toml
bitcoin_network = "signet"
dbtc_min_confirmations = 1      # 100 for mainnet
mempool_api_url = "https://mempool.space"
```

| Field | Values | Description |
|-------|--------|-------------|
| `bitcoin_network` | `"signet"`, `"testnet"`, `"mainnet"` | Network for key derivation and address format |
| `dbtc_min_confirmations` | `1` (testing), `100` (mainnet) | Deep-anchor burial depth |
| `mempool_api_url` | `https://mempool.space` | Explorer API for balance, broadcast, confirmation tracking |

No local Bitcoin node is required. All signet operations use the public mempool.space API.

---

## How dBTC Works

### Deposit (BTC → dBTC)

1. User creates an HTLC on Bitcoin signet with a hashlock derived from their DSM identity
2. DSM SDK monitors the HTLC for confirmation (deep-anchor burial)
3. Once buried, dBTC tokens are minted on the user's DSM state chain
4. The dBTC amount equals the HTLC value minus fees

### Withdrawal (dBTC → BTC)

1. User initiates a withdrawal specifying amount and destination BTC address
2. SDK burns dBTC tokens on the DSM state chain
3. SDK constructs and broadcasts the Bitcoin sweep transaction
4. Both outputs (exit anchor + successor HTLC) require deep-anchor burial (100 blocks on mainnet, 1 on signet)

### Fungibility

dBTC tokens are fungible via shared CPTA (Content-addressed Policy Token Anchor) manifolds. All vaults referencing the same CPTA policy hash enter the same economic equivalence class — a satoshi from Vault A is identical to one from Vault B.

---

## Typical Workflow

1. Ensure `bitcoin_network = "signet"` in your config (this is the default)
2. Import or create a Bitcoin wallet in the app
3. Fund the wallet with signet BTC (use a [signet faucet](https://signet.bc-2.jp/))
4. Create an HTLC deposit to bridge BTC → dBTC
5. Track confirmations through the mempool explorer links in the UI
6. Transfer dBTC bilaterally (BLE/online) or withdraw back to BTC

---

## Testing

### SDK Integration Tests

```bash
cd dsm_client/deterministic_state_machine
cargo test --package dsm_sdk --test bitcoin_tap_e2e -- --test-threads=1 --nocapture
```

This runs 15 integration tests covering deposit operations, fee calculations, content encoding, RBF opt-in, and header chain validation.

### Unit Tests

```bash
cd dsm_client/deterministic_state_machine
cargo test --package dsm_sdk -- bitcoin_tap --nocapture
```

---

## Android Assets

After frontend Bitcoin changes, rebuild and copy the Android bundle:

```bash
cd dsm_client/new_frontend
npm run build:android-webpack
npm run copy:android
```

Or use the combined command:

```bash
cd dsm_client/new_frontend
npm run build:full-deploy
```

---

## Source Layout

| File | Purpose |
|------|---------|
| `dsm/src/bitcoin/` | Core Bitcoin types, HTLC construction |
| `dsm_sdk/src/sdk/bitcoin_tap_sdk.rs` | SDK Bitcoin bridge (deposit, withdraw, sweep) |
| `dsm_sdk/src/handlers/bitcoin_invoke_routes.rs` | JNI invoke handler for all `bitcoin.*` routes |
| `dsm_sdk/tests/bitcoin_tap_e2e.rs` | Integration test suite (15 tests) |
| `dsm_sdk/src/network.rs` | Config parsing (`bitcoin_network`, `mempool_api_url`, etc.) |

---

## Key Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Deep-anchor depth | 100 (mainnet) / 1 (signet) | Blocks before successor vault becomes Active |
| Fee rate | 10 sat/vByte (floor) | Minimum withdrawal fee rate |
| HTLC timelock | Configurable | Refund timelock for deposit HTLCs |
| RBF | Always opt-in | All inputs signal RBF (BIP 125) |

---

Next: [Chapter 9 — BLE Testing](09-ble-testing.md)
