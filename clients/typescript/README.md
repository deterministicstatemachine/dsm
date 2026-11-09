# dsm-app-client (TypeScript)

A client for a `dsm-app-host`'s local ingress: your app's own DSM account, and the terminal dev wallet. Node.js 20+.

```bash
make clients            # from the repo root: npm ci, types from proto/dsm_app.proto, tsc
```

- `AppAccount`: `offer`, `sessions`, `request`, `status`, `balances`, `policyCommitOf`, `claimFaucet`, and `ingress.activity`.
- `WalletAccount`: `preview`, `approve`, `sessions`, `sync`, `pending`, `respond`, `log`, `disconnect`.
- `scope.*` and `intent.*` build grants and requests; `pb` is every generated message.
- `localAccount("app" | "wallet")` finds the accounts `make app-dev` and `make dev-wallet` run. Elsewhere, `new AppAccount(await Ingress.fromSecretFile(url, secretFile))`.

Two command-line tools come with it: `dsm-app` (your app's account) and `dsm-dev-wallet` (the terminal wallet). From the repo root, `make app ARGS=...` and `make wallet ARGS=...` run them.

The guide: [BUILDING_APPS.md](../../BUILDING_APPS.md).
