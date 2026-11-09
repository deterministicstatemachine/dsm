# dsm-app-client (TypeScript)

Plug your app into DSM: a client for a `dsm-app-host`'s local ingress, which is your app's own DSM account. Node.js 20+.

```bash
make clients            # from the repo root: npm ci, types from proto/dsm_app.proto, tsc
```

- `AppAccount`: `offer`, `connections`, `request`, `result`, `wait`; `issue`, `give`; `openVault`, `vaults`, `closeVault`; `decide`; `owned`, `owns`, `identity`, `fund`; and `ingress.activity`.
- `WalletAccount`: `preview`, `approve`, `connections`, `sync`, `pending`, `respond`, `log`, `disconnect`.
- `grant.*` builds what an offer asks for; `ask.*` builds requests (`send`, `owns`, `accept`, `contacts`, `login`, `sign`, `price`, `trade`, `match.*`, `duel.*`).
- Objects are named by symbol (`"ERA"`, `"SWORD"`) or id; amounts in the object's own units (`"0.10"`). Results are plain: `outcome`, `fact`, `owns`, `signed`, with the wire's message as `raw`. `pb` is every generated message.
- `localAccount("app" | "wallet" | "wallet2")` finds the accounts `make app-dev`, `make dev-wallet` and `make dev-wallet2` run. Elsewhere, `new AppAccount(await Ingress.fromSecretFile(url, secretFile))`.

Two command-line tools come with it: `dsm-app` (your app's account) and `dsm-dev-wallet` (a terminal wallet; `DSM_WALLET_NAME=wallet2` for the second). From the repo root, `make app ARGS=...`, `make wallet ARGS=...` and `make wallet2 ARGS=...` run them.

The guide: [BUILDING_APPS.md](../../BUILDING_APPS.md).
