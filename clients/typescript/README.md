# dsm-app-client (TypeScript)

Plug your app into DSM: a client for a `dsm-app-host`'s local ingress, which is your app's own DSM account. Node.js 20+.

Its protobuf types (`src/generated/dsm_app_pb.ts`) are committed, so it builds with `tsc` alone and no protoc. From a release, `install.sh` puts its package in `~/.local/share/dsm/clients`; install it into your app:

```bash
npm install ~/.local/share/dsm/clients/dsm-app-client-0.1.0-beta.4.tgz
```

From the repo root, `make clients` runs `npm ci` and `tsc`; after a change to `proto/dsm_app.proto`, `make client-types` regenerates the types, and CI fails when they differ (`ci/client_types_check.sh`).

- `AppAccount`: `offer`, `connections`, `request`, `result`, `wait`; `issue`, `give`; `openVault`, `vaults`, `closeVault`; `decide`; `owned`, `owns`, `identity`, `fund`; and `ingress.activity`.
- `WalletAccount`: `preview`, `approve`, `connections`, `sync`, `pending`, `respond`, `log`, `disconnect`.
- `grant.*` builds what an offer asks for; `ask.*` builds requests (`send`, `owns`, `accept`, `contacts`, `login`, `sign`, `price`, `trade`, `match.*`, `duel.*`).
- Objects are named by symbol (`"ERA"`, `"SWORD"`) or id; amounts in the object's own units (`"0.10"`). Results are plain: `outcome`, `fact`, `owns`, `signed`, with the wire's message as `raw`. `pb` is every generated message.
- `localAccount("app" | "wallet" | "wallet2")` finds the accounts `dsm-app up` and `dsm-dev-wallet up` run (from the repo, `make app-dev`, `make dev-wallet` and `make dev-wallet2`). Elsewhere, `new AppAccount(await Ingress.fromSecretFile(url, secretFile))`.

Two command-line tools come with it: `dsm-app` (your app's account: `dsm-app up` starts it with the `dsm-app-host` on PATH) and `dsm-dev-wallet` (a terminal wallet; `DSM_WALLET_NAME=wallet2` for the second). `install.sh` puts both on PATH. From the repo root, `make app ARGS=...`, `make wallet ARGS=...` and `make wallet2 ARGS=...` run them.

The guide: [BUILDING_APPS.md](../../BUILDING_APPS.md).
