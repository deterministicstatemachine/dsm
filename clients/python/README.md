# dsm-app-client (Python)

Plug your app into DSM: a client for a `dsm-app-host`'s local ingress, which is your app's own DSM account. Python 3.10+, standard library plus `protobuf`.

```bash
make clients                      # from the repo root: generates dsm_app_client/generated/dsm_app_pb2.py
pip install -e clients/python     # installs protobuf too
python clients/python/examples/account_status.py
```

- `AppAccount`: `offer`, `connections`, `request`, `result`, `wait`; `issue`, `give`; `open_vault`, `vaults`, `close_vault`; `decide`; `owned`, `owns`, `identity`, `fund`; and `ingress.activity`.
- `WalletAccount`: `preview`, `approve`, `connections`, `sync`, `pending`, `respond`, `log`, `disconnect`.
- `grant.*` builds what an offer asks for; `ask.*` builds requests (`send`, `owns`, `accept`, `contacts`, `login`, `sign`, `price`, `trade`, `match.*`, `duel.*`).
- Objects are named by symbol (`"ERA"`, `"SWORD"`) or id; amounts in the object's own units (`"0.10"`). Results are plain dataclasses: `outcome`, `fact`, `owns`, `signed`, with the wire's message as `raw`. `pb` is every generated message.
- `local_app()` and `local_wallet("wallet" | "wallet2")` find the accounts `make app-dev` and `make dev-wallet` run. Elsewhere, `AppAccount(Ingress.from_secret_file(url, secret_file))`.

The guide: [BUILDING_APPS.md](../../BUILDING_APPS.md).
