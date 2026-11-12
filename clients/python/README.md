# dsm-app-client (Python)

Plug your app into DSM: a client for a `dsm-app-host`'s local ingress, which is your app's own DSM account. Python 3.10+, standard library plus `protobuf`.

Its protobuf types (`dsm_app_client/generated/dsm_app_pb2.py`) are committed, so it installs with no protoc. From a release, `install.sh` puts its wheel in `~/.local/share/dsm/clients`:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install ~/.local/share/dsm/clients/dsm_app_client-0.1.0b4-py3-none-any.whl
python3 ~/.local/share/dsm/examples/account_status.py
```

From the repo root, `pip install -e clients/python` instead, and the examples are in `clients/python/examples`: `account_status.py` (your account at a glance) and `first_payment.py` (a connect code, a wallet, 0.05 ERA received). After a change to `proto/dsm_app.proto`, `make client-types` regenerates the types; CI fails when they differ (`ci/client_types_check.sh`).

- `AppAccount`: `offer`, `connections`, `request`, `result`, `wait`; `issue`, `give`; `open_vault`, `vaults`, `close_vault`; `decide`; `owned`, `owns`, `identity`, `fund`; and `ingress.activity`.
- `WalletAccount`: `preview`, `approve`, `connections`, `sync`, `pending`, `respond`, `log`, `disconnect`.
- `grant.*` builds what an offer asks for; `ask.*` builds requests (`send`, `owns`, `accept`, `contacts`, `login`, `sign`, `price`, `trade`, `match.*`, `duel.*`).
- Objects are named by symbol (`"ERA"`, `"SWORD"`) or id; amounts in the object's own units (`"0.10"`). Results are plain dataclasses: `outcome`, `fact`, `owns`, `signed`, with the wire's message as `raw`. `pb` is every generated message.
- `local_app()` and `local_wallet("wallet" | "wallet2")` find the accounts `dsm-app up` and `dsm-dev-wallet up` (or, from the repo, `make app-dev` and `make dev-wallet`) run. Elsewhere, `AppAccount(Ingress.from_secret_file(url, secret_file))`.

The guide: [BUILDING_APPS.md](../../BUILDING_APPS.md).
