# dsm-app-client (Python)

A client for a `dsm-app-host`'s local ingress: your app's own DSM account. Python 3.10+, standard library plus `protobuf`.

```bash
make clients                      # from the repo root: generates dsm_app_client/generated/dsm_app_pb2.py
pip install -e clients/python     # installs protobuf too
python clients/python/examples/account_status.py
```

- `AppAccount`: `offer`, `sessions`, `request`, `status`, `balances`, `policy_commit_of`, `claim_faucet`, and `ingress.activity`.
- `WalletAccount`: `preview`, `approve`, `pending`, `respond`, `disconnect`.
- `scope.*` and `intent.*` build grants and requests; `pb` is every generated message.
- `local_app()` / `local_wallet()` find the accounts `make app-dev` and `make dev-wallet` run. Elsewhere, `AppAccount(Ingress.from_secret_file(url, secret_file))`.

The guide: [BUILDING_APPS.md](../../BUILDING_APPS.md).
