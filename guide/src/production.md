# Run your app's account in production

`make app-dev` runs your app's account for you while you develop. In production you run the same program, `dsm-app-host`, yourself, beside your server.

## Build it

From the repo, the way `make app-dev` builds it:

```bash
cargo build --release --locked -p dsm-app-host
```

The program is `target/release/dsm-app-host`.

## Run it

The command, with your own paths and names in place of `myapp`'s:

```bash
dsm-app-host \
  --data-dir /var/lib/myapp/dsm \
  --ingress-secret-dir /run/myapp/dsm-ingress \
  --env-config /etc/myapp/dsm_env_config.toml \
  --game-bind 127.0.0.1:8787 \
  --relay-bind 0.0.0.0:8443 \
  --relay-endpoint https://dsm.myapp.example:8443 \
  --relay-name dsm.myapp.example
```

| Flag | What it is |
|---|---|
| `--data-dir` | The account: its state and `RECOVERY_MNEMONIC`. The first start creates the account and writes the mnemonic there (mode 0600). |
| `--ingress-secret-dir` | Where each launch writes a new ingress secret, `ingress-token`. It must be apart from the data directory: your app gets the secret and nothing of the account. |
| `--env-config` | The network's storage set, each member with its own certificate authority. The wallet's own is [`dsm_client/frontend/public/dsm_env_config.toml`](https://github.com/deterministicstatemachine/dsm/blob/main/dsm_client/frontend/public/dsm_env_config.toml), and `make app-dev` uses it too. |
| `--game-bind` | The ingress your server calls. Loopback only; anything else is refused. |
| `--relay-bind`, `--relay-endpoint`, `--relay-name` | Where wallets reach your account. The host makes its own TLS certificate for these names, and every connect code pins it, so you need no certificate authority. |

The first lines it logs name the relay and its certificate pin, the ingress, and where this launch's secret is. Your server opens the account from the ingress's address and that secret file: `new AppAccount(await Ingress.fromSecretFile(url, secretFile))` in TypeScript, `AppAccount(Ingress.from_secret_file(url, secret_file))` in Python.

## What protects it, and what does not

- The ingress listens on loopback only. Every call needs the launch's secret as `Authorization: Bearer <secret>`, must name the ingress as its `Host`, and may come from no other web origin. A web page on the same machine can neither read the secret nor send it.
- Wallets reach the relay over TLS pinned by the connect code. The relay carries messages; nothing it carries is evidence.
- A grant caps what your app can take from a wallet, per request and in total. Anything outside it waits for the player, on their device.

> [!CAUTION]
> **Your account is a hot wallet.** `RECOVERY_MNEMONIC` is a file in the data directory, and the host reads it on every start. Whoever can read it, or holds root on the machine, controls the account. Anything holding the ingress secret can move everything the account holds; the host has no spending policy of its own. Keep on it only what it needs to work with, sweep the rest to an account you keep elsewhere, back up the mnemonic offline, and lock the machine down like any server that holds money.

Next, if you want your own network: [A storage set of your own](own-storage-set.md).
