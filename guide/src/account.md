# Your app's own DSM account

Your app gets a DSM account. Not an API key, not a merchant id: an account like a wallet's, with its own identity, running the same code a phone runs.

<div class="flow"><span>your web app</span><i>→</i><span>loopback ingress<br>+ per-launch secret</span><i>→</i><span class="here">dsm-app-host<br>your account</span><i>→</i><span>storage nodes</span></div>

Your web app stays what it is: Node, Python, whatever it is today. Beside it runs one process, the app host, and that process is your account. Your app talks to it over a local socket on the same machine, loopback only, with a secret the host writes for each launch. Wallets reach the host over TLS, through its relay.

## 1. Start it

In your app's folder:

```bash
dsm-app up
```

This runs `dsm-app-host` in the background with a data directory, a directory for the ingress secret, and the beta network's client config, which the host carries: the same five storage nodes the wallet ships with. It keeps them under `.dsm-dev` in this folder.

The first launch creates the account. It writes a recovery mnemonic once to the data directory, readable by you alone, and makes the account the way a phone does. The host waits until the network holds the account's directory entry, and only then opens its ingress. Then the account is funded from the network's faucet.

What it prints, from a run on the beta network (13 seconds, on a Mac):

```text
[dsm-app] app account running
  storage set:    the beta network (carried in dsm-app-host)
  ingress:        http://127.0.0.1:8787   (your server calls this)
  ingress secret: …/.dsm-dev/app/ingress/ingress-token
  relay:          https://127.0.0.1:8443   (wallets reach this)
  recovery:       …/.dsm-dev/app/data/RECOVERY_MNEMONIC
  log:            …/.dsm-dev/app/host.log
funded: claimed 100.00 ERA (economic position 1)
```

`…` is your app's folder. Line by line:

- **storage set**: the beta network, hosted.
- **ingress**, on loopback port 8787: your server calls this.
- **ingress secret**: in its own directory, so your app can read the secret and nothing else of the account.
- **relay**, on port 8443: wallets reach this.
- **recovery**: the recovery mnemonic.
- **funded**: 100 ERA from the faucet.

> [!WARNING]
> Back up the recovery mnemonic like a wallet's, because that is what it is. Whoever can read the data directory controls the account.

`dsm-app up` returns once the account is running; the host keeps running in the background. `dsm-app down` stops it, and `dsm-app status` says whether it runs. Run `dsm-app up` again whenever you like: it keeps the same account, and claims nothing more from the faucet once the account holds ERA (it says `already holds` and the amount).

## 2. Look at it

`dsm-app` talks to the account through the same ingress your code will. `id` prints the account's identity:

```bash
dsm-app id
```

```text
P1TTQ65K20YCW6FCHVJ8A8V0VQ55NN3DZK6KCBFMCC3M98KN3X2G
```

`owned` prints what it holds: a hundred ERA from the faucet, and nothing of dBTC yet.

```bash
dsm-app owned
```

```text
ERA                100.00   currency NNG176RZ6ACTWCDPRNYHXZK2DCZ72SPA9Q6XWGRGQ9JGKZYTESG0
dBTC           0.00000000   currency 0EJ2PSRS2YQR8BR77P3WZ92SV12VJT7XP6NWP0SH5P8MWD81C8H0
```

Each line is an object: its symbol, the amount in its own units, its kind, and its id.

`activity` is the account's own record of every call made through the ingress:

```bash
dsm-app activity
```

```text
account P1TTQ65K20YCW6FCHVJ8A8V0VQ55NN3DZK6KCBFMCC3M98KN3X2G
1  ROUTE  faucet.claim  claim ERA from the network's faucet  -> claimed 100.00 ERA (economic position 1)
```

Your app can read the activity too, from any point. That is how it learns what happened without trusting anyone's say-so. Your identity and ids will differ from these; everything else reads the same.

## 3. The ingress

Three routes make the ingress:

| Route | What it does |
|---|---|
| `POST /ingress` | Makes a call, and records it in the account's activity. |
| `POST /ingress/quiet` | Makes a call that is not recorded: what your app polls with. |
| `GET /activity/{after}` | Reads what was recorded after that point. |

Every call carries the launch's secret as `Authorization: Bearer <secret>`, must name the ingress as its `Host`, and may come from no other web origin. A web page in a browser on the same machine can neither read the secret nor send it. The clients wrap all of this; you will not write these requests by hand.

## 4. The wire

On the wire, each call is one protobuf message, the route's name and its arguments, answered with one message back. The schema is one file, [`proto/dsm_app.proto`](https://github.com/deterministicstatemachine/dsm/blob/main/proto/dsm_app.proto), and the TypeScript and Python clients are generated from it. For a client in another language, that file is all you need: send an `IngressRequest` (a `RouterInvokeOp` or `RouterQueryOp`: the route's name and an `ArgPack` holding its request message) to `POST /ingress`, and an `IngressResponse` comes back. [`clients/typescript/src/ingress.ts`](https://github.com/deterministicstatemachine/dsm/blob/main/clients/typescript/src/ingress.ts) is the whole exchange, in one short file.

## 5. The first call

Here is the first call in TypeScript and in Python: open the local account, and ask for its connections. First the client, into your app's folder. TypeScript, from the package the install put in `~/.local/share/dsm/clients`:

```bash
npm init -y
npm install ~/.local/share/dsm/clients/dsm-app-client-0.1.0-beta.4.tgz
```

`npm init -y` makes a `package.json` if your folder has none. The client's types are inside the package, so nothing is compiled. Then:

```ts
import { localAccount } from "dsm-app-client";

const app = await localAccount("app");
console.log(await app.connections());
```

```python
from dsm_app_client import local_app

app = local_app()
print(app.connections())
```

Each prints an empty list: nothing is connected yet. `localAccount("app")` and `local_app()` find the account `dsm-app up` started by looking for the `.dsm-dev` folder above the folder you run in; from anywhere else, name it with `DSM_DEV_DIR`. [Write it into your app](clients.md) runs whole programs.

The Python client goes into a virtual environment, from its package beside the TypeScript one:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install ~/.local/share/dsm/clients/dsm_app_client-0.1.0b4-py3-none-any.whl
python3 ~/.local/share/dsm/examples/account_status.py
```

`account_status.py` prints your account at a glance: its identity, what it owns, every connected wallet with what it may do, and the latest activity. Its types are inside the package too, so pip installs it with nothing to compile; it fetches one dependency, `protobuf`.

## The whole page, as one script

```bash
dsm-app up
dsm-app id
dsm-app owned
dsm-app activity
```

Next: [Make an offer, connect a wallet](connect.md).
