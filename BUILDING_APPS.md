# Building Apps on DSM

Your app stays an ordinary app: a game, a shop, a service, in whatever language you already use. It gets **its own DSM account**, and players connect **their DSM wallet** (Android or iOS) to it by scanning a code. You never write Kotlin, Swift or Rust, and you never hold a player's keys.

This is DSM Connect (Amendment A11). The code is [crates/dsm-app-host/](crates/dsm-app-host/) (your app's account) and the SDK's `connect` module ([dsm_sdk/src/sdk/connect/](dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/connect/)).

## How it fits together

```
 your app's server ──HTTP+protobuf (loopback, secret)──► dsm-app-host ──► storage nodes
                                                          (your app's      (the network's
                                                           DSM account)     storage set)
                                                               ▲
 player's DSM wallet (phone) ──HTTPS, pinned in the code──────┘  (the relay)
```

- **`dsm-app-host` is your app's account**: one real DSM identity, running the same SDK on the same production path a phone runs. It holds tokens, issues tokens, runs vaults and receives payments.
- **Your server talks to it** over a local ingress: protobuf over HTTP, on a loopback address only, with a secret. The [TypeScript](clients/typescript/) and [Python](clients/python/) clients do this for you.
- **A wallet connects** by scanning a `dsm:connect/v1:` code your app shows. The player approves a **grant**: what your app may ask for without asking them again, with caps.
- **Your app then asks** (be paid, prove holdings, take an item you issued). The wallet answers through your account's relay. **An answer is a notification, never evidence**: a payment counts when your own account accepted the transfer. The clients give you that as the request's **fact**.

Your app needs a server side, even a small one, because the account's secret must never reach a browser page. The [starter app](examples/connect-starter/) is about 200 lines.

## Start in five minutes

You need what [QUICKSTART.md](QUICKSTART.md) lists for local storage nodes (Rust, Node.js 20+, protoc, PostgreSQL).

```bash
make app-dev       # your own storage set on this machine, and your app's account on it, funded
make starter       # the starter app: open http://127.0.0.1:3000
```

In the starter, press **Show a connect code**. Then connect a wallet. With no phone:

```bash
make dev-wallet                                  # a player's wallet in the terminal, funded
make dev-wallet-connect CODE=dsm:connect/v1:...  # the code the starter shows
```

With phones (debug builds of the wallet):

```bash
make phones-local                                # every adb device and booted iOS Simulator, on your local set
make phones-connect CODE=dsm:connect/v1:...      # open the code in each wallet
```

Back in the starter, the wallet appears under **Connected wallets**. Request a payment inside the grant and watch it become `PAID`. Request one over the per-request cap and it waits for the player: `make dev-wallet-pending`, then `make wallet ARGS="approve <session> <seq>"` (or approve it on the phone).

`make dev-down` stops everything. `make developer-path` runs this whole path end to end, as CI does.

## Your app's account

`make app-dev` runs it for you. In production you run it yourself:

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
| `--ingress-secret-dir` | Where each launch writes a new ingress secret, `ingress-token`. It must be apart from the data dir: your app gets the secret and nothing of the account. |
| `--env-config` | The network's storage set and its CA. The wallet's own is [`dsm_client/frontend/public/dsm_env_config.toml`](dsm_client/frontend/public/dsm_env_config.toml) (with its `ca.crt`); `make app-dev` uses your local set's. |
| `--game-bind` | The ingress your server calls. Loopback only; anything else is refused. |
| `--relay-bind`, `--relay-endpoint`, `--relay-name` | Where wallets reach your account. The host makes its own TLS certificate for these names, and every connect code pins it, so you need no certificate authority. |

The first lines it logs name the relay and its certificate pin, the ingress, and where this launch's secret is.

### What protects it, and what does not

- The ingress listens on loopback only. Every call needs the launch's secret as `Authorization: Bearer <secret>`, must name the ingress as its `Host`, and may come from no other web origin. A web page on the same machine can neither read the secret nor send it.
- Wallets reach the relay over TLS pinned by the connect code. The relay carries messages; nothing it carries is evidence.
- A grant caps what your app can spend from a wallet, per request and in total. Anything outside it waits for the player on their device.
- **Your account is a hot wallet.** `RECOVERY_MNEMONIC` is a file in the data dir, and the host reads it on every start. Whoever can read it, or holds root on the machine, controls the account. Anything holding the ingress secret can move everything the account holds; the host has no spending policy of its own. Keep only working balances on it, sweep the rest to an account you keep elsewhere, back up the mnemonic offline, and lock the machine down like any server that holds money.

## The clients

Both name the routes and carry bytes; every rule is the SDK's, in Rust.

### TypeScript (Node.js 20+)

[clients/typescript/](clients/typescript/), built by `make clients`.

```ts
import { localAccount, scope, intent, pb, encodeB32 } from "dsm-app-client";

const app = await localAccount("app");           // or: new AppAccount(await Ingress.fromSecretFile(url, file))
const era = await app.policyCommitOf("ERA");

// 1. A connect code: be paid up to 0.10 ERA a request, 1.00 ERA in all; prove ERA holdings.
const offer = await app.offer({
  displayName: "My Game",
  scopes: [scope.pay(era, 10n, 100n), scope.holdings([era])],
  freeRequests: 64,
});
console.log(offer.code);                         // show it as a QR code

// 2. Once a wallet connected:
const [session] = await app.sessions();
const ref = await app.request(session.sessionId, intent.pay(era, 5n, "a sword"));

// 3. What came of it. Only the fact is evidence.
const status = await app.status(ref);
if (status.fact === pb.ConnectFact.PAID) {
  console.log("paid by", encodeB32(session.peerDeviceId));
}
```

### Python (3.10+)

[clients/python/](clients/python/). `make clients` generates its protobuf types; install it with `pip install -e clients/python`.

```python
from dsm_app_client import local_app, scope, intent, pb

app = local_app()
era = app.policy_commit_of("ERA")
offer = app.offer("My Game", [scope.pay(era, 10, 100), scope.holdings([era])], free_requests=64)
print(offer.code)

session = app.sessions()[0]
ref = app.request(session.session_id, intent.pay(era, 5, "a sword"))
if app.status(ref).fact == pb.CONNECT_FACT_PAID:
    print("paid")
```

Any other language: generate types from [`proto/dsm_app.proto`](proto/dsm_app.proto) and send an `IngressRequest` (a `RouterInvokeOp` or `RouterQueryOp`: the route's name and an `ArgPack` holding its request message) to `POST /ingress`. An `IngressResponse` comes back: either an error, or `0x03` followed by an `Envelope`. [clients/typescript/src/ingress.ts](clients/typescript/src/ingress.ts) is the whole exchange, in one short file.

## Grants

What an offer can ask a player to grant (`ConnectScopeKind` in `proto/dsm_app.proto`):

| Scope | Lets your app | Client helper |
|---|---|---|
| `PAY` | be paid in a token, within a cap per request and in total | `scope.pay` / `intent.pay` |
| `HOLDINGS` | ask for a proof of what the wallet holds of your tokens (and of items you issued) | `scope.holdings` / `intent.holdings` |
| `ACCEPT_ISSUED` | hand the player an item your account issued; the wallet takes it once its policy re-hashes to its anchor | `scope.acceptIssued` / `intent.acceptIssued` |
| `CONTACTS` | read the DSM identities of the wallet's contacts, and nothing more | `scope.contacts` |
| `SWAP` | quote and trade between two tokens against a vault | `pb.ConnectScopeV1` |
| `ESCROW` | lock stakes in matches your app referees, and collect results | `pb.ConnectScopeV1` |
| `DUEL` | stake in matches a pinned program decides | `pb.ConnectScopeV1` |

`freeRequests` is how many requests that spend nothing the wallet answers before each one waits for the player.

## Requests and facts

`connect.app.request` returns a request reference. Read `connect.app.status` for it:

| | Where it comes from | Use it for |
|---|---|---|
| `outcome` | the wallet's answer: `CARRIED_OUT`, `AWAITING_APPROVAL`, `DECLINED`, `FAILED` | what to show the player while you wait |
| `fact` | what your own account established: `PAID` (a transfer it accepted), `HOLDINGS` (a proof it verified), ... | deciding anything: delivering the sword, crediting a balance |

A wallet that disconnects can be asked nothing more; the next request is refused.

## Items, and what happens offline

Items your app issues are tokens. Once in a player's wallet, they are the player's: players can send them to each other in the wallet, and your app sees who holds what with a `HOLDINGS` request.

Your app's own calls are all online: the wallet reaches your relay over HTTPS, and a payment counts once your account accepted it. Offline transfers are the wallet's own feature, between two wallets: an offline-bearer transfer carries any token whose policy lets it move, from one wallet's offline account to another's. Today that needs a hardware board on both sides, it is available on Android (the iOS app has no board link yet, and fails closed), and a trade is two one-way transfers: the offline path carries transfers only, never a swap.

## Testing

- `make dev-wallet` runs a second account as a player's wallet; `make wallet ARGS=...` drives it: `connect`, `sessions`, `pending`, `approve`, `decline`, `log`, `disconnect`.
- `make app ARGS=...` drives your app's account from the terminal: `offer`, `sessions`, `pay`, `holdings`, `status`, `activity`.
- `make developer-path` runs the starter and the terminal wallet through connect, pay inside and over the grant, holdings and disconnect, then the Python client, all against your local set. CI runs it on every change.

## Reference

The routes your app's account uses (`connect_routes.rs`):

| Route | Kind | Request | Answer |
|---|---|---|---|
| `connect.app.offer` | invoke | `ConnectAppOfferRequestV1` | `ConnectAppOfferV1` (the code) |
| `connect.app.offerOf` | query | `ConnectOfferRefV1` | `ConnectAppOfferV1` |
| `connect.app.sessions` | query | none | `ConnectSessionsV1` |
| `connect.app.request` | invoke | `ConnectAppRequestIntentV1` | `ConnectRequestRefV1` |
| `connect.app.status` | invoke | `ConnectRequestRefV1` | `ConnectAppStatusV1` |
| `balance.list` | query | none | `BalancesListResponse` |
| `faucet.claim` | invoke | `FaucetClaimRequest` | `FaucetClaimResponse` |

And a wallet's: `connect.preview` (query), `connect.approve`, `connect.sync`, `connect.list` (query), `connect.pending` (query), `connect.respond`, `connect.log` (query), `connect.disconnect`.

`GET /activity/{after}` returns `AppHostActivityV1`: your account's id, and a record of each call and each wallet's visit to the relay.
