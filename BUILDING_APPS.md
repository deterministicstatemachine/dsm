# Plug Your App Into DSM

Your app stays what it is: a game, a shop, a service, in the language you already use. You don't build on DSM the way you build on a blockchain, with contracts and a new language. You plug in: your app gets **its own DSM account**, and your users connect **their DSM wallet** to it. From then on your app can ask the wallet for things, and your own account tells you, with evidence, what happened.

- You write no Kotlin, Swift or Rust. The wallet exists, on Android and iOS.
- You hold no user's keys, passwords or card numbers.
- You learn a dozen words: `offer`, `connections`, `request`, `result`; `send`, `owns`, `accept`, `trade`, `match`, `login`; `issue`, `give`.

This is DSM Connect (Amendment A11). The code is [crates/dsm-app-host/](crates/dsm-app-host/) (your app's account) and the SDK's `connect` module ([dsm_sdk/src/sdk/connect/](dsm_client/deterministic_state_machine/dsm_sdk/src/sdk/connect/)).

## What you can replace

Everything below works today, on the path the check in this repo runs on every change (`make developer-path`).

| You run today | With DSM | Why it's better |
|---|---|---|
| Passwords, password resets, an authenticator app, SMS codes, security keys | `ask.login`: the player approves "Sign in to *your app*" on their device, and the wallet's identity signs it. Your account verifies the signature and gives you the fact `signed`. | Nothing to store but a nonce, nothing to leak, nothing to phish: the words are shown on the device and signed there. Post-quantum signatures. No hardware key to buy, ship or replace. |
| A payment processor for in-app purchases | `ask.send`: the wallet sends your account ERA, or a coin you issued. Fact: `received`. | A transfer your account accepted is final; there is no chargeback. Small amounts cost what a storage write costs, not a percentage plus a fixed fee. Inside the grant's caps the player is not asked again. |
| An inventory database as the source of truth for who owns what | `issue` an object, `give` it, and later `ask.owns`: the wallet proves what it owns, your account verifies the proof. Fact: `owns`. | Items are the player's: they can send them to each other in the wallet, and your app still sees who holds what. Your database keeps game state; ownership lives with the player. |
| An escrow service, or trusting yourself with both players' stakes | `ask.match.stake`, `decide`, `ask.match.collect`: both players stake from their own wallets, your app decides, the winner collects. | Your app never holds the stakes. Each wallet locks its own, under terms it built itself; your key only decides. |
| A marketplace backend with its own order book and settlement | `openVault` and `ask.trade`: your account's vault sells your coin for ERA (or any pair) at a fee you set. | Prices come from the vault's reserves, trades settle on the players' own devices, and your account earns the fee. |
| Account recovery flows, "forgot password" | None. The identity is the player's wallet, which they back up themselves. | Your app has nothing to recover. |

What DSM does not replace: your app's own logic and state (DSM holds identities, objects and facts, not your game); and government identity. If you need KYC, keep your own record of it keyed by the player's DSM identity, which a sign-in proves: DSM itself holds no personal data, so KYC attaches to the identity, not to a password.

### The two sides of every request

Every request has two answers, and only one is evidence:

| | Where it comes from | Use it for |
|---|---|---|
| **outcome** | the wallet's word: `carried_out`, `awaiting_approval`, `declined`, `failed` | what to show the player while you wait |
| **fact** | what your own account established: `received`, `owns`, `signed`, `staked`, `collected`, ... | deciding anything: delivering the item, logging the player in, crediting the sale |

## Who pays for what

Storage on DSM is paid for by the account that writes: a one-time entry payment (a flat rate to three storage operators), then credits consumed by each write, priced in token units by a network parameter. Nobody is billed per month or per user, and reading is free. That leaves you three ways to set things up:

1. **Players pay their own way.** Each player's wallet is their own account, on the public set. In the beta, the faucet funds every new wallet. Later they buy ERA like anything else. Your app pays only for its own account's writes. This is the setup `make app-dev` and the public beta give you.
2. **Your app pays for its players.** `give` a player ERA when they connect; their wallet spends it on its own writes. What you give is theirs, and works anywhere on DSM, so this is a gift, not a subscription.
3. **Your app runs the storage, and players pay nothing.** Run your own storage set ([dsm_storage_node/RUN_A_NODE.md](dsm_storage_node/RUN_A_NODE.md)) and point your players' wallets at it, the way `make phones-local` points them at your local set. A node may enforce the entry payment and credits, or not; on your own set, that is your call. You pay the hosting; accounts on your set are still their owners', and a wallet on your set reaches only your set.

What this replaces, in cost: a hardware key per user and its replacements; SMS codes per message; a processor's percentage on every payment; an escrow or marketplace provider. What you pay instead is your account's storage writes, in ERA, and hosting if you choose setup 3.

## How it fits together

```
 your app's server ──HTTP+protobuf (loopback, secret)──► dsm-app-host ──► storage nodes
                                                          (your app's      (the network's
                                                           DSM account)     storage set)
                                                               ▲
 player's DSM wallet (phone) ──HTTPS, pinned in the code──────┘  (the relay)
```

- **`dsm-app-host` is your app's account**: one real DSM identity, running the same SDK on the same path a phone runs. It owns objects, issues them, runs vaults, receives payments and referees matches.
- **Your server talks to it** over a local ingress: protobuf over HTTP, on a loopback address only, with a secret. The [TypeScript](clients/typescript/) and [Python](clients/python/) clients do this for you, in plain words.
- **A wallet connects** by scanning a `dsm:connect/v1:` code your app shows. The player approves a **grant**: what your app may ask for without asking them again, with caps.
- **Your app then asks**, and reads the **fact** your own account established.

Your app needs a server side, even a small one, because the account's secret must never reach a browser page. The [starter](examples/connect-starter/) is one file, and its page is where you build your app from pieces.

## Start in five minutes

You need what [QUICKSTART.md](QUICKSTART.md)'s prerequisites list (Rust, Node.js 20+, protoc, and PostgreSQL for the local storage set).

```bash
make app-dev       # your own storage set on this machine, and your app's account on it, funded
make starter       # the starter app: open http://127.0.0.1:3000
```

The starter's page is a builder. It has three kinds of pieces, in the order an app uses them:

1. **Objects your app issues**: a coin, points, an item (supply 1 is a one-of-a-kind), a ticket; and a shop, a vault that sells one object for another.
2. **What the wallet lets your app do**: the offer. Tick the grants (send, owns, accept, contacts, match, trade), set each cap, and press **Show the connect code**.
3. **Ask a connected wallet**: send, prove what it owns, sign in, sign a statement, accept or receive an object, price or make a trade through your shop, stake on a match, decide it, collect.

Under every piece is the exact code it is, in TypeScript or Python, with a Copy button. The page never makes up that code: it asks the starter's server, which runs one mapping from piece to client call ([src/pieces.ts](examples/connect-starter/src/pieces.ts)) both to show the code and to make the call. Set the pieces up the way your app needs them, press the button to see it happen, then paste the code into your own app.

Press **Show the connect code**. Then connect a wallet. With no phone:

```bash
make dev-wallet                                  # a player's wallet in the terminal, funded
make dev-wallet-connect CODE=dsm:connect/v1:...  # the code the starter shows
```

With phones (debug builds of the wallet):

```bash
make phones-local                                # every adb device and booted iOS Simulator, on your local set
make phones-connect CODE=dsm:connect/v1:...      # open the code in each wallet
```

After `make nodes-reset` (a new set, with new CAs), clear the phones' wallets and run `make phones-local` again.

Back in the starter, the wallet appears under **Connected wallets**. Under **Ask a connected wallet**, ask it to send 0.05 ERA and watch the fact become `received`. Ask for 0.20, over the per-request cap, and it waits for the player: `make dev-wallet-pending`, then `make wallet ARGS="approve <connection> <seq>"` (or approve it on the phone). Ask it to **sign in** and approve that the same way: the fact is `signed`.

`make dev-down` stops everything. `make developer-path` runs the whole path, every helper once, as CI does.

## The clients

### TypeScript (Node.js 20+)

[clients/typescript/](clients/typescript/), built by `make clients`.

```ts
import { localAccount, grant, ask } from "dsm-app-client";

const app = await localAccount("app");          // or: new AppAccount(await Ingress.fromSecretFile(url, file))

// 1. A connect code. Amounts are in the object's own units: 0.10 ERA.
const offer = await app.offer({
  name: "My Game",
  grants: [grant.send("ERA", "0.10", "1.00"), grant.owns(["ERA"]), grant.accept()],
});
console.log(offer.code);                        // show it as a QR code

// 2. Once a wallet connected:
const [player] = await app.connections();
const paid = await app.wait(await app.request(player, ask.send("ERA", "0.05", "a sword")));
if (paid.fact === "received") {
  const sword = await app.issue({ symbol: "SWORD", name: "Sword", supply: "1" });
  await app.wait(await app.request(player, ask.accept(sword)), { until: "answered" });
  await app.give(player, sword, "1");
}

// 3. Sign in: the player approves the words on the device.
const login = await app.wait(await app.request(player, ask.login("My Game")));
if (login.fact === "signed") console.log(`${player.peer} signed in`);
```

### Python (3.10+)

[clients/python/](clients/python/). `make clients` generates its protobuf types; install it into a virtual environment:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e clients/python
```

```python
from dsm_app_client import local_app, grant, ask

app = local_app()
offer = app.offer("My Game", [grant.send("ERA", "0.10", "1.00"), grant.owns(["ERA"]), grant.accept()])
print(offer.code)

player = app.connections()[0]
paid = app.wait(app.request(player, ask.send("ERA", "0.05", "a sword")))
if paid.fact == "received":
    sword = app.issue("SWORD", "Sword", "1")
    app.wait(app.request(player, ask.accept(sword)), until="answered")
    app.give(player, sword, "1")
```

[clients/python/examples/first_payment.py](clients/python/examples/first_payment.py) is this, as a program: it prints the connect code, waits for a wallet to connect to it, asks for 0.05 ERA and prints the fact.

```bash
python3 clients/python/examples/first_payment.py              # then: make dev-wallet-connect CODE=<the code it prints>
```

A wallet connects to an app once. If the terminal wallet is already connected to your account (through the starter, say), it disconnects first (`make wallet ARGS="disconnect <connection>"`), or a second wallet connects: `make dev-wallet2`, then `make wallet2 ARGS="connect <the code>"`.

Any other language: generate types from [`proto/dsm_app.proto`](proto/dsm_app.proto) and send an `IngressRequest` (a `RouterInvokeOp` or `RouterQueryOp`: the route's name and an `ArgPack` holding its request message) to `POST /ingress`. An `IngressResponse` comes back: either an error, or `0x03` followed by an `Envelope`. [clients/typescript/src/ingress.ts](clients/typescript/src/ingress.ts) is the whole exchange, in one short file.

### Objects, not tokens

Everything an account can hold is an **object**: ERA, a sword, a ticket, a coin you issued. A currency is an object counted in units; an item is an object of which exactly one exists. You name an object by its symbol (`"ERA"`, `"SWORD"`) or by its id, and amounts in its own units (`"0.10"`, `"1"`); Rust converts them, in both directions, so no client carries the unit rule. `issue` makes a new object; your account then holds its whole supply, and `give` hands some to a wallet that has accepted it.

## Grants

What an offer asks the player to let your app do without asking again:

| `grant.` | Lets your app | Asked with |
|---|---|---|
| `send(object, perRequest, total)` | be sent an object, within caps per request and in total | `ask.send` |
| `owns(objects)` | be shown a proof of what the wallet owns of these objects, and of any you issued | `ask.owns` |
| `accept()` | hand the player objects your account issued | `ask.accept`, then `give` |
| `contacts()` | read the DSM identities of the wallet's contacts, and nothing more | `ask.contacts` |
| `trade(a, b, caps)` | trade between two objects through your vaults, within caps | `ask.price`, `ask.trade`; a wallet receives only an object it added, so `ask.accept` your coin first |
| `match(caps)` | take stakes in matches your app referees, within caps | `ask.match.stake`, `decide`, `ask.match.collect` |
| `duel(programs, caps)` | take stakes in matches a pinned program decides | `ask.duel.*` |

`ask.login` and `ask.sign` are never in a grant: each waits for the player on the device. Requests that spend nothing are free up to the offer's `freeRequests` (default 64); past that each is refused.

## Matches

A **match** is a contest your app referees. Each player's wallet stakes from its own balance, under terms the wallet builds itself (A wins, B wins, or void); your app's key decides. `ask.match.stake` names the opponent by the other player's connection (`connection.opponent`); side B passes side A's stake id as `against`, so both stakes share one verdict. `app.decide(stake, "A" | "B" | "void")`, then the winner's `ask.match.collect([stakeA, stakeB])`. Facts: `staked`, `collected`.

A **duel** is a contest a program decides from both players' signed moves, with no referee (SoFi Amendment S22). The `ask.duel` helpers carry the setup, readies, signed moves and settlement; the setup and moves are built with the program's own library (for the bundled program, [crates/wildstate-duel-wasm/](crates/wildstate-duel-wasm/)). The check does not run a duel; the SDK's own tests do (`connect_duel_e2e_tests.rs`).

## Offline

Your app's own calls are all online. Offline transfers are the wallet's feature, between two wallets: a bearer transfer carries any object whose policy lets it move, from one wallet's offline account to another's. Today that needs a hardware board on both sides, it is available on Android (the iOS app has no board link yet, and fails closed), and a trade offline is two one-way transfers.

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
| `--env-config` | The network's storage set, each member with its own CA. The wallet's own is [`dsm_client/frontend/public/dsm_env_config.toml`](dsm_client/frontend/public/dsm_env_config.toml); `make app-dev` uses your local set's. |
| `--game-bind` | The ingress your server calls. Loopback only; anything else is refused. |
| `--relay-bind`, `--relay-endpoint`, `--relay-name` | Where wallets reach your account. The host makes its own TLS certificate for these names, and every connect code pins it, so you need no certificate authority. |

The first lines it logs name the relay and its certificate pin, the ingress, and where this launch's secret is.

### What protects it, and what does not

- The ingress listens on loopback only. Every call needs the launch's secret as `Authorization: Bearer <secret>`, must name the ingress as its `Host`, and may come from no other web origin. A web page on the same machine can neither read the secret nor send it.
- Wallets reach the relay over TLS pinned by the connect code. The relay carries messages; nothing it carries is evidence.
- A grant caps what your app can take from a wallet, per request and in total. Anything outside it waits for the player on their device.
- **Your account is a hot wallet.** `RECOVERY_MNEMONIC` is a file in the data dir, and the host reads it on every start. Whoever can read it, or holds root on the machine, controls the account. Anything holding the ingress secret can move everything the account holds; the host has no spending policy of its own. Keep only working balances on it, sweep the rest to an account you keep elsewhere, back up the mnemonic offline, and lock the machine down like any server that holds money.

## Testing

- `make dev-wallet` runs a second account as a player's wallet, and `make dev-wallet2` a third for matches. `make wallet ARGS=...` (and `make wallet2 ARGS=...`) drives them: `connect`, `connections`, `pending`, `approve`, `decline`, `log`, `disconnect`, `owned`.
- `make app ARGS=...` drives your app's account from the terminal: `offer`, `connections`, `send`, `owns`, `accept`, `login`, `result`, `issue`, `give`, `owned`, `activity`.
- `make developer-path` runs every helper once against your local set: connect, send inside and over the grant, prove what is owned, sign in, issue and give an item, open a vault and trade, referee a match between two wallets, disconnect; then the Python client. CI runs it on every change.
- `make first-run` is a newcomer's first run, proven: a clean Ubuntu (in Docker) with nothing on it but what QUICKSTART.md's prerequisites say to install, a fresh clone, and this page's commands alone, in TypeScript (the starter) and in Python (`first_payment.py`), each to a wallet connected and a payment received. The prerequisites are read out of QUICKSTART.md, and every command it types is one this page shows, so the docs cannot drift from what works. A release runs it.

## Reference

The routes your app's account uses:

| Route | Kind | Request | Answer | Client |
|---|---|---|---|---|
| `connect.app.offer` | invoke | `ConnectAppOfferRequestV1` | `ConnectAppOfferV1` | `offer` |
| `connect.app.sessions` | query | none | `ConnectSessionsV1` | `connections` |
| `connect.app.request` | invoke | `ConnectAppRequestIntentV1` | `ConnectRequestRefV1` | `request` |
| `connect.app.status` | invoke | `ConnectRequestRefV1` | `ConnectAppStatusV1` | `result`, `wait` |
| `balance.list` | query | none | `BalancesListResponse` | `owned`, `owns` |
| `wallet.amount` | query | `WalletAmountRequest` | `WalletAmountResponse` | amounts, both ways |
| `token.create` | invoke | `TokenCreateRequest` | `TokenCreateResponse` | `issue` |
| `wallet.sendSmart` | invoke | `OnlineTransferSmartRequest` | `OnlineTransferResponse` | `give` |
| `sofi.createVault`, `sofi.vaults`, `sofi.close` | invoke | `SofiCreateVaultRequest`, none, `SofiCloseRequest` | `SofiVaultCreatedResponse`, `SofiVaultsResponse` | `openVault`, `vaults`, `closeVault` |
| `escrow.adjudicate` | invoke | `EscrowOutcomeRequest` | `EscrowVerdictResponse` | `decide` |
| `faucet.claim` | invoke | `FaucetClaimRequest` | `FaucetClaimResponse` | `fund` |

And a wallet's: `connect.preview` (query), `connect.approve`, `connect.sync`, `connect.list` (query), `connect.pending` (query), `connect.respond`, `connect.log` (query), `connect.disconnect`.

`GET /activity/{after}` returns `AppHostActivityV1`: your account's identity, and a record of each call and each wallet's visit to the relay. Every plain result keeps the wire's message as `raw`, and `pb` exports every generated message, for anything the plain fields leave out.
