# Grants, commands and routes

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

`ask.login` and `ask.sign` are never in a grant: each waits for the player on the device. Requests that spend nothing are free up to the offer's `freeRequests` (64 unless the offer says otherwise); past that, each waits for the player.

The wallet answers a connection's requests in order: a request that waits for the player holds up every later one on that connection. On the beta network a request settles in a few seconds to about half a minute; `wait` (in the clients) polls until it has.

## Outcomes and facts

| Outcome, the wallet's word | |
|---|---|
| `carried_out` | the wallet did it |
| `awaiting_approval` | it waits for the player |
| `declined` | the player said no |
| `failed` | it could not be done |

| Fact, your account's evidence | |
|---|---|
| `received` | your account took up a transfer the wallet sent |
| `owns` | a proof of the wallet's holdings verified |
| `signed` | a signature over the asked words checked |
| `staked` | the wallet's stake is held under the match's terms |
| `collected` | the match's verdict paid the wallet |
| `none` | nothing to establish: a price, a trade's notification, contacts |

## The app's command line

`make app ARGS="..."` drives your app's account; `make app ARGS=help` lists the commands. Amounts are in the object's own units.

| Command | What it does |
|---|---|
| `id` | this account's identity |
| `fund` | ERA from the faucet, unless the account holds some |
| `owned` | what it owns |
| `issue <SYMBOL> <name> <supply> [decimals]` | issue a new object; this account holds the supply |
| `give <wallet> <object> <amount>` | give a connected wallet some of an object |
| `offer <name> <object> <per-request> <total> [coin]` | a connect code: be sent `<object>` within those caps, be shown what the wallet owns, hand it objects this account issues, read its contacts, referee matches it stakes `<object>` in (1.00 a match, 2.00 in all); with `[coin]`, sell it `<coin>` for `<object>` through this account's vault (1.00 a trade, 5.00 in all) |
| `connections` | every connected wallet |
| `send <connection> <object> <amount>` | ask a wallet to send this account some of an object |
| `owns <connection> <object>` | ask a wallet to prove what it owns of an object |
| `accept <connection> <object>` | ask a wallet to accept an object this account issued |
| `login <connection>` | ask a wallet to sign in (the player approves on the device) |
| `contacts <connection>` | ask a wallet who its contacts are |
| `vault <a> <reserve-a> <b> <reserve-b>` | open a vault that trades between two objects, funded from what this account owns (the fee is 0.30%) |
| `vaults` | this account's vaults and their reserves |
| `price <connection> <from> <to> <amount>` | ask what `<amount>` of `<from>` would get in `<to>` through this account's vaults (information, never a fact) |
| `trade <connection> <from> <to> <amount> [percent]` | the wallet accepts `<to>`, this account prices the trade, then asks for it at no less than `[percent]` (95) of the price |
| `stake <connection> <opponent> <match> <object> <amount> <A\|B> [against]` | ask a wallet to stake on a match this account referees, against the wallet of `<opponent>` (its connection); side B passes side A's stake id as `[against]` |
| `decide <stake> <A\|B\|void>` | decide a match: who the stakes pay |
| `collect <connection> <stake>...` | ask the winner's wallet to collect the stakes |
| `result <connection> <seq>` | what became of a request |
| `activity [after]` | what calls and wallets did to this account |

## The terminal wallets

`make wallet ARGS="..."` drives the wallet `make dev-wallet` runs, and `make wallet2 ARGS="..."` the one `make dev-wallet2` runs: `connect`, `connections`, `pending`, `approve`, `decline`, `log`, `disconnect`, `owned`. `make wallet ARGS=help` lists them.

## The make targets

| Target | What it does |
|---|---|
| `make doctor` | check the machine's prerequisites, changing nothing |
| `make clients` | build the TypeScript client and generate the Python client's types |
| `make app-dev` | your app's own DSM account on the beta network, funded |
| `make app-dev-local` | the same, on a storage set of your own |
| `make app-dev-down` | stop your app's account |
| `make starter` | the starter app, on http://127.0.0.1:3000 |
| `make dev-wallet`, `make dev-wallet2` | a player's wallet in the terminal, and a second one for matches, funded |
| `make dev-wallet-connect CODE=...` | connect the terminal wallet to an app |
| `make dev-wallet-pending` | requests waiting for the terminal wallet's approval |
| `make phones-connect CODE=...` | open a connect code in the wallet on every phone |
| `make phones-local` | point the phones' wallets at your local set |
| `make dev-down` | stop the terminal wallets, your app's account and the local nodes |
| `make dev-reset` | forget the accounts made on this machine, and your local set if they were on it |
| `make developer-path` | the whole developer path end to end, as CI runs it |
| `make first-run` | a newcomer's first run on a clean Ubuntu, from the docs alone, to a payment received |

## Routes

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

## Offline

Your app's own calls are all online. Offline transfers are the wallet's feature, between two wallets: a bearer transfer carries any object whose policy lets it move, from one wallet's offline account to another's. Today that needs a hardware board on both sides, it is available on Android (the iOS app has no board link yet, and refuses), and a trade offline is two one-way transfers.

## More

- [BUILDING_APPS.md](https://github.com/deterministicstatemachine/dsm/blob/main/BUILDING_APPS.md): this guide's material on one page.
- [QUICKSTART.md](https://github.com/deterministicstatemachine/dsm/blob/main/QUICKSTART.md): the machine set-up, and the rest of the repo's build.
- [`clients/typescript`](https://github.com/deterministicstatemachine/dsm/tree/main/clients/typescript) and [`clients/python`](https://github.com/deterministicstatemachine/dsm/tree/main/clients/python): the clients, each with its README.
