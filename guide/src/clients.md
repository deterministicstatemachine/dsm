# Write it into your app

Everything the command line did, your app does with a client: TypeScript for Node.js 20 or later, Python 3.10 or later. Both are generated from the same schema and use the same words: `offer`, `connections`, `request`, `result`, `wait`; `issue`, `give`; `owned`, `owns`. Requests are built with `ask.*`, and what an offer asks for with `grant.*`.

Your app needs a server side, even a small one, because the account's secret must never reach a browser page. The [starter](https://github.com/deterministicstatemachine/dsm/tree/main/examples/connect-starter) is one server file, and a page.

## TypeScript

The client lives in [`clients/typescript`](https://github.com/deterministicstatemachine/dsm/tree/main/clients/typescript). `make app-dev` built it; on its own:

```bash
make clients
```

Your app depends on it by path, the way the starter does in its `package.json`:

```json
"dependencies": {
  "dsm-app-client": "file:../../clients/typescript"
}
```

The path is from your app's folder to `clients/typescript` in your clone of the repo.

The whole path, in one program: an offer, a payment, an item, a sign-in.

```ts
import { localAccount, grant, ask } from "dsm-app-client";

const app = await localAccount("app");

// 1. A connect code. Amounts are in the object's own units: 0.10 ERA.
const offer = await app.offer({
  name: "My Game",
  grants: [grant.send("ERA", "0.10", "1.00"), grant.owns(["ERA"]), grant.accept()],
});
console.log(offer.code);

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

`localAccount("app")` finds the account `make app-dev` runs. On a server of your own, open it from the ingress's address and the secret file the host writes: `new AppAccount(await Ingress.fromSecretFile(url, secretFile))`.

## Python

The client lives in [`clients/python`](https://github.com/deterministicstatemachine/dsm/tree/main/clients/python). `make clients` (which `make app-dev` runs) generates its protobuf types. Install it into a virtual environment:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e clients/python
```

The same path:

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

`local_app()` finds the account `make app-dev` runs. On a server of your own: `AppAccount(Ingress.from_secret_file(url, secret_file))`.

### Your first payment, in Python

[`first_payment.py`](https://github.com/deterministicstatemachine/dsm/blob/main/clients/python/examples/first_payment.py) is that path as a program. It prints a connect code, waits for a wallet to connect to it, asks for 0.05 ERA and prints the fact:

```bash
python3 clients/python/examples/first_payment.py
```

While it waits, connect a wallet to the code it prints: in a second terminal, `make dev-wallet-connect CODE=<the code>`, or open it on a phone.

A wallet connects to an app once. If the terminal wallet is still connected to your account, from the earlier pages, it disconnects first (`make wallet ARGS="disconnect $S"`), or a second wallet connects: `make dev-wallet2`, then `make wallet2 ARGS="connect <the code>"`.

This is the program the newcomer check (`make first-run`) runs on a clean Ubuntu, after the starter's page has done the same in TypeScript: each to a wallet connected and its own payment received.

## Any other language

Generate types from [`proto/dsm_app.proto`](https://github.com/deterministicstatemachine/dsm/blob/main/proto/dsm_app.proto), and send an `IngressRequest` (a `RouterInvokeOp` or `RouterQueryOp`: the route's name and an `ArgPack` holding its request message) to `POST /ingress`. An `IngressResponse` comes back: either an error, or `0x03` followed by an `Envelope`. [`clients/typescript/src/ingress.ts`](https://github.com/deterministicstatemachine/dsm/blob/main/clients/typescript/src/ingress.ts) is the whole exchange, in one short file. The routes are in the [reference](reference.md#routes).

## Objects

Everything an account can hold is an **object**: ERA, a sword, a ticket, a coin you issued. A currency is an object counted in units; an item is an object of which exactly one exists. You name an object by its symbol (`"ERA"`, `"SWORD"`) or by its id, and amounts in its own units (`"0.10"`, `"1"`); your account converts them, in both directions, so no client carries the unit rule. `issue` makes a new object, your account then holds its whole supply, and `give` hands some to a wallet that has accepted it.

Next, when you want it: [Shops, matches and contacts](advanced.md).
