# Connect starter

An ordinary web app plugged into DSM, in one TypeScript file: show a connect code (and its QR), see connected wallets, ask them to send ERA, prove what they own and sign in, issue an item and give it, sell a coin through a vault, referee a match, and watch the facts your account establishes.

```bash
make app-dev     # from the repo root: your app's account on your local storage set
make starter     # http://127.0.0.1:3000
```

- [src/server.ts](src/server.ts) is the server: the only thing that talks to the account, and the only thing that holds its secret.
- [page.html](page.html) is the page: it talks to the server, never to the account.
- [src/check.ts](src/check.ts) drives every helper once through the server's API and two terminal wallets; `make developer-path` runs it.

Settings, as environment variables: `STARTER_NAME`, `STARTER_PER_REQUEST` and `STARTER_TOTAL` (the send grant's caps, in ERA; default 0.10 and 1.00), `STARTER_STAKE` (a match's stake, in ERA; default 1.00), `STARTER_PORT`.

The guide: [BUILDING_APPS.md](../../BUILDING_APPS.md).
