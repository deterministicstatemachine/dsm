# Connect starter

A Web2 app with its own DSM account, in about 200 lines of TypeScript: show a connect code (and its QR), see connected wallets, ask them to pay and to prove holdings, and watch the facts your account establishes.

```bash
make app-dev     # from the repo root: your app's account on your local storage set
make starter     # http://127.0.0.1:3000
```

- [src/server.ts](src/server.ts) is the server: the only thing that talks to the account, and the only thing that holds its secret.
- [page.html](page.html) is the page: it talks to the server, never to the account.
- [src/check.ts](src/check.ts) drives the whole path through the server's API and the terminal wallet; `make developer-path` runs it.

Settings, as environment variables: `STARTER_NAME`, `STARTER_TOKEN` (default `ERA`), `STARTER_PER_REQUEST` and `STARTER_TOTAL` (the grant's caps in base units), `STARTER_FREE_REQUESTS`, `STARTER_PORT`.

The guide: [BUILDING_APPS.md](../../BUILDING_APPS.md).
