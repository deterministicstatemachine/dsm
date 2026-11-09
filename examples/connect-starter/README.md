# Connect starter

An ordinary web app plugged into DSM, and the place to build one from pieces.

```bash
make app-dev     # from the repo root: your app's account on your local storage set
make starter     # http://127.0.0.1:3000
```

The page has three kinds of pieces: objects your app issues (and a shop that sells one), what the wallet lets your app do (the offer and its grants), and what your app asks a connected wallet (send, owns, sign in, sign, accept, give, price, trade, stake, decide, collect). Under each piece is the code it is, in TypeScript or Python; the button makes the same call. Nothing on the page is a mock-up: every call reaches your account, and the facts it establishes show in the tables below.

- [src/server.ts](src/server.ts) is the server: the only thing that talks to the account, and the only thing that holds its secret. Its routes take pieces.
- [src/pieces.ts](src/pieces.ts) is the one mapping from a piece to a client call, read twice: to make the call, and to write it out as code.
- [page.html](page.html) is the page: it composes pieces and talks to the server, never to the account.
- [src/check.ts](src/check.ts) drives every piece once through the server's API and two terminal wallets; `make developer-path` runs it.

Settings, as environment variables: `STARTER_NAME`, `STARTER_PER_REQUEST` and `STARTER_TOTAL` (the send grant the page starts from, in ERA; default 0.10 and 1.00), `STARTER_STAKE` (the match cap, in ERA; default 1.00), `STARTER_PORT`.

The guide: [BUILDING_APPS.md](../../BUILDING_APPS.md).
