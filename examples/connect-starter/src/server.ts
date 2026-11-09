// SPDX-License-Identifier: MIT OR Apache-2.0

// The starter: an ordinary web app, plugged into DSM.
//
// This server is the only thing that talks to the app's DSM account (`make
// app-dev` runs it); it holds the ingress secret, and the page it serves never
// does. The page asks this server, and this server asks the account:
//
//   GET  /                   the page
//   GET  /api/state          the account, what it owns, its connections, requests made, activity
//   POST /api/offer          a connect code (and its QR) for a wallet to scan
//   POST /api/send           ask a wallet to send some ERA       {connection, amount}
//   POST /api/owns           ask a wallet to prove what it owns  {connection}
//   POST /api/login          ask a wallet to sign in             {connection}
//   POST /api/issue          issue an object                     {symbol, name, supply, decimals?}
//   POST /api/give           give a wallet an object it accepts  {connection, object, amount}
//   POST /api/vault          open a vault: the coin against ERA  {object, reserve, era}
//   POST /api/trade          ask a wallet to buy the coin        {connection, era}
//   POST /api/match/stake    ask a wallet to stake on a match    {connection, side, against?}
//   POST /api/match/decide   decide a match                      {stake, decision}
//   POST /api/match/collect  ask a wallet to collect             {connection, stakes}
//
// What counts is the fact the account established (a transfer it accepted, a
// proof it verified, a signature it checked), never the wallet's say-so.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import QRCode from "qrcode";
import { AppAccount, ask, grant, localAccount, loginStatement } from "dsm-app-client";
import type { Cap, Connection, Decision, RequestRef, Result } from "dsm-app-client";

const PORT = Number(process.env.STARTER_PORT ?? "3000");
const NAME = process.env.STARTER_NAME ?? "Connect Starter";
// The grant asked for, in ERA.
const PER_REQUEST = process.env.STARTER_PER_REQUEST ?? "0.10";
const TOTAL = process.env.STARTER_TOTAL ?? "1.00";
const STAKE_CAP: Cap = { object: "ERA", perRequest: process.env.STARTER_STAKE ?? "1.00", total: "2.00" };
const TRADE_CAP: Cap = { object: "ERA", perRequest: "1.00", total: "5.00" };

/** A request this application made, as the page shows it. */
interface Made {
  ref: RequestRef;
  what: string;
  /** For a sign-in: the words asked for, to compare with what was signed. */
  statement?: string;
  result: Result | undefined;
  error: string;
}

const made: Made[] = [];
/** The coin this app sells through its vault, once it has issued one. */
let coin: string | undefined;

/** A request whose result can no longer change, so it is not asked about again. */
function settled(m: Made): boolean {
  if (m.error.length > 0) return true;
  const r = m.result;
  if (r === undefined) return false;
  if (r.fact !== "none") return r.answered;
  if (r.price !== undefined) return r.answered;
  return r.outcome === "declined" || r.outcome === "failed";
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

async function state(app: AppAccount): Promise<unknown> {
  for (const m of made) {
    if (settled(m)) continue;
    try {
      m.result = await app.result(m.ref);
    } catch (e) {
      m.error = e instanceof Error ? e.message : String(e);
    }
  }
  const identity = await app.identity();
  return {
    name: NAME,
    account: identity.id,
    owned: (await app.owned()).map((o) => ({ symbol: o.object.symbol, amount: o.display, kind: o.object.kind, id: o.object.id })),
    vaults: (await app.vaults()).map((v) => ({
      id: hex(v.id),
      pair: `${v.a.symbol}/${v.b.symbol}`,
      reserves: `${v.a.display} ${v.a.symbol}, ${v.b.display} ${v.b.symbol}`,
      active: v.active,
    })),
    connections: (await app.connections()).map((c) => ({ id: c.id, wallet: c.peer, connected: c.connected, grants: c.grants })),
    requests: made.map((m) => ({
      connection: m.ref.connection,
      seq: m.ref.seq.toString(),
      what: m.what,
      answered: m.result?.answered ?? !m.error,
      outcome: m.result?.outcome ?? "",
      reason: m.result?.reason ?? "",
      fact: m.result?.fact ?? "",
      detail: m.result?.detail ?? "",
      owns: m.result?.owns?.map((o) => ({ object: o.object, amount: o.amount.toString() })) ?? [],
      price: m.result?.price === undefined ? undefined : { in: m.result.price.amountIn.toString(), out: m.result.price.amountOut.toString() },
      stakes: m.result?.match?.stakes.map(hex) ?? [],
      signedAsAsked: m.result?.signed === undefined ? undefined : m.result.signed.statement === m.statement,
      error: m.error,
    })),
    activity: (await app.ingress.activity(0n)).entries.slice(-15).map((e) => ({
      seq: e.seq.toString(),
      name: e.name,
      summary: e.summary,
      result: e.error.length > 0 ? `refused: ${e.error}` : e.result,
    })),
  };
}

async function body(req: IncomingMessage): Promise<Record<string, string>> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  return text.length === 0 ? {} : (JSON.parse(text) as Record<string, string>);
}

function send(res: ServerResponse, status: number, value: unknown): void {
  const text = JSON.stringify(value, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v));
  res.writeHead(status, { "content-type": "application/json" });
  res.end(text);
}

function field(fields: Record<string, string>, name: string): string {
  const value = fields[name];
  if (value === undefined || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function remember(ref: RequestRef, what: string, statement?: string): { seq: string } {
  made.push({ ref, what, statement, result: undefined, error: "" });
  return { seq: ref.seq.toString() };
}

async function connected(app: AppAccount, id: string): Promise<Connection> {
  const c = await app.connection(id);
  if (!c.connected) throw new Error(`connection ${id} is disconnected: the wallet can be asked nothing more`);
  return c;
}

async function route(app: AppAccount, page: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  const path = `${req.method} ${url.pathname}`;
  if (path === "GET /") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(page);
    return;
  }
  if (path === "GET /api/state") {
    send(res, 200, await state(app));
    return;
  }
  const fields = req.method === "POST" ? await body(req) : {};
  switch (path) {
    case "POST /api/offer": {
      const grants = [grant.send("ERA", PER_REQUEST, TOTAL), grant.owns(["ERA"]), grant.accept(), grant.match([STAKE_CAP])];
      if (coin !== undefined) grants.push(grant.trade("ERA", coin, [TRADE_CAP]));
      const offer = await app.offer({ name: NAME, grants });
      const qr = await QRCode.toString(offer.code, { type: "svg", errorCorrectionLevel: "M", margin: 1 });
      send(res, 200, { code: offer.code, qr });
      return;
    }
    case "POST /api/send": {
      const c = await connected(app, field(fields, "connection"));
      const amount = field(fields, "amount");
      send(res, 200, remember(await app.request(c, ask.send("ERA", amount, `${NAME}: ${amount} ERA`)), `send ${amount} ERA`));
      return;
    }
    case "POST /api/owns": {
      const c = await connected(app, field(fields, "connection"));
      const objects = coin === undefined ? ["ERA"] : ["ERA", coin, ...(await app.owned()).filter((o) => o.object.kind === "unique").map((o) => o.object.id)];
      send(res, 200, remember(await app.request(c, ask.owns(objects)), "prove what it owns"));
      return;
    }
    case "POST /api/login": {
      const c = await connected(app, field(fields, "connection"));
      const nonce = crypto.randomUUID();
      send(res, 200, remember(await app.request(c, ask.login(NAME, nonce)), "sign in", loginStatement(NAME, nonce)));
      return;
    }
    case "POST /api/issue": {
      const issued = await app.issue({
        symbol: field(fields, "symbol"),
        name: field(fields, "name"),
        supply: field(fields, "supply"),
        decimals: fields.decimals === undefined ? 0 : Number(fields.decimals),
      });
      if (issued.kind === "currency") coin = issued.id;
      send(res, 200, { id: issued.id, symbol: issued.symbol, kind: issued.kind });
      return;
    }
    case "POST /api/give": {
      const c = await connected(app, field(fields, "connection"));
      const object = field(fields, "object");
      const amount = field(fields, "amount");
      const accepted = await app.wait(await app.request(c, ask.accept(object)), { until: "answered" });
      if (accepted.outcome !== "carried_out") throw new Error(`the wallet did not accept ${object}: ${accepted.reason}`);
      await app.give(c, object, amount, `${NAME}: ${object}`);
      send(res, 200, { given: `${amount} ${object}` });
      return;
    }
    case "POST /api/vault": {
      const object = field(fields, "object");
      const vault = await app.openVault({ a: object, reserveA: field(fields, "reserve"), b: "ERA", reserveB: field(fields, "era"), label: `${NAME} shop` });
      coin = (await app.object(object)).id;
      send(res, 200, { id: hex(vault.id) });
      return;
    }
    case "POST /api/trade": {
      if (coin === undefined) throw new Error("issue a coin and open a vault first");
      const c = await connected(app, field(fields, "connection"));
      const era = field(fields, "era");
      const priced = await app.wait(await app.request(c, ask.price("ERA", coin, era)));
      if (priced.price === undefined) throw new Error(`no price: ${priced.reason}`);
      const atLeast = (priced.price.amountOut * 95n) / 100n;
      const ref = await app.request(c, ask.trade("ERA", coin, era, atLeast));
      send(res, 200, { ...remember(ref, `trade ${era} ERA for the coin`), priced: priced.price.amountOut.toString() });
      return;
    }
    case "POST /api/match/stake": {
      const c = await connected(app, field(fields, "connection"));
      const others = (await app.connections()).filter((o) => o.connected && o.id !== c.id);
      const opponent = others[0];
      if (opponent === undefined) throw new Error("a match needs a second connected wallet");
      const side = field(fields, "side") === "B" ? "B" : "A";
      const against = fields.against === undefined ? undefined : Uint8Array.from(Buffer.from(fields.against, "hex"));
      const ref = await app.request(
        c,
        ask.match.stake({ match: `${NAME}: match 1`, object: "ERA", amount: STAKE_CAP.perRequest, side, opponent: opponent.opponent, against, memo: "match 1" }),
      );
      send(res, 200, remember(ref, `stake ${STAKE_CAP.perRequest} ERA as side ${side}`));
      return;
    }
    case "POST /api/match/decide": {
      const decision = field(fields, "decision") as Decision;
      const verdict = await app.decide(Uint8Array.from(Buffer.from(field(fields, "stake"), "hex")), decision);
      send(res, 200, { state: verdict.state, outcome: Buffer.from(verdict.outcome).toString() });
      return;
    }
    case "POST /api/match/collect": {
      const c = await connected(app, field(fields, "connection"));
      const stakes = field(fields, "stakes").split(",").map((s) => Uint8Array.from(Buffer.from(s, "hex")));
      send(res, 200, remember(await app.request(c, ask.match.collect(stakes)), "collect the match"));
      return;
    }
    default:
      send(res, 404, { error: `no route ${path}` });
  }
}

async function main(): Promise<void> {
  const app = await localAccount("app");
  const page = await readFile(new URL("../page.html", import.meta.url), "utf8");
  console.log(`[starter] ${NAME}: account ${await app.id()}`);
  createServer((req, res) => {
    route(app, page, req, res).catch((e: unknown) => {
      send(res, 500, { error: e instanceof Error ? e.message : String(e) });
    });
  }).listen(PORT, "127.0.0.1", () => {
    console.log(`[starter] open http://127.0.0.1:${PORT}`);
  });
}

main().catch((e: unknown) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
