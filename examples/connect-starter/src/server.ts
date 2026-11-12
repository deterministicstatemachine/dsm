// SPDX-License-Identifier: MIT OR Apache-2.0

// The starter: an ordinary web app, plugged into DSM, and the place to build
// one from pieces.
//
// This server is the only thing that talks to the app's DSM account (`make
// app-dev` runs it); it holds the ingress secret, and the page it serves never
// does. The page composes pieces (what the wallet lets the app do, what the
// app asks a wallet, what the app does on its own account) and asks this
// server; the server turns each piece into one client call (src/pieces.ts),
// makes it, and can write the same call out in TypeScript and Python, so what
// the page shows is what runs:
//
//   GET  /                   the page
//   GET  /api/state          the account, what it owns, its vaults, connections, requests made, activity
//   POST /api/code           the code a piece is                  {piece: "offer"|"ask"|"issue"|"vault"|"give"|"decide", ...}
//   POST /api/offer          a connect code (and its QR)          {name?, grants?: GrantPiece[]}
//   POST /api/ask            ask a connected wallet               {connection, ask: AskPiece}
//   POST /api/issue          issue an object                      {symbol, name, supply, decimals?, transferable?, burnable?}
//   POST /api/give           give a wallet an object it accepts   {connection, object, amount}
//   POST /api/vault          open a vault between two objects     {a, reserveA, b, reserveB, feeBps?, label?}
//   POST /api/decide         decide a match                       {stake, decision}
//
// What counts is the fact the account established (a transfer it accepted, a
// proof it verified, a signature it checked), never the wallet's say-so.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import QRCode from "qrcode";
import { AppAccount, localAccount, loginStatement } from "dsm-app-client";
import type { Connection, Decision, RequestRef, Result } from "dsm-app-client";
import { fromOwnPage } from "./own-page.js";
import {
  askCall,
  giveCall,
  issueCall,
  loginCall,
  offerCall,
  pyOf,
  stakeCall,
  stakeIdCall,
  tradeCalls,
  tsOf,
  vaultCall,
  type AskPiece,
  type CodeAsk,
  type DecidePiece,
  type GivePiece,
  type GrantPiece,
  type IssuePiece,
  type VaultPiece,
} from "./pieces.js";

const PORT = Number(process.env.STARTER_PORT ?? "3000");
const NAME = process.env.STARTER_NAME ?? "Connect Starter";
// The offer the page starts from, in ERA. The page can change every piece of it.
const PER_REQUEST = process.env.STARTER_PER_REQUEST ?? "0.10";
const TOTAL = process.env.STARTER_TOTAL ?? "1.00";
const STAKE = process.env.STARTER_STAKE ?? "1.00";

/** The grants the offer carries when the page (or the check) names none. */
function defaultGrants(coin: string | undefined): GrantPiece[] {
  const grants: GrantPiece[] = [
    { kind: "send", object: "ERA", perRequest: PER_REQUEST, total: TOTAL },
    { kind: "owns", objects: ["ERA"] },
    { kind: "accept" },
    { kind: "match", object: "ERA", perRequest: STAKE, total: "2.00" },
  ];
  if (coin !== undefined) grants.push({ kind: "trade", from: "ERA", to: coin, perRequest: "1.00", total: "5.00" });
  return grants;
}

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
/** The coin this app sells through its vault, once it has opened one. */
let coin: string | undefined;

/** The vaults as the page shows them. */
interface VaultRow {
  id: string;
  pair: string;
  reserves: string;
  active: boolean;
}
/**
 * The account's vaults, as last read. Reading them walks each vault's history,
 * and the account refuses that while one of its own steps is pending (taking in
 * a send, say): so they are read again only after something here changed them,
 * not on every poll of the page, and a read the account refuses for now keeps
 * the last list and is tried on the next poll.
 */
let vaults: VaultRow[] = [];
let vaultsChanged = false;

async function vaultRows(app: AppAccount): Promise<VaultRow[]> {
  if (!vaultsChanged) return vaults;
  try {
    vaults = (await app.vaults()).map((v) => ({
      id: hex(v.id),
      pair: `${v.a.symbol}/${v.b.symbol}`,
      reserves: `${v.a.display} ${v.a.symbol}, ${v.b.display} ${v.b.symbol}`,
      active: v.active,
    }));
    vaultsChanged = false;
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (!message.includes("is pending")) throw e;
  }
  return vaults;
}

/**
 * A request whose result can no longer change, so it is not asked about again.
 * A read that failed is asked again on the next poll: the page shows the
 * failure until a read succeeds.
 */
function settled(m: Made): boolean {
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
      m.error = "";
      // A trade moves the vault's reserves once it is carried out.
      if (m.what.startsWith("trade") && settled(m)) vaultsChanged = true;
    } catch (e) {
      m.error = e instanceof Error ? e.message : String(e);
    }
  }
  const identity = await app.identity();
  return {
    name: NAME,
    account: identity.id,
    coin,
    owned: (await app.owned()).map((o) => ({ symbol: o.object.symbol, amount: o.display, kind: o.object.kind, id: o.object.id })),
    vaults: await vaultRows(app),
    connections: (await app.connections()).map((c) => ({ id: c.id, wallet: c.peer, connected: c.connected, grants: c.grants })),
    requests: made.map((m) => ({
      connection: m.ref.connection,
      seq: m.ref.seq.toString(),
      what: m.what,
      answered: m.result?.answered ?? false,
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

type Fields = Record<string, unknown>;

async function body(req: IncomingMessage): Promise<Fields> {
  const chunks: Buffer[] = [];
  for await (const chunk of req) chunks.push(chunk as Buffer);
  const text = Buffer.concat(chunks).toString("utf8");
  if (text.length === 0) return {};
  const parsed: unknown = JSON.parse(text);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) throw new Error("the request body is not an object");
  return parsed as Fields;
}

function send(res: ServerResponse, status: number, value: unknown): void {
  const text = JSON.stringify(value, (_k, v: unknown) => (typeof v === "bigint" ? v.toString() : v));
  res.writeHead(status, { "content-type": "application/json" });
  res.end(text);
}

function text(fields: Fields, name: string): string {
  const value = fields[name];
  if (typeof value !== "string" || value.length === 0) throw new Error(`${name} is required`);
  return value;
}

function optionalText(fields: Fields, name: string, fallback: string): string {
  const value = fields[name];
  return typeof value === "string" && value.length > 0 ? value : fallback;
}

function number(fields: Fields, name: string, fallback: number): number {
  const value = fields[name];
  if (value === undefined || value === "") return fallback;
  const n = typeof value === "number" ? value : Number(value);
  if (!Number.isFinite(n)) throw new Error(`${name} is not a number`);
  return n;
}

function flag(fields: Fields, name: string, fallback: boolean): boolean {
  const value = fields[name];
  if (value === undefined) return fallback;
  return value === true || value === "true";
}

function object(fields: Fields, name: string): Fields {
  const value = fields[name];
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${name} is required`);
  return value as Fields;
}

function objects(fields: Fields, name: string): Fields[] {
  const value = fields[name];
  if (!Array.isArray(value) || !value.every((v) => typeof v === "object" && v !== null)) throw new Error(`${name} must be a list`);
  return value as Fields[];
}

function texts(fields: Fields, name: string): string[] {
  const value = fields[name];
  if (!Array.isArray(value) || !value.every((v) => typeof v === "string")) throw new Error(`${name} must be a list of names`);
  return value as string[];
}

// ───────────────────────── pieces, read off the request ─────────────────────────

function grantPiece(f: Fields): GrantPiece {
  switch (f.kind) {
    case "send":
      return { kind: "send", object: text(f, "object"), perRequest: text(f, "perRequest"), total: text(f, "total") };
    case "owns":
      return { kind: "owns", objects: texts(f, "objects") };
    case "accept":
      return { kind: "accept" };
    case "contacts":
      return { kind: "contacts" };
    case "trade":
      return { kind: "trade", from: text(f, "from"), to: text(f, "to"), perRequest: text(f, "perRequest"), total: text(f, "total") };
    case "match":
      return { kind: "match", object: text(f, "object"), perRequest: text(f, "perRequest"), total: text(f, "total") };
    default:
      throw new Error(`no grant piece ${String(f.kind)}`);
  }
}

function askPiece(f: Fields): AskPiece {
  switch (f.kind) {
    case "send":
      return { kind: "send", object: text(f, "object"), amount: text(f, "amount"), memo: optionalText(f, "memo", "") };
    case "owns":
      return { kind: "owns", objects: texts(f, "objects") };
    case "accept":
      return { kind: "accept", object: text(f, "object") };
    case "contacts":
      return { kind: "contacts" };
    case "login":
      return { kind: "login" };
    case "sign":
      return { kind: "sign", statement: text(f, "statement") };
    case "price":
      return { kind: "price", from: text(f, "from"), to: text(f, "to"), amount: text(f, "amount") };
    case "trade": {
      const pct = number(f, "atLeastPercent", 95);
      if (!Number.isInteger(pct) || pct < 1 || pct > 100) throw new Error("atLeastPercent is 1 to 100");
      return { kind: "trade", from: text(f, "from"), to: text(f, "to"), amount: text(f, "amount"), atLeastPercent: pct };
    }
    case "stake":
      return {
        kind: "stake",
        match: text(f, "match"),
        object: text(f, "object"),
        amount: text(f, "amount"),
        side: text(f, "side") === "B" ? "B" : "A",
        against: optionalText(f, "against", ""),
      };
    case "collect":
      return { kind: "collect", stakes: texts(f, "stakes") };
    default:
      throw new Error(`no request piece ${String(f.kind)}`);
  }
}

function issuePiece(f: Fields): IssuePiece {
  return {
    symbol: text(f, "symbol"),
    name: optionalText(f, "name", text(f, "symbol").toLowerCase()),
    supply: text(f, "supply"),
    decimals: number(f, "decimals", 0),
    transferable: flag(f, "transferable", true),
    burnable: flag(f, "burnable", false),
  };
}

function vaultPiece(f: Fields): VaultPiece {
  return {
    a: text(f, "a"),
    reserveA: text(f, "reserveA"),
    b: text(f, "b"),
    reserveB: text(f, "reserveB"),
    feeBps: number(f, "feeBps", 30),
    label: optionalText(f, "label", ""),
  };
}

function givePiece(f: Fields): GivePiece {
  return { object: text(f, "object"), amount: text(f, "amount") };
}

function decidePiece(f: Fields): DecidePiece {
  const decision = text(f, "decision");
  if (decision !== "A" && decision !== "B" && decision !== "void") throw new Error(`decision is "A", "B" or "void", not ${decision}`);
  return { stake: text(f, "stake"), decision: decision as Decision };
}

function codeAsk(f: Fields): CodeAsk {
  switch (f.piece) {
    case "offer": {
      const o = object(f, "offer");
      const grants = o.grants === undefined ? defaultGrants(coin) : objects(o, "grants").map(grantPiece);
      return { piece: "offer", offer: { name: optionalText(o, "name", NAME), grants } };
    }
    case "ask":
      return { piece: "ask", connection: text(f, "connection"), ask: askPiece(object(f, "ask")), app: NAME };
    case "issue":
      return { piece: "issue", issue: issuePiece(object(f, "issue")) };
    case "vault":
      return { piece: "vault", vault: vaultPiece(object(f, "vault")) };
    case "give":
      return { piece: "give", connection: text(f, "connection"), give: givePiece(object(f, "give")), app: NAME };
    case "decide":
      return { piece: "decide", decide: decidePiece(object(f, "decide")) };
    default:
      throw new Error(`no piece ${String(f.piece)}`);
  }
}

// ───────────────────────── making the calls ─────────────────────────

function remember(ref: RequestRef, what: string, statement?: string): { seq: string } {
  made.push({ ref, what, statement, result: undefined, error: "" });
  return { seq: ref.seq.toString() };
}

async function connected(app: AppAccount, id: string): Promise<Connection> {
  const c = await app.connection(id);
  if (!c.connected) throw new Error(`connection ${id} is disconnected: the wallet can be asked nothing more`);
  return c;
}

/** The request a piece makes, as the page later shows it. */
function label(p: AskPiece): string {
  switch (p.kind) {
    case "send":
      return `send ${p.amount} ${p.object}`;
    case "owns":
      return `prove what it owns of ${p.objects.join(", ")}`;
    case "accept":
      return `accept ${p.object}`;
    case "contacts":
      return "its contacts";
    case "login":
      return "sign in";
    case "sign":
      return `sign: ${p.statement}`;
    case "price":
      return `price ${p.amount} ${p.from} in ${p.to}`;
    case "trade":
      return `trade ${p.amount} ${p.from} for ${p.to}`;
    case "stake":
      return `stake ${p.amount} ${p.object} as side ${p.side}`;
    case "collect":
      return "collect the match";
  }
}

/** Make the request a piece describes: the calls its shown code makes, with their values. */
async function makeAsk(app: AppAccount, c: Connection, p: AskPiece): Promise<{ seq: string; priced?: string }> {
  switch (p.kind) {
    case "login": {
      const nonce = crypto.randomUUID();
      return remember(await app.request(c, loginCall(NAME, nonce).value), label(p), loginStatement(NAME, nonce));
    }
    case "trade": {
      // A wallet receives only what it has taken up itself: the object the trade
      // pays out is accepted first, as an item is before it is given.
      const t = tradeCalls(p);
      const accepted = await app.wait(await app.request(c, t.accept.value), { until: "answered" });
      if (accepted.outcome !== "carried_out") throw new Error(`the wallet did not accept ${p.to}: ${accepted.reason}`);
      const priced = await app.wait(await app.request(c, t.price.value));
      if (priced.price === undefined) throw new Error(`no price: ${priced.reason}`);
      const atLeast = t.atLeast(priced.price.amountOut).value;
      const ref = await app.request(c, t.trade(atLeast).value);
      vaultsChanged = true;
      return { ...remember(ref, label(p)), priced: priced.price.amountOut.toString() };
    }
    case "stake": {
      const other = (await app.connections()).find((o) => o.connected && o.id !== c.id);
      if (other === undefined) throw new Error("a match needs a second connected wallet");
      return remember(await app.request(c, stakeCall(p, other.opponent).value), label(p));
    }
    default:
      return remember(await app.request(c, askCall(p).value), label(p));
  }
}

async function route(app: AppAccount, page: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
  if (!fromOwnPage({ method: req.method, host: req.headers.host, origin: req.headers.origin, contentType: req.headers["content-type"] }, PORT)) {
    send(res, 403, { error: "this server answers its own page only" });
    return;
  }
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
    case "POST /api/code": {
      const c = codeAsk(fields);
      send(res, 200, { ts: tsOf(c), py: pyOf(c) });
      return;
    }
    case "POST /api/offer": {
      const name = optionalText(fields, "name", NAME);
      const pieces = fields.grants === undefined ? defaultGrants(coin) : objects(fields, "grants").map(grantPiece);
      if (pieces.length === 0) throw new Error("an offer asks for at least one grant");
      const offer = await app.offer(offerCall({ name, grants: pieces }).value);
      const qr = await QRCode.toString(offer.code, { type: "svg", errorCorrectionLevel: "M", margin: 1 });
      send(res, 200, { code: offer.code, qr });
      return;
    }
    case "POST /api/ask": {
      const c = await connected(app, text(fields, "connection"));
      send(res, 200, await makeAsk(app, c, askPiece(object(fields, "ask"))));
      return;
    }
    case "POST /api/issue": {
      const issued = await app.issue(issueCall(issuePiece(fields)).value);
      send(res, 200, { id: issued.id, symbol: issued.symbol, kind: issued.kind });
      return;
    }
    case "POST /api/give": {
      const c = await connected(app, text(fields, "connection"));
      const p = givePiece(fields);
      const accepted = await app.wait(await app.request(c, askCall({ kind: "accept", object: p.object }).value), { until: "answered" });
      if (accepted.outcome !== "carried_out") throw new Error(`the wallet did not accept ${p.object}: ${accepted.reason}`);
      const g = giveCall(NAME, p).value;
      await app.give(c, g.object, g.amount, g.memo);
      send(res, 200, { given: `${p.amount} ${p.object}` });
      return;
    }
    case "POST /api/vault": {
      const p = vaultPiece(fields);
      const vault = await app.openVault(vaultCall(p).value);
      // The offer's trade grant names the object this vault sells for ERA.
      coin = (await app.object(p.a === "ERA" ? p.b : p.a)).id;
      vaultsChanged = true;
      send(res, 200, { id: hex(vault.id) });
      return;
    }
    case "POST /api/decide": {
      const p = decidePiece(fields);
      const verdict = await app.decide(stakeIdCall(p.stake).value, p.decision);
      send(res, 200, { state: verdict.state, outcome: Buffer.from(verdict.outcome).toString() });
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
