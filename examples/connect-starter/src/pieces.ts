// SPDX-License-Identifier: MIT OR Apache-2.0

// The pieces an app is built from, as the starter's page composes them: what
// the wallet lets the app do (grants), what the app asks a connected wallet
// (asks), and what the app does on its own account (issue, vault, give,
// decide). Each piece is plain JSON from the page.
//
// A piece becomes client calls. Each call is one `Call`: the value the starter
// hands the client (`value`), and that same call written out in TypeScript
// (`ts`) and in Python (`py`). The server runs `value`; the page shows `ts`
// and `py` inside the programs `tsOf` and `pyOf` write. So the code the page
// shows and the code the starter runs are one mapping, made in one place, and
// src/shown-code.test.ts evaluates every `ts` and `py` against the real
// client libraries and checks it is `value`: the two cannot drift apart.

import { ask, grant } from "dsm-app-client";
import type { Ask, Cap, Decision, Grant, IssueOptions, OfferOptions, Opponent } from "dsm-app-client";

export type GrantPiece =
  | { kind: "send"; object: string; perRequest: string; total: string }
  | { kind: "owns"; objects: string[] }
  | { kind: "accept" }
  | { kind: "contacts" }
  | { kind: "trade"; from: string; to: string; perRequest: string; total: string }
  | { kind: "match"; object: string; perRequest: string; total: string };

export type AskPiece =
  | { kind: "send"; object: string; amount: string; memo: string }
  | { kind: "owns"; objects: string[] }
  | { kind: "accept"; object: string }
  | { kind: "contacts" }
  | { kind: "login" }
  | { kind: "sign"; statement: string }
  | { kind: "price"; from: string; to: string; amount: string }
  | { kind: "trade"; from: string; to: string; amount: string; atLeastPercent: number }
  | { kind: "stake"; match: string; object: string; amount: string; side: "A" | "B"; against: string }
  | { kind: "collect"; stakes: string[] };

export type StakePiece = Extract<AskPiece, { kind: "stake" }>;
export type TradePiece = Extract<AskPiece, { kind: "trade" }>;
/** The asks that are one call with nothing from the program's own variables in it. */
export type PlainAskPiece = Exclude<AskPiece, { kind: "login" } | { kind: "trade" } | { kind: "stake" }>;

export interface OfferPiece {
  name: string;
  grants: GrantPiece[];
}
export interface IssuePiece {
  symbol: string;
  name: string;
  supply: string;
  decimals: number;
  transferable: boolean;
  burnable: boolean;
}
export interface VaultPiece {
  a: string;
  reserveA: string;
  b: string;
  reserveB: string;
  feeBps: number;
  label: string;
}
export interface GivePiece {
  object: string;
  amount: string;
}
export interface DecidePiece {
  stake: string;
  decision: Decision;
}

/** What the page asks code for: one piece, with the connection it is about where one is. */
export type CodeAsk =
  | { piece: "offer"; offer: OfferPiece }
  | { piece: "ask"; connection: string; ask: AskPiece; app: string }
  | { piece: "issue"; issue: IssuePiece }
  | { piece: "vault"; vault: VaultPiece }
  | { piece: "give"; connection: string; give: GivePiece; app: string }
  | { piece: "decide"; decide: DecidePiece };

/**
 * One client call a program makes: the value the starter hands the client,
 * and the same call written in TypeScript and in Python.
 *
 * `ts` and `py` are expressions that evaluate to `value` (a grant, an ask,
 * an options object, a stake id, an amount) with the program's own variables
 * bound (`Env`). Where the call is a method on the account (`method` set),
 * `py` is the whole `app.<method>(...)` call, whose bound arguments are
 * `value`; `ts` is the options literal where the method takes one, else the
 * whole call, with `value`'s literals in it.
 */
export interface Call<T> {
  value: T;
  ts: string;
  py: string;
  method?: "offer" | "issue" | "openVault" | "give";
}

/**
 * What a program's own variables hold where its calls refer to them. The
 * server has the real ones (a nonce it made, the price it got, the other
 * connected wallet); the test binds fixed ones and evaluates the shown code
 * with them.
 */
export interface Env {
  /** `nonce`: the sign-in's nonce. */
  nonce: string;
  /** `other.opponent`: the other connected wallet, as a match's opponent. */
  opponent: Opponent;
  /** `priced.price.amountOut`: what the price said a trade would get. */
  amountOut: bigint;
  /** `atLeast`: the least a trade accepts, from the price. */
  atLeast: bigint;
}

// ───────────────────────── the calls ─────────────────────────

const q = (s: string): string => JSON.stringify(s);
const list = (xs: string[]): string => `[${xs.map(q).join(", ")}]`;

function cap(object: string, perRequest: string, total: string): Cap {
  return { object, perRequest, total };
}

export function grantCall(p: GrantPiece): Call<Grant> {
  switch (p.kind) {
    case "send":
      return {
        value: grant.send(p.object, p.perRequest, p.total),
        ts: `grant.send(${q(p.object)}, ${q(p.perRequest)}, ${q(p.total)})`,
        py: `grant.send(${q(p.object)}, ${q(p.perRequest)}, ${q(p.total)})`,
      };
    case "owns":
      return { value: grant.owns(p.objects), ts: `grant.owns(${list(p.objects)})`, py: `grant.owns(${list(p.objects)})` };
    case "accept":
      return { value: grant.accept(), ts: "grant.accept()", py: "grant.accept()" };
    case "contacts":
      return { value: grant.contacts(), ts: "grant.contacts()", py: "grant.contacts()" };
    case "trade":
      return {
        value: grant.trade(p.from, p.to, [cap(p.from, p.perRequest, p.total)]),
        ts: `grant.trade(${q(p.from)}, ${q(p.to)}, [{ object: ${q(p.from)}, perRequest: ${q(p.perRequest)}, total: ${q(p.total)} }])`,
        py: `grant.trade(${q(p.from)}, ${q(p.to)}, [Cap(${q(p.from)}, ${q(p.perRequest)}, ${q(p.total)})])`,
      };
    case "match":
      return {
        value: grant.match([cap(p.object, p.perRequest, p.total)]),
        ts: `grant.match([{ object: ${q(p.object)}, perRequest: ${q(p.perRequest)}, total: ${q(p.total)} }])`,
        py: `grant.match([Cap(${q(p.object)}, ${q(p.perRequest)}, ${q(p.total)})])`,
      };
  }
}

function hex(s: string): Uint8Array {
  if (!/^([0-9a-f]{2})+$/i.test(s)) throw new Error(`not a hex id: ${s}`);
  return Uint8Array.from(Buffer.from(s, "hex"));
}

/** A stake id, from the hex a "staked" result showed. */
export function stakeIdCall(id: string): Call<Uint8Array> {
  return { value: hex(id), ts: `Buffer.from(${q(id)}, "hex")`, py: `bytes.fromhex(${q(id)})` };
}

/** The asks that are one call, with nothing from the program's own variables in it. */
export function askCall(p: PlainAskPiece): Call<Ask> {
  switch (p.kind) {
    case "send": {
      const memo = p.memo.length > 0 ? `, ${q(p.memo)}` : "";
      return {
        value: ask.send(p.object, p.amount, p.memo),
        ts: `ask.send(${q(p.object)}, ${q(p.amount)}${memo})`,
        py: `ask.send(${q(p.object)}, ${q(p.amount)}${memo})`,
      };
    }
    case "owns":
      return { value: ask.owns(p.objects), ts: `ask.owns(${list(p.objects)})`, py: `ask.owns(${list(p.objects)})` };
    case "accept":
      return { value: ask.accept(p.object), ts: `ask.accept(${q(p.object)})`, py: `ask.accept(${q(p.object)})` };
    case "contacts":
      return { value: ask.contacts(), ts: "ask.contacts()", py: "ask.contacts()" };
    case "sign":
      return { value: ask.sign(p.statement), ts: `ask.sign(${q(p.statement)})`, py: `ask.sign(${q(p.statement)})` };
    case "price":
      return {
        value: ask.price(p.from, p.to, p.amount),
        ts: `ask.price(${q(p.from)}, ${q(p.to)}, ${q(p.amount)})`,
        py: `ask.price(${q(p.from)}, ${q(p.to)}, ${q(p.amount)})`,
      };
    case "collect":
      return {
        value: ask.match.collect(p.stakes.map(hex)),
        ts: `ask.match.collect(${list(p.stakes)}.map((s) => Buffer.from(s, "hex")))`,
        py: `ask.match.collect([bytes.fromhex(s) for s in ${list(p.stakes)}])`,
      };
  }
}

/** A sign-in: the program made `nonce` and keeps it, to check the answer against. */
export function loginCall(app: string, nonce: string): Call<Ask> {
  return { value: ask.login(app, nonce), ts: `ask.login(${q(app)}, nonce)`, py: `ask.login(${q(app)}, nonce)` };
}

/**
 * A trade is three calls in a row: the wallet accepts the object the trade
 * pays out (it receives only what it has taken up), the app prices the
 * trade, then asks for it at no less than the piece's share of that price.
 */
export function tradeCalls(p: TradePiece): {
  accept: Call<Ask>;
  price: Call<Ask>;
  atLeast: (amountOut: bigint) => Call<bigint>;
  trade: (atLeast: bigint) => Call<Ask>;
} {
  return {
    accept: askCall({ kind: "accept", object: p.to }),
    price: askCall({ kind: "price", from: p.from, to: p.to, amount: p.amount }),
    atLeast: (amountOut) => ({
      value: (amountOut * BigInt(p.atLeastPercent)) / 100n,
      ts: `(priced.price.amountOut * ${p.atLeastPercent}n) / 100n`,
      py: `priced.price[1] * ${p.atLeastPercent} // 100`,
    }),
    trade: (atLeast) => ({
      value: ask.trade(p.from, p.to, p.amount, atLeast),
      ts: `ask.trade(${q(p.from)}, ${q(p.to)}, ${q(p.amount)}, atLeast)`,
      py: `ask.trade(${q(p.from)}, ${q(p.to)}, ${q(p.amount)}, at_least)`,
    }),
  };
}

/** A stake against `other`, the other connected wallet. Side B passes side A's stake id as against. */
export function stakeCall(p: StakePiece, opponent: Opponent): Call<Ask> {
  const against = p.against.length > 0 ? hex(p.against) : undefined;
  return {
    value: ask.match.stake({ match: p.match, object: p.object, amount: p.amount, side: p.side, opponent, against }),
    ts: [
      `ask.match.stake({`,
      `  match: ${q(p.match)}, object: ${q(p.object)}, amount: ${q(p.amount)}, side: ${q(p.side)}, opponent: other.opponent,`,
      against === undefined
        ? `  // side B passes side A's stake id as against`
        : `  against: Buffer.from(${q(p.against)}, "hex"), // side A's stake, so both share one verdict`,
      `})`,
    ].join("\n"),
    py: [
      `ask.match.stake(`,
      `    ${q(p.match)}, ${q(p.object)}, ${q(p.amount)}, ${q(p.side)}, other.opponent,`,
      against === undefined
        ? `    # side B passes side A's stake id as against=`
        : `    against=bytes.fromhex(${q(p.against)}),  # side A's stake, so both share one verdict`,
      `)`,
    ].join("\n"),
  };
}

export function offerCall(p: OfferPiece): Call<OfferOptions> {
  const grants = p.grants.map(grantCall);
  return {
    value: { name: p.name, grants: grants.map((g) => g.value) },
    ts: [`{`, `  name: ${q(p.name)},`, `  grants: [`, ...grants.map((g) => `    ${g.ts},`), `  ],`, `}`].join("\n"),
    py: [`app.offer(${q(p.name)}, [`, ...grants.map((g) => `    ${g.py},`), `])`].join("\n"),
    method: "offer",
  };
}

/** What `issue` is given: the defaults left out, as the shown code leaves them out. */
export function issueCall(p: IssuePiece): Call<IssueOptions> {
  const value: IssueOptions = { symbol: p.symbol, name: p.name, supply: p.supply };
  const ts = [`{`, `  symbol: ${q(p.symbol)},`, `  name: ${q(p.name)},`, `  supply: ${q(p.supply)}, // the whole supply that will ever exist`];
  let py = `app.issue(${q(p.symbol)}, ${q(p.name)}, ${q(p.supply)}`;
  if (p.decimals !== 0) {
    value.decimals = p.decimals;
    ts.push(`  decimals: ${p.decimals},`);
    py += `, decimals=${p.decimals}`;
  }
  if (!p.transferable) {
    value.transferable = false;
    ts.push(`  transferable: false, // bound to whoever holds it`);
    py += `, transferable=False`;
  }
  if (p.burnable) {
    value.burnable = true;
    ts.push(`  burnable: true,`);
    py += `, burnable=True`;
  }
  ts.push(`}`);
  return { value, ts: ts.join("\n"), py: `${py})`, method: "issue" };
}

export interface VaultOptions {
  a: string;
  reserveA: string;
  b: string;
  reserveB: string;
  feeBps: number;
  label?: string;
}

export function vaultCall(p: VaultPiece): Call<VaultOptions> {
  const value: VaultOptions = { a: p.a, reserveA: p.reserveA, b: p.b, reserveB: p.reserveB, feeBps: p.feeBps };
  if (p.label.length > 0) value.label = p.label;
  const label = p.label.length > 0 ? ` label: ${q(p.label)},` : "";
  const pyLabel = p.label.length > 0 ? `, label=${q(p.label)}` : "";
  return {
    value,
    ts: [`{`, `  a: ${q(p.a)}, reserveA: ${q(p.reserveA)},`, `  b: ${q(p.b)}, reserveB: ${q(p.reserveB)},`, `  feeBps: ${p.feeBps},${label}`, `}`].join("\n"),
    py: `app.open_vault(${q(p.a)}, ${q(p.reserveA)}, ${q(p.b)}, ${q(p.reserveB)}, fee_bps=${p.feeBps}${pyLabel})`,
    method: "openVault",
  };
}

export interface GiveArgs {
  object: string;
  amount: string;
  memo: string;
}

/** The give itself; the wallet has accepted the object first (`askCall` accept). */
export function giveCall(app: string, p: GivePiece): Call<GiveArgs> {
  const memo = `${app}: ${p.object}`;
  return {
    value: { object: p.object, amount: p.amount, memo },
    ts: `app.give(connection, ${q(p.object)}, ${q(p.amount)}, ${q(memo)})`,
    py: `app.give(connection, ${q(p.object)}, ${q(p.amount)}, ${q(memo)})`,
    method: "give",
  };
}

/**
 * Every call the program for `c` makes, in the program's order, with the
 * program's variables holding `env`. The test evaluates each one's `ts` and
 * `py` with `env` bound and checks it is `value`.
 */
export function callsOf(c: CodeAsk, env: Env): Call<unknown>[] {
  switch (c.piece) {
    case "offer":
      return [...c.offer.grants.map(grantCall), offerCall(c.offer)];
    case "issue":
      return [issueCall(c.issue)];
    case "vault":
      return [vaultCall(c.vault)];
    case "give":
      return [askCall({ kind: "accept", object: c.give.object }), giveCall(c.app, c.give)];
    case "decide":
      return [stakeIdCall(c.decide.stake)];
    case "ask":
      switch (c.ask.kind) {
        case "login":
          return [loginCall(c.app, env.nonce)];
        case "trade": {
          const t = tradeCalls(c.ask);
          return [t.accept, t.price, t.atLeast(env.amountOut), t.trade(env.atLeast)];
        }
        case "stake":
          return [stakeCall(c.ask, env.opponent)];
        default:
          return [askCall(c.ask)];
      }
  }
}

// ───────────────────────── the programs, from the calls ─────────────────────────

/** The TypeScript a piece is: a whole program, from the import to what it prints. */
export function tsOf(c: CodeAsk): string {
  switch (c.piece) {
    case "offer":
      return [
        `import { localAccount, grant } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `const offer = await app.offer(${offerCall(c.offer).ts});`,
        `console.log(offer.code); // show it as a QR, or as a link on the same device`,
      ].join("\n");
    case "issue":
      return [
        `import { localAccount } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `const issued = await app.issue(${issueCall(c.issue).ts});`,
        `console.log(issued.id, issued.kind); // this account holds the supply`,
      ].join("\n");
    case "vault":
      return [
        `import { localAccount } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `const vault = await app.openVault(${vaultCall(c.vault).ts});`,
        `console.log(vault.id); // wallets trade ${c.vault.a} for ${c.vault.b} through it`,
      ].join("\n");
    case "give":
      return [
        `import { localAccount, ask } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `const connection = await app.connection(${q(c.connection)});`,
        `// The wallet takes up the object first, so it can hold it.`,
        `const accepted = await app.wait(await app.request(connection, ${askCall({ kind: "accept", object: c.give.object }).ts}), { until: "answered" });`,
        `if (accepted.outcome !== "carried_out") throw new Error(accepted.reason);`,
        `await ${giveCall(c.app, c.give).ts};`,
      ].join("\n");
    case "decide":
      return [
        `import { localAccount } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `// The stake id is from a "staked" result; the decision is "A", "B" or "void".`,
        `const verdict = await app.decide(${stakeIdCall(c.decide.stake).ts}, ${q(c.decide.decision)});`,
        `console.log(verdict.state);`,
      ].join("\n");
    case "ask":
      return tsAsk(c.connection, c.ask, c.app);
  }
}

/** The program's variables are the program's: the text does not depend on what they hold. */
const UNBOUND: Env = { nonce: "", opponent: { genesis: new Uint8Array(), deviceId: new Uint8Array(), signingKey: new Uint8Array() }, amountOut: 0n, atLeast: 0n };

function tsAsk(connection: string, a: AskPiece, app: string): string {
  const head = [
    `import { localAccount, ask${a.kind === "login" ? ", loginStatement" : ""} } from "dsm-app-client";`,
    ``,
    `const app = await localAccount("app");`,
    `const connection = await app.connection(${q(connection)});`,
  ];
  const tail = [`const result = await app.wait(ref);`, `console.log(result.outcome, result.fact); // the fact is the evidence`];
  switch (a.kind) {
    case "send":
      return [
        ...head,
        `const ref = await app.request(connection, ${askCall(a).ts});`,
        ...tail,
        `if (result.fact === "received") { /* paid: the transfer is accepted on this account */ }`,
      ].join("\n");
    case "owns":
      return [
        ...head,
        `const ref = await app.request(connection, ${askCall(a).ts});`,
        ...tail,
        `for (const o of result.owns ?? []) console.log(o.object, o.amount); // proven, not said`,
      ].join("\n");
    case "accept":
      return [
        ...head,
        `const ref = await app.request(connection, ${askCall(a).ts});`,
        `const result = await app.wait(ref, { until: "answered" });`,
        `console.log(result.outcome); // "carried_out": the wallet can now hold it`,
      ].join("\n");
    case "contacts":
      return [...head, `const ref = await app.request(connection, ${askCall(a).ts});`, ...tail].join("\n");
    case "login":
      return [
        ...head,
        `const nonce = crypto.randomUUID(); // keep it: the answer is checked against it`,
        `const ref = await app.request(connection, ${loginCall(app, UNBOUND.nonce).ts});`,
        `const result = await app.wait(ref); // waits for the player to approve on the device`,
        `const signedIn = result.fact === "signed" && result.signed?.statement === loginStatement(${q(app)}, nonce);`,
      ].join("\n");
    case "sign":
      return [
        ...head,
        `const ref = await app.request(connection, ${askCall(a).ts});`,
        `const result = await app.wait(ref); // waits for the player to approve on the device`,
        `console.log(result.fact === "signed", result.signed?.statement);`,
      ].join("\n");
    case "price":
      return [
        ...head,
        `const priced = await app.wait(await app.request(connection, ${askCall(a).ts}));`,
        `console.log(priced.price?.amountOut); // in ${a.to}'s smallest unit; information, never a fact`,
      ].join("\n");
    case "trade": {
      const t = tradeCalls(a);
      return [
        ...head,
        `// A wallet receives only what it has taken up itself: it accepts ${a.to} first.`,
        `const accepted = await app.wait(await app.request(connection, ${t.accept.ts}), { until: "answered" });`,
        `if (accepted.outcome !== "carried_out") throw new Error(accepted.reason);`,
        `const priced = await app.wait(await app.request(connection, ${t.price.ts}));`,
        `if (priced.price === undefined) throw new Error(priced.reason);`,
        `const atLeast = ${t.atLeast(UNBOUND.amountOut).ts};`,
        `const ref = await app.request(connection, ${t.trade(UNBOUND.atLeast).ts});`,
        ...tail,
      ].join("\n");
    }
    case "stake":
      return [
        ...head,
        `const other = (await app.connections()).find((c) => c.connected && c.id !== connection.id);`,
        `if (other === undefined) throw new Error("a match needs a second connected wallet");`,
        `const ref = await app.request(connection, ${stakeCall(a, UNBOUND.opponent).ts});`,
        ...tail,
        `console.log(result.match?.stakes); // the stake ids: decide with app.decide, collect with ask.match.collect`,
      ].join("\n");
    case "collect":
      return [...head, `const ref = await app.request(connection, ${askCall(a).ts});`, ...tail].join("\n");
  }
}

/** The Python a piece is. */
export function pyOf(c: CodeAsk): string {
  switch (c.piece) {
    case "offer":
      return [
        `from dsm_app_client import local_app, grant${c.offer.grants.some((g) => g.kind === "trade" || g.kind === "match") ? ", Cap" : ""}`,
        ``,
        `app = local_app()`,
        `offer = ${offerCall(c.offer).py}`,
        `print(offer.code)  # show it as a QR, or as a link on the same device`,
      ].join("\n");
    case "issue":
      return [
        `from dsm_app_client import local_app`,
        ``,
        `app = local_app()`,
        `issued = ${issueCall(c.issue).py}  # the whole supply that will ever exist`,
        `print(issued.id, issued.kind)  # this account holds the supply`,
      ].join("\n");
    case "vault":
      return [
        `from dsm_app_client import local_app`,
        ``,
        `app = local_app()`,
        `vault = ${vaultCall(c.vault).py}`,
        `print(vault.id.hex())  # wallets trade ${c.vault.a} for ${c.vault.b} through it`,
      ].join("\n");
    case "give":
      return [
        `from dsm_app_client import local_app, ask`,
        ``,
        `app = local_app()`,
        `connection = app.connection(${q(c.connection)})`,
        `# The wallet takes up the object first, so it can hold it.`,
        `accepted = app.wait(app.request(connection, ${askCall({ kind: "accept", object: c.give.object }).py}), until="answered")`,
        `if accepted.outcome != "carried_out":`,
        `    raise RuntimeError(accepted.reason)`,
        giveCall(c.app, c.give).py,
      ].join("\n");
    case "decide":
      return [
        `from dsm_app_client import local_app`,
        ``,
        `app = local_app()`,
        `# The stake id is from a "staked" result; the decision is "A", "B" or "void".`,
        `verdict = app.decide(${stakeIdCall(c.decide.stake).py}, ${q(c.decide.decision)})`,
        `print(verdict.state)`,
      ].join("\n");
    case "ask":
      return pyAsk(c.connection, c.ask, c.app);
  }
}

function pyAsk(connection: string, a: AskPiece, app: string): string {
  const head = [
    `from dsm_app_client import local_app, ask${a.kind === "login" ? ", login_statement" : ""}`,
    ...(a.kind === "login" ? [`import uuid`] : []),
    ``,
    `app = local_app()`,
    `connection = app.connection(${q(connection)})`,
  ];
  const tail = [`result = app.wait(ref)`, `print(result.outcome, result.fact)  # the fact is the evidence`];
  switch (a.kind) {
    case "send":
      return [
        ...head,
        `ref = app.request(connection, ${askCall(a).py})`,
        ...tail,
        `if result.fact == "received":`,
        `    pass  # paid: the transfer is accepted on this account`,
      ].join("\n");
    case "owns":
      return [
        ...head,
        `ref = app.request(connection, ${askCall(a).py})`,
        ...tail,
        `for object_id, amount in result.owns:`,
        `    print(object_id, amount)  # proven, not said`,
      ].join("\n");
    case "accept":
      return [
        ...head,
        `ref = app.request(connection, ${askCall(a).py})`,
        `result = app.wait(ref, until="answered")`,
        `print(result.outcome)  # "carried_out": the wallet can now hold it`,
      ].join("\n");
    case "contacts":
      return [...head, `ref = app.request(connection, ${askCall(a).py})`, ...tail].join("\n");
    case "login":
      return [
        ...head,
        `nonce = str(uuid.uuid4())  # keep it: the answer is checked against it`,
        `ref = app.request(connection, ${loginCall(app, UNBOUND.nonce).py})`,
        `result = app.wait(ref)  # waits for the player to approve on the device`,
        `signed_in = result.fact == "signed" and result.signed[0] == login_statement(${q(app)}, nonce)`,
      ].join("\n");
    case "sign":
      return [
        ...head,
        `ref = app.request(connection, ${askCall(a).py})`,
        `result = app.wait(ref)  # waits for the player to approve on the device`,
        `print(result.fact == "signed", result.signed)`,
      ].join("\n");
    case "price":
      return [
        ...head,
        `priced = app.wait(app.request(connection, ${askCall(a).py}))`,
        `print(priced.price)  # (amount in, amount out, hops) in smallest units; information, never a fact`,
      ].join("\n");
    case "trade": {
      const t = tradeCalls(a);
      return [
        ...head,
        `# A wallet receives only what it has taken up itself: it accepts ${a.to} first.`,
        `accepted = app.wait(app.request(connection, ${t.accept.py}), until="answered")`,
        `if accepted.outcome != "carried_out":`,
        `    raise RuntimeError(accepted.reason)`,
        `priced = app.wait(app.request(connection, ${t.price.py}))`,
        `if priced.price is None:`,
        `    raise RuntimeError(priced.reason)`,
        `at_least = ${t.atLeast(UNBOUND.amountOut).py}`,
        `ref = app.request(connection, ${t.trade(UNBOUND.atLeast).py})`,
        ...tail,
      ].join("\n");
    }
    case "stake":
      return [
        ...head,
        `other = next(c for c in app.connections() if c.connected and c.id != connection.id)`,
        `ref = app.request(connection, ${stakeCall(a, UNBOUND.opponent).py})`,
        ...tail,
        `print(result.match[0] if result.match else None)  # the stake ids: decide with app.decide, collect with ask.match.collect`,
      ].join("\n");
    case "collect":
      return [...head, `ref = app.request(connection, ${askCall(a).py})`, ...tail].join("\n");
  }
}
