// SPDX-License-Identifier: MIT OR Apache-2.0

// The pieces an app is built from, as the starter's page composes them: what
// the wallet lets the app do (grants), what the app asks a connected wallet
// (asks), and what the app does on its own account (issue, vault, give,
// decide). Each piece is plain JSON from the page. This file turns a piece
// into the client call the starter makes (`toGrant`, `toAsk`) and into the
// same call written out in TypeScript and Python (`tsOf`, `pyOf`), so the
// code the page shows is the code the starter runs: one mapping, read twice.

import { ask, grant } from "dsm-app-client";
import type { Ask, Cap, Decision, Grant, Opponent } from "dsm-app-client";

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
  | { piece: "give"; connection: string; give: GivePiece }
  | { piece: "decide"; decide: DecidePiece };

// ───────────────────────── the calls the starter makes ─────────────────────────

function cap(object: string, perRequest: string, total: string): Cap {
  return { object, perRequest, total };
}

export function toGrant(p: GrantPiece): Grant {
  switch (p.kind) {
    case "send":
      return grant.send(p.object, p.perRequest, p.total);
    case "owns":
      return grant.owns(p.objects);
    case "accept":
      return grant.accept();
    case "contacts":
      return grant.contacts();
    case "trade":
      return grant.trade(p.from, p.to, [cap(p.from, p.perRequest, p.total)]);
    case "match":
      return grant.match([cap(p.object, p.perRequest, p.total)]);
  }
}

function hex(s: string): Uint8Array {
  if (!/^([0-9a-f]{2})+$/i.test(s)) throw new Error(`not a hex id: ${s}`);
  return Uint8Array.from(Buffer.from(s, "hex"));
}

/**
 * The ask a piece makes. A sign-in's nonce and a stake's opponent are not in
 * the piece: the server makes the nonce (and keeps it, to check the answer)
 * and reads the opponent off the other connected wallet. `ask.login` and the
 * trade (a price first, then the trade) are made by the caller, which needs
 * their intermediate results; this covers the rest.
 */
export function toAsk(p: Exclude<AskPiece, { kind: "login" } | { kind: "trade" }>, opponent?: Opponent): Ask {
  switch (p.kind) {
    case "send":
      return ask.send(p.object, p.amount, p.memo);
    case "owns":
      return ask.owns(p.objects);
    case "accept":
      return ask.accept(p.object);
    case "contacts":
      return ask.contacts();
    case "sign":
      return ask.sign(p.statement);
    case "price":
      return ask.price(p.from, p.to, p.amount);
    case "stake": {
      if (opponent === undefined) throw new Error("a stake needs a second connected wallet to play against");
      return ask.match.stake({
        match: p.match,
        object: p.object,
        amount: p.amount,
        side: p.side,
        opponent,
        against: p.against.length > 0 ? hex(p.against) : undefined,
        memo: p.match,
      });
    }
    case "collect":
      return ask.match.collect(p.stakes.map(hex));
  }
}

export function stakeIds(stakes: string[]): Uint8Array[] {
  return stakes.map(hex);
}

// ───────────────────────── the same calls, written out ─────────────────────────

const q = (s: string): string => JSON.stringify(s);
const list = (xs: string[]): string => `[${xs.map(q).join(", ")}]`;

function tsGrant(p: GrantPiece): string {
  switch (p.kind) {
    case "send":
      return `grant.send(${q(p.object)}, ${q(p.perRequest)}, ${q(p.total)})`;
    case "owns":
      return `grant.owns(${list(p.objects)})`;
    case "accept":
      return "grant.accept()";
    case "contacts":
      return "grant.contacts()";
    case "trade":
      return `grant.trade(${q(p.from)}, ${q(p.to)}, [{ object: ${q(p.from)}, perRequest: ${q(p.perRequest)}, total: ${q(p.total)} }])`;
    case "match":
      return `grant.match([{ object: ${q(p.object)}, perRequest: ${q(p.perRequest)}, total: ${q(p.total)} }])`;
  }
}

function pyGrant(p: GrantPiece): string {
  switch (p.kind) {
    case "send":
      return `grant.send(${q(p.object)}, ${q(p.perRequest)}, ${q(p.total)})`;
    case "owns":
      return `grant.owns(${list(p.objects)})`;
    case "accept":
      return "grant.accept()";
    case "contacts":
      return "grant.contacts()";
    case "trade":
      return `grant.trade(${q(p.from)}, ${q(p.to)}, [Cap(${q(p.from)}, ${q(p.perRequest)}, ${q(p.total)})])`;
    case "match":
      return `grant.match([Cap(${q(p.object)}, ${q(p.perRequest)}, ${q(p.total)})])`;
  }
}

/** The TypeScript a piece is: a whole program, from the import to what it prints. */
export function tsOf(c: CodeAsk): string {
  switch (c.piece) {
    case "offer":
      return [
        `import { localAccount, grant } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `const offer = await app.offer({`,
        `  name: ${q(c.offer.name)},`,
        `  grants: [`,
        ...c.offer.grants.map((g) => `    ${tsGrant(g)},`),
        `  ],`,
        `});`,
        `console.log(offer.code); // show it as a QR, or as a link on the same device`,
      ].join("\n");
    case "issue": {
      const i = c.issue;
      const extra = [
        i.decimals !== 0 ? `  decimals: ${i.decimals},` : "",
        !i.transferable ? `  transferable: false, // bound to whoever holds it` : "",
        i.burnable ? `  burnable: true,` : "",
      ].filter((l) => l.length > 0);
      return [
        `import { localAccount } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `const issued = await app.issue({`,
        `  symbol: ${q(i.symbol)},`,
        `  name: ${q(i.name)},`,
        `  supply: ${q(i.supply)}, // the whole supply that will ever exist`,
        ...extra,
        `});`,
        `console.log(issued.id, issued.kind); // this account holds the supply`,
      ].join("\n");
    }
    case "vault": {
      const v = c.vault;
      return [
        `import { localAccount } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `const vault = await app.openVault({`,
        `  a: ${q(v.a)}, reserveA: ${q(v.reserveA)},`,
        `  b: ${q(v.b)}, reserveB: ${q(v.reserveB)},`,
        `  feeBps: ${v.feeBps},${v.label.length > 0 ? ` label: ${q(v.label)},` : ""}`,
        `});`,
        `console.log(vault.id); // wallets trade ${v.a} for ${v.b} through it`,
      ].join("\n");
    }
    case "give":
      return [
        `import { localAccount, ask } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `const connection = await app.connection(${q(c.connection)});`,
        `// The wallet takes up the object first, so it can hold it.`,
        `const accepted = await app.wait(await app.request(connection, ask.accept(${q(c.give.object)})), { until: "answered" });`,
        `if (accepted.outcome !== "carried_out") throw new Error(accepted.reason);`,
        `await app.give(connection, ${q(c.give.object)}, ${q(c.give.amount)});`,
      ].join("\n");
    case "decide":
      return [
        `import { localAccount } from "dsm-app-client";`,
        ``,
        `const app = await localAccount("app");`,
        `const stake = Buffer.from(${q(c.decide.stake)}, "hex"); // a stake id from a "staked" result`,
        `const verdict = await app.decide(stake, ${q(c.decide.decision)}); // "A", "B" or "void"`,
        `console.log(verdict.state);`,
      ].join("\n");
    case "ask":
      return tsAsk(c.connection, c.ask, c.app);
  }
}

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
        `const ref = await app.request(connection, ask.send(${q(a.object)}, ${q(a.amount)}${a.memo.length > 0 ? `, ${q(a.memo)}` : ""}));`,
        ...tail,
        `if (result.fact === "received") { /* paid: the transfer is accepted on this account */ }`,
      ].join("\n");
    case "owns":
      return [
        ...head,
        `const ref = await app.request(connection, ask.owns(${list(a.objects)}));`,
        ...tail,
        `for (const o of result.owns ?? []) console.log(o.object, o.amount); // proven, not said`,
      ].join("\n");
    case "accept":
      return [
        ...head,
        `const ref = await app.request(connection, ask.accept(${q(a.object)}));`,
        `const result = await app.wait(ref, { until: "answered" });`,
        `console.log(result.outcome); // "carried_out": the wallet can now hold it`,
      ].join("\n");
    case "contacts":
      return [...head, `const ref = await app.request(connection, ask.contacts());`, ...tail].join("\n");
    case "login":
      return [
        ...head,
        `const nonce = crypto.randomUUID(); // keep it: the answer is checked against it`,
        `const ref = await app.request(connection, ask.login(${q(app)}, nonce));`,
        `const result = await app.wait(ref); // waits for the player to approve on the device`,
        `const signedIn = result.fact === "signed" && result.signed?.statement === loginStatement(${q(app)}, nonce);`,
      ].join("\n");
    case "sign":
      return [
        ...head,
        `const ref = await app.request(connection, ask.sign(${q(a.statement)}));`,
        `const result = await app.wait(ref); // waits for the player to approve on the device`,
        `console.log(result.fact === "signed", result.signed?.statement);`,
      ].join("\n");
    case "price":
      return [
        ...head,
        `const priced = await app.wait(await app.request(connection, ask.price(${q(a.from)}, ${q(a.to)}, ${q(a.amount)})));`,
        `console.log(priced.price?.amountOut); // in ${a.to}'s smallest unit; information, never a fact`,
      ].join("\n");
    case "trade":
      return [
        ...head,
        `// A wallet receives only what it has taken up itself: it accepts ${a.to} first.`,
        `const accepted = await app.wait(await app.request(connection, ask.accept(${q(a.to)})), { until: "answered" });`,
        `if (accepted.outcome !== "carried_out") throw new Error(accepted.reason);`,
        `const priced = await app.wait(await app.request(connection, ask.price(${q(a.from)}, ${q(a.to)}, ${q(a.amount)})));`,
        `if (priced.price === undefined) throw new Error(priced.reason);`,
        `const atLeast = (priced.price.amountOut * ${a.atLeastPercent}n) / 100n;`,
        `const ref = await app.request(connection, ask.trade(${q(a.from)}, ${q(a.to)}, ${q(a.amount)}, atLeast));`,
        ...tail,
      ].join("\n");
    case "stake":
      return [
        ...head,
        `const other = (await app.connections()).find((c) => c.connected && c.id !== connection.id);`,
        `if (other === undefined) throw new Error("a match needs a second connected wallet");`,
        `const ref = await app.request(connection, ask.match.stake({`,
        `  match: ${q(a.match)}, object: ${q(a.object)}, amount: ${q(a.amount)}, side: ${q(a.side)}, opponent: other.opponent,`,
        a.against.length > 0 ? `  against: Buffer.from(${q(a.against)}, "hex"), // side A's stake, so both share one verdict` : `  // side B passes side A's stake id as against`,
        `}));`,
        ...tail,
        `console.log(result.match?.stakes); // the stake ids: decide with app.decide, collect with ask.match.collect`,
      ].join("\n");
    case "collect":
      return [
        ...head,
        `const stakes = ${list(a.stakes)}.map((s) => Buffer.from(s, "hex"));`,
        `const ref = await app.request(connection, ask.match.collect(stakes));`,
        ...tail,
      ].join("\n");
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
        `offer = app.offer(${q(c.offer.name)}, [`,
        ...c.offer.grants.map((g) => `    ${pyGrant(g)},`),
        `])`,
        `print(offer.code)  # show it as a QR, or as a link on the same device`,
      ].join("\n");
    case "issue": {
      const i = c.issue;
      const extra = [
        i.decimals !== 0 ? `, decimals=${i.decimals}` : "",
        !i.transferable ? `, transferable=False` : "",
        i.burnable ? `, burnable=True` : "",
      ].join("");
      return [
        `from dsm_app_client import local_app`,
        ``,
        `app = local_app()`,
        `issued = app.issue(${q(i.symbol)}, ${q(i.name)}, ${q(i.supply)}${extra})  # the whole supply that will ever exist`,
        `print(issued.id, issued.kind)  # this account holds the supply`,
      ].join("\n");
    }
    case "vault": {
      const v = c.vault;
      return [
        `from dsm_app_client import local_app`,
        ``,
        `app = local_app()`,
        `vault = app.open_vault(${q(v.a)}, ${q(v.reserveA)}, ${q(v.b)}, ${q(v.reserveB)}, fee_bps=${v.feeBps}${v.label.length > 0 ? `, label=${q(v.label)}` : ""})`,
        `print(vault.id.hex())  # wallets trade ${v.a} for ${v.b} through it`,
      ].join("\n");
    }
    case "give":
      return [
        `from dsm_app_client import local_app, ask`,
        ``,
        `app = local_app()`,
        `connection = app.connection(${q(c.connection)})`,
        `# The wallet takes up the object first, so it can hold it.`,
        `accepted = app.wait(app.request(connection, ask.accept(${q(c.give.object)})), until="answered")`,
        `if accepted.outcome != "carried_out":`,
        `    raise RuntimeError(accepted.reason)`,
        `app.give(connection, ${q(c.give.object)}, ${q(c.give.amount)})`,
      ].join("\n");
    case "decide":
      return [
        `from dsm_app_client import local_app`,
        ``,
        `app = local_app()`,
        `stake = bytes.fromhex(${q(c.decide.stake)})  # a stake id from a "staked" result`,
        `verdict = app.decide(stake, ${q(c.decide.decision)})  # "A", "B" or "void"`,
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
        `ref = app.request(connection, ask.send(${q(a.object)}, ${q(a.amount)}${a.memo.length > 0 ? `, ${q(a.memo)}` : ""}))`,
        ...tail,
        `if result.fact == "received":`,
        `    pass  # paid: the transfer is accepted on this account`,
      ].join("\n");
    case "owns":
      return [
        ...head,
        `ref = app.request(connection, ask.owns(${list(a.objects)}))`,
        ...tail,
        `for object_id, amount in result.owns:`,
        `    print(object_id, amount)  # proven, not said`,
      ].join("\n");
    case "accept":
      return [
        ...head,
        `ref = app.request(connection, ask.accept(${q(a.object)}))`,
        `result = app.wait(ref, until="answered")`,
        `print(result.outcome)  # "carried_out": the wallet can now hold it`,
      ].join("\n");
    case "contacts":
      return [...head, `ref = app.request(connection, ask.contacts())`, ...tail].join("\n");
    case "login":
      return [
        ...head,
        `nonce = str(uuid.uuid4())  # keep it: the answer is checked against it`,
        `ref = app.request(connection, ask.login(${q(app)}, nonce))`,
        `result = app.wait(ref)  # waits for the player to approve on the device`,
        `signed_in = result.fact == "signed" and result.signed[0] == login_statement(${q(app)}, nonce)`,
      ].join("\n");
    case "sign":
      return [
        ...head,
        `ref = app.request(connection, ask.sign(${q(a.statement)}))`,
        `result = app.wait(ref)  # waits for the player to approve on the device`,
        `print(result.fact == "signed", result.signed)`,
      ].join("\n");
    case "price":
      return [
        ...head,
        `priced = app.wait(app.request(connection, ask.price(${q(a.from)}, ${q(a.to)}, ${q(a.amount)})))`,
        `print(priced.price)  # (amount in, amount out, hops) in smallest units; information, never a fact`,
      ].join("\n");
    case "trade":
      return [
        ...head,
        `# A wallet receives only what it has taken up itself: it accepts ${a.to} first.`,
        `accepted = app.wait(app.request(connection, ask.accept(${q(a.to)})), until="answered")`,
        `if accepted.outcome != "carried_out":`,
        `    raise RuntimeError(accepted.reason)`,
        `priced = app.wait(app.request(connection, ask.price(${q(a.from)}, ${q(a.to)}, ${q(a.amount)})))`,
        `if priced.price is None:`,
        `    raise RuntimeError(priced.reason)`,
        `at_least = priced.price[1] * ${a.atLeastPercent} // 100`,
        `ref = app.request(connection, ask.trade(${q(a.from)}, ${q(a.to)}, ${q(a.amount)}, at_least))`,
        ...tail,
      ].join("\n");
    case "stake":
      return [
        ...head,
        `other = next(c for c in app.connections() if c.connected and c.id != connection.id)`,
        `ref = app.request(connection, ask.match.stake(`,
        `    ${q(a.match)}, ${q(a.object)}, ${q(a.amount)}, ${q(a.side)}, other.opponent,`,
        a.against.length > 0 ? `    against=bytes.fromhex(${q(a.against)}),  # side A's stake, so both share one verdict` : `    # side B passes side A's stake id as against=`,
        `))`,
        ...tail,
        `print(result.match[0] if result.match else None)  # the stake ids: decide with app.decide, collect with ask.match.collect`,
      ].join("\n");
    case "collect":
      return [
        ...head,
        `stakes = [bytes.fromhex(s) for s in ${list(a.stakes)}]`,
        `ref = app.request(connection, ask.match.collect(stakes))`,
        ...tail,
      ].join("\n");
  }
}
