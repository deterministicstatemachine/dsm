// SPDX-License-Identifier: MIT OR Apache-2.0

// Every helper once, end to end: what a developer does after `make app-dev`,
// `make dev-wallet`, `make dev-wallet2` and `make starter`, driven through the
// starter's own HTTP API on one side and the terminal wallets on the other.
// CI runs this (`make developer-path`), so the guide and the videos fail CI
// before they go stale.
//
//    1. the app issues a coin and opens a vault that sells it for ERA
//    2. the starter shows a connect code; the wallet reads and approves it
//    3. the starter sees the wallet connected
//    4. a send inside the grant: carried out, and RECEIVED on the app's account
//    5. a send over the cap: held for the player; approved; then RECEIVED
//    6. a proof of what the wallet owns: OWNS, verified by the app's account
//    7. a sign-in: held for the player; approved; SIGNED, with the words asked for
//    8. the app issues an item; the wallet accepts it; the app gives it; the wallet owns it
//    9. a price, then a trade through the app's vault: the wallet owns the coin
//   10. a match the app referees: both wallets stake, the app decides, the winner collects
//   11. the wallet disconnects; the next request is refused

import { localAccount } from "dsm-app-client";
import type { WalletAccount } from "dsm-app-client";

const STARTER = process.env.STARTER_URL ?? "http://127.0.0.1:3000";
const STEP_MS = 240_000;

interface Row {
  connection: string;
  seq: string;
  outcome: string;
  fact: string;
  reason: string;
  detail: string;
  error: string;
  owns: { object: string; amount: string }[];
  stakes: string[];
  signedAsAsked?: boolean;
}
interface State {
  connections: { id: string; wallet: string; connected: boolean }[];
  requests: Row[];
}

async function api<T>(path: string, payload?: Record<string, string>): Promise<T> {
  const res = await fetch(STARTER + path, payload === undefined ? {} : {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = (await res.json()) as T & { error?: string };
  if (!res.ok) throw new Error(`${path}: ${body.error}`);
  return body;
}

async function until<T>(what: string, probe: () => Promise<T | undefined>): Promise<T> {
  const deadline = Date.now() + STEP_MS;
  for (;;) {
    const found = await probe();
    if (found !== undefined) return found;
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 500));
  }
}

async function row(connection: string, seq: string): Promise<Row | undefined> {
  const s = await api<State>("/api/state");
  const r = s.requests.find((x) => x.connection === connection && x.seq === seq);
  if (r?.error) throw new Error(`request ${seq}: ${r.error}`);
  return r;
}

/** Wait for a request's fact, or for the outcome `or`. */
async function settled(what: string, connection: string, seq: string, fact: string, or?: string): Promise<Row> {
  return until(what, async () => {
    const r = await row(connection, seq);
    if (r === undefined) return undefined;
    if (r.outcome === "declined" || r.outcome === "failed") throw new Error(`${what}: ${r.outcome}: ${r.reason}`);
    return r.fact === fact || (or !== undefined && r.outcome === or) ? r : undefined;
  });
}

/** The wallet approves what waits for the player on `connection`, then syncs until the request shows `fact`. */
async function approved(wallet: WalletAccount, connection: string, seq: string, what: string, fact: string): Promise<Row> {
  const waiting = await wallet.pending();
  const held = waiting.find((p) => p.connection === connection && p.seq.toString() === seq);
  if (held === undefined) throw new Error(`${what}: the wallet does not list request ${seq} as waiting`);
  await wallet.respond(connection, BigInt(seq), "approve");
  return until(`${what} after approval`, async () => {
    await wallet.sync();
    const r = await row(connection, seq);
    return r !== undefined && r.fact === fact ? r : undefined;
  });
}

async function connect(wallet: WalletAccount): Promise<string> {
  const offer = await api<{ code: string }>("/api/offer", {});
  const preview = await wallet.preview(offer.code);
  // A wallet connects to an application once: an earlier run's connection ends first.
  for (const earlier of await wallet.connections()) {
    if (earlier.peer === preview.app && earlier.connected) await wallet.disconnect(earlier);
  }
  const connection = await wallet.approve(preview);
  await until("the starter to see the wallet", async () => {
    const s = await api<State>("/api/state");
    return s.connections.find((x) => x.id === connection.id && x.connected);
  });
  return connection.id;
}

function step(n: number, line: string): void {
  console.log(`[developer-path] ${n}. ${line}`);
}

async function main(): Promise<void> {
  const wallet = await localAccount("wallet");
  const other = await localAccount("wallet2");

  const coin = await api<{ symbol: string }>("/api/issue", { symbol: "GOLD", name: "Starter gold", supply: "1000000", decimals: "2" });
  const vault = await api<{ id: string }>("/api/vault", { object: "GOLD", reserve: "1000", era: "10" });
  step(1, `the app issued ${coin.symbol} and opened vault ${vault.id.slice(0, 12)}… selling it for ERA`);

  const cid = await connect(wallet);
  step(2, `the wallet approved the offer: connection ${cid}`);
  step(3, `the starter sees the wallet connected`);

  const within = await api<{ seq: string }>("/api/send", { connection: cid, amount: "0.05" });
  const received = await settled("the send inside the grant", cid, within.seq, "received");
  step(4, `a send inside the grant: ${received.outcome}, ${received.fact}`);

  const over = await api<{ seq: string }>("/api/send", { connection: cid, amount: "0.20" });
  const held = await settled("the send over the cap to wait", cid, over.seq, "received", "awaiting_approval");
  const approvedSend = await approved(wallet, cid, over.seq, "the send over the cap", "received");
  step(5, `a send over the cap: ${held.reason}; approved; ${approvedSend.fact}`);

  const owns = await api<{ seq: string }>("/api/owns", { connection: cid });
  const proven = await settled("the proof of what the wallet owns", cid, owns.seq, "owns");
  step(6, `a proof of what the wallet owns: ${proven.fact} (${proven.owns.length} object(s))`);

  const login = await api<{ seq: string }>("/api/login", { connection: cid });
  await settled("the sign-in to wait for the player", cid, login.seq, "signed", "awaiting_approval");
  const signed = await approved(wallet, cid, login.seq, "the sign-in", "signed");
  if (signed.signedAsAsked !== true) throw new Error("the wallet signed other words than the sign-in asked for");
  step(7, `a sign-in: held for the player; approved; ${signed.fact}, the words asked for`);

  await api("/api/issue", { symbol: "SWORD", name: "Starter sword", supply: "1" });
  await api("/api/give", { connection: cid, object: "SWORD", amount: "1" });
  const sword = await until("the wallet to own the sword", async () => {
    const o = await wallet.owns("SWORD").catch(() => undefined);
    return o !== undefined && o.amount === 1n ? o : undefined;
  });
  step(8, `the app issued ${sword.object.symbol} (${sword.object.kind}), the wallet accepted it, the app gave it: the wallet owns ${sword.display}`);

  const trade = await api<{ seq: string; priced: string }>("/api/trade", { connection: cid, era: "0.50" });
  await until("the trade to be carried out", async () => {
    const r = await row(cid, trade.seq);
    if (r?.outcome === "failed" || r?.outcome === "declined") throw new Error(`the trade: ${r.outcome}: ${r.reason}`);
    return r?.outcome === "carried_out" ? r : undefined;
  });
  const gold = await until("the wallet to own the coin", async () => {
    const o = await wallet.owns("GOLD").catch(() => undefined);
    return o !== undefined && o.amount > 0n ? o : undefined;
  });
  step(9, `priced at ${trade.priced} smallest units of GOLD; traded 0.50 ERA: the wallet owns ${gold.display} GOLD`);

  const cid2 = await connect(other);
  const stakeA = await api<{ seq: string }>("/api/match/stake", { connection: cid, side: "A" });
  const stakedA = await settled("side A's stake", cid, stakeA.seq, "staked");
  const stakeB = await api<{ seq: string }>("/api/match/stake", { connection: cid2, side: "B", against: stakedA.stakes[0] ?? "" });
  const stakedB = await settled("side B's stake", cid2, stakeB.seq, "staked");
  const verdict = await api<{ outcome: string }>("/api/match/decide", { stake: stakedA.stakes[0] ?? "", decision: "A" });
  const collect = await api<{ seq: string }>("/api/match/collect", { connection: cid, stakes: `${stakedA.stakes[0]},${stakedB.stakes[0]}` });
  const collected = await settled("side A's collect", cid, collect.seq, "collected");
  step(10, `a match: both wallets staked; the app decided ${verdict.outcome}; the winner collected ${collected.stakes.length} stake(s)`);

  await wallet.disconnect(cid);
  await until("the starter to see the wallet disconnected", async () => {
    const s = await api<State>("/api/state");
    return s.connections.find((x) => x.id === cid && !x.connected);
  });
  try {
    await api("/api/send", { connection: cid, amount: "0.05" });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (!message.includes("disconnected")) throw e;
    step(11, `after the wallet disconnected, a request is refused: ${message}`);
    await other.disconnect(cid2);
    console.log("[developer-path] every step passed");
    return;
  }
  throw new Error("a request to a disconnected wallet was accepted");
}

main().catch((e: unknown) => {
  console.error(`[developer-path] FAILED: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
