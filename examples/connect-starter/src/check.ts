// SPDX-License-Identifier: MIT OR Apache-2.0

// The developer path, end to end: what a developer does after `make app-dev`,
// `make dev-wallet` and `make starter`, driven through the starter's own HTTP
// API on one side and the terminal dev wallet on the other. CI runs this
// (`make developer-path`), so the walkthrough's steps fail CI before they
// ever go stale.
//
//   1. the starter shows a connect code; the wallet previews and approves it
//   2. the starter sees the wallet connected
//   3. a payment inside the grant: carried out, and PAID on the app's account
//   4. a payment over the cap: held for the player; approved; then PAID
//   5. a holdings proof: HOLDINGS, verified by the app's account
//   6. the wallet disconnects; the next request is refused

import { encodeB32, localAccount, pb } from "dsm-app-client";

const STARTER = process.env.STARTER_URL ?? "http://127.0.0.1:3000";
const STEP_MS = 240_000;

interface Row {
  session: string;
  seq: string;
  outcome: string;
  fact: string;
  reason: string;
  error: string;
}
interface State {
  sessions: { id: string; wallet: string; connected: boolean }[];
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

async function request(session: string, seq: string): Promise<Row | undefined> {
  const s = await api<State>("/api/state");
  return s.requests.find((r) => r.session === session && r.seq === seq);
}

function step(n: number, line: string): void {
  console.log(`[developer-path] ${n}. ${line}`);
}

async function main(): Promise<void> {
  const wallet = await localAccount("wallet");

  const offer = await api<{ code: string }>("/api/offer", {});
  const preview = await wallet.preview(offer.code);
  // A wallet connects to an application once: an earlier run's session ends first.
  for (const earlier of await wallet.sessions()) {
    const sameApp = encodeB32(earlier.peerDeviceId) === encodeB32(preview.appDeviceId);
    if (sameApp && earlier.status === pb.ConnectSessionStatus.CONNECTED) {
      await wallet.disconnect(earlier.sessionId);
    }
  }
  const session = await wallet.approve(preview.offerDigest);
  const sid = encodeB32(session.sessionId);
  step(1, `the wallet approved "${preview.displayName}": ${preview.scopeLines.join("; ")}`);

  await until("the starter to see the wallet", async () => {
    const s = await api<State>("/api/state");
    return s.sessions.find((x) => x.id === sid && x.connected);
  });
  step(2, `the starter sees session ${sid}`);

  const within = await api<{ seq: string }>("/api/pay", { session: sid, amount: "5" });
  const paid = await until("the payment inside the grant", async () => {
    const r = await request(sid, within.seq);
    return r !== undefined && r.fact === "PAID" && r.outcome === "CARRIED_OUT" ? r : undefined;
  });
  step(3, `a payment inside the grant: ${paid.outcome}, ${paid.fact}`);

  const over = await api<{ seq: string }>("/api/pay", { session: sid, amount: "20" });
  const held = await until("the payment over the cap to wait", async () => {
    const r = await request(sid, over.seq);
    return r !== undefined && r.outcome === "AWAITING_APPROVAL" ? r : undefined;
  });
  const waiting = await wallet.pending();
  if (!waiting.some((p) => encodeB32(p.sessionId) === sid && p.seq.toString() === over.seq)) {
    throw new Error("the wallet does not list the held payment as pending");
  }
  const decided = await wallet.respond(session.sessionId, BigInt(over.seq), "approve");
  const approvedPaid = await until("the approved payment", async () => {
    await wallet.sync();
    const r = await request(sid, over.seq);
    return r !== undefined && r.fact === "PAID" ? r : undefined;
  });
  step(4, `a payment over the cap: ${held.reason}; approved (${pb.ConnectOutcome[decided.outcome]}); ${approvedPaid.fact}`);

  const proof = await api<{ seq: string }>("/api/holdings", { session: sid });
  const proven = await until("the holdings proof", async () => {
    const r = await request(sid, proof.seq);
    return r !== undefined && r.fact === "HOLDINGS" ? r : undefined;
  });
  step(5, `a holdings proof: ${proven.fact}`);

  await wallet.disconnect(session.sessionId);
  await until("the starter to see the wallet disconnected", async () => {
    const s = await api<State>("/api/state");
    return s.sessions.find((x) => x.id === sid && !x.connected);
  });
  try {
    await api("/api/pay", { session: sid, amount: "5" });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    if (!message.includes("disconnected")) throw e;
    step(6, `after the wallet disconnected, a request is refused: ${message}`);
    console.log("[developer-path] every step passed");
    return;
  }
  throw new Error("a request to a disconnected wallet was accepted");
}

main().catch((e: unknown) => {
  console.error(`[developer-path] FAILED: ${e instanceof Error ? e.message : e}`);
  process.exit(1);
});
