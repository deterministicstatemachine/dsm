// SPDX-License-Identifier: MIT OR Apache-2.0

// The DSM Connect starter: a Web2 application with its own DSM account.
//
// This server is the only thing that talks to the account (`make app-dev`
// runs it). It holds the ingress secret; the page it serves never does. The
// page asks this server, and this server asks the account:
//
//   GET  /             the page
//   GET  /api/state    the account, its balances, connected wallets, requests made, activity
//   POST /api/offer    a new connect code (and its QR) for a wallet to scan
//   POST /api/pay      ask a connected wallet to pay       {session, amount}
//   POST /api/holdings ask a connected wallet to prove what it holds {session}
//
// What counts as paid is the fact the account established (a transfer it
// accepted onto its own relationship with the wallet), never the wallet's say-so.

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { readFile } from "node:fs/promises";
import QRCode from "qrcode";
import { AppAccount, decodeId, encodeB32, intent, localAccount, pb, scope } from "dsm-app-client";
import type { RequestRef } from "dsm-app-client";

const PORT = Number(process.env.STARTER_PORT ?? "3000");
const NAME = process.env.STARTER_NAME ?? "Connect Starter";
const TICKER = process.env.STARTER_TOKEN ?? "ERA";
// The grant asked for, in the token's base units (ERA has 2 decimals: 10 = 0.10 ERA).
const PER_REQUEST = BigInt(process.env.STARTER_PER_REQUEST ?? "10");
const TOTAL = BigInt(process.env.STARTER_TOTAL ?? "100");
const FREE_REQUESTS = Number(process.env.STARTER_FREE_REQUESTS ?? "64");

/** A request this application made, as the page shows it. */
interface Made {
  ref: RequestRef;
  what: string;
  status: pb.ConnectAppStatusV1 | undefined;
  error: string;
}

const made: Made[] = [];

/** A request whose status can no longer change, so it is not asked about again. */
function settled(m: Made): boolean {
  if (m.error.length > 0) return true;
  const s = m.status;
  if (s === undefined) return false;
  if (s.fact === pb.ConnectFact.PAID || s.fact === pb.ConnectFact.HOLDINGS) return s.answered;
  return s.outcome === pb.ConnectOutcome.DECLINED || s.outcome === pb.ConnectOutcome.FAILED;
}

async function token(app: AppAccount): Promise<Uint8Array> {
  return app.policyCommitOf(TICKER);
}

async function state(app: AppAccount): Promise<unknown> {
  for (const m of made) {
    if (settled(m)) continue;
    try {
      m.status = await app.status(m.ref);
    } catch (e) {
      m.error = e instanceof Error ? e.message : String(e);
    }
  }
  const activity = await app.ingress.activity(0n);
  return {
    name: NAME,
    account: encodeB32(activity.deviceId),
    balances: (await app.balances()).map((b) => ({ symbol: b.symbol, amount: b.displayAmount })),
    sessions: (await app.sessions()).map((s) => ({
      id: encodeB32(s.sessionId),
      wallet: encodeB32(s.peerDeviceId),
      connected: s.status === pb.ConnectSessionStatus.CONNECTED,
      grants: s.scopeLines,
    })),
    requests: made.map((m) => ({
      session: encodeB32(m.ref.sessionId),
      seq: m.ref.seq.toString(),
      what: m.what,
      answered: m.status?.answered ?? !m.error,
      outcome: m.status === undefined ? "" : pb.ConnectOutcome[m.status.outcome],
      reason: m.status?.reason ?? "",
      fact: m.status === undefined ? "" : pb.ConnectFact[m.status.fact],
      detail: m.status?.factDetail ?? "",
      error: m.error,
    })),
    activity: activity.entries.slice(-15).map((e) => ({
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

async function route(app: AppAccount, page: string, req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", "http://localhost");
  if (req.method === "GET" && url.pathname === "/") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(page);
    return;
  }
  if (req.method === "GET" && url.pathname === "/api/state") {
    send(res, 200, await state(app));
    return;
  }
  if (req.method === "POST" && url.pathname === "/api/offer") {
    const t = await token(app);
    const offer = await app.offer({
      displayName: NAME,
      scopes: [scope.pay(t, PER_REQUEST, TOTAL), scope.holdings([t])],
      freeRequests: FREE_REQUESTS,
    });
    const qr = await QRCode.toString(offer.code, { type: "svg", errorCorrectionLevel: "M", margin: 1 });
    send(res, 200, { code: offer.code, qr });
    return;
  }
  if (req.method === "POST" && url.pathname === "/api/pay") {
    const fields = await body(req);
    const amount = BigInt(field(fields, "amount"));
    const ref = await app.request(
      decodeId(field(fields, "session"), "the session id"),
      intent.pay(await token(app), amount, `${NAME}: pay ${amount}`),
    );
    made.push({ ref, what: `pay ${amount} base units of ${TICKER}`, status: undefined, error: "" });
    send(res, 200, { seq: ref.seq });
    return;
  }
  if (req.method === "POST" && url.pathname === "/api/holdings") {
    const fields = await body(req);
    const ref = await app.request(decodeId(field(fields, "session"), "the session id"), intent.holdings([await token(app)]));
    made.push({ ref, what: `prove holdings of ${TICKER}`, status: undefined, error: "" });
    send(res, 200, { seq: ref.seq });
    return;
  }
  send(res, 404, { error: `no route ${req.method} ${url.pathname}` });
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
