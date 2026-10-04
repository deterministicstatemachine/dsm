// SPDX-License-Identifier: MIT OR Apache-2.0

// DSM Connect (DSM Amendment A11): this wallet connected to Web2 applications.
// Every call sends what the player chose; Rust verifies every offer, keeps
// every grant and carries out every request. The screen renders what Rust
// answers, nothing more: scopes, spends and requests come back already
// rendered, and nothing here decides what an application may do.
import * as pb from '../proto/dsm_app_pb';
import { routerInvokeBin, routerQueryBin } from './WebViewBridge';
import { decodeFramedEnvelopeV3 } from './decoding';

type Reply = pb.ConnectReplyV1['reply'];

function argPack(body: Uint8Array): Uint8Array {
  return new pb.ArgPack({ codec: pb.Codec.PROTO, body: new Uint8Array(body) }).toBinary();
}

function reply(route: string, framed: Uint8Array): Reply {
  const env = decodeFramedEnvelopeV3(framed);
  if (env.payload.case === 'error') throw new Error(env.payload.value.message);
  if (env.payload.case !== 'connectReply') {
    throw new Error(`${route} answered ${env.payload.case ?? 'nothing'}`);
  }
  return env.payload.value.reply;
}

async function query(route: string, body: Uint8Array): Promise<Reply> {
  return reply(route, await routerQueryBin(route, argPack(body)));
}

async function invoke(route: string, body: Uint8Array): Promise<Reply> {
  return reply(route, await routerInvokeBin(route, argPack(body)));
}

/** An offer a scanned code names, verified by Rust, for the approval screen. */
export interface Preview {
  offerDigest: Uint8Array;
  displayName: string;
  appDeviceId: Uint8Array;
  endpoint: string;
  /** Each scope the application asks for, as Rust renders it. */
  scopeLines: string[];
}

/** A connected (or once connected) application. */
export interface Session {
  sessionId: Uint8Array;
  displayName: string;
  peerDeviceId: Uint8Array;
  endpoint: string;
  scopeLines: string[];
  lastSeq: bigint;
  connected: boolean;
  spent: { symbol: string; spent: string; total: string }[];
  /** Why the last sync with it did not complete; empty when it did. */
  lastError: string;
}

/** A request outside its grant, waiting for the player. */
export interface Pending {
  sessionId: Uint8Array;
  seq: bigint;
  displayName: string;
  summary: string;
  reason: string;
}

/** What the wallet did with one request. */
export interface LogEntry {
  seq: bigint;
  summary: string;
  outcome: 'carriedOut' | 'awaitingApproval' | 'declined' | 'failed';
  detail: string;
}

function session(s: pb.ConnectSessionV1): Session {
  return {
    sessionId: s.sessionId,
    displayName: s.displayName,
    peerDeviceId: s.peerDeviceId,
    endpoint: s.endpoint,
    scopeLines: s.scopeLines,
    lastSeq: s.lastSeq,
    connected: s.status === pb.ConnectSessionStatus.CONNECTED,
    spent: s.spent.map((x) => ({ symbol: x.symbol, spent: x.spentDisplay, total: x.totalDisplay })),
    lastError: s.lastError,
  };
}

function outcome(o: pb.ConnectOutcome): LogEntry['outcome'] {
  switch (o) {
    case pb.ConnectOutcome.CARRIED_OUT: return 'carriedOut';
    case pb.ConnectOutcome.AWAITING_APPROVAL: return 'awaitingApproval';
    case pb.ConnectOutcome.DECLINED: return 'declined';
    case pb.ConnectOutcome.FAILED: return 'failed';
    default: throw new Error(`unknown connect outcome ${o}`);
  }
}

/** connect.preview: read a scanned code, fetch and verify its offer. */
export async function preview(code: string): Promise<Preview> {
  const r = await query('connect.preview', new pb.ConnectPreviewRequestV1({ code }).toBinary());
  if (r.case !== 'preview') throw new Error(`connect.preview answered ${r.case ?? 'nothing'}`);
  return {
    offerDigest: r.value.offerDigest,
    displayName: r.value.displayName,
    appDeviceId: r.value.appDeviceId,
    endpoint: r.value.endpoint,
    scopeLines: r.value.scopeLines,
  };
}

/** connect.approve: the player approves the offer as it asked. */
export async function approve(offerDigest: Uint8Array): Promise<Session> {
  const r = await invoke('connect.approve', new pb.ConnectApproveRequestV1({ offerDigest: new Uint8Array(offerDigest) }).toBinary());
  if (r.case !== 'session') throw new Error(`connect.approve answered ${r.case ?? 'nothing'}`);
  return session(r.value);
}

function sessions(route: string, r: Reply): Session[] {
  if (r.case !== 'sessions') throw new Error(`${route} answered ${r.case ?? 'nothing'}`);
  return r.value.sessions.map(session);
}

/** connect.list: every application this wallet connected to. */
export async function list(): Promise<Session[]> {
  return sessions('connect.list', await query('connect.list', new Uint8Array()));
}

/** connect.sync: take in and carry out connected applications' requests now. */
export async function sync(): Promise<Session[]> {
  return sessions('connect.sync', await invoke('connect.sync', new Uint8Array()));
}

/** connect.pending: requests outside their grant, waiting for the player. */
export async function pending(): Promise<Pending[]> {
  const r = await query('connect.pending', new Uint8Array());
  if (r.case !== 'pending') throw new Error(`connect.pending answered ${r.case ?? 'nothing'}`);
  return r.value.pending.map((p) => ({
    sessionId: p.sessionId,
    seq: p.seq,
    displayName: p.displayName,
    summary: p.summary,
    reason: p.reason,
  }));
}

/** connect.respond: the player's decision on a waiting request. */
export async function respond(sessionId: Uint8Array, seq: bigint, choice: 'approve' | 'decline'): Promise<Session> {
  const decision = choice === 'approve' ? pb.ConnectDecision.APPROVE : pb.ConnectDecision.DECLINE;
  const r = await invoke('connect.respond', new pb.ConnectRespondRequestV1({ sessionId: new Uint8Array(sessionId), seq, decision }).toBinary());
  if (r.case !== 'session') throw new Error(`connect.respond answered ${r.case ?? 'nothing'}`);
  return session(r.value);
}

/** connect.disconnect: the application's grant ends. */
export async function disconnect(sessionId: Uint8Array): Promise<Session> {
  const r = await invoke('connect.disconnect', new pb.ConnectSessionRefV1({ sessionId: new Uint8Array(sessionId) }).toBinary());
  if (r.case !== 'session') throw new Error(`connect.disconnect answered ${r.case ?? 'nothing'}`);
  return session(r.value);
}

/** connect.log: what the wallet did with each of an application's requests. */
export async function log(sessionId: Uint8Array): Promise<LogEntry[]> {
  const r = await query('connect.log', new pb.ConnectSessionRefV1({ sessionId: new Uint8Array(sessionId) }).toBinary());
  if (r.case !== 'log') throw new Error(`connect.log answered ${r.case ?? 'nothing'}`);
  return r.value.entries.map((e) => ({ seq: e.seq, summary: e.summary, outcome: outcome(e.outcome), detail: e.detail }));
}
