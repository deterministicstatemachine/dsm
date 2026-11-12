// SPDX-License-Identifier: MIT OR Apache-2.0

// What comes back, in plain terms. Every result keeps the wire's message as
// `raw`, for anything these fields leave out.

import {
  ConnectFact,
  ConnectOutcome,
  ConnectSessionStatus,
  type ConnectAppStatusV1,
  type ConnectPendingV1,
  type ConnectPreviewV1,
  type ConnectSessionV1,
} from "./generated/dsm_app_pb.js";
import { encodeB32 } from "./b32.js";
import type { Opponent } from "./requests.js";

/** A wallet connected to the application, or one that was. */
export interface Connection {
  /** The connection's id (Base32 Crockford). */
  id: string;
  rawId: Uint8Array;
  /** The other side's name: the application's, or the wallet's. */
  name: string;
  /** The other side's DSM identity (Base32 Crockford). */
  peer: string;
  connected: boolean;
  /** Each grant, as Rust renders it for people. */
  grants: string[];
  /** What the grants' caps have taken so far. */
  spent: { symbol: string; spent: string; total: string }[];
  /** Why the last exchange with it did not complete; empty when it did. */
  lastError: string;
  /** The other side's identity as a match names an opponent. */
  opponent: Opponent;
  raw: ConnectSessionV1;
}

export function connectionOf(s: ConnectSessionV1): Connection {
  return {
    id: encodeB32(s.sessionId),
    rawId: s.sessionId,
    name: s.displayName,
    peer: encodeB32(s.peerDeviceId),
    connected: s.status === ConnectSessionStatus.CONNECTED,
    grants: s.scopeLines,
    spent: s.spent.map((x) => ({ symbol: x.symbol, spent: x.spentDisplay, total: x.totalDisplay })),
    lastError: s.lastError,
    opponent: { genesis: s.peerGenesis, deviceId: s.peerDeviceId, signingKey: s.peerSigningKey },
    raw: s,
  };
}

/** What the wallet said: a notification, never evidence. */
export type Outcome = "unanswered" | "carried_out" | "awaiting_approval" | "declined" | "failed";

/** What the application's own account established: the evidence. */
export type Fact =
  | "none"
  | "received"
  | "owns"
  | "staked"
  | "collected"
  | "contributed"
  | "taken_back"
  | "written"
  | "duel_staked"
  | "duel_started"
  | "duel_withdrawn"
  | "duel_settled"
  | "signed";

const OUTCOMES: Record<ConnectOutcome, Outcome> = {
  [ConnectOutcome.UNSPECIFIED]: "unanswered",
  [ConnectOutcome.CARRIED_OUT]: "carried_out",
  [ConnectOutcome.AWAITING_APPROVAL]: "awaiting_approval",
  [ConnectOutcome.DECLINED]: "declined",
  [ConnectOutcome.FAILED]: "failed",
};

const FACTS: Record<ConnectFact, Fact> = {
  [ConnectFact.UNSPECIFIED]: "none",
  [ConnectFact.NONE]: "none",
  [ConnectFact.PAID]: "received",
  [ConnectFact.HOLDINGS]: "owns",
  [ConnectFact.ESCROW_LOCKED]: "staked",
  [ConnectFact.ESCROW_RELEASED]: "collected",
  [ConnectFact.CONTRIBUTED]: "contributed",
  [ConnectFact.CONTRIBUTION_RELEASED]: "taken_back",
  [ConnectFact.APP_CELL_HELD]: "written",
  [ConnectFact.DUEL_LOCKED]: "duel_staked",
  [ConnectFact.DUEL_STARTED]: "duel_started",
  [ConnectFact.DUEL_WITHDRAWN]: "duel_withdrawn",
  [ConnectFact.DUEL_SETTLED]: "duel_settled",
  [ConnectFact.SIGNED]: "signed",
};

/** A request this application made, by connection and sequence number. */
export interface RequestRef {
  /** The connection's id (Base32 Crockford), as `Connection.id` and `Pending.connection` name it. */
  connection: string;
  seq: bigint;
}

/** What became of a request. */
export interface Result {
  request: RequestRef;
  /** The wallet posted a signed answer. */
  answered: boolean;
  outcome: Outcome;
  /** Why, when the wallet declined, failed or holds it for the player. */
  reason: string;
  fact: Fact;
  /** Why the fact holds, or why the answer established none. */
  detail: string;
  /** fact "received": the accepted transfer's id. */
  received?: Uint8Array;
  /** fact "owns": what the wallet proved, by object id (Base32 Crockford) and amount in the smallest unit. */
  owns?: { object: string; amount: bigint }[];
  /** fact "staked" or "collected": the stakes, the match's verdict cell, and the amount staked. */
  match?: { stakes: Uint8Array[]; cell: Uint8Array; amount: bigint };
  /** fact "contributed" or "taken_back": the contributions, the wallet's verdict cell for the commitment, and the amount committed. */
  contribution?: { contributions: Uint8Array[]; cell: Uint8Array; amount: bigint };
  /** A state write: the cell this account derived and, once its occupant is final, the step the next cell's name commits. Fact "written" only when the wallet's write holds it. */
  state?: { cell: Uint8Array; step?: Uint8Array };
  /** A price: what the wallet's vaults would give. Information, never a fact. */
  price?: { amountIn: bigint; amountOut: bigint; hops: number };
  /** fact "signed": the statement the wallet signed, and its signature over `raw.answerBody`. */
  signed?: { statement: string; signature: Uint8Array };
  raw: ConnectAppStatusV1;
}

export function resultOf(ref: RequestRef, s: ConnectAppStatusV1): Result {
  const result: Result = {
    request: ref,
    answered: s.answered,
    outcome: OUTCOMES[s.outcome],
    reason: s.reason,
    fact: FACTS[s.fact],
    detail: s.factDetail,
    raw: s,
  };
  if (s.fact === ConnectFact.PAID) result.received = s.paidTx;
  if (s.fact === ConnectFact.HOLDINGS) {
    result.owns = s.holdings.map((h) => ({ object: encodeB32(h.policyCommit), amount: h.amount }));
  }
  if (s.fact === ConnectFact.ESCROW_LOCKED || s.fact === ConnectFact.ESCROW_RELEASED) {
    result.match = { stakes: s.escrowVaultIds, cell: s.escrowVerdictCell, amount: s.escrowAmount };
  }
  if (s.fact === ConnectFact.CONTRIBUTED || s.fact === ConnectFact.CONTRIBUTION_RELEASED) {
    result.contribution = { contributions: s.escrowVaultIds, cell: s.escrowVerdictCell, amount: s.escrowAmount };
  }
  if (s.appCell.length > 0) {
    result.state = { cell: s.appCell, step: s.appCellStep.length > 0 ? s.appCellStep : undefined };
  }
  if (s.quote !== undefined && s.quote.amountIn > 0n) {
    result.price = { amountIn: s.quote.amountIn, amountOut: s.quote.amountOut, hops: s.quote.hops };
  }
  if (s.fact === ConnectFact.SIGNED) result.signed = { statement: s.signedStatement, signature: s.answerSignature };
  return result;
}

/** A connect code, as the wallet reads it before anyone approves it. */
export interface Preview {
  digest: Uint8Array;
  /** The application's name, as it gives it. */
  name: string;
  /** The application's DSM identity (Base32 Crockford). */
  app: string;
  /** What it asks for, as Rust renders it for the approval screen. */
  asks: string[];
  raw: ConnectPreviewV1;
}

export function previewOf(p: ConnectPreviewV1): Preview {
  return { digest: p.offerDigest, name: p.displayName, app: encodeB32(p.appDeviceId), asks: p.scopeLines, raw: p };
}

/** A request waiting for the player, on the wallet's side. */
export interface Pending {
  connection: string;
  rawConnection: Uint8Array;
  seq: bigint;
  /** The application's name. */
  from: string;
  /** The request, as Rust renders it. */
  summary: string;
  /** Why the grant does not cover it. */
  reason: string;
  /** Approved already; it goes through on the next sync. */
  approved: boolean;
  raw: ConnectPendingV1;
}

export function pendingOf(p: ConnectPendingV1): Pending {
  return {
    connection: encodeB32(p.sessionId),
    rawConnection: p.sessionId,
    seq: p.seq,
    from: p.displayName,
    summary: p.summary,
    reason: p.reason,
    approved: p.approved,
    raw: p,
  };
}
