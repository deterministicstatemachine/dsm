# SPDX-License-Identifier: MIT OR Apache-2.0
"""What comes back, in plain terms. Every result keeps the wire's message as
`raw`, for anything these fields leave out."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .b32 import encode_b32
from .generated import dsm_app_pb2 as pb
from .requests import Opponent


@dataclass(frozen=True)
class Connection:
    """A wallet connected to the application, or one that was."""

    id: str  # Base32 Crockford
    raw_id: bytes
    name: str  # the other side's name
    peer: str  # the other side's DSM identity (Base32 Crockford)
    connected: bool
    grants: Tuple[str, ...]  # each grant, as Rust renders it for people
    spent: Tuple[Tuple[str, str, str], ...]  # (symbol, spent, total) per cap
    last_error: str
    opponent: Opponent  # the other side's identity as a match names an opponent
    raw: pb.ConnectSessionV1


def connection_of(s: pb.ConnectSessionV1) -> Connection:
    return Connection(
        id=encode_b32(s.session_id),
        raw_id=s.session_id,
        name=s.display_name,
        peer=encode_b32(s.peer_device_id),
        connected=s.status == pb.CONNECT_SESSION_STATUS_CONNECTED,
        grants=tuple(s.scope_lines),
        spent=tuple((x.symbol, x.spent_display, x.total_display) for x in s.spent),
        last_error=s.last_error,
        opponent=Opponent(genesis=s.peer_genesis, device_id=s.peer_device_id, signing_key=s.peer_signing_key),
        raw=s,
    )


OUTCOMES: Dict[int, str] = {
    pb.CONNECT_OUTCOME_UNSPECIFIED: "unanswered",
    pb.CONNECT_OUTCOME_CARRIED_OUT: "carried_out",
    pb.CONNECT_OUTCOME_AWAITING_APPROVAL: "awaiting_approval",
    pb.CONNECT_OUTCOME_DECLINED: "declined",
    pb.CONNECT_OUTCOME_FAILED: "failed",
}

FACTS: Dict[int, str] = {
    pb.CONNECT_FACT_UNSPECIFIED: "none",
    pb.CONNECT_FACT_NONE: "none",
    pb.CONNECT_FACT_PAID: "received",
    pb.CONNECT_FACT_HOLDINGS: "owns",
    pb.CONNECT_FACT_ESCROW_LOCKED: "staked",
    pb.CONNECT_FACT_ESCROW_RELEASED: "collected",
    pb.CONNECT_FACT_DUEL_LOCKED: "duel_staked",
    pb.CONNECT_FACT_DUEL_STARTED: "duel_started",
    pb.CONNECT_FACT_DUEL_WITHDRAWN: "duel_withdrawn",
    pb.CONNECT_FACT_DUEL_SETTLED: "duel_settled",
    pb.CONNECT_FACT_SIGNED: "signed",
}


@dataclass(frozen=True)
class RequestRef:
    """A request this application made, by connection and sequence number."""

    connection: str  # the connection's id (Base32 Crockford), as Connection.id and Pending.connection name it
    seq: int


@dataclass(frozen=True)
class Result:
    """What became of a request."""

    request: RequestRef
    answered: bool  # the wallet posted a signed answer
    outcome: str  # what the wallet said: a notification, never evidence
    reason: str
    fact: str  # what this account established itself: the evidence
    detail: str
    received: Optional[bytes] = None  # fact "received": the accepted transfer's id
    owns: Tuple[Tuple[str, int], ...] = ()  # fact "owns": (object id, amount) pairs
    match: Optional[Tuple[Tuple[bytes, ...], bytes, int]] = None  # (stakes, verdict cell, amount)
    price: Optional[Tuple[int, int, int]] = None  # (amount in, amount out, hops); information, never a fact
    signed: Optional[Tuple[str, bytes]] = None  # fact "signed": (statement, signature over raw.answer_body)
    raw: Optional[pb.ConnectAppStatusV1] = None


def result_of(ref: RequestRef, s: pb.ConnectAppStatusV1) -> Result:
    received = s.paid_tx if s.fact == pb.CONNECT_FACT_PAID else None
    owns: Tuple[Tuple[str, int], ...] = ()
    if s.fact == pb.CONNECT_FACT_HOLDINGS:
        owns = tuple((encode_b32(h.policy_commit), h.amount) for h in s.holdings)
    match = None
    if s.fact in (pb.CONNECT_FACT_ESCROW_LOCKED, pb.CONNECT_FACT_ESCROW_RELEASED):
        match = (tuple(s.escrow_vault_ids), s.escrow_verdict_cell, s.escrow_amount)
    price = None
    if s.HasField("quote") and s.quote.amount_in > 0:
        price = (s.quote.amount_in, s.quote.amount_out, s.quote.hops)
    signed = (s.signed_statement, s.answer_signature) if s.fact == pb.CONNECT_FACT_SIGNED else None
    return Result(
        request=ref,
        answered=s.answered,
        outcome=OUTCOMES.get(s.outcome, "unanswered"),
        reason=s.reason,
        fact=FACTS.get(s.fact, "none"),
        detail=s.fact_detail,
        received=received,
        owns=owns,
        match=match,
        price=price,
        signed=signed,
        raw=s,
    )


@dataclass(frozen=True)
class Preview:
    """A connect code, as the wallet reads it before anyone approves it."""

    digest: bytes
    name: str  # the application's name, as it gives it
    app: str  # the application's DSM identity (Base32 Crockford)
    asks: Tuple[str, ...]  # what it asks for, as Rust renders it for the approval screen
    raw: pb.ConnectPreviewV1


def preview_of(p: pb.ConnectPreviewV1) -> Preview:
    return Preview(
        digest=p.offer_digest, name=p.display_name, app=encode_b32(p.app_device_id), asks=tuple(p.scope_lines), raw=p
    )


@dataclass(frozen=True)
class Pending:
    """A request waiting for the player, on the wallet's side."""

    connection: str
    raw_connection: bytes
    seq: int
    from_: str  # the application's name
    summary: str  # the request, as Rust renders it
    reason: str  # why the grant does not cover it
    approved: bool  # approved already; it goes through on the next sync
    raw: pb.ConnectPendingV1


def pending_of(p: pb.ConnectPendingV1) -> Pending:
    return Pending(
        connection=encode_b32(p.session_id),
        raw_connection=p.session_id,
        seq=p.seq,
        from_=p.display_name,
        summary=p.summary,
        reason=p.reason,
        approved=p.approved,
        raw=p,
    )
