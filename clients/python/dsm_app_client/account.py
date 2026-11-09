# SPDX-License-Identifier: MIT OR Apache-2.0
"""An account a dsm-app-host runs, reached through its ingress.

Your application's account is an AppAccount; a wallet you script (the
terminal dev wallet) is a WalletAccount. Both are the same SDK on the same
path a phone runs: these classes name its routes, resolve the names you use
into the wire's bytes, and read its answers back into plain values.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Dict, List, Literal, Optional, Sequence, Union

from .b32 import decode_id, encode_b32
from .generated import dsm_app_pb2 as pb
from .ingress import Ingress, connect_reply, payload
from .objects import Amount, ObjectInfo, ObjectRef, Owned, describe, direct_id, owned_of
from .requests import Ask, Cap, Grant
from .results import (
    Connection,
    Pending,
    Preview,
    RequestRef,
    Result,
    connection_of,
    pending_of,
    preview_of,
    result_of,
)


@dataclass(frozen=True)
class Identity:
    """An account's DSM identity."""

    id: str  # as people read it (Base32 Crockford)
    raw: bytes


ConnectionRef = Union[str, bytes, Connection]
"""A connection, by its id (Base32 Crockford), its raw id, or the connection itself."""


def _raw_of(ref: ConnectionRef, what: str) -> bytes:
    if isinstance(ref, Connection):
        return ref.raw_id
    if isinstance(ref, bytes):
        return ref
    return decode_id(ref, what)


class Account:
    """What every account can do: name itself, say what it owns, be funded on a development set."""

    def __init__(self, ingress: Ingress) -> None:
        self.ingress = ingress
        self._objects: Optional[List[ObjectInfo]] = None

    def identity(self) -> Identity:
        device_id = self.ingress.activity(0).device_id
        if len(device_id) != 32:
            raise RuntimeError("the host named no account: is it still starting?")
        return Identity(id=encode_b32(device_id), raw=device_id)

    def id(self) -> str:
        """This account's identity, as people read it."""
        return self.identity().id

    def owned(self) -> List[Owned]:
        """Everything this account owns."""
        route = "balance.list"
        envelope = self.ingress.call("query", route, None, quiet=True)
        owned = [owned_of(b) for b in payload(route, envelope, "balances_list_response").balances]
        self._objects = [o.object for o in owned]
        return owned

    def owns(self, object: ObjectRef) -> Optional[Owned]:
        """What this account owns of one object, or None when it owns none."""
        raw = self.object_id(object)
        return next((o for o in self.owned() if o.object.raw == raw), None)

    def object(self, ref: ObjectRef) -> ObjectInfo:
        """An object this account knows, by symbol or id."""
        if isinstance(ref, ObjectInfo):
            return ref
        direct = direct_id(ref)

        def known() -> Optional[ObjectInfo]:
            objects = self._objects if self._objects is not None else [o.object for o in self.owned()]
            for o in objects:
                if (direct is not None and o.raw == direct) or (direct is None and o.symbol == ref):
                    return o
            return None

        found = known()
        if found is None:
            self._objects = None
            found = known()
        if found is None:
            raise LookupError(f"this account knows no object {describe(ref)}: it holds none, and issued none by that name")
        return found

    def object_id(self, ref: ObjectRef) -> bytes:
        """The raw id of an object: given directly, or looked up by symbol among what this account knows."""
        direct = direct_id(ref)
        return direct if direct is not None else self.object(ref).raw

    def units(self, object: ObjectRef, amount: Amount) -> int:
        """`amount` of `object` in the object's smallest unit. Rust parses what people write."""
        if isinstance(amount, int):
            return amount
        route = "wallet.amount"
        request = pb.WalletAmountRequest(token_id=self.object(object).symbol, entered=amount)
        return payload(route, self.ingress.call("query", route, request, quiet=True), "wallet_amount_response").base_units

    def display(self, object: ObjectRef, amount: Amount) -> str:
        """`amount` of `object` in the object's own units, as Rust renders it."""
        if isinstance(amount, str):
            return amount
        route = "wallet.amount"
        request = pb.WalletAmountRequest(token_id=self.object(object).symbol, base_units=amount)
        return payload(route, self.ingress.call("query", route, request, quiet=True), "wallet_amount_response").display_amount

    def fund(self) -> tuple[bool, str]:
        """Ask the development set's faucet for ERA, once: (funded, what it said)."""
        route = "faucet.claim"
        request = pb.FaucetClaimRequest(device_id=self.identity().raw)
        claim = payload(route, self.ingress.call("invoke", route, request), "faucet_claim_response")
        return claim.success, claim.message

    def _cap(self, c: Cap) -> pb.ConnectCapV1:
        return pb.ConnectCapV1(
            policy_commit=self.object_id(c.object),
            per_request=self.units(c.object, c.per_request),
            total=self.units(c.object, c.total),
        )

    def _ids(self, objects: Sequence[ObjectRef]) -> List[bytes]:
        return [self.object_id(o) for o in objects]

    def scope(self, g: Grant) -> pb.ConnectScopeV1:
        """A grant, on the wire."""
        caps = [self._cap(c) for c in g.caps]
        if g.kind == "send":
            return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_PAY, caps=caps)
        if g.kind == "owns":
            return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_HOLDINGS, policy_commits=self._ids(g.objects))
        if g.kind == "accept":
            return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_ACCEPT_ISSUED)
        if g.kind == "contacts":
            return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_CONTACTS)
        if g.kind == "trade":
            return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_SWAP, policy_commits=self._ids(g.objects), caps=caps)
        if g.kind == "match":
            return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_ESCROW, caps=caps)
        if g.kind == "duel":
            return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_DUEL, programs=list(g.programs), caps=caps)
        raise ValueError(f"no grant of kind {g.kind!r}")

    def intent(self, a: Ask) -> pb.ConnectAppRequestIntentV1:
        """A request, on the wire (its connection unset)."""
        m = pb.ConnectAppRequestIntentV1()
        if a.kind == "send":
            assert a.object is not None and a.amount is not None
            m.pay.CopyFrom(
                pb.ConnectPayV1(policy_commit=self.object_id(a.object), amount=self.units(a.object, a.amount), memo=a.memo)
            )
        elif a.kind == "owns":
            m.holdings.CopyFrom(pb.ConnectHoldingsV1(policy_commits=self._ids(a.objects)))
        elif a.kind == "accept":
            assert a.object is not None
            m.accept_issued.CopyFrom(pb.ConnectAcceptIssuedV1(anchor=self.object_id(a.object)))
        elif a.kind == "contacts":
            m.contacts.CopyFrom(pb.ConnectContactsV1())
        elif a.kind == "sign":
            m.sign.CopyFrom(pb.ConnectSignV1(statement=a.statement))
        elif a.kind == "price":
            assert a.object is not None and a.to is not None and a.amount is not None
            m.quote.CopyFrom(
                pb.ConnectQuoteV1(
                    token_in=self.object_id(a.object),
                    token_out=self.object_id(a.to),
                    amount_in=self.units(a.object, a.amount),
                )
            )
        elif a.kind == "trade":
            assert a.object is not None and a.to is not None and a.amount is not None and a.at_least is not None
            m.swap.CopyFrom(
                pb.ConnectSwapV1(
                    token_in=self.object_id(a.object),
                    token_out=self.object_id(a.to),
                    amount_in=self.units(a.object, a.amount),
                    min_amount_out=self.units(a.to, a.at_least),
                )
            )
        elif a.kind == "stake":
            assert a.object is not None and a.amount is not None and a.opponent is not None
            m.escrow_lock.CopyFrom(
                pb.ConnectEscrowLockV1(
                    external=a.match,
                    policy_commit=self.object_id(a.object),
                    amount=self.units(a.object, a.amount),
                    side=1 if a.side == "A" else 2,
                    opponent_genesis=a.opponent.genesis,
                    opponent_device_id=a.opponent.device_id,
                    opponent_signing_key=a.opponent.signing_key,
                    counterpart_vault_id=a.against,
                    memo=a.memo,
                )
            )
        elif a.kind == "collect":
            m.escrow_release.CopyFrom(pb.ConnectEscrowReleaseV1(vault_ids=list(a.stakes)))
        elif a.kind == "duel_session_key":
            m.duel_session_key.CopyFrom(pb.ConnectDuelSessionKeyV1(match_nonce=a.nonce))
        elif a.kind == "duel_stake":
            assert a.object is not None and a.amount is not None and a.opponent is not None
            m.duel_lock.CopyFrom(
                pb.ConnectDuelLockV1(
                    setup=a.setup,
                    side=1 if a.side == "A" else 2,
                    policy_commit=self.object_id(a.object),
                    amount=self.units(a.object, a.amount),
                    opponent_genesis=a.opponent.genesis,
                    opponent_device_id=a.opponent.device_id,
                    counterpart_vault_id=a.against,
                    memo=a.memo,
                    opponent_holdings=a.opponent_owns,
                )
            )
        elif a.kind == "duel_ready":
            m.duel_ready.CopyFrom(
                pb.ConnectDuelReadyV1(match_cell=a.cell, opponent_ready=a.opponent_ready, opponent_reveal=a.opponent_reveal)
            )
        elif a.kind == "duel_withdraw":
            m.duel_withdraw.CopyFrom(pb.ConnectDuelWithdrawV1(match_cell=a.cell))
        elif a.kind == "duel_sign":
            m.duel_sign.CopyFrom(
                pb.ConnectDuelSignV1(
                    match_cell=a.cell,
                    preceding=[pb.ConnectDuelSignedEntryV1(entry=e.entry, signature=e.signature) for e in a.entries],
                    entry=a.entry,
                )
            )
        elif a.kind == "duel_settle":
            m.duel_settle.CopyFrom(
                pb.ConnectDuelSettleV1(
                    match_cell=a.cell,
                    entries=[pb.ConnectDuelSignedEntryV1(entry=e.entry, signature=e.signature) for e in a.entries],
                )
            )
        elif a.kind == "duel_collect":
            m.duel_collect.CopyFrom(pb.ConnectDuelCollectV1(vault_ids=list(a.stakes)))
        else:
            raise ValueError(f"no request of kind {a.kind!r}")
        return m


@dataclass(frozen=True)
class Offer:
    """A connect code, ready to show."""

    code: str  # the dsm:connect/v1: text: show it as a QR code, or as a link on the same device
    digest: bytes
    raw: pb.ConnectAppOfferV1


@dataclass(frozen=True)
class Vault:
    """A vault of this application's: two objects it trades between, at a fee."""

    id: bytes
    a: tuple[str, str, int, str]  # (object id, symbol, reserve in smallest units, reserve as displayed)
    b: tuple[str, str, int, str]
    fee_bps: int
    generation: int  # trades and closes it has taken
    active: bool
    label: str
    raw: pb.SofiOwnedVaultV1


def _vault_of(v: pb.SofiOwnedVaultV1) -> Vault:
    return Vault(
        id=v.vault_id,
        a=(encode_b32(v.token_a_policy_commit), v.token_a_symbol, v.reserve_a, v.reserve_a_display),
        b=(encode_b32(v.token_b_policy_commit), v.token_b_symbol, v.reserve_b, v.reserve_b_display),
        fee_bps=v.fee_bps,
        generation=v.generation,
        active=v.status == pb.SOFI_VAULT_STATUS_ACTIVE,
        label=v.label,
        raw=v,
    )


Decision = Literal["A", "B", "void"]
_DECISIONS = {"A": b"a-wins", "B": b"b-wins", "void": b"void"}


class AppAccount(Account):
    """Your application's own account."""

    def offer(
        self,
        name: str,
        grants: Sequence[Grant],
        adopt: Sequence[ObjectRef] = (),
        free_requests: int = 64,
    ) -> Offer:
        """A connect code for a wallet to scan. The host names its own relay and certificate in it."""
        route = "connect.app.offer"
        request = pb.ConnectAppOfferRequestV1(
            display_name=name,
            scopes=[self.scope(g) for g in grants],
            token_anchors=self._ids(adopt),
            free_requests=free_requests,
        )
        offer = connect_reply(route, self.ingress.call("invoke", route, request), "offer")
        return Offer(code=offer.code, digest=offer.offer_digest, raw=offer)

    def connections(self) -> List[Connection]:
        """Every wallet connected to this application, and every one that disconnected."""
        route = "connect.app.sessions"
        envelope = self.ingress.call("query", route, None, quiet=True)
        return [connection_of(s) for s in connect_reply(route, envelope, "sessions").sessions]

    def connection(self, ref: ConnectionRef) -> Connection:
        wanted = encode_b32(_raw_of(ref, "the connection id"))
        for c in self.connections():
            if c.id == wanted:
                return c
        raise LookupError(f"no connection {wanted}")

    def request(self, connection: ConnectionRef, what: Ask) -> RequestRef:
        """Ask a connected wallet for something; the wallet answers on its own time. Read it with `result` or `wait`."""
        route = "connect.app.request"
        request = self.intent(what)
        request.session_id = _raw_of(connection, "the connection id")
        ref = connect_reply(route, self.ingress.call("invoke", route, request), "request")
        return RequestRef(connection=encode_b32(ref.session_id), seq=ref.seq)

    def result(self, ref: RequestRef) -> Result:
        """The wallet's answer (a notification) and the fact this account established (the evidence)."""
        route = "connect.app.status"
        request = pb.ConnectRequestRefV1(session_id=_raw_of(ref.connection, "the connection id"), seq=ref.seq)
        return result_of(ref, connect_reply(route, self.ingress.call("invoke", route, request, quiet=True), "status"))

    def wait(self, ref: RequestRef, until: Literal["fact", "answered"] = "fact", timeout: float = 240.0) -> Result:
        """Wait for a request to settle: a fact, a declined or failed answer, or (until="answered") any answer."""
        deadline = time.monotonic() + timeout
        while True:
            r = self.result(ref)
            if until == "answered":
                done = r.answered or r.outcome == "awaiting_approval"
            else:
                done = r.fact != "none" or r.outcome in ("declined", "failed") or (r.answered and r.price is not None)
            if done:
                return r
            if time.monotonic() > deadline:
                raise TimeoutError(f"request {ref.seq} did not settle: {r.outcome}, {r.reason or r.detail}")
            time.sleep(0.5)

    def issue(
        self,
        symbol: str,
        name: str,
        supply: str,
        decimals: int = 0,
        transferable: bool = True,
        burnable: bool = False,
        description: str = "",
        icon: str = "",
    ) -> ObjectInfo:
        """Issue a new object. This account holds its whole supply, and can give it out."""
        route = "token.create"
        request = pb.TokenCreateRequest(
            ticker=symbol,
            alias=name,
            decimals=decimals,
            genesis_supply_entered=supply,
            burn_enabled=burnable,
            transferable=transferable,
            threshold=1,
            description=description,
            icon_url=icon,
        )
        created = payload(route, self.ingress.call("invoke", route, request), "token_create_response")
        if not created.success:
            raise RuntimeError(f"issuing {symbol}: {created.message}")
        for o in self.owned():
            if o.object.raw == created.policy_anchor:
                return o.object
        raise RuntimeError(f"issued {symbol}, but this account does not list it yet")

    def give(self, to: Union[str, bytes, Connection], object: ObjectRef, amount: Amount, memo: str = "") -> None:
        """Give a wallet `amount` of `object`, from what this account owns. The wallet must have
        accepted the object first (`ask.accept`), unless it already holds some."""
        route = "wallet.sendSmart"
        if isinstance(to, Connection):
            recipient = to.raw.peer_device_id
        elif isinstance(to, bytes):
            recipient = to
        else:
            recipient = decode_id(to, "the wallet's identity")
        info = self.object(object)
        request = pb.OnlineTransferSmartRequest(
            recipient_device_id=recipient, amount=self.display(info, amount), token_id=info.symbol, memo=memo
        )
        sent = payload(route, self.ingress.call("invoke", route, request), "online_transfer_response")
        if not sent.success:
            raise RuntimeError(f"giving {describe(object)}: {sent.message}")

    def open_vault(
        self, a: ObjectRef, reserve_a: Amount, b: ObjectRef, reserve_b: Amount, fee_bps: int = 30, label: str = ""
    ) -> Vault:
        """Open a vault that trades between `a` and `b`, funded from what this account owns."""
        route = "sofi.createVault"
        oa, ob = self.object(a), self.object(b)
        sides = sorted([(oa, reserve_a), (ob, reserve_b)], key=lambda s: encode_b32(s[0].raw))
        request = pb.SofiCreateVaultRequest(
            token_a_policy_commit=sides[0][0].raw,
            token_b_policy_commit=sides[1][0].raw,
            reserve_a_entered=self.display(sides[0][0], sides[0][1]),
            reserve_b_entered=self.display(sides[1][0], sides[1][1]),
            fee_bps=fee_bps,
            label=label,
        )
        created = payload(route, self.ingress.call("invoke", route, request), "sofi_vault_created_response")
        for v in self.vaults():
            if v.id == created.vault_id:
                return v
        raise RuntimeError("opened a vault, but this account does not list it yet")

    def vaults(self) -> List[Vault]:
        """Every vault this account owns."""
        route = "sofi.vaults"
        envelope = self.ingress.call("invoke", route, None, quiet=True)
        return [_vault_of(v) for v in payload(route, envelope, "sofi_vaults_response").vaults]

    def close_vault(self, vault_id: bytes) -> None:
        """Close a vault: its reserves come back to this account."""
        self.ingress.call("invoke", "sofi.close", pb.SofiCloseRequest(vault_id=vault_id))

    def decide(self, stake: bytes, decision: Decision) -> pb.EscrowVerdictResponse:
        """Decide a match this application referees: who the stake pays. Both stakes share one verdict."""
        route = "escrow.adjudicate"
        request = pb.EscrowOutcomeRequest(vault_id=stake, outcome=_DECISIONS[decision])
        return payload(route, self.ingress.call("invoke", route, request), "escrow_verdict_response")


class WalletAccount(Account):
    """A wallet's side: the terminal dev wallet, or any wallet you script."""

    def preview(self, code: str) -> Preview:
        """What a connect code asks for, before anyone approves it."""
        route = "connect.preview"
        request = pb.ConnectPreviewRequestV1(code=code)
        return preview_of(connect_reply(route, self.ingress.call("query", route, request), "preview"))

    def approve(self, offer: Union[Preview, bytes], granted: Sequence[Grant] = ()) -> Connection:
        """Approve an offer. With no grants given it grants exactly what the offer asked."""
        route = "connect.approve"
        digest = offer if isinstance(offer, bytes) else offer.digest
        request = pb.ConnectApproveRequestV1(offer_digest=digest, granted=[self.scope(g) for g in granted])
        return connection_of(connect_reply(route, self.ingress.call("invoke", route, request), "session"))

    def connections(self) -> List[Connection]:
        route = "connect.list"
        envelope = self.ingress.call("query", route, None, quiet=True)
        return [connection_of(s) for s in connect_reply(route, envelope, "sessions").sessions]

    def sync(self) -> List[Connection]:
        """Fetch and carry out what connected applications asked, now."""
        route = "connect.sync"
        return [connection_of(s) for s in connect_reply(route, self.ingress.call("invoke", route, None), "sessions").sessions]

    def pending(self) -> List[Pending]:
        route = "connect.pending"
        envelope = self.ingress.call("query", route, None, quiet=True)
        return [pending_of(p) for p in connect_reply(route, envelope, "pending").pending]

    def respond(self, connection: ConnectionRef, seq: int, decision: Literal["approve", "decline"]) -> pb.ConnectDecidedV1:
        route = "connect.respond"
        request = pb.ConnectRespondRequestV1(
            session_id=_raw_of(connection, "the connection id"),
            seq=seq,
            decision=pb.CONNECT_DECISION_APPROVE if decision == "approve" else pb.CONNECT_DECISION_DECLINE,
        )
        return connect_reply(route, self.ingress.call("invoke", route, request), "decided")

    def log(self, connection: ConnectionRef) -> pb.ConnectLogV1:
        route = "connect.log"
        request = pb.ConnectSessionRefV1(session_id=_raw_of(connection, "the connection id"))
        return connect_reply(route, self.ingress.call("query", route, request, quiet=True), "log")

    def disconnect(self, connection: ConnectionRef) -> Connection:
        route = "connect.disconnect"
        request = pb.ConnectSessionRefV1(session_id=_raw_of(connection, "the connection id"))
        return connection_of(connect_reply(route, self.ingress.call("invoke", route, request), "session"))


def _dev_dir() -> str:
    named = os.environ.get("DSM_DEV_DIR")
    if named:
        return os.path.abspath(named)
    here = os.getcwd()
    while True:
        candidate = os.path.join(here, ".dsm-dev")
        if os.path.isdir(candidate):
            return candidate
        parent = os.path.dirname(here)
        if parent == here:
            raise FileNotFoundError(
                "no .dsm-dev directory above here: run `make app-dev` in the DSM repo, or set DSM_DEV_DIR"
            )
        here = parent


def _local_ingress(name: str) -> Ingress:
    url: Optional[str] = os.environ.get("DSM_INGRESS_URL")
    secret_file: Optional[str] = os.environ.get("DSM_INGRESS_SECRET_FILE")
    if name == "app" and url and secret_file:
        return Ingress.from_secret_file(url, secret_file)
    base = os.path.join(_dev_dir(), name)
    with open(os.path.join(base, "ingress-url"), encoding="utf-8") as fh:
        recorded = fh.read().strip()
    return Ingress.from_secret_file(recorded, os.path.join(base, "ingress", "ingress-token"))


def local_app() -> AppAccount:
    """The account `make app-dev` runs (or DSM_INGRESS_URL + DSM_INGRESS_SECRET_FILE)."""
    return AppAccount(_local_ingress("app"))


def local_wallet(name: str = "wallet") -> WalletAccount:
    """A terminal dev wallet `make dev-wallet` runs: "wallet" or "wallet2"."""
    return WalletAccount(_local_ingress(name))
