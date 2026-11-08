# SPDX-License-Identifier: MIT OR Apache-2.0
"""An account a dsm-app-host runs, reached through its ingress.

Your application's account is an AppAccount; a wallet you script (the
terminal dev wallet) is a WalletAccount. Both are the same SDK on the same
production path a phone runs; these classes name its routes and nothing more.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Literal, Optional, Sequence

from .b32 import decode_id, encode_b32
from .generated import dsm_app_pb2 as pb
from .ingress import Ingress, connect_reply, payload


class Account:
    def __init__(self, ingress: Ingress) -> None:
        self.ingress = ingress

    def device_id(self) -> bytes:
        """This account's device id (32 bytes)."""
        device_id = self.ingress.activity(0).device_id
        if len(device_id) != 32:
            raise RuntimeError("the host named no account: is it still starting?")
        return device_id

    def id(self) -> str:
        """This account's device id as people read it (Base32 Crockford)."""
        return encode_b32(self.device_id())

    def balances(self) -> List[pb.BalanceGetResponse]:
        route = "balance.list"
        envelope = self.ingress.call("query", route, None, quiet=True)
        return list(payload(route, envelope, "balances_list_response").balances)

    def policy_commit_of(self, ticker: str) -> bytes:
        """The policy commit (32 bytes) of a token this account holds, by its ticker."""
        for b in self.balances():
            if ticker in (b.token_id, b.symbol):
                return decode_id(b.policy_anchor_b32, f"{ticker}'s policy anchor")
        raise LookupError(f"this account holds no {ticker}")

    def claim_faucet(self) -> pb.FaucetClaimResponse:
        route = "faucet.claim"
        request = pb.FaucetClaimRequest(device_id=self.device_id())
        return payload(route, self.ingress.call("invoke", route, request), "faucet_claim_response")


class scope:
    """Scopes an application asks a wallet to grant."""

    @staticmethod
    def pay(token: bytes, per_request: int, total: int) -> pb.ConnectScopeV1:
        """Pay this application's account in `token`, at most `per_request` each time and `total` in all (base units)."""
        return pb.ConnectScopeV1(
            kind=pb.CONNECT_SCOPE_KIND_PAY,
            caps=[pb.ConnectCapV1(policy_commit=token, per_request=per_request, total=total)],
        )

    @staticmethod
    def holdings(tokens: Sequence[bytes]) -> pb.ConnectScopeV1:
        """Prove holdings of these tokens (objects this application issued are always included)."""
        return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_HOLDINGS, policy_commits=list(tokens))

    @staticmethod
    def accept_issued() -> pb.ConnectScopeV1:
        """Take objects this application's account issued."""
        return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_ACCEPT_ISSUED)

    @staticmethod
    def contacts() -> pb.ConnectScopeV1:
        """Read the DSM identities of the wallet's contacts, and nothing more."""
        return pb.ConnectScopeV1(kind=pb.CONNECT_SCOPE_KIND_CONTACTS)


class intent:
    """Requests an application makes of a connected wallet."""

    @staticmethod
    def pay(token: bytes, amount: int, memo: str) -> pb.ConnectAppRequestIntentV1:
        return pb.ConnectAppRequestIntentV1(pay=pb.ConnectPayV1(policy_commit=token, amount=amount, memo=memo))

    @staticmethod
    def holdings(tokens: Sequence[bytes]) -> pb.ConnectAppRequestIntentV1:
        return pb.ConnectAppRequestIntentV1(holdings=pb.ConnectHoldingsV1(policy_commits=list(tokens)))

    @staticmethod
    def accept_issued(anchor: bytes) -> pb.ConnectAppRequestIntentV1:
        return pb.ConnectAppRequestIntentV1(accept_issued=pb.ConnectAcceptIssuedV1(anchor=anchor))


@dataclass(frozen=True)
class RequestRef:
    session_id: bytes
    seq: int


class AppAccount(Account):
    """Your application's own account."""

    def offer(
        self,
        display_name: str,
        scopes: Sequence[pb.ConnectScopeV1],
        free_requests: int,
        token_anchors: Sequence[bytes] = (),
    ) -> pb.ConnectAppOfferV1:
        """The `dsm:connect/v1:` code a wallet scans. The host names its own relay endpoint and pin in it."""
        route = "connect.app.offer"
        request = pb.ConnectAppOfferRequestV1(
            display_name=display_name,
            scopes=list(scopes),
            token_anchors=list(token_anchors),
            free_requests=free_requests,
        )
        return connect_reply(route, self.ingress.call("invoke", route, request), "offer")

    def sessions(self) -> List[pb.ConnectSessionV1]:
        route = "connect.app.sessions"
        return list(connect_reply(route, self.ingress.call("query", route, None, quiet=True), "sessions").sessions)

    def request(self, session_id: bytes, kind: pb.ConnectAppRequestIntentV1) -> RequestRef:
        """Ask a connected wallet for something; read the answer with `status`."""
        route = "connect.app.request"
        request = pb.ConnectAppRequestIntentV1()
        request.CopyFrom(kind)
        request.session_id = session_id
        ref = connect_reply(route, self.ingress.call("invoke", route, request), "request")
        return RequestRef(session_id=ref.session_id, seq=ref.seq)

    def status(self, ref: RequestRef) -> pb.ConnectAppStatusV1:
        """The wallet's answer (a notification) and the fact this account established (the evidence)."""
        route = "connect.app.status"
        request = pb.ConnectRequestRefV1(session_id=ref.session_id, seq=ref.seq)
        return connect_reply(route, self.ingress.call("invoke", route, request, quiet=True), "status")


class WalletAccount(Account):
    """A wallet's side of Connect: the terminal dev wallet, or any wallet you script."""

    def preview(self, code: str) -> pb.ConnectPreviewV1:
        route = "connect.preview"
        request = pb.ConnectPreviewRequestV1(code=code)
        return connect_reply(route, self.ingress.call("query", route, request), "preview")

    def approve(self, offer_digest: bytes, granted: Sequence[pb.ConnectScopeV1] = ()) -> pb.ConnectSessionV1:
        """Approve an offer. With no scopes given it grants exactly what the offer asked."""
        route = "connect.approve"
        request = pb.ConnectApproveRequestV1(offer_digest=offer_digest, granted=list(granted))
        return connect_reply(route, self.ingress.call("invoke", route, request), "session")

    def pending(self) -> List[pb.ConnectPendingV1]:
        route = "connect.pending"
        return list(connect_reply(route, self.ingress.call("query", route, None, quiet=True), "pending").pending)

    def respond(self, session_id: bytes, seq: int, decision: Literal["approve", "decline"]) -> pb.ConnectDecidedV1:
        route = "connect.respond"
        request = pb.ConnectRespondRequestV1(
            session_id=session_id,
            seq=seq,
            decision=pb.CONNECT_DECISION_APPROVE if decision == "approve" else pb.CONNECT_DECISION_DECLINE,
        )
        return connect_reply(route, self.ingress.call("invoke", route, request), "decided")

    def disconnect(self, session_id: bytes) -> pb.ConnectSessionV1:
        route = "connect.disconnect"
        request = pb.ConnectSessionRefV1(session_id=session_id)
        return connect_reply(route, self.ingress.call("invoke", route, request), "session")


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


def local_wallet() -> WalletAccount:
    """The terminal dev wallet `make dev-wallet` runs."""
    return WalletAccount(_local_ingress("wallet"))
