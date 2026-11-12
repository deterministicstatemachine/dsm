# SPDX-License-Identifier: MIT OR Apache-2.0
"""What an application asks a wallet to grant (`grant`), and what it asks a
connected wallet to do (`ask`). Each builder returns a plain description; the
account turns it into the wire's message when it sends it, resolving object
symbols and amounts through Rust."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

from .generated import dsm_app_pb2 as pb
from .objects import Amount, ObjectRef


@dataclass(frozen=True)
class Cap:
    """A limit on what a grant lets the application take of one object."""

    object: ObjectRef
    per_request: Amount  # the most any one request may take
    total: Amount  # the most all requests may take together


@dataclass(frozen=True)
class Grant:
    kind: str
    caps: Tuple[Cap, ...] = ()
    objects: Tuple[ObjectRef, ...] = ()
    programs: Tuple[bytes, ...] = ()


class grant:
    """What an offer asks a wallet to let the application do without asking again."""

    @staticmethod
    def send(object: ObjectRef, per_request: Amount, total: Amount) -> Grant:
        """Send this application `object`, up to `per_request` each time and `total` in all."""
        return Grant("send", caps=(Cap(object, per_request, total),))

    @staticmethod
    def owns(objects: Sequence[ObjectRef]) -> Grant:
        """Prove what it owns of these objects. Objects this application issued are always included."""
        return Grant("owns", objects=tuple(objects))

    @staticmethod
    def accept() -> Grant:
        """Accept objects this application issues."""
        return Grant("accept")

    @staticmethod
    def contacts() -> Grant:
        """Tell this application who its contacts are (their DSM identities), and nothing more."""
        return Grant("contacts")

    @staticmethod
    def trade(a: ObjectRef, b: ObjectRef, caps: Sequence[Cap]) -> Grant:
        """Trade between these two objects through this application's vaults, within `caps`."""
        return Grant("trade", objects=(a, b), caps=tuple(caps))

    @staticmethod
    def match(caps: Sequence[Cap]) -> Grant:
        """Stake in matches this application referees, within `caps`."""
        return Grant("match", caps=tuple(caps))

    @staticmethod
    def contribute(caps: Sequence[Cap]) -> Grant:
        """Commit amounts to what this application names, the wallet's to take back, within `caps`."""
        return Grant("contribute", caps=tuple(caps))

    @staticmethod
    def duel(programs: Sequence[bytes], caps: Sequence[Cap]) -> Grant:
        """Stake in matches these programs decide (each by the hash it is pinned by), within `caps`."""
        return Grant("duel", programs=tuple(programs), caps=tuple(caps))


@dataclass(frozen=True)
class Opponent:
    """The other player, as this application's connection to it names it."""

    genesis: bytes
    device_id: bytes
    signing_key: bytes


@dataclass(frozen=True)
class SignedEntry:
    """One signed entry of a duel's transcript."""

    entry: bytes
    signature: bytes


@dataclass(frozen=True)
class Ask:
    kind: str
    object: Optional[ObjectRef] = None
    amount: Optional[Amount] = None
    memo: str = ""
    objects: Tuple[ObjectRef, ...] = ()
    statement: str = ""
    to: Optional[ObjectRef] = None
    at_least: Optional[Amount] = None
    match: bytes = b""
    side: str = ""
    opponent: Optional[Opponent] = None
    against: bytes = b""
    stakes: Tuple[bytes, ...] = ()
    nonce: bytes = b""
    setup: bytes = b""
    opponent_owns: Optional[pb.HoldingsProofV1] = None
    cell: bytes = b""
    opponent_ready: bytes = b""
    opponent_reveal: bytes = b""
    entries: Tuple[SignedEntry, ...] = ()
    entry: bytes = b""


def login_statement(app: str, nonce: str) -> str:
    """The words a sign-in asks the player to approve. Compare the signed statement with this."""
    return f"Sign in to {app} ({nonce})"


class _Match:
    """Matches this application referees."""

    @staticmethod
    def stake(
        match: bytes | str,
        object: ObjectRef,
        amount: Amount,
        side: str,
        opponent: Opponent,
        against: bytes = b"",
        memo: str = "",
    ) -> Ask:
        """Stake `amount` of `object` on the match `match` describes (its agreed bytes, 1 to 256),
        on side "A" or "B", against `opponent`. Side B passes side A's stake id as `against`."""
        return Ask(
            "stake",
            match=match.encode() if isinstance(match, str) else match,
            object=object,
            amount=amount,
            side=side,
            opponent=opponent,
            against=against,
            memo=memo,
        )

    @staticmethod
    def collect(stakes: Sequence[bytes]) -> Ask:
        """Collect the stakes a decided match pays this wallet (one or two stake ids)."""
        return Ask("collect", stakes=tuple(stakes))


class _Duel:
    """Matches a pinned program decides from both players' signed moves (SoFi Amendment S22)."""

    @staticmethod
    def session_key(nonce: bytes) -> Ask:
        return Ask("duel_session_key", nonce=nonce)

    @staticmethod
    def stake(
        setup: bytes,
        side: str,
        object: ObjectRef,
        amount: Amount,
        opponent: Opponent,
        opponent_owns: pb.HoldingsProofV1,
        against: bytes = b"",
        memo: str = "",
    ) -> Ask:
        return Ask(
            "duel_stake",
            setup=setup,
            side=side,
            object=object,
            amount=amount,
            opponent=opponent,
            opponent_owns=opponent_owns,
            against=against,
            memo=memo,
        )

    @staticmethod
    def ready(cell: bytes, opponent_ready: bytes = b"", opponent_reveal: bytes = b"") -> Ask:
        return Ask("duel_ready", cell=cell, opponent_ready=opponent_ready, opponent_reveal=opponent_reveal)

    @staticmethod
    def withdraw(cell: bytes) -> Ask:
        return Ask("duel_withdraw", cell=cell)

    @staticmethod
    def sign(cell: bytes, preceding: Sequence[SignedEntry], entry: bytes) -> Ask:
        return Ask("duel_sign", cell=cell, entries=tuple(preceding), entry=entry)

    @staticmethod
    def settle(cell: bytes, entries: Sequence[SignedEntry]) -> Ask:
        return Ask("duel_settle", cell=cell, entries=tuple(entries))

    @staticmethod
    def collect(stakes: Sequence[bytes]) -> Ask:
        return Ask("duel_collect", stakes=tuple(stakes))


class _Contribution:
    """Contributions (DSM Amendment A35): an amount the wallet commits to what this application
    names. Both outcomes return it to the wallet; the application decides when, never to whom."""

    @staticmethod
    def commit(to: bytes | str, object: ObjectRef, amount: Amount, memo: str = "") -> Ask:
        """Commit `amount` of `object` to what `to` describes (its agreed bytes, 1 to 256)."""
        return Ask(
            "contribute",
            match=to.encode() if isinstance(to, str) else to,
            object=object,
            amount=amount,
            memo=memo,
        )

    @staticmethod
    def take_back(contributions: Sequence[bytes]) -> Ask:
        """Take contributions back into this wallet (one to eight contribution ids)."""
        return Ask("take_back", stakes=tuple(contributions))


class ask:
    """What an application asks a connected wallet to do."""

    match = _Match
    contribution = _Contribution
    duel = _Duel

    @staticmethod
    def send(object: ObjectRef, amount: Amount, memo: str = "") -> Ask:
        """Send this application `amount` of `object`."""
        return Ask("send", object=object, amount=amount, memo=memo)

    @staticmethod
    def owns(objects: Sequence[ObjectRef]) -> Ask:
        """Prove what the wallet owns of these objects."""
        return Ask("owns", objects=tuple(objects))

    @staticmethod
    def accept(object: ObjectRef) -> Ask:
        """Accept an object this application issued, so the wallet can hold it."""
        return Ask("accept", object=object)

    @staticmethod
    def contacts() -> Ask:
        """The DSM identities of the wallet's contacts."""
        return Ask("contacts")

    @staticmethod
    def sign(statement: str) -> Ask:
        """Sign a statement. Never in a grant: the player reads it and approves it on the device."""
        return Ask("sign", statement=statement)

    @staticmethod
    def login(app: str, nonce: Optional[str] = None) -> Ask:
        """Sign in: the player approves `login_statement(app, nonce)` on the device, and the
        wallet's identity signs it. Keep the nonce; accept the sign-in only when the result's
        fact is "signed" and its statement is the one you asked for."""
        return Ask("sign", statement=login_statement(app, nonce or str(uuid.uuid4())))

    @staticmethod
    def price(from_: ObjectRef, to: ObjectRef, amount: Amount) -> Ask:
        """What `amount` of `from_` would get in `to`, through this application's vaults. Information, never a fact."""
        return Ask("price", object=from_, to=to, amount=amount)

    @staticmethod
    def trade(from_: ObjectRef, to: ObjectRef, amount: Amount, at_least: Amount) -> Ask:
        """Trade `amount` of `from_` for at least `at_least` of `to`, through this application's vaults."""
        return Ask("trade", object=from_, to=to, amount=amount, at_least=at_least)
