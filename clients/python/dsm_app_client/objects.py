# SPDX-License-Identifier: MIT OR Apache-2.0
"""Objects and amounts, as an application names them.

An object is a kind of thing an account can hold: ERA, an item, a ticket, a
currency a game issued. On the wire it is a 32-byte policy commit; here it is
named by its symbol ("ERA", "SWORD") or by that id. An amount is written in the
object's own units ("0.10", "1"); Rust converts it to and from the object's
smallest unit, so no client carries the unit rule.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Union

from .b32 import decode_b32
from .generated import dsm_app_pb2 as pb


@dataclass(frozen=True)
class ObjectInfo:
    """An object as this account knows it."""

    id: str  # Base32 Crockford of the 32-byte policy commit
    raw: bytes
    symbol: str  # ERA, SWORD; not unique on its own
    name: str
    decimals: int
    kind: str  # "unique": exactly one exists (an item); "currency": counted in units
    supply: str  # the whole supply that will ever exist, in its own units; "" when unknown here
    protocol: bool  # an asset the protocol defines (ERA), rather than one an account issued
    icon: str


ObjectRef = Union[str, bytes, ObjectInfo]
"""An object, by its symbol ("ERA"), its id (Base32 Crockford), its raw 32-byte id, or its description."""

Amount = Union[str, int]
"""An amount: a string in the object's own units ("1.50"), or an int in its smallest unit."""


@dataclass(frozen=True)
class Owned:
    """What an account holds of one object."""

    object: ObjectInfo
    amount: int  # in the object's smallest unit
    display: str  # the same, in the object's own units, as Rust renders it
    locked: int  # held in vaults or stakes


def object_of(b: pb.BalanceGetResponse) -> ObjectInfo:
    return ObjectInfo(
        id=b.policy_anchor_b32,
        raw=decode_b32(b.policy_anchor_b32),
        symbol=b.symbol or b.token_id,
        name=b.token_name,
        decimals=b.decimals,
        kind="unique" if b.holding == pb.BALANCE_HOLDING_STATE_OBJECT else "currency",
        supply=b.genesis_supply_display,
        protocol=b.protocol_defined,
        icon=b.icon_url,
    )


def owned_of(b: pb.BalanceGetResponse) -> Owned:
    return Owned(object=object_of(b), amount=b.available, display=b.display_amount, locked=b.locked)


def direct_id(ref: ObjectRef) -> Optional[bytes]:
    """The raw id a reference names directly, or None when it is a symbol to look up."""
    if isinstance(ref, ObjectInfo):
        return ref.raw
    if isinstance(ref, bytes):
        return ref
    if len(ref) == 52:
        try:
            raw = decode_b32(ref)
        except ValueError:
            return None
        if len(raw) == 32:
            return raw
    return None


def describe(ref: ObjectRef) -> str:
    if isinstance(ref, ObjectInfo):
        return ref.symbol
    if isinstance(ref, bytes):
        return ref.hex()
    return ref
