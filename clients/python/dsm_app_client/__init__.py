# SPDX-License-Identifier: MIT OR Apache-2.0
"""Plug your application into DSM: a client for a dsm-app-host's local
ingress, which is your application's own DSM account (DSM Connect, Amendment
A11). Its protobuf types are generated from proto/dsm_app.proto and shipped
in the package (generated/dsm_app_pb2.py), so it installs with no protoc."""

from .account import (
    Account,
    AppAccount,
    Decision,
    Identity,
    Offer,
    Vault,
    WalletAccount,
    local_app,
    local_wallet,
)
from .b32 import decode_b32, decode_id, encode_b32
from .generated import dsm_app_pb2 as pb
from .ingress import Ingress, IngressError
from .objects import Amount, ObjectInfo, ObjectRef, Owned
from .requests import Ask, Cap, Grant, Opponent, SignedEntry, ask, grant, login_statement
from .results import Connection, Pending, Preview, RequestRef, Result

__all__ = [
    "Account",
    "Amount",
    "AppAccount",
    "Ask",
    "Cap",
    "Connection",
    "Decision",
    "Grant",
    "Identity",
    "Ingress",
    "IngressError",
    "ObjectInfo",
    "ObjectRef",
    "Offer",
    "Opponent",
    "Owned",
    "Pending",
    "Preview",
    "RequestRef",
    "Result",
    "SignedEntry",
    "Vault",
    "WalletAccount",
    "ask",
    "decode_b32",
    "decode_id",
    "encode_b32",
    "grant",
    "local_app",
    "local_wallet",
    "login_statement",
    "pb",
]
