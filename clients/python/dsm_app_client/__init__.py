# SPDX-License-Identifier: MIT OR Apache-2.0
"""A client for a dsm-app-host's local ingress: your application's own DSM
account (DSM Connect, Amendment A11). Generate the protobuf types first:
`make clients` in the DSM repo (or `protoc -I proto --python_out=...`)."""

from .account import (
    Account,
    AppAccount,
    RequestRef,
    WalletAccount,
    intent,
    local_app,
    local_wallet,
    scope,
)
from .b32 import decode_b32, decode_id, encode_b32
from .generated import dsm_app_pb2 as pb
from .ingress import Ingress, IngressError

__all__ = [
    "Account",
    "AppAccount",
    "Ingress",
    "IngressError",
    "RequestRef",
    "WalletAccount",
    "decode_b32",
    "decode_id",
    "encode_b32",
    "intent",
    "local_app",
    "local_wallet",
    "pb",
    "scope",
]
