# SPDX-License-Identifier: MIT OR Apache-2.0
"""The local ingress a dsm-app-host serves (crates/dsm-app-host/src/game.rs).

    POST /ingress          an IngressRequest, answered with an IngressResponse;
                           a call that changes the account is recorded
    POST /ingress/quiet    the same, never recorded (what you poll)
    GET  /activity/{after} the record after `after` (AppHostActivityV1)

It listens on a loopback address only. Every request carries the secret the
host wrote for this launch, as `Authorization: Bearer <secret>`. Keep the
secret on your server.

This module carries bytes. Every rule is the SDK's, in Rust.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from typing import Literal, Optional

from google.protobuf.message import Message

from .generated import dsm_app_pb2 as pb

ENVELOPE_V3_FRAME = 0x03

CallKind = Literal["invoke", "query"]


class IngressError(Exception):
    """Why a call through the ingress did not succeed.

    `code` is the SDK's error code (1 invalid input, 2 refused by the route,
    5 not ready), or the HTTP status when the host refused the call.
    """

    def __init__(self, route: str, code: int, detail: str) -> None:
        super().__init__(f"{route}: {detail} (code {code})")
        self.route = route
        self.code = code
        self.detail = detail


class Ingress:
    def __init__(self, url: str, secret: str) -> None:
        self.url = url.rstrip("/")
        self._secret = secret

    @classmethod
    def from_secret_file(cls, url: str, secret_file: str) -> "Ingress":
        with open(secret_file, encoding="utf-8") as fh:
            secret = fh.read()
        if not secret:
            raise ValueError(f"{secret_file} is empty: is the host running?")
        return cls(url, secret)

    def _send(self, path: str, route: str, body: Optional[bytes]) -> bytes:
        headers = {"Authorization": f"Bearer {self._secret}"}
        if body is not None:
            headers["Content-Type"] = "application/x-protobuf"
        request = urllib.request.Request(
            self.url + path,
            data=body,
            headers=headers,
            method="POST" if body is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read()
        except urllib.error.HTTPError as e:
            raise IngressError(route, e.code, e.read().decode("utf-8", "replace")) from e

    def call(
        self,
        kind: CallKind,
        method: str,
        args: Optional[Message] = None,
        quiet: bool = False,
    ) -> pb.Envelope:
        """Call a route with its own request message (or none). Returns the Envelope it answered with."""
        pack = pb.ArgPack(
            codec=pb.CODEC_PROTO,
            body=args.SerializeToString() if args is not None else b"",
        ).SerializeToString()
        request = pb.IngressRequest()
        if kind == "invoke":
            request.router_invoke.method = method
            request.router_invoke.args = pack
        else:
            request.router_query.method = method
            request.router_query.args = pack
        raw = self._send("/ingress/quiet" if quiet else "/ingress", method, request.SerializeToString())
        response = pb.IngressResponse.FromString(raw)
        which = response.WhichOneof("result")
        if which == "error":
            raise IngressError(method, response.error.code, response.error.message)
        if which != "ok_bytes":
            raise IngressError(method, 0, "the ingress answered with neither a result nor an error")
        framed = response.ok_bytes
        if not framed or framed[0] != ENVELOPE_V3_FRAME:
            raise IngressError(method, 0, "the answer is not a framed Envelope v3")
        envelope = pb.Envelope.FromString(framed[1:])
        if envelope.WhichOneof("payload") == "error":
            raise IngressError(method, envelope.error.code, envelope.error.message)
        return envelope

    def activity(self, after: int = 0) -> pb.AppHostActivityV1:
        """The record of what calls and wallets did to this account, after `after`."""
        path = f"/activity/{after}"
        return pb.AppHostActivityV1.FromString(self._send(path, path, None))


def payload(route: str, envelope: pb.Envelope, expected: str) -> Message:
    """The one answer a route gives; any other is an error to see, never a value to guess at."""
    which = envelope.WhichOneof("payload")
    if which != expected:
        raise IngressError(route, 0, f"answered with {which}, not {expected}")
    return getattr(envelope, expected)


def connect_reply(route: str, envelope: pb.Envelope, expected: str) -> Message:
    """The Connect reply a `connect.*` route answers with."""
    reply = payload(route, envelope, "connect_reply")
    which = reply.WhichOneof("reply")
    if which != expected:
        raise IngressError(route, 0, f"answered with {which}, not {expected}")
    return getattr(reply, expected)
