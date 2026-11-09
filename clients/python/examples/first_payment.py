#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Your first payment, in Python: a connect code, a wallet that connects to
it, 0.05 ERA asked for, and the fact your own account established. Runs
against `make app-dev`; connect a wallet with
`make dev-wallet-connect CODE=<the code printed>`, or scan it with a phone."""

import sys
import time

from dsm_app_client import ask, grant, local_app


def main() -> int:
    app = local_app()
    before = {c.id for c in app.connections()}
    offer = app.offer("My Game", [grant.send("ERA", "0.10", "1.00"), grant.owns(["ERA"]), grant.accept()])
    print(f"connect code: {offer.code}", flush=True)
    print("waiting for a wallet to connect to it...", flush=True)

    deadline = time.monotonic() + 240
    player = None
    while player is None:
        if time.monotonic() > deadline:
            print("no wallet connected within four minutes", file=sys.stderr)
            return 1
        new = [c for c in app.connections() if c.connected and c.id not in before]
        if new:
            player = new[0]
        else:
            time.sleep(1)
    print(f"wallet {player.peer} connected; asking it for 0.05 ERA", flush=True)

    paid = app.wait(app.request(player, ask.send("ERA", "0.05", "a sword")))
    print(f"outcome {paid.outcome}, fact {paid.fact}", flush=True)
    if paid.fact != "received":
        print(f"not received: {paid.reason} {paid.detail}".rstrip(), file=sys.stderr)
        return 1
    print("received: your account accepted the transfer; it is final", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
