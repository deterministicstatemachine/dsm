#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""My Game, plugged into DSM, in one file: a connect code, a wallet that
connects to it, a payment, gems handed over, and a sign-in. It talks to the
account `make app-dev` runs.

    python3 guide/examples/my_game.py
"""

import sys
import time

from dsm_app_client import ask, grant, local_app


def main() -> int:
    app = local_app()

    # The wallets connected before this run, so the one that connects now stands out.
    before = {c.id for c in app.connections()}

    # 1. The offer: what My Game may do without asking the player again.
    offer = app.offer("My Game", [grant.send("ERA", "0.10", "1.00"), grant.owns(["ERA"]), grant.accept()])
    print(f"connect code: {offer.code}", flush=True)
    print("waiting for a wallet to connect to it...", flush=True)

    # 2. A wallet connects: scanned on a phone, or `make dev-wallet-connect CODE=...`.
    while True:
        new = [c for c in app.connections() if c.connected and c.id not in before]
        if new:
            player = new[0]
            break
        time.sleep(1)
    print(f"wallet {player.peer} connected", flush=True)

    # 3. 0.05 ERA, inside the grant, so the player is not asked again.
    paid = app.wait(app.request(player, ask.send("ERA", "0.05", "100 gems")))
    print(f"payment: outcome {paid.outcome}, fact {paid.fact}", flush=True)
    if paid.fact != "received":
        return 1

    # 4. Your own coin. Issuing it again with the same terms answers with the
    #    same coin, so this runs again and again. The wallet accepts it, then
    #    your account gives.
    gems = app.issue("GEMS", "Gems", "1000000")
    app.wait(app.request(player, ask.accept(gems)), until="answered")
    app.give(player, gems, "100")
    print(f"gave 100 {gems.symbol}", flush=True)

    # 5. A sign-in. It always waits for the player to approve it on the device.
    print("sign-in asked: approve it on the device", flush=True)
    login = app.wait(app.request(player, ask.login("My Game")))
    print(f"sign-in: outcome {login.outcome}, fact {login.fact}", flush=True)
    if login.fact == "signed" and login.signed is not None:
        print(f"signed: {login.signed[0]}", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
