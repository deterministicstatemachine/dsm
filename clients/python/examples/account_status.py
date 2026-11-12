#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Your application's account at a glance: its identity, what it owns, every
connected wallet, and the latest activity. Runs against `dsm-app up` (from the repo, `make app-dev`)."""

from dsm_app_client import local_app


def main() -> None:
    app = local_app()
    print(f"account {app.id()}")
    for o in app.owned():
        print(f"  {o.object.symbol:<8} {o.display:>16}   {o.object.kind}")
    connections = app.connections()
    print(f"{len(connections)} connection(s) with wallets")
    for c in connections:
        state = "connected" if c.connected else "disconnected"
        print(f"  connection {c.id}  wallet {c.peer}  {state}")
        for line in c.grants:
            print(f"    may: {line}")
    for e in app.ingress.activity(0).entries[-5:]:
        print(f"  {e.seq}  {e.name}  {e.summary}")


if __name__ == "__main__":
    main()
