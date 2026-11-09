#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Your application's account at a glance: its id, what it holds, every
connected wallet, and the latest activity. Runs against `make app-dev`."""

from dsm_app_client import encode_b32, local_app, pb


def main() -> None:
    app = local_app()
    print(f"account {app.id()}")
    for b in app.balances():
        print(f"  {b.symbol:<8} {b.display_amount:>16}")
    sessions = app.sessions()
    print(f"{len(sessions)} session(s) with wallets")
    for s in sessions:
        status = pb.ConnectSessionStatus.Name(s.status)
        print(f"  session {encode_b32(s.session_id)}  wallet {encode_b32(s.peer_device_id)}  {status}")
    for e in app.ingress.activity(0).entries[-5:]:
        print(f"  {e.seq}  {e.name}  {e.summary}")


if __name__ == "__main__":
    main()
