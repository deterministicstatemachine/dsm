#!/usr/bin/env python3
"""Two-device composition verdict: both phones answer `dlv.composeVault` and
the run passes only if the answers are byte-identical.

The route runs the DISCOVERED-vault composition on each device —
advertisement -> presentation -> c_n -> exact CCB(V_n) bytes -> P0-P6 ->
receipted fold — so agreement here is agreement on the authenticated
successor state itself, not on any cached mirror.

usage: rig_compose_verdict.py <vault_b32> <token_a_b32> <token_b_b32> <fee_bps> \
           <nameA> <serialA> <portA> <nameB> <serialB> <portB>
prints one line per device (`name generation:reserve_a:reserve_b:c_n`) and a
final PASS/FAIL. Exit 0 iff PASS.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ui_driver import Device

vault, tok_a, tok_b, fee = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
devs = [
    (sys.argv[5], sys.argv[6], int(sys.argv[7])),
    (sys.argv[8], sys.argv[9], int(sys.argv[10])),
]
params = f"{vault}:{tok_a}:{tok_b}:{fee}"

answers = []
for name, serial, port in devs:
    d = Device(transport="", name=name, port=port, serial=serial)
    d._resolve_transport()
    d.attach(timeout=60)
    ans = d.eval_js(f"window.__dsmRigQuery('dlv.composeVault', {params!r})")
    print(f"[{name} {time.strftime('%H:%M:%S')}] {ans}", flush=True)
    answers.append(ans)
    d.detach()

if answers[0] == answers[1] and answers[0]:
    print(f"PASS — both devices compose {answers[0]}")
    sys.exit(0)
print(f"FAIL — {devs[0][0]}={answers[0]!r} vs {devs[1][0]}={answers[1]!r}")
sys.exit(1)
