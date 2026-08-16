#!/usr/bin/env python3
"""Onboard one fresh phone: launch -> INITIALIZE -> genesis -> relaunch -> wallet_ready -> dismiss lock prompt.
usage: rig_onboard.py <name> <serial> <cdp_port>
"""
import os, sys, time, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ui_driver import Device, DriverError

name, serial, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = Device(transport='', name=name, port=port, serial=serial)
d._resolve_transport()
PKG = 'com.dsm.wallet'

def log(m): print(f"[{name} {time.strftime('%H:%M:%S')}] {m}", flush=True)
def launch():
    d.shell(f'am force-stop {PKG}'); time.sleep(1.5)
    d.shell(f'am start -n {PKG}/.ui.MainActivity'); time.sleep(4)
    d.attach(timeout=90)
def wait_any(texts, timeout):
    dl = time.time() + timeout
    while time.time() < dl:
        s = d.screen_text().lower()
        for t in texts:
            if t.lower() in s: return t
        time.sleep(1.5)
    raise DriverError(f"[{name}] none of {texts} within {timeout}s; screen={d.screen_text()[:200]!r}")

# ── phase 1: launch, INITIALIZE ────────────────────────────────────────────
launch()
got = wait_any(['WALLET SETUP REQUIRED', 'INITIALIZE', 'GENESIS: INITIALIZED', 'PUBLISHING IDENTITY'], 90)
log(f"first screen: {got}")
if got in ('WALLET SETUP REQUIRED', 'INITIALIZE'):
    d.tap('INITIALIZE', exact=True)
    log("tapped INITIALIZE")
    # genesis v2: securing_device -> publication_pending
    got = wait_any(['PUBLISHING IDENTITY', 'GENESIS: COMMITTED', 'GENESIS: INITIALIZED', 'DO NOT LEAVE'], 120)
    log(f"after INITIALIZE: {got}")
    if got == 'DO NOT LEAVE':
        got = wait_any(['PUBLISHING IDENTITY', 'GENESIS: COMMITTED', 'GENESIS: INITIALIZED'], 180)
        log(f"securing done: {got}")
    time.sleep(3)

# ── phase 2: relaunch to publish (publication runs at process start) ───────
if not d.sees('GENESIS: INITIALIZED'):
    log("relaunching to trigger publication")
    launch()
    got = wait_any(['GENESIS: INITIALIZED', 'NETWORK: CONNECTED', 'PROTECT YOUR WALLET', 'SYSTEM ERROR'], 180)
    log(f"after relaunch: {got}")
    if got == 'SYSTEM ERROR':
        raise DriverError(f"[{name}] SYSTEM ERROR: {d.screen_text()[:300]!r}")

# ── phase 3: dismiss lock prompt ───────────────────────────────────────────
time.sleep(2)
if d.sees('PROTECT YOUR WALLET'):
    d.tap('LATER', exact=True); log("dismissed lock prompt (LATER)"); time.sleep(1.5)
log(f"HOME: {d.screen_text().replace(chr(10),' | ')[:220]}")
d.detach()
