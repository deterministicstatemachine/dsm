#!/usr/bin/env python3
"""Rig helpers over ui_driver (scripts/ui_driver.py): faucet claim, read contact URI, add contact, go home.
usage:
  rig_contacts_faucet.py faucet <name> <serial> <port> [n]
  rig_contacts_faucet.py uri    <name> <serial> <port>            -> prints dsm:contact/v3:... on last line
  rig_contacts_faucet.py add    <name> <serial> <port> <uri>
  rig_contacts_faucet.py home   <name> <serial> <port>
"""
import os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ui_driver import Device, DriverError

cmd, name, serial, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
d = Device(transport='', name=name, port=port, serial=serial)
d._resolve_transport()
for _try in range(3):
    try: d.attach(timeout=40); break
    except DriverError as e:
        if _try==2: raise
        time.sleep(3)
def log(m): print(f"[{name} {time.strftime('%H:%M:%S')}] {m}", flush=True)
def dismiss_lock():
    if d.sees('PROTECT YOUR WALLET'): d.tap('LATER', exact=True); time.sleep(1)
def go_home():
    # The wallet ignores Android BACK; its on-screen B button is 'back'.
    for _ in range(6):
        if d.sees('GENESIS: INITIALIZED') and d.sees('CONTACTS'): return
        d.tap('B', exact=True, timeout=10); time.sleep(1.5)
    dismiss_lock()
    if not (d.sees('GENESIS: INITIALIZED') and d.sees('CONTACTS')):
        raise DriverError(f"[{name}] not at home: {d.screen_text()[:200]!r}")

dismiss_lock()
if cmd == 'home':
    go_home(); log(d.screen_text().replace('\n',' | ')[:200])

elif cmd == 'faucet':
    n = int(sys.argv[5]) if len(sys.argv) > 5 else 1
    go_home(); d.tap('TOKENS', exact=True); time.sleep(3)
    d.tap('Faucet', exact=True); time.sleep(2)
    for i in range(n):
        d.tap('CLAIM FAUCET'); time.sleep(4)
        dl = time.time() + 30
        while time.time() < dl and 'CLAIMING' in d.screen_text().upper(): time.sleep(1)
        s = d.screen_text(); m = [l for l in s.split('\n') if 'Claimed' in l or 'ERA' in l and 'claim' in l.lower()]
        log(f"claim {i+1}: {m[:2] if m else s.replace(chr(10),' | ')[:160]}")
    go_home()

elif cmd == 'uri':
    go_home(); d.tap('CONTACTS', exact=True); time.sleep(3)
    d.tap('MY QR', exact=True); time.sleep(4)
    uri = d.eval_js("(document.querySelector('textarea[readonly]')||{}).value || ''")
    if not uri.startswith('dsm:contact/v3:'): raise DriverError(f"[{name}] no URI: {d.screen_text()[:200]!r}")
    log(f"uri len={len(uri)}"); go_home(); print(uri)

elif cmd == 'add':
    uri = sys.argv[5]
    go_home(); d.tap('CONTACTS', exact=True); time.sleep(3)
    d.tap('ADD CONTACT', exact=True); time.sleep(3)
    # React textarea: focus by tap, then set value via native setter + input event (fast, exact — 'input text' mangles ':' '/' chars)
    ok = d.eval_js(f"""(() => {{
      const el=[...document.querySelectorAll('input,textarea')].find(e=>(e.placeholder||'').startsWith('dsm:contact/v3'));
      if(!el) return 'NOFIELD';
      el.focus();
      const proto = el.tagName==='TEXTAREA'? window.HTMLTextAreaElement.prototype : window.HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto,'value').set.call(el, {uri!r});
      el.dispatchEvent(new Event('input',{{bubbles:true}}));
      return 'OK:'+el.value.length; }})()""")
    log(f"paste: {ok}")
    if not str(ok).startswith('OK'): raise DriverError(f"[{name}] paste failed: {ok}")
    d.dismiss_keyboard(); time.sleep(0.5)
    d.tap('USE CONTACT CODE'); time.sleep(6)
    dl = time.time() + 40
    while time.time() < dl and not d.sees('CONTACT FOUND'):
        if 'Error' in d.screen_text() or '✗' in d.screen_text(): break
        time.sleep(1.5)
    s = d.screen_text()
    if 'CONTACT FOUND' not in s.upper(): raise DriverError(f"[{name}] no CONTACT FOUND: {s.replace(chr(10),' | ')[:300]!r}")
    d.tap('ADD', exact=True); time.sleep(6)
    dl = time.time() + 40
    while time.time() < dl:
        s = d.screen_text()
        if 'added' in s.lower() or 'Error' in s or '✗' in s: break
        time.sleep(1.5)
    line = [l for l in s.split('\n') if 'added' in l.lower() or 'Error' in l or '✗' in l]
    log(f"result: {line[:2] if line else s.replace(chr(10),' | ')[:240]}")
    go_home()
d.detach()
