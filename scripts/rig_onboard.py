#!/usr/bin/env python3
"""Onboard one fresh phone through today's wizard: beta acknowledgement ->
look chooser -> intro -> INITIALIZE -> the 24 words (read off the page) ->
the three word checks (answered from what was read) -> wallet_ready ->
dismiss the lock and tour prompts.
usage: rig_onboard.py <name> <serial> <cdp_port>
"""
import json, os, re, sys, time
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
def click_js(selector_expr):
    """Activate a control through the full pointer sequence (a tap alone only
    focuses a StateBoy brick; observed 2026-08-17)."""
    return d.eval_js("(() => { const el=" + selector_expr + "; if(!el) return 'NOEL'; "
                     "['pointerdown','mousedown','pointerup','mouseup','click'].forEach(t=>el.dispatchEvent(new MouseEvent(t,{bubbles:true,cancelable:true}))); return 'CLICKED'; })()")

launch()
got = wait_any(['Before you start', 'Choose your look', 'PRESS A', 'IT LIVES', 'WALLET SETUP REQUIRED', 'GENESIS: INITIALIZED', 'PROTECT YOUR WALLET'], 90)
# The agreement mounts once the page has read its preferences, over whatever rendered first.
dl = time.time() + 20
while got != 'Before you start' and time.time() < dl:
    if d.sees('Before you start'): got = 'Before you start'
    time.sleep(1)
log(f"first screen: {got}")

# ── beta acknowledgement: every point ticked, then the agreement ──────────
if got == 'Before you start':
    n = d.eval_js("(() => { let n=0; for (const el of document.querySelectorAll('[role=checkbox],input[type=checkbox]')) { const on = el.getAttribute('aria-checked')==='true' || el.checked; if(!on){ el.click(); n++; } } return n; })()")
    log(f"ticked {n} points")
    time.sleep(1)
    d.tap('I UNDERSTAND AND AGREE'); time.sleep(3)
    got = wait_any(['Choose your look', 'PRESS A', 'IT LIVES', 'WALLET SETUP REQUIRED'], 60)
    log(f"after agreement: {got}")

# ── look chooser: keep the default, OK ─────────────────────────────────────
if got == 'Choose your look':
    d.tap('OK', exact=True); time.sleep(3)
    got = wait_any(['PRESS A', 'IT LIVES', 'WALLET SETUP REQUIRED', 'INTRODUCING'], 60)
    log(f"after look: {got}")

# ── intro dialog: press A until the setup menu ─────────────────────────────
dl = time.time() + 90
while time.time() < dl and not d.sees('WALLET SETUP REQUIRED'):
    d.tap('A', exact=True, timeout=10); time.sleep(2.5)
if not d.sees('WALLET SETUP REQUIRED'):
    if d.sees('GENESIS: INITIALIZED'):
        log("already onboarded")
    else:
        raise DriverError(f"[{name}] no setup menu: {d.screen_text()[:200]!r}")

if d.sees('WALLET SETUP REQUIRED'):
    d.tap('INITIALIZE', exact=True); time.sleep(1)
    r = click_js("[...document.querySelectorAll('.dsm-menu-item')].find(e=>e.textContent.trim()==='INITIALIZE')")
    log(f"INITIALIZE: {r}")
    wait_any(['RECOVERY PHRASE', 'WORDS 1'], 60)

    # ── the 24 words, page by page ─────────────────────────────────────────
    words = {}
    for page in range(4):
        d.wait_for(f"WORDS {page*6+1}", timeout=30)
        got_words = d.eval_js("JSON.stringify([...document.querySelectorAll('li.sb-phrase__word')].map(li=>[li.querySelector('.sb-phrase__n').textContent.trim(), li.querySelector('.sb-phrase__w').textContent.trim()]))")
        for n_, w in json.loads(got_words):
            words[int(n_)] = w
        log(f"page {page+1}: {len(words)} words read")
        if page < 3:
            d.tap('NEXT WORDS'); time.sleep(1.5)
    if len(words) != 24:
        raise DriverError(f"[{name}] read {len(words)} words, not 24")
    d.tap('I WROTE THEM DOWN'); time.sleep(2)

    # ── the three checks ────────────────────────────────────────────────────
    for check in range(3):
        d.wait_for('Pick the word you wrote down', timeout=30)
        hero = d.eval_js("(document.querySelector('.sb-hero__value')||{}).textContent||''")
        m = re.search(r'#(\d+)', hero)
        if not m:
            raise DriverError(f"[{name}] no word index on check {check+1}: {hero!r}")
        position = int(m.group(1))
        answer = words[position]
        log(f"check {check+1}: word #{position} -> {answer}")
        d.tap(answer.upper(), exact=True); time.sleep(2)
        if d.sees('That is not word'):
            raise DriverError(f"[{name}] check {check+1} refused {answer!r} for #{position}")

    # ── genesis: securing -> publishing -> home ─────────────────────────────
    got = wait_any(['PROTECT YOUR WALLET', 'GENESIS: INITIALIZED', 'NEW HERE', 'SYSTEM ERROR'], 240)
    log(f"after create: {got}")
    if got == 'SYSTEM ERROR':
        raise DriverError(f"[{name}] SYSTEM ERROR: {d.screen_text()[:300]!r}")

# ── dismiss the lock and tour prompts ──────────────────────────────────────
time.sleep(2)
if d.sees('PROTECT YOUR WALLET'):
    d.tap('LATER', exact=True); log("dismissed lock prompt (LATER)"); time.sleep(1.5)
if d.sees('NEW HERE'):
    d.tap('NOT NOW', exact=True); log("dismissed tour prompt (NOT NOW)"); time.sleep(1.5)
log(f"HOME: {d.screen_text().replace(chr(10),' | ')[:220]}")
d.detach()
