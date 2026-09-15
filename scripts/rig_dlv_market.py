#!/usr/bin/env python3
"""Drive the SoFi/DLV market on the rig through the PRODUCTION UI (CDP substitutes for finger taps only).

usage:
  rig_dlv_market.py create-token <name> <serial> <port> <TICKER> <alias> <decimals>   # unlimited supply, mint/burn on, nothing allocated
  rig_dlv_market.py add-token    <name> <serial> <port> <policyAnchor>       # ADD TOKEN by CPTA anchor (adoption)
  rig_dlv_market.py mint         <name> <serial> <port> <SYMBOL> <amountBase> # creator mints through the policy
  rig_dlv_market.py anchors      <name> <serial> <port>                      # ticker -> CPTA anchor (from the Liquidity picker)
  rig_dlv_market.py create-vault <name> <serial> <port> <anchorA> <anchorB> <reserveA> <reserveB> <feeBps>
  rig_dlv_market.py vaults       <name> <serial> <port>                      # My vaults lines (reserves / ad seq / pending)
  rig_dlv_market.py swap         <name> <serial> <port> <inputBase> <fromAnchor> <toAnchor> [quote|execute|full]   # amount is the INPUT; the quote's output is exact
  rig_dlv_market.py reconcile    <name> <serial> <port>
  rig_dlv_market.py balances     <name> <serial> <port>
  rig_dlv_market.py offline      <name> <serial> <port>                      # am force-stop (adb survives)
  rig_dlv_market.py online       <name> <serial> <port>                      # relaunch + settle foreground
  rig_dlv_market.py screen       <name> <serial> <port>
"""
import sys, time, re
sys.path.insert(0, 'scripts')
from ui_driver import Device, DriverError

PKG = 'com.dsm.wallet'
cmd, name, serial, port = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
args = sys.argv[5:]
d = Device(transport='', name=name, port=port, serial=serial)
d._resolve_transport()

def log(m): print(f"[{name} {time.strftime('%H:%M:%S')}] {m}", flush=True)

def attach():
    for i in range(4):
        try:
            d.attach(timeout=40); return
        except DriverError:
            if i == 3: raise
            time.sleep(3)

# ── JS idioms proven on this rig ─────────────────────────────────────────────
MOUSE = "['pointerdown','mousedown','pointerup','mouseup','click'].forEach(t=>el.dispatchEvent(new MouseEvent(t,{bubbles:true,cancelable:true})))"

def js_click_text(text, exact=True):
    cmp = "e.textContent.trim()===T" if exact else "e.textContent.trim().toLowerCase().includes(T.toLowerCase())"
    return d.eval_js(f"""(() => {{ const T={text!r}; const els=[...document.querySelectorAll('button,.dsm-menu-item,[role=button],a')].filter(e=>{cmp});
      const vis=els.filter(e=>{{const r=e.getBoundingClientRect(); return r.width>0&&r.height>0;}}); const el=vis[0]; if(!el) return 'NOEL';
      el.scrollIntoView({{block:'center',behavior:'instant'}}); {MOUSE}; return 'CLICKED'; }})()""")

def js_click_sel(sel):
    return d.eval_js(f"""(() => {{ const el=document.querySelector({sel!r}); if(!el) return 'NOEL'; if(el.disabled) return 'DISABLED';
      el.scrollIntoView({{block:'center',behavior:'instant'}}); {MOUSE}; return 'CLICKED'; }})()""")

def js_set_input(sel, value):
    return d.eval_js(f"""(() => {{ const el=document.querySelector({sel!r}); if(!el) return 'NOEL';
      const proto = el.tagName==='TEXTAREA' ? HTMLTextAreaElement.prototype : HTMLInputElement.prototype;
      Object.getOwnPropertyDescriptor(proto,'value').set.call(el,{value!r}); el.dispatchEvent(new Event('input',{{bubbles:true}}));
      el.dispatchEvent(new Event('change',{{bubbles:true}})); return el.value; }})()""")

def js_set_select(sel, value):
    return d.eval_js(f"""(() => {{ const el=document.querySelector({sel!r}); if(!el) return 'NOEL';
      const opts=[...el.options].map(o=>o.value); if(!opts.includes({value!r})) return 'NOOPT:'+opts.join(',');
      Object.getOwnPropertyDescriptor(HTMLSelectElement.prototype,'value').set.call(el,{value!r}); el.dispatchEvent(new Event('change',{{bubbles:true}})); return el.value; }})()""")

def wait_text(text, timeout=60, any_of=None):
    t0 = time.time()
    while time.time() - t0 < timeout:
        s = d.screen_text()
        if any_of:
            for a in any_of:
                if a.lower() in s.lower(): return a
        elif text.lower() in s.lower(): return text
        time.sleep(0.7)
    raise DriverError(f"[{name}] never saw {text or any_of!r} within {timeout}s; screen: {d.screen_text().replace(chr(10),' | ')[:300]!r}")

def screen(): return d.screen_text().replace('\n', ' | ')

def dismiss_lock():
    if d.sees('PROTECT YOUR WALLET'):
        js_click_text('NEVER ASK'); time.sleep(1)

def go_home():
    for _ in range(8):
        dismiss_lock()
        if d.sees('GENESIS: INITIALIZED') and d.sees('CONTACTS') and d.sees('SOFI'): return
        # Status cards ("Policy Published…", token-added) sit over the screen with an OK.
        if d.sees('OK') and (d.sees('Published') or d.sees('added')):
            try: d.tap('OK', exact=True, timeout=5)
            except DriverError: pass
            time.sleep(1.0); continue
        # The wallet ignores Android BACK; its on-screen B button is 'back' (a real OS tap,
        # not a DOM click — the B is not a <button>).
        try: d.tap('B', exact=True, timeout=8)
        except DriverError: js_click_sel('.cancel-button')
        time.sleep(1.5)
    raise DriverError(f"[{name}] not at home: {screen()[:200]!r}")

def home_brick(label):
    """Home bricks only FOCUS on a plain tap; dispatch the full mouse sequence."""
    r = js_click_text(label, exact=True); time.sleep(2.0); return r

def sofi_brick(label):
    r = d.eval_js(f"""(() => {{ const el=document.querySelector('.dsm-menu-item.home-brick[data-label="{label}"]') || [...document.querySelectorAll('.dsm-menu-item')].find(e=>e.textContent.trim()==={label!r}); if(!el) return 'NOEL'; {MOUSE}; return 'CLICKED'; }})()""")
    time.sleep(2.0); return r

def open_liquidity():
    go_home(); home_brick('SOFI'); wait_text('LIQUIDITY', 20); sofi_brick('LIQUIDITY'); wait_text('Liquidity', 20); time.sleep(1.5)

def open_swap():
    go_home(); home_brick('SOFI'); wait_text('SWAP', 20); sofi_brick('SWAP'); wait_text(None, 20, any_of=['From token', 'Quote', 'Swap']); time.sleep(1.0)

# ── commands ─────────────────────────────────────────────────────────────────
if cmd == 'offline':
    d.shell(f'am force-stop {PKG}'); time.sleep(1.5)
    log(f"force-stopped; pid={d.shell(f'pidof {PKG}').strip() or 'none'}"); sys.exit(0)

if cmd == 'online':
    d.shell(f'monkey -p {PKG} -c android.intent.category.LAUNCHER 1 >/dev/null 2>&1'); time.sleep(6)
    attach(); dismiss_lock(); log(f"relaunched: {screen()[:160]}"); sys.exit(0)

attach(); dismiss_lock()

if cmd == 'screen':
    log(screen()[:600]); sys.exit(0)

if cmd == 'balances':
    go_home(); home_brick('WALLET'); wait_text(None, 20, any_of=['Overview', 'Send', 'Swap']); time.sleep(1.5)
    rows = d.eval_js("[...document.querySelectorAll('.balance-list-row')].map(r=>[(r.querySelector('.token-symbol')||{}).innerText,(r.querySelector('.balance-amount')||{}).innerText])")
    log(f"balances: {rows}"); go_home(); sys.exit(0)

if cmd == 'create-token':
    ticker, alias, decimals = args[0], args[1], args[2]
    go_home(); home_brick('TOKENS'); wait_text('Create Token', 20); time.sleep(1)
    js_click_text('+ Create Token', exact=False); wait_text('Create Token Policy', 20)
    log(f"ticker: {js_set_input('input#tcd-ticker', ticker)} alias: {js_set_input('input#tcd-alias', alias)}")
    js_click_sel('.tcd-btn--pri'); time.sleep(1.2)
    # step 2: decimals slider (native setter), supply, allocation
    d.eval_js(f"(() => {{ const el=document.querySelector('input[type=range].tcd-slider'); if(!el) return 'NOEL'; Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(el,'{decimals}'); el.dispatchEvent(new Event('input',{{bubbles:true}})); el.dispatchEvent(new Event('change',{{bubbles:true}})); return el.value; }})()")
    # Beta refuses capped issuance and a non-zero initial allocation, and mint/burn is off by
    # default: switch on unlimited supply and mint/burn authority; nothing is allocated.
    for toggle in ('tcd-unlimited', 'tcd-mintburn'):
        state = d.eval_js("(() => { const el=document.getElementById('%s'); if(!el) return 'NOEL'; if(!el.checked) el.click(); return String(el.checked); })()" % toggle)
        log(f"{toggle}: {state}")
    js_click_sel('.tcd-btn--pri'); time.sleep(1.2)
    r = js_click_sel('.tcd-btn--create'); log(f"publish: {r}")
    wait_text('Policy Published', 120)
    card = d.eval_js("(document.querySelector('.tcd-card')||{}).innerText||''")
    m = re.search(r'POLICY ANCHOR \(CPTA\)\s*([0-9A-HJKMNP-TV-Z]{52})', card, re.I)
    log(f"created {ticker}; anchor={m.group(1) if m else 'NOT FOUND'}")
    print("ANCHOR:", m.group(1) if m else '')
    js_click_sel('.tcd-btn--pri'); time.sleep(1)   # Done
    go_home(); sys.exit(0)

if cmd == 'add-token':
    anchor = args[0]
    go_home(); home_brick('TOKENS'); wait_text('Add Token', 20); time.sleep(1)
    log(f"open: {js_click_text('+ Add Token (CPTA)', exact=True)}"); time.sleep(0.8)
    log(f"anchor: {js_set_input('input[aria-label=\"CPTA policy anchor\"]', anchor)[:12]}…")
    log(f"ADD: {js_click_text('ADD', exact=True)}")
    t0 = time.time(); got = None
    while time.time() - t0 < 120:
        status = d.eval_js("[...document.querySelectorAll('[role=status]')].map(e=>e.innerText).join(' || ')")
        banner = d.eval_js("[...document.querySelectorAll('.error-banner,.warning-banner,[role=alert]')].map(e=>e.innerText).join(' || ')")
        busy = d.eval_js("[...document.querySelectorAll('button')].some(b=>b.innerText.trim()==='ADDING...')")
        if status and not busy: got = 'added'; log(f"status: {status[:200]}"); break
        if banner and not busy: got = 'refused'; log(f"banner: {banner[:200]}"); break
        time.sleep(0.8)
    log(f"result: {got}")
    go_home(); sys.exit(0 if got == 'added' else 2)

if cmd == 'mint':
    symbol, amount = args[0], args[1]
    go_home(); home_brick('TOKENS'); wait_text('Add Token', 20); time.sleep(1.5)
    # The success banner is cleared by the post-mint balance refresh, so the row's own
    # balance text changing is the durable signal; the banner is only a faster path.
    # Match the balance span itself ("<amount> <SYMBOL>"): once the row expands, its detail panel
    # repeats the ticker, so anchoring on the ticker span finds the wrong container.
    row_balance = lambda: d.eval_js(f"""(() => {{ const re=new RegExp('^([0-9][0-9.,]*) '+{symbol!r}+'(?![A-Za-z0-9])');
      const hit=[...document.querySelectorAll('span')].map(x=>x.textContent.trim().match(re)).find(m=>m); return hit ? hit[1] : 'NOBAL'; }})()""")
    before = row_balance(); log(f"balance before: {before}")
    r = d.eval_js(f"""(() => {{ const S={symbol!r};
      const el=[...document.querySelectorAll('span,div')].filter(e=>e.textContent.trim()===S).pop();
      if(!el) return 'NOROW'; el.scrollIntoView({{block:'center',behavior:'instant'}}); {MOUSE}; return 'EXPANDED'; }})()""")
    log(f"row {symbol}: {r}"); time.sleep(1.2)
    log(f"MINT: {js_click_text('MINT', exact=True)}"); time.sleep(0.8)
    log(f"amount: {js_set_input('input[aria-label=\"mint amount\"]', amount)}")
    log(f"CONFIRM: {js_click_text('CONFIRM', exact=True)}")
    t0 = time.time(); got = None
    while time.time() - t0 < 180 and got is None:
        sc = d.screen_text().lower()
        if f'minted {amount}'.lower() in sc: got = 'minted'
        elif any(w in sc for w in ('failed', 'refused', 'error')): got = 'error'
        else:
            now = row_balance()
            if now not in (before, 'NOBAL'): got = 'minted'; log(f"balance after: {now}")
        time.sleep(0.7)
    log(f"result: {got} :: {screen()[:240]}")
    go_home(); sys.exit(0 if got == 'minted' else 2)

if cmd == 'anchors':
    open_liquidity(); js_click_text('+ Create vault', exact=False); wait_text('New AMM vault', 20)
    opts = d.eval_js("[...document.querySelectorAll('select#liq-token-a option')].map(o=>[o.textContent.trim(), o.value])")
    for t, v in opts: print(f"{t}\t{v}")
    js_click_text('Cancel', exact=True); go_home(); sys.exit(0)

if cmd == 'create-vault':
    a, b, ra, rb, fee = args[0], args[1], args[2], args[3], args[4]
    open_liquidity(); js_click_text('+ Create vault', exact=False); wait_text('New AMM vault', 20)
    log(f"tokenA: {js_set_select('select#liq-token-a', a)[:20]}"); time.sleep(0.5)
    log(f"tokenB: {js_set_select('select#liq-token-b', b)[:20]}")
    log(f"reserves: {js_set_input('input#liq-reserve-a', ra)} / {js_set_input('input#liq-reserve-b', rb)} fee: {js_set_input('input#liq-fee', fee)}")
    time.sleep(0.5)
    r = js_click_text('Create', exact=True); log(f"Create: {r}")
    wait_text('Create AMM vault', 20); log(f"confirm: {js_click_sel('button.bilateral-btn-accept')}")
    got = wait_text(None, 180, any_of=['Vault created + published', 'not yet advertised', 'error', 'failed', 'must be lex-lower'])
    log(f"result: {got} :: {screen()[:300]}")
    sys.exit(0 if got == 'Vault created + published' else 3 if got == 'not yet advertised' else 4 if got == 'must be lex-lower' else 2)

if cmd == 'vaults':
    open_liquidity(); js_click_sel('button[aria-label="Refresh"]'); time.sleep(3)
    s = d.screen_text()
    lines = [l for l in s.split('\n') if any(k in l for k in ('My vaults', 'reserves:', 'vault ', 'settled trade', 'fee ', 'Reconcile', 'No AMM'))]
    for l in lines: print(l)
    go_home(); sys.exit(0)

if cmd == 'reconcile':
    open_liquidity(); js_click_sel('button[aria-label="Refresh"]')
    # The pending-trade line and its Reconcile button render only after the refresh completes.
    t0 = time.time()
    while time.time() - t0 < 60 and 'settled trade' not in d.screen_text(): time.sleep(1)
    log(f"before: {[l for l in d.screen_text().split(chr(10)) if 'settled trade' in l or 'reserves:' in l]}")
    if 'settled trade' not in d.screen_text():
        # The owner's own sync catch-up may already have applied it; the proofs judge generations and reserves.
        log("nothing to reconcile (no pending settled trade)"); go_home(); sys.exit(0)
    r = js_click_text('Reconcile', exact=True); log(f"Reconcile: {r}")
    got = wait_text(None, 240, any_of=['Reconciled', 'reconcile failed', 'error'])
    log(f"result: {got} :: {[l for l in d.screen_text().split(chr(10)) if 'Reconciled' in l or 'reserves:' in l or 'settled trade' in l or 'error' in l.lower()]}")
    sys.exit(0 if got == 'Reconciled' else 2)

if cmd == 'swap':
    amount, frm, to = args[0], args[1], args[2]
    mode = args[3] if len(args) > 3 else 'full'
    if mode in ('quote', 'full'):
        open_swap()
        log(f"amount: {js_set_input('input#swap-amount', amount)} from: {js_set_input('input#swap-from', frm)[:12]}… to: {js_set_input('input#swap-to', to)[:12]}…")
        time.sleep(0.5)
        r = js_click_text('Quote', exact=True); log(f"Quote: {r}")
        # The 'Route ready' banner only flashes; the quote CARD (+ Swap button) is the durable signal.
        t0 = time.time(); got = None
        while time.time() - t0 < 90:
            s2 = d.screen_text()
            if 'exact output' in s2: got = 'quoted'; break
            b = d.eval_js("[...document.querySelectorAll('.warning-banner,.error-banner')].map(b=>b.innerText).join(' || ')")
            if 'Failed' in b or 'No liquidity' in b or 'error' in b.lower(): got = b; break
            time.sleep(0.7)
        card = [l for l in d.screen_text().split('\n') if 'exact output' in l or 'discovered' in l or ('vault' in l and 'fee' in l) or (l.strip().split(' ')[0].isdigit() and len(l) > 40)]
        hops = re.search(r'(\d+) hops? bound', d.screen_text())
        log(f"quote: {got} :: {card[:4]}")
        print("HOPS:", hops.group(1) if hops else '?')
        if got != 'quoted': log(f"SCREEN: {screen()[:400]}"); sys.exit(2)
        if mode == 'quote': sys.exit(0)
    # execute the (possibly stale) quote that is on screen
    r = d.eval_js("(() => { const el=[...document.querySelectorAll('button.send-button')].find(b=>b.innerText.trim()==='Swap'); if(!el) return 'NOEL'; if(el.disabled) return 'DISABLED'; %s; return 'CLICKED'; })()" % MOUSE)
    log(f"Swap: {r}")
    t0 = time.time()
    while time.time() - t0 < 20 and not d.eval_js("!!document.querySelector('.bilateral-transfer-overlay')"): time.sleep(0.4)
    msg = d.eval_js("(document.querySelector('.bilateral-transfer-message')||{}).innerText||'NO MODAL'")
    log(f"modal: {msg[:140]}")
    log(f"confirm: {js_click_sel('button.bilateral-btn-accept')}")
    t0 = time.time(); last = ''; final = None
    while time.time() - t0 < 300:
        b = d.eval_js("[...document.querySelectorAll('.warning-banner,.error-banner')].map(b=>b.innerText.replace(/\\n/g,' | ')).join(' || ')")
        if b != last: log(f"  +{time.time()-t0:5.1f}s {b[:260]}"); last = b
        if 'Failed' in b: final = 'Failed'; break
        if 'Trade settled' in b: final = 'Trade settled'
        s2 = d.screen_text()
        if final is None and 'Route' not in s2 and 'OVERVIEW' in s2 and time.time() - t0 > 6: final = 'returned-to-overview'; break
        if final and 'Trade settled' not in b: break
        time.sleep(1.0)
    log(f"result: {final} :: last banner: {last[:200]}")
    sys.exit(0 if final in ('Trade settled', 'returned-to-overview') else 3)

print("unknown cmd", cmd); sys.exit(64)
