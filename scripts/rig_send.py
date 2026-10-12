#!/usr/bin/env python3
"""Drive one online send from the wallet UI over CDP: WALLET -> Send tab -> recipient (by alias) -> amount -> Send -> Confirm.
usage: rig_send.py <name> <serial> <cdp_port> <recipient_alias> <amount>
Requires the app in the FOREGROUND (the driver heartbeat is a rAF echo) and mutual contacts.
"""
import os, sys, time, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ui_driver import Device, DriverError
name, serial, port, alias, amount = sys.argv[1], sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5]
d = Device(transport='', name=name, port=port, serial=serial); d._resolve_transport(); d.attach(timeout=40)
def log(m): print(f"[{name} {time.strftime('%H:%M:%S')}] {m}", flush=True)
def go_home():
    for _ in range(6):
        if d.sees('GENESIS: INITIALIZED') and d.sees('CONTACTS'): return
        d.tap('B', exact=True, timeout=10); time.sleep(1.5)
    raise DriverError(f"[{name}] not at home: {d.screen_text()[:200]!r}")
if d.sees('PROTECT YOUR WALLET'): d.tap('LATER', exact=True); time.sleep(1)
go_home(); d.tap('WALLET', exact=True); time.sleep(4)
r = d.eval_js("""(() => { const b=[...document.querySelectorAll('button.tab-button')].find(b=>b.textContent.trim()==='Send'); if(!b) return 'NOTAB'; ['pointerdown','mousedown','pointerup','mouseup','click'].forEach(t=>b.dispatchEvent(new MouseEvent(t,{bubbles:true,cancelable:true}))); return 'OK'; })()""")
log(f"send tab: {r}"); time.sleep(2.5)
r = d.eval_js(f"""(() => {{
  const sel=document.querySelector('select#recipient'); if(!sel) return 'NOSELECT';
  const opt=[...sel.options].find(o=>o.textContent.trim()==={alias!r}); if(!opt) return 'NOOPT:'+[...sel.options].map(o=>o.textContent).join(',');
  Object.getOwnPropertyDescriptor(window.HTMLSelectElement.prototype,'value').set.call(sel,opt.value); sel.dispatchEvent(new Event('change',{{bubbles:true}}));
  const amt=document.querySelector('input#amount'); if(!amt) return 'NOAMT';
  Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype,'value').set.call(amt,{amount!r}); amt.dispatchEvent(new Event('input',{{bubbles:true}}));
  return 'OK sel='+sel.value.slice(0,10)+' amt='+amt.value; }})()""")
log(f"form: {r}")
if not str(r).startswith('OK'): raise DriverError(r)
time.sleep(1.5)
log(f"confirm-line: {d.eval_js("(document.querySelector('.send-recipient-confirm')||{}).textContent")}")
r = d.eval_js("""(() => { const b=document.querySelector('button.send-button'); if(!b) return 'NOBTN'; if(b.disabled) return 'DISABLED'; ['pointerdown','mousedown','pointerup','mouseup','click'].forEach(t=>b.dispatchEvent(new MouseEvent(t,{bubbles:true,cancelable:true}))); return 'CLICKED'; })()""")
log(f"send-button: {r}"); time.sleep(2)
dl=time.time()+15
while time.time()<dl and not d.eval_js("!!document.querySelector('button.bilateral-btn-accept')"): time.sleep(0.5)
msg = d.eval_js("(document.querySelector('.bilateral-transfer-overlay')||{}).innerText||''"); log(f"modal: {msg.replace(chr(10),' | ')[:160]}")
r = d.eval_js("""(() => { const b=document.querySelector('button.bilateral-btn-accept'); if(!b) return 'NOCONFIRM'; ['pointerdown','mousedown','pointerup','mouseup','click'].forEach(t=>b.dispatchEvent(new MouseEvent(t,{bubbles:true,cancelable:true}))); return 'CONFIRMED'; })()""")
log(f"confirm: {r}")
for i in range(40):
    time.sleep(3); s=d.screen_text()
    if 'Sending' not in s: break
log(f"screen: {s.replace(chr(10),' | ')[:300]}")
d.detach()
