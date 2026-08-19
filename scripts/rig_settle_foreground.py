#!/usr/bin/env python3
"""Clear Android permission dialogs + the wallet's lock prompt so the WebView owns the foreground.
usage: rig_settle_foreground.py <name> <serial> <port>"""
import sys, time, re; sys.path.insert(0, 'scripts')
from ui_driver import Device
name, serial, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = Device(transport='', name=name, port=port, serial=serial); d._resolve_transport()
def focus(): return d.shell("dumpsys window | grep -m1 mCurrentFocus")
def allow_permission_dialog():
    d.shell("uiautomator dump /sdcard/ui.xml >/dev/null 2>&1"); xml = d.shell("cat /sdcard/ui.xml")
    for rid in ("permission_allow_foreground_only_button", "permission_allow_button", "permission_allow_one_time_button"):
        m = re.search(r'resource-id="com\.android\.permissioncontroller:id/%s"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"' % rid, xml)
        if m:
            x = (int(m.group(1)) + int(m.group(3)))//2; y = (int(m.group(2)) + int(m.group(4)))//2
            d.shell(f"input tap {x} {y}"); time.sleep(1.2); return True
    return False
for _ in range(6):
    f = focus()
    if 'permissioncontroller' in f:
        print(f"[{name}] permission dialog -> allow"); allow_permission_dialog(); continue
    break
print(f"[{name}] foreground: {focus().strip()[-70:]}")
d.attach()
if d.sees('PROTECT YOUR WALLET'):
    r = d.eval_js("(() => { const el=[...document.querySelectorAll('button,.dsm-menu-item,[role=button]')].find(e=>e.textContent.trim()==='NEVER ASK'); if(!el) return 'NOEL'; ['pointerdown','mousedown','pointerup','mouseup','click'].forEach(t=>el.dispatchEvent(new MouseEvent(t,{bubbles:true,cancelable:true}))); return 'CLICKED'; })()")
    print(f"[{name}] lock prompt -> NEVER ASK: {r}"); time.sleep(1)
print(f"[{name}] SCREEN: {d.screen_text().replace(chr(10),' | ')[:200]}")
