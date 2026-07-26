#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Drive the shipping DSM wallet UI on a real device.

The rule this file exists to obey: automation operates the UI a person would
operate. It finds a control by the text the user reads, and then dispatches a
genuine pointer or keyboard event at that control's real on-screen position.

It never sets React state, never calls a native setter, and never invokes a
router method directly. If a control is not visible, not rendered, or covered,
the click misses and the step fails — which is the point. A driver that pokes
the store instead would report success on a screen the user cannot actually
use, which is how "it works" gets claimed for a broken flow.

CDP is used only to locate things and to read what is on screen. Every action
goes through Input.dispatch*, the same queue the touchscreen feeds.
"""

from __future__ import annotations

import json
import subprocess
import time
import urllib.request
from dataclasses import dataclass
from typing import Any


class DriverError(RuntimeError):
    pass


@dataclass
class Device:
    """One phone, addressed by adb transport id."""

    transport: str
    name: str
    port: int

    # ── adb ────────────────────────────────────────────────────────────────
    def adb(self, *args: str, timeout: int = 60) -> str:
        proc = subprocess.run(
            ["adb", "-t", self.transport, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            raise DriverError(f"[{self.name}] adb {' '.join(args)}: {proc.stderr.strip()}")
        return proc.stdout

    def shell(self, cmd: str, timeout: int = 60) -> str:
        return self.adb("shell", cmd, timeout=timeout)

    # ── CDP attach ─────────────────────────────────────────────────────────
    def _webview_socket(self) -> str:
        """Find the WebView's abstract unix socket for this app's process."""
        out = self.shell("cat /proc/net/unix")
        socks = [
            line.split()[-1].lstrip("@")
            for line in out.splitlines()
            if "webview_devtools_remote" in line
        ]
        if not socks:
            raise DriverError(
                f"[{self.name}] no WebView devtools socket — is the app running "
                "and is WebView debugging enabled in this build?"
            )
        return sorted(set(socks))[0]

    def attach(self) -> None:
        sock = self._webview_socket()
        subprocess.run(
            ["adb", "-t", self.transport, "forward", f"tcp:{self.port}", f"localabstract:{sock}"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )

    def detach(self) -> None:
        subprocess.run(
            ["adb", "-t", self.transport, "forward", "--remove", f"tcp:{self.port}"],
            capture_output=True,
            text=True,
            timeout=30,
        )

    # ── CDP plumbing ───────────────────────────────────────────────────────
    def _ws_url(self) -> str:
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json", timeout=15) as r:
            targets = json.loads(r.read())
        pages = [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
        if not pages:
            raise DriverError(f"[{self.name}] no debuggable page")
        return pages[0]["webSocketDebuggerUrl"]

    def cdp(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """One CDP call. Uses a short-lived websocket so a dropped BLE-busy
        page cannot wedge a long-lived connection mid-run."""
        try:
            from websocket import create_connection  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise DriverError("pip install websocket-client") from exc

        ws = create_connection(self._ws_url(), timeout=45)
        try:
            ws.send(json.dumps({"id": 1, "method": method, "params": params or {}}))
            while True:
                msg = json.loads(ws.recv())
                if msg.get("id") == 1:
                    if "error" in msg:
                        raise DriverError(f"[{self.name}] {method}: {msg['error']}")
                    return msg.get("result")
        finally:
            ws.close()

    def eval_js(self, expr: str) -> Any:
        """Read-only evaluation. Used to LOCATE and to OBSERVE, never to act."""
        res = self.cdp(
            "Runtime.evaluate",
            {"expression": expr, "returnByValue": True, "awaitPromise": True},
        )
        if res.get("exceptionDetails"):
            raise DriverError(f"[{self.name}] js: {res['exceptionDetails'].get('text')}")
        return res.get("result", {}).get("value")

    # ── locating ───────────────────────────────────────────────────────────
    def find(self, text: str, *, exact: bool = False) -> dict[str, float] | None:
        """Centre of the smallest visible element whose text matches.

        Smallest wins because ancestors contain the same text; the button is
        the tightest box around it. Invisible and zero-area nodes are skipped
        so we never "click" something the user cannot see.
        """
        match = "t === needle" if exact else "t.includes(needle)"
        return self.eval_js(
            f"""
            (() => {{
              const needle = {json.dumps(text)};
              let best = null;
              for (const el of document.querySelectorAll('button,a,input,[role="button"],div,span,li,label')) {{
                const t = (el.innerText || el.value || '').trim();
                if (!t || !({match})) continue;
                const r = el.getBoundingClientRect();
                if (r.width < 1 || r.height < 1) continue;
                const s = getComputedStyle(el);
                if (s.visibility === 'hidden' || s.display === 'none' || s.opacity === '0') continue;
                const area = r.width * r.height;
                if (!best || area < best.area)
                  best = {{ x: r.left + r.width / 2, y: r.top + r.height / 2, area }};
              }}
              return best && {{ x: best.x, y: best.y }};
            }})()
            """
        )

    def wait_for(self, text: str, *, timeout: float = 45.0, exact: bool = False) -> dict[str, float]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            hit = self.find(text, exact=exact)
            if hit:
                return hit
            time.sleep(0.5)
        raise DriverError(f"[{self.name}] never saw {text!r} within {timeout:.0f}s")

    # ── acting: genuine input events only ──────────────────────────────────
    def tap(self, text: str, *, timeout: float = 45.0, exact: bool = False) -> None:
        pt = self.wait_for(text, timeout=timeout, exact=exact)
        for kind in ("mousePressed", "mouseReleased"):
            self.cdp(
                "Input.dispatchMouseEvent",
                {
                    "type": kind,
                    "x": pt["x"],
                    "y": pt["y"],
                    "button": "left",
                    "clickCount": 1,
                    "buttons": 1 if kind == "mousePressed" else 0,
                },
            )
        time.sleep(0.35)

    def type_into(self, placeholder: str, value: str) -> None:
        """Focus a field by tapping it, then type character-by-character.

        Input.insertText goes through the same path as the soft keyboard, so
        React's onChange fires exactly as it would for a person. Setting .value
        directly would bypass React's synthetic event and is precisely the
        shortcut this driver refuses to take.
        """
        pt = self.eval_js(
            f"""
            (() => {{
              const el = document.querySelector({json.dumps(f'input[placeholder="{placeholder}"]')});
              if (!el) return null;
              const r = el.getBoundingClientRect();
              return {{ x: r.left + r.width / 2, y: r.top + r.height / 2 }};
            }})()
            """
        )
        if not pt:
            raise DriverError(f"[{self.name}] no input with placeholder {placeholder!r}")
        for kind in ("mousePressed", "mouseReleased"):
            self.cdp(
                "Input.dispatchMouseEvent",
                {
                    "type": kind,
                    "x": pt["x"],
                    "y": pt["y"],
                    "button": "left",
                    "clickCount": 1,
                    "buttons": 1 if kind == "mousePressed" else 0,
                },
            )
        time.sleep(0.2)
        self.cdp("Input.insertText", {"text": value})
        time.sleep(0.2)

    # ── observing ──────────────────────────────────────────────────────────
    def screen_text(self) -> str:
        return self.eval_js("document.body.innerText") or ""

    def sees(self, text: str) -> bool:
        return text.lower() in self.screen_text().lower()

    def screenshot(self, path: str) -> None:
        data = self.cdp("Page.captureScreenshot", {"format": "png"})
        import base64

        with open(path, "wb") as fh:
            fh.write(base64.b64decode(data["data"]))
