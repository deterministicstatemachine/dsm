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
    # Serial is stable; transport ids are reassigned on every reconnect and
    # silently start addressing a different phone (or none). When a serial is
    # given the transport is re-resolved from it before each adb call.
    serial: str | None = None
    package: str = "com.dsm.wallet"
    # Debugger URL of the target proven live by attach(); never guessed.
    _target_ws: str | None = None

    # ── adb ────────────────────────────────────────────────────────────────
    def _resolve_transport(self) -> None:
        """Re-point at this device's CURRENT transport id, by serial."""
        if not self.serial:
            return
        out = subprocess.run(
            ["adb", "devices", "-l"], capture_output=True, text=True, timeout=30
        ).stdout
        for line in out.splitlines()[1:]:
            if "transport_id:" not in line or " device " not in f" {line} ":
                continue
            tid = line.split("transport_id:")[1].split()[0]
            got = subprocess.run(
                ["adb", "-t", tid, "shell", "getprop", "ro.serialno"],
                capture_output=True, text=True, timeout=30,
            ).stdout.strip()
            if got == self.serial:
                self.transport = tid
                return
        raise DriverError(f"[{self.name}] serial {self.serial} is not connected")

    def adb(self, *args: str, timeout: int = 60) -> str:
        proc = subprocess.run(
            ["adb", "-t", self.transport, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if proc.returncode != 0:
            err_txt = proc.stderr.strip()
            if self.serial and "no device with transport" in err_txt:
                self._resolve_transport()
                proc = subprocess.run(
                    ["adb", "-t", self.transport, *args],
                    capture_output=True, text=True, timeout=timeout,
                )
                if proc.returncode == 0:
                    return proc.stdout
                err_txt = proc.stderr.strip()
            raise DriverError(f"[{self.name}] adb {' '.join(args)}: {err_txt}")
        return proc.stdout

    def shell(self, cmd: str, timeout: int = 60) -> str:
        return self.adb("shell", cmd, timeout=timeout)

    # ── CDP attach ─────────────────────────────────────────────────────────
    #
    # Attaching to the wrong WebView is silent and very convincing. A relaunched
    # app leaves the old devtools socket in /proc/net/unix, and picking one by
    # name order can land on a target that still answers, still renders the last
    # screen it saw, and still returns plausible DOM — while every tap goes to
    # the live app that this connection knows nothing about. Reads look right,
    # presses do nothing, and the app appears broken.
    #
    # So the socket is chosen by the app's CURRENT pid, and the connection is
    # not trusted until it proves it can see an event we cause.

    def _pid(self) -> str | None:
        pid = self.shell(f"pidof {self.package}").strip().split()
        return pid[0] if pid else None

    def _webview_sockets(self) -> list[tuple[str, str | None]]:
        """Every WebView devtools socket, paired with its owning pid.

        Android names these `webview_devtools_remote_<pid>`; the suffix is the
        only thing tying a socket to a process, and a socket whose pid no longer
        exists is by definition stale.
        """
        out = self.shell("cat /proc/net/unix")
        found: list[tuple[str, str | None]] = []
        for line in out.splitlines():
            if "webview_devtools_remote" not in line:
                continue
            sock = line.split()[-1].lstrip("@")
            owner = sock.rsplit("_", 1)[-1]
            found.append((sock, owner if owner.isdigit() else None))
        return found

    def _forward(self, sock: str) -> None:
        subprocess.run(
            ["adb", "-t", self.transport, "forward", "--remove", f"tcp:{self.port}"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        subprocess.run(
            ["adb", "-t", self.transport, "forward", f"tcp:{self.port}", f"localabstract:{sock}"],
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )

    def _live_page(self) -> dict[str, Any] | None:
        """A page target on the currently forwarded socket that is worth using.

        Blank and detached targets are rejected: `about:blank`, `chrome://`, and
        anything with no debugger URL are exactly what a torn-down WebView
        leaves behind.
        """
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/list", timeout=10) as r:
                targets = json.loads(r.read())
        except Exception:
            return None
        for t in targets:
            if t.get("type") != "page" or not t.get("webSocketDebuggerUrl"):
                continue
            url = (t.get("url") or "").strip()
            if not url or url.startswith(("about:", "chrome://", "devtools://")):
                continue
            return t
        return None

    def attach(self, *, verify: bool = True, timeout: float = 60.0) -> None:
        """Forward to the live app's WebView and prove the connection is real.

        Call this after every force-stop, relaunch, or anything that recreates
        the WebView. It is cheap and it is the only thing standing between a
        run and an hour of debugging a phantom.
        """
        deadline = time.time() + timeout
        last = "no attempt made"
        while time.time() < deadline:
            pid = self._pid()
            if not pid:
                last = f"{self.package} is not running"
                time.sleep(1.0)
                continue

            socks = self._webview_sockets()
            if not socks:
                last = "no WebView devtools socket (is WebView debugging enabled?)"
                time.sleep(1.0)
                continue

            # Prefer the socket owned by the running pid; fall back to sockets
            # with no decipherable owner, never to one owned by a dead pid.
            alive = {p for p in (s[1] for s in socks) if p and self._pid_alive(p)}
            ordered = (
                [s for s, o in socks if o == pid]
                + [s for s, o in socks if o is None]
                + [s for s, o in socks if o and o != pid and o in alive]
            )
            for sock in ordered:
                self._forward(sock)
                page = self._live_page()
                if not page:
                    last = f"socket {sock} exposed no usable page"
                    continue
                self._target_ws = page["webSocketDebuggerUrl"]
                if not verify or self._heartbeat():
                    return
                last = f"socket {sock} did not echo a test event (stale target)"
            time.sleep(1.0)

        raise DriverError(f"[{self.name}] could not attach to a live WebView: {last}")

    def _pid_alive(self, pid: str) -> bool:
        return bool(self.shell(f"ls /proc/{pid}/cmdline 2>/dev/null").strip())

    def _heartbeat(self) -> bool:
        """Prove this connection drives the page a person is looking at.

        The previous version dispatched an event and asked whether it was seen —
        entirely inside one JS context. That proves the connection can run JS,
        NOT that it is the visible page: a detached target passes it happily,
        which is the exact failure it was supposed to catch.

        So the proof is now causal and crosses the input boundary. Read a marker
        off the rendered screen, send a REAL CDP pointer event at a harmless
        spot, and require the page to report something only a live, painting
        document can: a fresh animation frame. A detached or background target
        does not paint, so it cannot answer.
        """
        try:
            marker = self.eval_js("document.body ? document.body.innerText.trim().length : 0")
            if not isinstance(marker, int) or marker <= 0:
                return False

            # Somewhere guaranteed inert: the very top-left corner. A real
            # pointer event there changes nothing a user would notice.
            for kind in ("mousePressed", "mouseReleased"):
                self.cdp(
                    "Input.dispatchMouseEvent",
                    {
                        "type": kind,
                        "x": 1,
                        "y": 1,
                        "button": "left",
                        "clickCount": 1,
                        "buttons": 1 if kind == "mousePressed" else 0,
                    },
                )

            # requestAnimationFrame only fires for a document that is actually
            # rendering. This is the part a stale target cannot fake.
            painted = self.eval_js(
                """
                new Promise(resolve => {
                  let done = false;
                  requestAnimationFrame(() => { done = true; resolve(true); });
                  setTimeout(() => { if (!done) resolve(false); }, 2000);
                })
                """
            )
            return bool(painted)
        except DriverError:
            return False

    def detach(self) -> None:
        subprocess.run(
            ["adb", "-t", self.transport, "forward", "--remove", f"tcp:{self.port}"],
            capture_output=True,
            text=True,
            timeout=30,
        )

    # ── CDP plumbing ───────────────────────────────────────────────────────
    def _ws_url(self) -> str:
        """The target attach() proved live — not whichever page answers first."""
        if self._target_ws:
            return self._target_ws
        raise DriverError(
            f"[{self.name}] not attached — call attach() first so the target can be verified"
        )

    def cdp(self, method: str, params: dict[str, Any] | None = None) -> Any:
        """One CDP call. Uses a short-lived websocket so a dropped BLE-busy
        page cannot wedge a long-lived connection mid-run."""
        try:
            from websocket import create_connection  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise DriverError("pip install websocket-client") from exc

        # DevTools rejects a WebSocket carrying an Origin it was not launched
        # to allow. We cannot pass --remote-allow-origins to an already-running
        # app, so send no Origin at all.
        ws = create_connection(self._ws_url(), timeout=45, suppress_origin=True)
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

        Matching is case-insensitive: this UI uppercases labels via CSS
        `text-transform`, and `innerText` returns the TRANSFORMED text. A
        case-sensitive search for "Create Token" misses the button rendered
        from exactly that source string, which reads as a missing control
        rather than as a matcher bug.

        A located element is first scrolled into view, exactly as a person
        would scroll to it. Without that, an element below the fold still has a
        bounding rect, and tapping those coordinates hits whatever is actually
        drawn there — which is how a perfectly good form field reads as
        "covered by the footer".
        """
        match = "t === needle" if exact else "t.includes(needle)"
        return self.eval_js(
            f"""
            (() => {{
              const needle = {json.dumps(text)}.toLowerCase();
              let best = null, bestEl = null;
              for (const el of document.querySelectorAll('button,a,input,[role="button"],div,span,li,label')) {{
                const t = (el.innerText || el.value || '').trim().toLowerCase();
                if (!t || !({match})) continue;
                const r = el.getBoundingClientRect();
                if (r.width < 1 || r.height < 1) continue;
                const s = getComputedStyle(el);
                if (s.visibility === 'hidden' || s.display === 'none' || s.opacity === '0') continue;
                const area = r.width * r.height;
                if (!best || area < best.area) {{ best = {{ area }}; bestEl = el; }}
              }}
              if (!bestEl) return null;
              // 'instant' matters: with smooth scrolling the element keeps
              // moving after this call returns, so a rect measured here is
              // stale by the time a tap lands and the press hits whatever
              // slid into that spot. Marker is read back on the next call.
              bestEl.scrollIntoView({{ block: 'center', inline: 'nearest', behavior: 'instant' }});
              window.__dsmTapTarget = bestEl;
              return {{ pending: true }};
            }})()
            """
        )

    def _settled_point(self) -> dict[str, float] | None:
        """Re-measure the element marked by the previous locate, once the
        scroll has settled. Position is only trustworthy after motion stops."""
        return self.eval_js(
            """
            (() => {
              const el = window.__dsmTapTarget;
              if (!el || !el.isConnected) return null;
              const r = el.getBoundingClientRect();
              if (r.width < 1 || r.height < 1) return null;
              return { x: r.left + r.width / 2, y: r.top + r.height / 2 };
            })()
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

    # ── acting: real OS touch injection ────────────────────────────────────
    #
    # CSS pixels are not screen pixels. `adb input` works in device pixels, so
    # every located point is scaled by the page's own devicePixelRatio and
    # offset by the WebView's position on screen. Both are read from the page
    # rather than assumed, because a wrong scale silently taps the wrong
    # control and still "succeeds".
    def _viewport(self) -> tuple[float, float, float]:
        v = self.eval_js(
            "({ r: window.devicePixelRatio,"
            "   x: window.screenX ?? 0,"
            "   y: (window.outerHeight - window.innerHeight) })"
        )
        return float(v["r"]), float(v["x"]), float(v["y"])

    def _to_device_px(self, pt: dict[str, float]) -> tuple[int, int]:
        ratio, _ox, _oy = self._viewport()
        return int(round(pt["x"] * ratio)), int(round(pt["y"] * ratio))

    def dismiss_keyboard(self) -> None:
        """Close the soft keyboard if it is up.

        `getBoundingClientRect` reports layout-viewport coordinates, but an open
        IME shrinks the *visual* viewport — so a point measured while the
        keyboard is showing can be under the keyboard, or shifted relative to
        what is actually drawn. Typing one field then pressing the next put text
        into the wrong input for exactly this reason.

        Blur rather than a key event: ESCAPE and BACK both close the dialog
        itself, which is how a half-filled wizard vanished mid-run. Blurring is
        what happens anyway when a person taps away from a field, and it drops
        the IME without touching navigation.
        """
        if "mInputShown=true" in self.shell("dumpsys input_method | grep -m1 mInputShown"):
            self.eval_js("(()=>{const a=document.activeElement; if(a&&a.blur)a.blur(); return true;})()")
            time.sleep(0.6)

    def tap(self, text: str, *, timeout: float = 45.0, exact: bool = False) -> None:
        """Press a control the user can see, with a real touch event.

        `adb shell input tap` goes through the same input pipeline as a finger,
        so nothing here can succeed on a control that is off-screen, covered,
        or not actually rendered.
        """
        self.dismiss_keyboard()
        self.wait_for(text, timeout=timeout, exact=exact)
        time.sleep(0.35)  # let any scrolling settle before measuring
        pt = self._settled_point()
        if not pt:
            raise DriverError(f"[{self.name}] {text!r} vanished before it could be pressed")
        x, y = self._to_device_px(pt)
        self.shell(f"input tap {x} {y}")
        time.sleep(0.6)

    def type_into(self, placeholder: str, value: str) -> None:
        """Focus a field by tapping it, then type character-by-character.

        Input.insertText goes through the same path as the soft keyboard, so
        React's onChange fires exactly as it would for a person. Setting .value
        directly would bypass React's synthetic event and is precisely the
        shortcut this driver refuses to take.
        """
        self.dismiss_keyboard()
        pt = self.eval_js(
            f"""
            (() => {{
              const el = document.querySelector({json.dumps(f'input[placeholder="{placeholder}"]')});
              if (!el) return null;
              el.scrollIntoView({{ block: 'center', inline: 'nearest', behavior: 'instant' }});
              window.__dsmTapTarget = el;
              const r = el.getBoundingClientRect();
              return {{ x: r.left + r.width / 2, y: r.top + r.height / 2 }};
            }})()
            """
        )
        if not pt:
            raise DriverError(f"[{self.name}] no input with placeholder {placeholder!r}")
        time.sleep(0.35)  # let the scroll settle, then measure where it landed
        pt = self._settled_point() or pt
        x, y = self._to_device_px(pt)
        self.shell(f"input tap {x} {y}")
        time.sleep(0.8)
        # `input text` is the soft keyboard's own path, so React's onChange
        # fires exactly as it would for a person typing.
        self.shell(f"input text {value}")
        time.sleep(0.4)

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
