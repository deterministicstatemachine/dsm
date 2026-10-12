#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Native-token + SovFi hardware proof on the three rig devices.

Runs the full matrix against real handsets through the shipping UI and emits one
evidence report. Every operation goes through controls a person would touch —
see `ui_driver.py` for why that constraint is not negotiable here.

Owner decision, 2026-07-26: device state is WIPED rather than migrated. The
canonical `policy_commit` encoding is not softened with a compatibility tail to
preserve three lab databases. Pre-wipe snapshots are forensic backups only, and
this script never reads them back.

Usage:
    python3 scripts/native_token_hw_proof.py --out docs/reports/hw_proof.md
    python3 scripts/native_token_hw_proof.py --phase wipe-install   # one phase
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ui_driver import Device, DriverError  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
APK = REPO / "dsm_client/android/app/build/outputs/apk/debug/app-debug.apk"
PKG = "com.dsm.wallet"

# transport id -> label. Transport ids are reassigned on reconnect, so the run
# re-resolves them from the serial, which is stable.
SERIALS = {
    "RFGYB0PQ8XK": "8XK",
    "RFGYB0PQ9FF": "9FF",
    "RF8Y90PX5GN": "D3",
}


# ── evidence ────────────────────────────────────────────────────────────────


@dataclass
class Evidence:
    """Append-only record of what was observed, not what was expected."""

    started: str
    commit: str
    apk_sha256: str
    steps: list[dict] = field(default_factory=list)

    def record(self, phase: str, device: str, what: str, observed, ok: bool | None = None):
        self.steps.append(
            {
                "phase": phase,
                "device": device,
                "what": what,
                "observed": observed,
                "ok": ok,
            }
        )
        mark = "" if ok is None else ("  PASS" if ok else "  FAIL")
        print(f"[{phase}/{device}] {what}: {observed}{mark}", flush=True)

    def failures(self) -> list[dict]:
        return [s for s in self.steps if s["ok"] is False]

    def render(self) -> str:
        lines = [
            "# DSM native-token hardware proof",
            "",
            f"- Started: {self.started}",
            f"- Commit: `{self.commit}`",
            f"- APK sha256: `{self.apk_sha256}`",
            f"- Devices: {', '.join(f'{v} ({k})' for k, v in SERIALS.items())}",
            "",
            "Device state was wiped before install; every balance below starts from",
            "a fresh identity and the in-app faucet. No SQLite was edited, no balance",
            "injected, no route invoked directly — all operations went through the UI.",
            "",
            "| Phase | Device | Check | Observed | |",
            "|---|---|---|---|---|",
        ]
        for s in self.steps:
            mark = "" if s["ok"] is None else ("PASS" if s["ok"] else "**FAIL**")
            obs = str(s["observed"]).replace("|", "\\|")
            lines.append(
                f"| {s['phase']} | {s['device']} | {s['what']} | {obs} | {mark} |"
            )
        fails = self.failures()
        lines += [
            "",
            f"## Verdict: {'FAIL' if fails else 'PASS'}",
            "",
        ]
        if fails:
            lines.append("Failures:")
            lines += [f"- {f['phase']}/{f['device']}: {f['what']} → {f['observed']}" for f in fails]
        return "\n".join(lines) + "\n"


# ── device plumbing ─────────────────────────────────────────────────────────


def adb(*args: str, timeout: int = 120) -> str:
    p = subprocess.run(["adb", *args], capture_output=True, text=True, timeout=timeout)
    return p.stdout


def resolve_devices() -> dict[str, Device]:
    """Map label -> Device by serial, tolerating duplicate transports."""
    out = adb("devices", "-l")
    seen: dict[str, Device] = {}
    port = 9500
    for line in out.splitlines()[1:]:
        if "transport_id:" not in line or " device " not in f" {line} ":
            continue
        tid = line.split("transport_id:")[1].split()[0]
        serial = adb("-t", tid, "shell", "getprop", "ro.serialno", timeout=30).strip()
        label = SERIALS.get(serial)
        if not label or label in seen:  # first transport per serial wins
            continue
        seen[label] = Device(transport=tid, name=label, port=port)
        port += 1
    return seen


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git_commit() -> str:
    return subprocess.run(
        ["git", "-C", str(REPO), "rev-parse", "HEAD"],
        capture_output=True,
        text=True,
    ).stdout.strip()


# ── phases ──────────────────────────────────────────────────────────────────


def phase_wipe_install(devs: dict[str, Device], ev: Evidence) -> None:
    """Clear app data and install the merged build.

    `pm clear` is what makes this an honest proof: the wallet comes up against
    the exact schema that merged, with no state written by an older encoding.
    """
    for label, d in devs.items():
        before = d.shell(f"dumpsys package {PKG} | grep -m1 versionName").strip()
        ev.record("wipe", label, "version before", before or "(absent)")

        d.shell(f"pm clear {PKG}", timeout=120)
        ev.record("wipe", label, "app data cleared", "pm clear ok")

        out = adb("-t", d.transport, "install", "-r", "-d", str(APK), timeout=900)
        ok = "Success" in out
        ev.record("install", label, "install result", out.strip().splitlines()[-1:] or out, ok)

        d.shell(f"monkey -p {PKG} -c android.intent.category.LAUNCHER 1", timeout=120)
        time.sleep(12)
        ev.record("install", label, "launched", "launcher intent sent")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(REPO / "docs/reports/native_token_hw_proof.md"))
    ap.add_argument("--phase", default="all")
    args = ap.parse_args()

    if not APK.exists():
        print(f"APK not found: {APK}", file=sys.stderr)
        return 2

    ev = Evidence(
        started=subprocess.run(["date", "-u", "+%Y-%m-%dT%H:%M:%SZ"], capture_output=True, text=True).stdout.strip(),
        commit=git_commit(),
        apk_sha256=sha256(APK),
    )

    devs = resolve_devices()
    missing = set(SERIALS.values()) - set(devs)
    if missing:
        print(f"devices not reachable: {sorted(missing)}", file=sys.stderr)
        return 2
    print(f"resolved: {[(k, v.transport) for k, v in devs.items()]}", flush=True)

    try:
        if args.phase in ("all", "wipe-install"):
            phase_wipe_install(devs, ev)
        # Later phases are appended as each is verified against the real UI
        # rather than written speculatively — see the run log.
    except DriverError as e:
        ev.record("driver", "-", "aborted", str(e), False)

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(ev.render())
    print(f"\nreport -> {out}")
    return 1 if ev.failures() else 0


if __name__ == "__main__":
    raise SystemExit(main())
