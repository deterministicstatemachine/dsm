#!/usr/bin/env python3
# ci/bridge_rpc_names.py: every bridge RPC name the frontend sends is one Kotlin
# handles, and every name Kotlin handles is one the frontend sends.
#
# The bridge between the WebView and Kotlin is a method name on a
# BridgeRpcRequest. Nothing checked that the two sides agreed: `hasIdentityDirect`
# was sent for months and answered by the unknown-method arm, and Kotlin kept
# eight arms nothing sent (2026-09-26, #1009 and its follow-up). A name only one
# side knows is a fake by construction — the frontend wraps it in a default that
# downstream code reads as a measurement, or Kotlin keeps a path nothing
# exercises.
#
# Sent names are read from the frontend's production sources and from the bridge
# object `public/index.html` installs: a string literal passed to callBin,
# sendBridgeRequestBytes, buildBridgeRequest, callBoundaryMethod,
# callBridgeMethod or encodeBridgeRequest, and an upper-case identifier passed to
# callBin, resolved from a `const NAME = '…'` in the same file (unresolved: fail).
# Handled names are the string arms of the `when (method)` inside
# SinglePathWebViewBridge.handleBinaryRpcInternal.
#
# Exit 0 only when both sets are non-empty and equal. There is no allowlist: a
# name one side must stop using is removed from that side.

import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FRONTEND_SRC = os.path.join(ROOT, "dsm_client", "frontend", "src")
INDEX_HTML = os.path.join(ROOT, "dsm_client", "frontend", "public", "index.html")
KOTLIN_BRIDGE = os.path.join(
    ROOT, "dsm_client", "android", "app", "src", "main", "java", "com", "dsm", "wallet",
    "bridge", "SinglePathWebViewBridge.kt",
)

CALL_RE = re.compile(
    r"\b(?:callBin|sendBridgeRequestBytes|buildBridgeRequest|callBoundaryMethod)\(\s*[\"']([A-Za-z0-9_]+)[\"']"
)
CALL_IDENT_RE = re.compile(r"\bcallBin\(\s*([A-Z][A-Z0-9_]+)\b")
HTML_RE = re.compile(r"\b(?:callBridgeMethod|encodeBridgeRequest)\(\s*[\"']([A-Za-z0-9_]+)[\"']")
ARM_RE = re.compile(r"^\s*\"([A-Za-z0-9_]+)\"\s*->", re.M)


def fail(msg):
    print(f"[bridge-rpc-names] FAIL: {msg}")


def frontend_sources():
    for dirpath, dirnames, filenames in os.walk(FRONTEND_SRC):
        if "__tests__" in dirpath or os.sep + "proto" in dirpath[len(FRONTEND_SRC):]:
            continue
        for name in filenames:
            if not name.endswith((".ts", ".tsx")):
                continue
            if ".test." in name or name == "setupTests.ts" or name.endswith(".d.ts"):
                continue
            yield os.path.join(dirpath, name)


def sent_names():
    """{name: [where, ...]}; exits 2 on an identifier that resolves to nothing."""
    sent = {}
    unresolved = []
    for path in frontend_sources():
        text = open(path, encoding="utf-8").read()
        rel = os.path.relpath(path, ROOT)
        for m in CALL_RE.finditer(text):
            sent.setdefault(m.group(1), []).append(f"{rel}:{text.count(chr(10), 0, m.start()) + 1}")
        for m in CALL_IDENT_RE.finditer(text):
            const = re.search(r"\bconst\s+" + m.group(1) + r"\s*=\s*[\"']([A-Za-z0-9_]+)[\"']", text)
            where = f"{rel}:{text.count(chr(10), 0, m.start()) + 1}"
            if const:
                sent.setdefault(const.group(1), []).append(where)
            else:
                unresolved.append(f"{where} ({m.group(1)})")
    html = open(INDEX_HTML, encoding="utf-8").read()
    for m in HTML_RE.finditer(html):
        sent.setdefault(m.group(1), []).append(
            f"{os.path.relpath(INDEX_HTML, ROOT)}:{html.count(chr(10), 0, m.start()) + 1}"
        )
    if unresolved:
        fail("callBin called with an identifier no `const NAME = '…'` in its file names:")
        for u in unresolved:
            print(f"  {u}")
        sys.exit(2)
    return sent


def handled_names():
    text = open(KOTLIN_BRIDGE, encoding="utf-8").read()
    fn = text.find("fun handleBinaryRpcInternal(")
    if fn < 0:
        fail(f"{os.path.relpath(KOTLIN_BRIDGE, ROOT)}: handleBinaryRpcInternal not found")
        sys.exit(2)
    when = text.find("when (method) {", fn)
    if when < 0:
        fail("handleBinaryRpcInternal has no `when (method) {` block")
        sys.exit(2)
    i = text.index("{", when)
    depth = 0
    j = i
    while j < len(text):
        c = text[j]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                break
        j += 1
    block = text[i:j + 1]
    handled = {}
    for m in ARM_RE.finditer(block):
        handled.setdefault(m.group(1), []).append(
            f"{os.path.relpath(KOTLIN_BRIDGE, ROOT)}:{text.count(chr(10), 0, i + m.start()) + 1}"
        )
    return handled


def main():
    sent = sent_names()
    handled = handled_names()
    if not sent or not handled:
        fail(f"a scan that finds nothing is not a scan (sent={len(sent)}, handled={len(handled)})")
        return 2
    status = 0
    unhandled = sorted(set(sent) - set(handled))
    if unhandled:
        fail("the frontend sends bridge RPC names Kotlin does not handle:")
        for name in unhandled:
            print(f"  {name}: " + ", ".join(sent[name]))
        status = 1
    unsent = sorted(set(handled) - set(sent))
    if unsent:
        fail("Kotlin handles bridge RPC names the frontend never sends (dead arms):")
        for name in unsent:
            print(f"  {name}: " + ", ".join(handled[name]))
        status = 1
    if status == 0:
        print(f"[bridge-rpc-names] OK: {len(sent)} names sent, {len(handled)} handled, the same set")
    return status


if __name__ == "__main__":
    sys.exit(main())
