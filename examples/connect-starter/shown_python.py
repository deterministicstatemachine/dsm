#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The Python half of src/shown-code.test.ts: the Python the page shows,
evaluated by the real Python client.

Reads JSON on stdin:
  env       what the programs' variables hold (nonce, opponent, amountOut,
            atLeast, connection)
  calls     [{py, method?}]: each a shown expression; with `method`, the whole
            `app.<method>(...)` call, whose arguments are bound to the real
            method's signature
  programs  {name: source}: each whole shown program

Writes JSON on stdout:
  calls     [{value} | {error}]: what each expression makes, described as the
            TypeScript side describes its own (bytes as hex, numbers as
            digits, the TypeScript field names)
  programs  {name: [problems]}: each program compiled, and every call in it
            bound to the real library's signature

Usage: shown_python.py <path to clients/python>  (run with -I; the path is
put on sys.path so the package needs no install step beyond its runtime).

Every expression evaluated here is what src/pieces.ts wrote for a piece the
test composed: this repository's own code, run so it is checked, never
anything from outside.
"""

from __future__ import annotations

import ast
import inspect
import json
import sys
from types import SimpleNamespace
from typing import Any, Callable, Dict, List

sys.path.insert(0, sys.argv[1])

from dsm_app_client import AppAccount, Ask, Cap, Grant, Opponent, ask, grant, local_app, login_statement  # noqa: E402

CAMEL = {
    "per_request": "perRequest",
    "at_least": "atLeast",
    "device_id": "deviceId",
    "signing_key": "signingKey",
    "reserve_a": "reserveA",
    "reserve_b": "reserveB",
    "fee_bps": "feeBps",
    "free_requests": "freeRequests",
}


def describe(v: Any) -> Any:
    """A value as the TypeScript side states it."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return str(v)
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).hex()
    if isinstance(v, str) or v is None:
        return v
    if isinstance(v, Cap):
        return {"object": describe(v.object), "perRequest": describe(v.per_request), "total": describe(v.total)}
    if isinstance(v, Opponent):
        return {"genesis": v.genesis.hex(), "deviceId": v.device_id.hex(), "signingKey": v.signing_key.hex()}
    if isinstance(v, Grant):
        return describe_grant(v)
    if isinstance(v, Ask):
        return describe_ask(v)
    if isinstance(v, (list, tuple)):
        return [describe(x) for x in v]
    if isinstance(v, dict):
        return {CAMEL.get(k, k): describe(x) for k, x in v.items() if x is not None}
    raise TypeError(f"cannot describe {type(v).__name__}")


def describe_grant(g: Grant) -> Dict[str, Any]:
    if g.kind in ("send", "match"):
        return {"kind": g.kind, "caps": describe(g.caps)}
    if g.kind == "owns":
        return {"kind": g.kind, "objects": describe(g.objects)}
    if g.kind == "trade":
        return {"kind": g.kind, "pair": describe(g.objects), "caps": describe(g.caps)}
    if g.kind in ("accept", "contacts"):
        return {"kind": g.kind}
    raise ValueError(f"no such grant kind {g.kind}")


def describe_ask(a: Ask) -> Dict[str, Any]:
    if a.kind == "send":
        return {"kind": a.kind, "object": describe(a.object), "amount": describe(a.amount), "memo": a.memo}
    if a.kind == "owns":
        return {"kind": a.kind, "objects": describe(a.objects)}
    if a.kind == "accept":
        return {"kind": a.kind, "object": describe(a.object)}
    if a.kind == "contacts":
        return {"kind": a.kind}
    if a.kind == "sign":
        return {"kind": a.kind, "statement": a.statement}
    if a.kind == "price":
        return {"kind": a.kind, "from": describe(a.object), "to": describe(a.to), "amount": describe(a.amount)}
    if a.kind == "trade":
        return {"kind": a.kind, "from": describe(a.object), "to": describe(a.to), "amount": describe(a.amount), "atLeast": describe(a.at_least)}
    if a.kind == "stake":
        out = {
            "kind": a.kind,
            "match": a.match.hex(),
            "object": describe(a.object),
            "amount": describe(a.amount),
            "side": a.side,
            "opponent": describe(a.opponent),
            "memo": a.memo,
        }
        if len(a.against) > 0:
            out["against"] = a.against.hex()
        return out
    if a.kind == "collect":
        return {"kind": a.kind, "stakes": describe(a.stakes)}
    raise ValueError(f"no such ask kind {a.kind}")


def environment(env: Dict[str, Any]) -> Dict[str, Any]:
    opponent = Opponent(
        genesis=bytes.fromhex(env["opponent"]["genesis"]),
        device_id=bytes.fromhex(env["opponent"]["deviceId"]),
        signing_key=bytes.fromhex(env["opponent"]["signingKey"]),
    )
    return {
        "ask": ask,
        "grant": grant,
        "Cap": Cap,
        "bytes": bytes,
        "nonce": env["nonce"],
        "other": SimpleNamespace(opponent=opponent),
        "priced": SimpleNamespace(price=(0, int(env["amountOut"]), 0)),
        "at_least": int(env["atLeast"]),
        "connection": env["connection"],
    }


SNAKE = {"offer": "offer", "issue": "issue", "openVault": "open_vault", "give": "give"}


def bound_arguments(text: str, method: str, env: Dict[str, Any]) -> Dict[str, Any]:
    """The arguments a shown `app.<method>(...)` call binds to the real method."""
    tree = ast.parse(text, mode="eval")
    call = tree.body
    if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
        raise ValueError(f"not a method call: {text}")
    if not (isinstance(call.func.value, ast.Name) and call.func.value.id == "app" and call.func.attr == SNAKE[method]):
        raise ValueError(f"not app.{SNAKE[method]}(...): {text}")
    args = [eval(compile(ast.Expression(a), "<shown>", "eval"), {}, env) for a in call.args]
    kwargs = {k.arg: eval(compile(ast.Expression(k.value), "<shown>", "eval"), {}, env) for k in call.keywords if k.arg is not None}
    bound = inspect.signature(getattr(AppAccount, SNAKE[method])).bind(None, *args, **kwargs)
    return {name: value for name, value in bound.arguments.items() if name != "self"}


def evaluate(call: Dict[str, Any], env: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if call.get("method"):
            return {"value": describe(bound_arguments(call["py"], call["method"], env))}
        return {"value": describe(eval(compile(call["py"], "<shown>", "eval"), {}, dict(env)))}
    except Exception as e:  # the test reports it against the shown text
        return {"error": f"{type(e).__name__}: {e}"}


def callee(func: ast.expr) -> List[str]:
    """`app.give` → ["app", "give"]; `ask.match.stake` → ["ask", "match", "stake"]."""
    if isinstance(func, ast.Name):
        return [func.id]
    if isinstance(func, ast.Attribute):
        return callee(func.value) + [func.attr]
    return []


LIBRARY: Dict[str, Any] = {"ask": ask, "grant": grant, "login_statement": login_statement, "local_app": local_app}


def resolve(chain: List[str]) -> Callable[..., Any] | None:
    """The real library function a shown call names, or None where it names something else."""
    if chain[0] == "app" and len(chain) == 2:
        return getattr(AppAccount, chain[1], None)
    if chain[0] in LIBRARY:
        target: Any = LIBRARY[chain[0]]
        for part in chain[1:]:
            target = getattr(target, part, None)
            if target is None:
                return None
        return target if callable(target) else None
    return None


def check_program(source: str) -> List[str]:
    problems: List[str] = []
    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [f"does not compile: {e}"]
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        chain = callee(node.func)
        if not chain or chain[0] not in ("app", *LIBRARY):
            continue
        target = resolve(chain)
        if target is None:
            problems.append(f"{'.'.join(chain)} is not in the Python client")
            continue
        if any(isinstance(a, ast.Starred) for a in node.args) or any(k.arg is None for k in node.keywords):
            continue
        placeholders = [None] * len(node.args)
        if chain[0] == "app":
            placeholders.insert(0, None)  # self
        try:
            inspect.signature(target).bind(*placeholders, **{k.arg: None for k in node.keywords if k.arg is not None})
        except TypeError as e:
            problems.append(f"{'.'.join(chain)}: {e}")
    return problems


def main() -> int:
    request = json.load(sys.stdin)
    env = environment(request["env"])
    report = {
        "calls": [evaluate(c, env) for c in request["calls"]],
        "programs": {name: check_program(source) for name, source in request["programs"].items()},
    }
    json.dump(report, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main())
