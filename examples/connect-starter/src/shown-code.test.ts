// SPDX-License-Identifier: MIT OR Apache-2.0

// The code the page shows is the code the starter runs: proven, not promised.
//
// For every piece the page can compose (each grant, each ask, issue, vault,
// give, decide), src/pieces.ts makes calls that carry the value the starter
// hands the client and the same call written in TypeScript and in Python.
// This test takes each call's text as shown, evaluates it with the real client
// library (`dsm-app-client`, and the Python package `dsm_app_client` through
// shown_python.py), with the program's own variables bound, and checks that
// what the text makes is what the starter runs. Then the whole TypeScript
// program of every piece is type-checked against the real client, and the
// whole Python program is compiled and every call in it bound to the real
// library's signatures.
//
//   npm test            (after npm run build)
//   make developer-path runs it before the live path; so does CI.
//
// The Python half needs the Python client importable with its protobuf
// runtime: DEVELOPER_PATH_PYTHON names the interpreter, else the repo's
// .venv (python3 -m venv .venv && pip install -e clients/python, as the
// guide says), else python3.

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { ask, grant } from "dsm-app-client";
import { callsOf, pyOf, tsOf, type Call, type CodeAsk, type Env } from "./pieces.js";

const STARTER = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const REPO = path.resolve(STARTER, "..", "..");
const APP = "Connect Starter";
const CONNECTION = "0123456789ABCDEFGHJKMNPQRS";
const STAKE_A = "aa".repeat(32);
const STAKE_B = "bb".repeat(32);

/** What the programs' variables hold, for both languages alike. */
const ENV: Env = {
  nonce: "6f1d2c3b-4a59-4e87-9c10-2b3a4c5d6e7f",
  opponent: { genesis: new Uint8Array(32).fill(1), deviceId: new Uint8Array(32).fill(2), signingKey: new Uint8Array(32).fill(3) },
  amountOut: 5000n,
  atLeast: 4750n,
};

/** Every kind of piece the page composes, with the values its fields start from. */
const PIECES: Record<string, CodeAsk> = {
  offer: {
    piece: "offer",
    offer: {
      name: "My Game",
      grants: [
        { kind: "send", object: "ERA", perRequest: "0.10", total: "1.00" },
        { kind: "owns", objects: ["ERA"] },
        { kind: "accept" },
        { kind: "contacts" },
        { kind: "match", object: "ERA", perRequest: "1.00", total: "2.00" },
        { kind: "trade", from: "ERA", to: "GOLD", perRequest: "1.00", total: "5.00" },
      ],
    },
  },
  issue_coin: { piece: "issue", issue: { symbol: "GOLD", name: "Starter gold", supply: "1000000", decimals: 2, transferable: true, burnable: false } },
  issue_item: { piece: "issue", issue: { symbol: "SWORD", name: "Starter sword", supply: "1", decimals: 0, transferable: false, burnable: true } },
  vault: { piece: "vault", vault: { a: "GOLD", reserveA: "1000", b: "ERA", reserveB: "10", feeBps: 30, label: "My Game shop" } },
  vault_unlabelled: { piece: "vault", vault: { a: "GOLD", reserveA: "1000", b: "ERA", reserveB: "10", feeBps: 25, label: "" } },
  give: { piece: "give", connection: CONNECTION, give: { object: "SWORD", amount: "1" }, app: APP },
  decide: { piece: "decide", decide: { stake: STAKE_A, decision: "A" } },
  send: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "send", object: "ERA", amount: "0.05", memo: "a sword" } },
  send_no_memo: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "send", object: "ERA", amount: "0.05", memo: "" } },
  owns: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "owns", objects: ["ERA", "GOLD"] } },
  accept: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "accept", object: "GOLD" } },
  contacts: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "contacts" } },
  login: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "login" } },
  sign: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "sign", statement: "I accept the tournament rules" } },
  price: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "price", from: "ERA", to: "GOLD", amount: "0.50" } },
  trade: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "trade", from: "ERA", to: "GOLD", amount: "0.50", atLeastPercent: 95 } },
  stake_a: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "stake", match: "match 1", object: "ERA", amount: "1.00", side: "A", against: "" } },
  stake_b: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "stake", match: "match 1", object: "ERA", amount: "1.00", side: "B", against: STAKE_A } },
  collect: { piece: "ask", connection: CONNECTION, app: APP, ask: { kind: "collect", stakes: [STAKE_A, STAKE_B] } },
};

/** A value as both languages can state it: bytes as hex, numbers as digits, nothing for what is unset. */
function describe(v: unknown): unknown {
  if (typeof v === "bigint" || typeof v === "number") return v.toString();
  if (v instanceof Uint8Array) return Buffer.from(v).toString("hex");
  if (Array.isArray(v)) return v.map(describe);
  if (v !== null && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) if (x !== undefined) out[k] = describe(x);
    return out;
  }
  return v;
}

/**
 * The shown TypeScript, evaluated with the real client and the program's
 * variables bound. The text is what src/pieces.ts wrote for a piece this test
 * composed: this repository's own code, run here so it is checked, never
 * anything from outside.
 */
function evaluateTs(text: string): unknown {
  const bound: Record<string, unknown> = {
    ask,
    grant,
    Buffer,
    nonce: ENV.nonce,
    other: { opponent: ENV.opponent },
    priced: { price: { amountOut: ENV.amountOut } },
    atLeast: ENV.atLeast,
    connection: CONNECTION,
  };
  const evaluate = new Function(...Object.keys(bound), `"use strict";\nreturn (\n${text}\n);`) as (...args: unknown[]) => unknown;
  return evaluate(...Object.values(bound));
}

/** Every string and number in a value, as the shown code must spell it. */
function literals(v: unknown): string[] {
  if (typeof v === "string") return [JSON.stringify(v)];
  if (typeof v === "number") return [String(v)];
  if (Array.isArray(v)) return v.flatMap(literals);
  if (v !== null && typeof v === "object") return Object.values(v).flatMap(literals);
  return [];
}

function checkTs(name: string, program: string, call: Call<unknown>): void {
  assert.ok(program.includes(call.ts), `${name}: the TypeScript program does not contain the call it is made of:\n${call.ts}\n---\n${program}`);
  if (call.method !== undefined && !call.ts.startsWith("{")) {
    // A method call with positional arguments: each of the value's literals is in it.
    for (const literal of literals(call.value)) {
      assert.ok(call.ts.includes(literal), `${name}: ${call.ts} does not spell ${literal}`);
    }
    return;
  }
  let made: unknown;
  try {
    made = evaluateTs(call.ts);
  } catch (e) {
    assert.fail(`${name}: the shown TypeScript does not evaluate: ${e instanceof Error ? e.message : String(e)}\n${call.ts}`);
  }
  assert.deepEqual(describe(made), describe(call.value), `${name}: the shown TypeScript makes something else than the starter runs:\n${call.ts}`);
}

interface PyCall {
  py: string;
  method?: string;
}
interface PyReport {
  calls: ({ value: unknown } | { error: string })[];
  programs: string[][];
}

function python(): string {
  if (process.env.DEVELOPER_PATH_PYTHON) return process.env.DEVELOPER_PATH_PYTHON;
  const venv = path.join(REPO, ".venv", "bin", "python");
  return existsSync(venv) ? venv : "python3";
}

/** The shown Python, evaluated by the real Python client in one interpreter run. */
function evaluatePy(calls: PyCall[], programs: Record<string, string>): PyReport {
  const input = {
    env: {
      nonce: ENV.nonce,
      opponent: describe(ENV.opponent),
      amountOut: ENV.amountOut.toString(),
      atLeast: ENV.atLeast.toString(),
      connection: CONNECTION,
    },
    calls,
    programs,
  };
  const run = spawnSync(python(), ["-I", path.join(STARTER, "shown_python.py"), path.join(REPO, "clients", "python")], {
    input: JSON.stringify(input),
    encoding: "utf8",
  });
  if (run.status !== 0) {
    assert.fail(
      `shown_python.py (${python()}) failed: ${run.stderr || run.error?.message}\n` +
        `The Python client must be importable with its protobuf runtime: python3 -m venv .venv && . .venv/bin/activate && pip install -e clients/python`,
    );
  }
  return JSON.parse(run.stdout) as PyReport;
}

/** `value` as Python states the same call's bound arguments: only the keys the TypeScript value has. */
function subset(expected: unknown, made: unknown): unknown {
  if (Array.isArray(expected) && Array.isArray(made)) return made.map((m, i) => subset(expected[i], m));
  if (expected !== null && typeof expected === "object" && made !== null && typeof made === "object" && !Array.isArray(expected)) {
    const out: Record<string, unknown> = {};
    const m = made as Record<string, unknown>;
    for (const k of Object.keys(expected)) out[k] = subset((expected as Record<string, unknown>)[k], m[k]);
    return out;
  }
  return made;
}

test("every call the page shows, in TypeScript, makes what the starter runs", () => {
  for (const [name, piece] of Object.entries(PIECES)) {
    const program = tsOf(piece);
    const calls = callsOf(piece, ENV);
    assert.ok(calls.length > 0, `${name}: no calls`);
    for (const call of calls) checkTs(name, program, call);
  }
});

test("every call the page shows, in Python, makes what the starter runs", () => {
  const flat: { name: string; call: Call<unknown> }[] = [];
  const programs: Record<string, string> = {};
  for (const [name, piece] of Object.entries(PIECES)) {
    const program = pyOf(piece);
    programs[name] = program;
    for (const call of callsOf(piece, ENV)) {
      assert.ok(program.includes(call.py), `${name}: the Python program does not contain the call it is made of:\n${call.py}\n---\n${program}`);
      flat.push({ name, call });
    }
  }
  const report = evaluatePy(
    flat.map(({ call }) => ({ py: call.py, method: call.method })),
    programs,
  );
  assert.equal(report.calls.length, flat.length);
  flat.forEach(({ name, call }, i) => {
    const made = report.calls[i];
    if (made === undefined || "error" in made) {
      assert.fail(`${name}: the shown Python does not evaluate: ${made === undefined ? "no answer" : made.error}\n${call.py}`);
    }
    const expected = describe(call.value);
    const got = call.method === undefined ? made.value : subset(expected, made.value);
    assert.deepEqual(got, expected, `${name}: the shown Python makes something else than the starter runs:\n${call.py}`);
  });
  for (const [name, problems] of Object.entries(report.programs)) {
    assert.deepEqual(problems, [], `${name}: the Python program does not hold against the real client:\n${problems.join("\n")}\n---\n${programs[name]}`);
  }
});

test("every TypeScript program the page shows type-checks against the real client", () => {
  const dir = path.join(STARTER, ".shown");
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir);
  for (const [name, piece] of Object.entries(PIECES)) writeFileSync(path.join(dir, `${name}.ts`), `${tsOf(piece)}\n`);
  writeFileSync(
    path.join(dir, "tsconfig.json"),
    JSON.stringify({ extends: "../tsconfig.json", compilerOptions: { rootDir: ".", noEmit: true, declaration: false }, include: ["./*.ts"] }, null, 2),
  );
  const tsc = spawnSync(path.join(STARTER, "node_modules", ".bin", "tsc"), ["-p", path.join(dir, "tsconfig.json")], { encoding: "utf8" });
  assert.equal(tsc.status, 0, `the shown TypeScript does not type-check:\n${tsc.stdout}${tsc.stderr}`);
});
