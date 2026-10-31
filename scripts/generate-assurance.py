#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""DSM's security-assurance record, beside the SBOM in one release bundle.

Writes `assurance.cdx.json` (CycloneDX 1.7) and `assurance-report.md` into an
SBOM run directory:

- the offline appliance's hardware and firmware (an HBOM), each firmware named
  by the git tree hash of its source at the commit under assessment;
- every requirement the repository maps to a gate (VERIFICATION_MATRIX), every
  internal security-audit finding (CONFORMANCE_GAPS, SA-*), the conformance
  status of each requirement, and the hardware properties the appliance must
  show on silicon;
- the evidence for each: what this run executed (with its command, exit code,
  log and the log's SHA-256), and what the repository records (named as a
  record, never as a result of this run).

Statuses: pass, fail (this run executed it), skipped (this run was told not
to), incomplete (named, but nothing in this run decides it), not-run (never
executed, such as a property of hardware not yet on the bench), recorded (the
repository records an earlier observation; this run did not repeat it).
"""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MATRIX = ROOT / "specs/requirements/VERIFICATION_MATRIX.md"
GAPS = ROOT / "specs/requirements/CONFORMANCE_GAPS.md"

# The offline appliance, as its firmware crates and README describe it.
HARDWARE = [
    {
        "bom-ref": "hw-pico2w",
        "type": "device",
        "name": "Raspberry Pi Pico 2 W",
        "manufacturer": "Raspberry Pi Ltd",
        "description": "The offline appliance's board: RP2350 with USB-CDC to the phone.",
    },
    {
        "bom-ref": "hw-rp2350",
        "type": "device",
        "name": "RP2350",
        "manufacturer": "Raspberry Pi Ltd",
        "description": "The appliance's microcontroller: Arm Cortex-M33 with TrustZone-M; the Secure world holds the partition key, the counter and the commit state.",
    },
    {
        "bom-ref": "hw-tropic01",
        "type": "device",
        "name": "TROPIC01",
        "manufacturer": "Tropic Square",
        "description": "Secure element on a MIKROE Secure Tropic Click, over SPI at 3.3 V: the chip signature, the MACANDD boot-fence and transfer-witness slots, and the monotonic counter.",
    },
]

FIRMWARE = [
    ("fw-anchor-pico", "crates/dsm-anchor-pico", "Single-image appliance firmware: TROPIC01 through libtropic-rs, the partition signature, the boot fence, and the appliance over USB-CDC."),
    ("fw-secure-monitor", "crates/dsm-anchor-secure-monitor", "TrustZone-M Secure world: TROPIC01, the partition key, the physical counter, prepare/commit/recovery state, the measurement seal, and the one Secure Gateway."),
    ("fw-nonsecure-app", "crates/dsm-anchor-nonsecure-app", "TrustZone-M Non-secure world: USB-CDC, protobuf and transport; reaches the Secure world only through the Secure Gateway."),
]

# What the appliance must show on silicon. Each stays not-run until a bench
# run records it.
HARDWARE_PROPERTIES = [
    ("HW-01", "Secure-element authentication: the appliance opens an authenticated session with its TROPIC01 and its certificate chain is checked."),
    ("HW-02", "Counter behaviour: the monotonic counter moves exactly once per committed transfer and never backwards."),
    ("HW-03", "Anti-cloning: a second device cannot present the same identity or reuse the counter."),
    ("HW-04", "Recovery after power loss: every crash point in prepare and commit recovers to one of the recovery table's outcomes."),
    ("HW-05", "Replay rejection: a transfer already committed is refused when presented again."),
    ("HW-06", "Completed offline transfers between two appliances over Bluetooth, settled online afterwards."),
]
HARDWARE_REASON = (
    "Not run on silicon. The hardware stage has not started; the Secure monitor's own manifest "
    "records full-crypto silicon validation as pending a clean TROPIC power cycle."
)


def git(*args):
    out = subprocess.run(["git", "-C", str(ROOT), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
    return out.stdout.strip() if out.returncode == 0 else ""


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def cells(line):
    return [c.strip() for c in line.strip().strip("|").split("|")]


def text_of(cell):
    return re.sub(r"\s+", " ", cell).strip()


def named_tests(cell):
    return [t for t in re.findall(r"`([A-Za-z_][\w:]*::[\w:]+)`", cell) if "::" in t]


def matrix_rows():
    rows = []
    for line in MATRIX.read_text().splitlines():
        if not line.startswith("| ") or re.match(r"^\|\s*:?-", line):
            continue
        c = cells(line)
        # Every requirement row of a matrix table: five cells, not the header.
        if len(c) < 5 or (c[0] == "Requirement" and c[1] == "Gate"):
            continue
        ids = re.findall(r"MR-[A-Z]+-\d{4}", c[0].split(":")[0])
        rows.append({"ids": ids, "text": text_of(c[0]), "gate": text_of(c[1]), "tests": named_tests(c[2]), "mutation": text_of(c[3]), "formal": text_of(c[4])})
    return rows


def audit_rows():
    rows = []
    for line in GAPS.read_text().splitlines():
        if not line.startswith("| SA-"):
            continue
        c = cells(line)
        status = text_of(c[-1])
        head = status.split("(")[0].strip().lower()
        if head.startswith("fixed in part") or head.startswith("partial"):
            state = "partial"
        elif head.startswith("fixed") or head.startswith("closed"):
            state = "closed"
        else:
            state = "open"
        rows.append({"id": c[0], "where": text_of(c[1]), "finding": text_of(c[2])[:400], "status": status, "state": state})
    return rows


def requirement_statuses():
    statuses = {}
    for line in GAPS.read_text().splitlines():
        m = re.match(r"\| (MR-[A-Z]+-\d{4}) \| (Met|Partial|Missing|Deferred|Violated|Not applicable|Superseded)\b", line)
        if m:
            statuses[m.group(1)] = m.group(2)
    return statuses


TIMESTAMP = re.compile(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ")
UNIT_BINARY = re.compile(r"Running unittests \S+ \(\S*/deps/(\w+)-[0-9a-f]+\)")
TEST_BINARY = re.compile(r"Running tests/\S+\.rs \(\S*/deps/(\w+)-[0-9a-f]+\)")
TEST_LINE = re.compile(r"^test (\S+)(?: - should panic)? \.\.\. ?(.*)$")
RESULT_LINE = re.compile(r"^test result: (ok|FAILED)\.")
FAILED_NAME = re.compile(r"^    (\S+)$")
SEVERITY = {"pass": 0, "skipped": 1, "fail": 2}


def crate_of_binaries():
    """Each binary target's name -> the crate name of the package that owns it.

    A package's binary can be named apart from its crate (the storage node's
    `storage_node`), and cargo names the binary, so the owner is read from the
    package manifests.
    """
    import tomllib

    owners = {}
    for manifest in git("ls-files", "*Cargo.toml").splitlines():
        data = tomllib.loads((ROOT / manifest).read_text())
        package = data.get("package")
        if not package:
            continue
        crate = data.get("lib", {}).get("name", package["name"]).replace("-", "_")
        bins = data.get("bin", [])
        names = [b["name"] for b in bins]
        declared = {b.get("path") for b in bins}
        if "src/main.rs" not in declared and (ROOT / manifest).parent.joinpath("src", "main.rs").exists():
            names.append(package["name"])
        for name in names:
            owners.setdefault(name.replace("-", "_"), set()).add(crate)
    return owners


def board_results(path):
    """Each test's full name -> pass/fail/skipped, from cargo's own output.

    Cargo runs one package at a time and names each test binary before it runs
    it: the package's unit tests as `Running unittests src/lib.rs
    (.../deps/<crate>-<hash>)` (or src/main.rs for a binary), then its
    integration tests as `Running tests/<file>.rs (...)`. The full name is the
    crate, the integration binary if any, and the test's path, as the
    verification matrix writes it, so a name is matched exactly.

    Under --nocapture a test's own output can stand between its name and its
    result, so a test whose result is not on its own line is decided by the
    binary's summary: failed if the binary lists it among its failures, passed
    otherwise. A binary that never prints its summary decides none of them.
    """
    results = {}
    if not path:
        return results
    owners = crate_of_binaries()

    def record(name, status):
        if SEVERITY[status] >= SEVERITY[results.get(name, status)]:
            results[name] = status

    crate, binary, started, failed = None, None, [], set()
    for raw in Path(path).read_text(errors="replace").splitlines():
        line = TIMESTAMP.sub("", raw).rstrip()
        m = UNIT_BINARY.search(line)
        if m:
            owner = owners.get(m.group(1), set())
            crate = crate if crate in owner else (min(owner) if len(owner) == 1 else m.group(1))
            binary, started, failed = None, [], set()
            continue
        m = TEST_BINARY.search(line)
        if m:
            binary, started, failed = m.group(1), [], set()
            continue
        m = TEST_LINE.match(line)
        if m and crate:
            name = "::".join(part for part in (crate, binary, m.group(1)) if part)
            outcome = {"ok": "pass", "FAILED": "fail", "ignored": "skipped"}.get(m.group(2))
            if outcome:
                record(name, outcome)
            else:
                started.append((m.group(1), name))
            continue
        m = FAILED_NAME.match(line)
        if m:
            failed.add(m.group(1))
            continue
        if RESULT_LINE.match(line):
            for short, name in started:
                record(name, "fail" if short in failed else "pass")
            started, failed = [], set()
    return results


TLA_REGISTRY = ROOT / "tools" / "vertical_validation" / "src" / "tla_runner.rs"
TLA_RUN = re.compile(r"Running TLC: (\S+) \((\S+\.cfg)\)")
TLA_VERDICT = re.compile(r"^\s+(PASSED|FAILED)\b")
FORMAL_SEVERITY = {"pass": 0, "incomplete": 1, "fail": 2}


def tla_results(log_path):
    """Each TLA+ specification and configuration the run checked -> pass/fail.

    The runner's registry names each configuration's label, specification and
    `.cfg`; its log gives one verdict per configuration. A specification fails
    if any of its configurations failed.
    """
    if not log_path or not Path(log_path).exists():
        return {}
    registry = TLA_REGISTRY.read_text()
    spec_of = {}
    for pattern in (
        r'expect_violation\(\s*"([^"]+)",\s*"([^"]+\.tla)",\s*"([^"]+\.cfg)"',
        r'label:\s*"([^"]+)"\.into\(\),\s*spec_file:\s*"([^"]+\.tla)"\.into\(\),\s*config_file:\s*"([^"]+\.cfg)"',
    ):
        for label, spec, _cfg in re.findall(pattern, registry):
            spec_of[label] = spec
    results = {}

    def record(name, status):
        if FORMAL_SEVERITY[status] >= FORMAL_SEVERITY[results.get(name, status)]:
            results[name] = status

    lines = Path(log_path).read_text(errors="replace").splitlines()
    for i, line in enumerate(lines):
        m = TLA_RUN.search(line)
        if not m:
            continue
        verdicts = [v.group(1) for v in (TLA_VERDICT.match(l) for l in lines[i + 1 : i + 4]) if v]
        status = {"PASSED": "pass", "FAILED": "fail"}.get(verdicts[0], "incomplete") if verdicts else "incomplete"
        label, cfg = m.group(1), m.group(2)
        names = [label, cfg, cfg.removesuffix(".cfg")]
        if label in spec_of:
            names += [spec_of[label], spec_of[label].removesuffix(".tla")]
        for name in names:
            record(name, status)
    return results


def formal_tla_status(artifact, results, overall):
    """A row's TLA+ artifact, decided by the specifications, configurations and labels it names.

    A row that names nothing the run can attribute takes the run's verdict when
    the run passed; when the run failed elsewhere, it is incomplete, never a
    failure borrowed from another specification.
    """
    if not results:
        return overall
    files = re.findall(r"\w+\.(?:tla|cfg)\b", artifact)
    words = [w for w in re.findall(r"[\w/-]+", artifact) if w in results]
    named = files or words
    if not named:
        return overall if overall != "fail" else "incomplete"
    states = [results.get(name, "incomplete") for name in named]
    return max(states, key=lambda state: FORMAL_SEVERITY[state])


def test_status(name, results):
    return results.get(name, "incomplete")


def board_status(results):
    if not results:
        return "incomplete"
    return "fail" if "fail" in results.values() else "pass"


def run_check(name, command, logs, cwd=ROOT):
    log = logs / f"{name}.log"
    out = subprocess.run(command, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
    log.write_text(out.stdout + out.stderr)
    return {"status": "pass" if out.returncode == 0 else "fail", "exit_code": out.returncode, "log": log}


def lean_check(logs):
    if shutil.which("lean") is None:
        return {"status": "skipped", "reason": "lean is not installed where this run executed"}
    files = sorted((ROOT / "lean4").glob("*.lean"))
    log = logs / "lean.log"
    failed = []
    lines = []
    for f in files:
        out = subprocess.run(["lean", "-DwarningAsError=true", str(f)], cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, encoding="utf-8")
        lines.append(f"{f.name}: {'OK' if out.returncode == 0 else 'FAIL'}\n{out.stdout}{out.stderr}")
        if out.returncode != 0:
            failed.append(f.name)
    log.write_text("\n".join(lines))
    return {"status": "fail" if failed else "pass", "exit_code": len(failed), "log": log, "modules": len(files), "failed": failed}


class Bom:
    def __init__(self, commit, run_dir):
        self.commit = commit
        self.run_dir = run_dir
        self.requirements = []
        self.claims = []
        self.evidence = []
        self.map = []
        self.report = []

    def rel(self, path):
        return str(Path(path).resolve().relative_to(self.run_dir.resolve().parent.parent)) if path else ""

    def add_evidence(self, ref, description, status, executed, **fields):
        data = [
            {"name": "status", "contents": {"attachment": {"content": status, "contentType": "text/plain"}}},
            {"name": "executed", "contents": {"attachment": {"content": executed, "contentType": "text/plain"}}},
            {"name": "commit", "contents": {"attachment": {"content": self.commit, "contentType": "text/plain"}}},
        ]
        for key, value in fields.items():
            if value in (None, "", []):
                continue
            data.append({"name": key, "contents": {"attachment": {"content": str(value), "contentType": "text/plain"}}})
        self.evidence.append({"bom-ref": ref, "propertyName": f"dsm:assurance:{status}", "description": description, "data": data})
        return ref

    def add_requirement(self, ref, identifier, text, target, evidence, conformance, rationale):
        self.requirements.append({"bom-ref": ref, "identifier": identifier, "text": text})
        claim = f"claim-{ref}"
        self.claims.append({"bom-ref": claim, "target": target, "predicate": text, "evidence": evidence})
        self.map.append({"requirement": ref, "claims": [claim], "conformance": {"score": conformance, "rationale": rationale}})


def score(statuses):
    if not statuses:
        return 0
    return round(sum(1 for s in statuses if s in ("pass", "recorded")) / len(statuses), 3)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run-dir", type=Path, help="the SBOM run directory (required)")
    ap.add_argument("--generated-at", help="the run's timestamp (required)")
    ap.add_argument("--sbom", type=Path, help="the consolidated software SBOM this record goes beside")
    ap.add_argument("--tla-evidence", type=Path, help="validation-evidence.json the SBOM run wrote")
    ap.add_argument("--board-log", type=Path, help="the cargo board log of this commit, to decide named tests")
    ap.add_argument("--skip-execution", action="store_const", const="yes", default="no", help="record what would be executed as skipped")
    args = ap.parse_args()
    if args.run_dir is None or args.generated_at is None:
        ap.error("--run-dir and --generated-at are required")
    if not args.run_dir.is_dir():
        ap.error(f"{args.run_dir} is not a directory")

    run_dir = args.run_dir
    logs = run_dir / "logs"
    if not logs.is_dir():
        logs.mkdir()
    commit = git("rev-parse", "HEAD") or "unknown"
    tree_state = "clean" if not git("status", "--porcelain") else "dirty"
    version = re.search(r'^version = "([^"]+)"', (ROOT / "dsm_client/deterministic_state_machine/dsm/Cargo.toml").read_text(), re.M).group(1)
    bom = Bom(commit, run_dir)
    # A board log decides named tests only for the commit it tested: a CI log
    # records the full SHA it checked out, and one that does not name this
    # commit would credit its results to code it never ran.
    if args.board_log and commit not in args.board_log.read_text(errors="replace"):
        ap.error(f"{args.board_log} does not name commit {commit}; its results cannot be credited to it")
    results = board_results(args.board_log)
    executing = args.skip_execution == "no"

    # ── Checks this run executes ─────────────────────────────────────────────
    checks = []
    def executed(name, title, command, outcome, why_not="this run was told to skip execution (CI's SBOM job; the release run executes)"):
        ref = f"ev-check-{name}"
        if outcome is None:
            status, fields = "skipped", {"command": " ".join(command), "reason": why_not}
        else:
            status = outcome["status"]
            fields = {"command": outcome.get("command", " ".join(command)), "exit_code": outcome.get("exit_code"), "reason": outcome.get("reason")}
            if outcome.get("log"):
                fields["log"] = bom.rel(outcome["log"])
                fields["log_sha256"] = sha256_file(outcome["log"])
        bom.add_evidence(ref, title, status, "this-run", **fields)
        checks.append((name, title, status, fields))
        return ref, status

    # The SBOM run executes the TLA check itself (validation-evidence.json); this record reads its result.
    tla, tla_why = None, "the SBOM run's TLA result was not given to this record"
    if args.tla_evidence and args.tla_evidence.exists():
        t = json.loads(args.tla_evidence.read_text())
        if t.get("status") == "skipped":
            tla_why = "the SBOM run skipped TLA validation (--skip-validation; CI's Formal Validation job runs it)"
        else:
            tla = {"status": t["status"], "exit_code": t.get("exit_code"), "log": run_dir.parent.parent / t["log_path"] if t.get("log_path") else None, "command": t.get("command")}
    tla_per_spec = tla_results(tla["log"] if tla and tla.get("log") else None)
    tla_ref, tla_status = executed("tla", "TLA+ model checking of every registered configuration", ["cargo", "run", "-p", "dsm_vertical_validation", "--", "tla-check"], tla, tla_why)
    lean_ref, lean_status = executed("lean", "Lean 4 kernel check of every module, sorry-free, warnings as errors", ["lean", "-DwarningAsError=true", "lean4/*.lean"], lean_check(logs) if executing else None)
    conf_ref, _ = executed("conformance-evidence", "Every requirement row names code and tests that exist", ["python3", "ci/conformance_evidence.py"], run_check("conformance-evidence", [sys.executable, "ci/conformance_evidence.py"], logs) if executing else None)
    guard_ref, _ = executed("real-code-guard", "No placeholder, fabricated result or boolean literal outside the baseline", ["python3", "scripts/real_code_guard.py"], run_check("real-code-guard", [sys.executable, "scripts/real_code_guard.py"], logs) if executing else None)
    sphincs_ref, _ = executed("sphincs-map", "Every SPHINCS+ signer and verifier is in the reviewed caller inventory", ["python3", "scripts/sphincs_source_map.py", "--check"], run_check("sphincs-map", [sys.executable, "scripts/sphincs_source_map.py", "--check"], logs) if executing else None)
    board_ref = bom.add_evidence(
        "ev-board", "The cargo board of this commit, deciding each named test",
        board_status(results), "this-run" if results else "not-given",
        log=bom.rel(args.board_log) if args.board_log else "",
        log_sha256=sha256_file(args.board_log) if args.board_log else "",
        reason="" if results else "no board log was given; each named test stays incomplete in this record (CI's board at this commit is where they run)",
    )

    # ── Software: every gate the verification matrix maps ────────────────────
    statuses = requirement_statuses()
    software_rows = []
    for i, row in enumerate(matrix_rows(), start=1):
        ident = ", ".join(row["ids"]) or f"row {i}"
        evidence = []
        test_states = []
        for t in row["tests"]:
            st = test_status(t, results)
            test_states.append(st)
        ev_tests = bom.add_evidence(f"ev-tests-{i}", f"Negative tests for {ident}: " + "; ".join(row["tests"]), "pass" if test_states and all(s == "pass" for s in test_states) else ("fail" if "fail" in test_states else "incomplete"), "this-run" if results else "not-given", tests="; ".join(f"{t}={s}" for t, s in zip(row["tests"], test_states)))
        evidence.append(ev_tests)
        mutation_state = "not-run" if row["mutation"].lower().startswith("not run") or row["mutation"] in ("", "—") else "recorded"
        evidence.append(bom.add_evidence(f"ev-mutation-{i}", f"Mutation control for {ident}", mutation_state, "recorded", record=row["mutation"], source="specs/requirements/VERIFICATION_MATRIX.md"))
        formal_state = "not-run"
        if row["formal"] not in ("", "—"):
            if "tla" in row["formal"].lower() or ".cfg" in row["formal"]:
                formal_state = formal_tla_status(row["formal"], tla_per_spec, tla_status)
            elif "lean" in row["formal"].lower():
                formal_state = lean_status
            else:
                formal_state = "recorded"
            evidence.append(bom.add_evidence(f"ev-formal-{i}", f"Formal artifact for {ident}", formal_state, "this-run" if formal_state in ("pass", "fail", "skipped") else "recorded", artifact=row["formal"]))
        conformance = [statuses.get(x, "unrecorded") for x in row["ids"]]
        states = [s for s in test_states] + [mutation_state]
        bom.add_requirement(f"req-{i}", ident, row["text"], "dsm-software", evidence, score(states), f"conformance per CONFORMANCE_GAPS: {', '.join(conformance)}; gate: {row['gate'][:300]}")
        software_rows.append((ident, test_states, mutation_state, formal_state, conformance))

    # ── Internal security audit ──────────────────────────────────────────────
    audit = audit_rows()
    for row in audit:
        ref = bom.add_evidence(f"ev-{row['id'].lower()}", f"{row['id']}: {row['finding'][:200]}", "recorded", "recorded", audit_status=row["status"], location=row["where"], source="specs/requirements/CONFORMANCE_GAPS.md")
        bom.add_requirement(f"req-{row['id'].lower()}", row["id"], row["finding"], "dsm-software", [ref], {"closed": 1, "partial": 0.5}.get(row["state"], 0), f"internal audit status: {row['status']}")

    # ── Hardware: the appliance on silicon ───────────────────────────────────
    for ident, text in HARDWARE_PROPERTIES:
        ref = bom.add_evidence(f"ev-{ident.lower()}", text, "not-run", "never", reason=HARDWARE_REASON)
        bom.add_requirement(f"req-{ident.lower()}", ident, text, "hw-pico2w", [ref], 0, HARDWARE_REASON)

    # ── The document ─────────────────────────────────────────────────────────
    firmware = []
    for ref, path, description in FIRMWARE:
        manifest = (ROOT / path / "Cargo.toml").read_text()
        fw_version = re.search(r'^version = "([^"]+)"', manifest, re.M).group(1)
        tree = git("rev-parse", f"HEAD:{path}")
        firmware.append({
            "bom-ref": ref, "type": "firmware", "name": Path(path).name, "version": fw_version, "description": description,
            "properties": [
                {"name": "dsm:source:path", "value": path},
                {"name": "dsm:source:git-tree", "value": tree},
                {"name": "dsm:build", "value": "not built in this run: a thumbv8m-only image, built from its own crate directory and flashed with picotool"},
            ],
        })
    sbom_link = []
    if args.sbom and args.sbom.exists():
        serial = json.loads(args.sbom.read_text()).get("serialNumber", "")
        if serial.startswith("urn:uuid:"):
            sbom_link = [{"type": "bom", "url": f"urn:cdx:{serial[len('urn:uuid:'):]}/1", "comment": "the software SBOM of this release"}]

    attested = len(bom.map)
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, f'dsm-assurance:{commit}:{run_dir.name}')}",
        "version": 1,
        "metadata": {
            "timestamp": args.generated_at,
            "component": {"bom-ref": "dsm-release", "type": "application", "name": "DSM", "version": version,
                          "properties": [{"name": "dsm:commit", "value": commit}, {"name": "dsm:tree-state", "value": tree_state}]},
        },
        "components": [
            {"bom-ref": "dsm-software", "type": "application", "name": "DSM software", "version": version,
             "description": "Core, SDK, storage node and frontend; every software component is in the SBOM this record goes beside.",
             **({"externalReferences": sbom_link} if sbom_link else {})},
            *[{k: v for k, v in h.items() if k != "manufacturer"} | {"manufacturer": {"name": h["manufacturer"]}} for h in HARDWARE],
            *firmware,
        ],
        "dependencies": [
            {"ref": "hw-pico2w", "dependsOn": ["hw-rp2350", "hw-tropic01", "fw-anchor-pico", "fw-secure-monitor", "fw-nonsecure-app"]},
        ],
        "definitions": {"standards": [{
            "bom-ref": "std-dsm", "name": "DSM security requirements", "version": commit[:12],
            "description": "Gates from specs/requirements/VERIFICATION_MATRIX.md, internal audit findings from specs/requirements/CONFORMANCE_GAPS.md, and the appliance's hardware properties.",
            "requirements": bom.requirements,
        }]},
        "declarations": {
            "assessors": [{"bom-ref": "assessor-dsm", "organization": {"name": "DSM (internal assessment)"}}],
            "attestations": [{"summary": f"DSM internal assurance at {commit[:12]}: {attested} requirements, each with its evidence and status.", "assessor": "assessor-dsm", "map": bom.map}],
            "claims": bom.claims,
            "evidence": bom.evidence,
        },
    }
    if sbom_link:
        doc["externalReferences"] = sbom_link
    (run_dir / "assurance.cdx.json").write_text(json.dumps(doc, indent=2) + "\n")

    # ── The report ───────────────────────────────────────────────────────────
    def count(states):
        out = {}
        for s in states:
            out[s] = out.get(s, 0) + 1
        return ", ".join(f"{n} {s}" for s, n in sorted(out.items())) or "none"
    all_tests = [s for _, ts, _, _, _ in software_rows for s in ts]
    conformance_counts = {}
    for status in statuses.values():
        conformance_counts[status] = conformance_counts.get(status, 0) + 1
    lines = [
        f"# DSM Security Assurance and Verification",
        "",
        f"- Commit: `{commit}` ({tree_state} tree), DSM {version}",
        f"- Generated: {args.generated_at}",
        f"- Machine-readable: `assurance.cdx.json` (CycloneDX 1.7: HBOM, firmware inventory, requirements, claims, evidence)",
        "",
        "Statuses: **pass**/**fail**, this run executed it; **skipped**, this run was told not to; **incomplete**, named but nothing in this run decides it; **not-run**, never executed; **recorded**, the repository records an earlier observation that this run did not repeat.",
        "",
        "## Checks executed by this run",
        "",
        "| Check | Status | Command | Log (SHA-256) |",
        "|---|---|---|---|",
    ]
    for name, title, status, fields in checks:
        log = f"`{fields['log']}` ({fields['log_sha256'][:16]}…)" if fields.get("log") else (fields.get("reason") or "")
        lines.append(f"| {title} | {status} | `{fields.get('command', '')}` | {log} |")
    lines += [
        "",
        "## Software verification",
        "",
        f"- Requirements mapped to a gate: {len(software_rows)} rows (`specs/requirements/VERIFICATION_MATRIX.md`).",
        f"- The cargo board of this commit: {board_status(results)}, `{bom.rel(args.board_log)}` ({sha256_file(args.board_log)[:16]}…)." if args.board_log else "- The cargo board of this commit: incomplete; no board log was given.",
        f"- Named negative tests: {len(all_tests)} ({count(all_tests)}){'' if results else '; no board log was given, so none is decided by this record'}.",
        f"- Mutation controls: {count([m for _, _, m, _, _ in software_rows])}.",
        f"- Formal artifacts named by a row: {count([f for _, _, _, f, _ in software_rows if f != 'not-run'])}.",
        f"- Conformance of every requirement (`CONFORMANCE_GAPS.md` §8): {', '.join(f'{n} {s}' for s, n in sorted(conformance_counts.items()))}.",
        "",
        "## Internal security audit",
        "",
        f"- Findings: {len(audit)} ({count([r['state'] for r in audit])}).",
        "",
        "| Finding | Status |",
        "|---|---|",
    ]
    for row in audit:
        if row["state"] != "closed":
            lines.append(f"| {row['id']}: {row['finding'][:160]} | {row['status']} |")
    lines += [
        "",
        "## Hardware and firmware",
        "",
        "| Component | Kind | Identity |",
        "|---|---|---|",
    ]
    for h in HARDWARE:
        lines.append(f"| {h['name']} | hardware ({h['manufacturer']}) | {h['description']} |")
    for f in firmware:
        tree = next(p["value"] for p in f["properties"] if p["name"] == "dsm:source:git-tree")
        lines.append(f"| {f['name']} {f['version']} | firmware | source tree `{tree}`; not built in this run |")
    lines += ["", "| Property | Status |", "|---|---|"]
    for ident, text in HARDWARE_PROPERTIES:
        lines.append(f"| {ident}: {text} | not-run |")
    lines += ["", HARDWARE_REASON, ""]
    (run_dir / "assurance-report.md").write_text("\n".join(lines))
    print(f"assurance: {attested} requirements, {len(bom.evidence)} evidence entries, checks: " + ", ".join(f"{n}={s}" for n, _, s, _ in checks))


if __name__ == "__main__":
    main()
