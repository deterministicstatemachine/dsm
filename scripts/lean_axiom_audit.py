#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Kernel axiom audit for every Lean proof module.

For each module, the kernel is asked which axioms each declared theorem
transitively depends on (Lean.collectAxioms, the same data `#print axioms`
reports). The result is written as a ledger, one row per theorem:

    specs/requirements/LEAN_AXIOM_LEDGER.tsv

Rules enforced (any violation fails, in generate and --check mode alike):
  * `sorryAx` never appears: no theorem rests on a placeholder.
  * `Lean.ofReduceBool` / `Lean.trustCompiler` never appear: no kernel proof
    trusts compiled code (native_decide).
  * Every other non-core axiom must be declared, with its justification, in
    specs/requirements/LEAN_DECLARED_ASSUMPTIONS.tsv. An undeclared axiom fails.
  * Every declared assumption must still exist (no stale declarations).

With --check the freshly computed ledger must equal the committed one, so any
change in what a theorem rests on is a reviewed diff, never silent.

The modules under lean4/Sphincs/RustExtraction use the Aeneas Lean backend and a
different toolchain; scripts/check_sphincs_source_refinement.sh gates them, and
they are listed in the ledger header as outside this audit.
"""
import pathlib
import re
import subprocess
import sys
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
lean_root = root / 'lean4'
out_dir = root / 'target' / 'lean-axiom-audit'
ledger_path = root / 'specs' / 'requirements' / 'LEAN_AXIOM_LEDGER.tsv'
declared_path = root / 'specs' / 'requirements' / 'LEAN_DECLARED_ASSUMPTIONS.tsv'

CORE = {'propext', 'Classical.choice', 'Quot.sound'}
FORBIDDEN = {'sorryAx', 'Lean.ofReduceBool', 'Lean.trustCompiler'}
OUTSIDE = 'lean4/Sphincs/RustExtraction (Aeneas backend; gated by scripts/check_sphincs_source_refinement.sh)'

AUDIT_SNIPPET = r'''
open Lean Elab Command in
#eval show CommandElabM Unit from do
  let env ← getEnv
  let some idx := env.getModuleIdx? `{module} | throwError "module {module} not loaded"
  let mut rows : Array String := #[]
  for (n, ci) in env.constants.map₁.toList do
    if env.getModuleIdxFor? n == some idx then
      if let .thmInfo _ := ci then
        if !n.isInternal then
          if (← findDeclarationRanges? n).isSome then
            let axs ← Lean.collectAxioms n
            let names := (axs.map toString).qsort (· < ·)
            rows := rows.push s!"{{n}}\t{{",".intercalate names.toList}}"
  for r in rows.qsort (· < ·) do
    IO.println s!"AXIOMS\t{{r}}"
'''


def modules():
    """All audited modules as (module_name, path), in import order."""
    paths = sorted(lean_root.glob('*.lean')) + sorted((lean_root / 'Sphincs').glob('*.lean'))
    found = {}
    for p in paths:
        name = '.'.join(p.relative_to(lean_root).with_suffix('').parts)
        imports = re.findall(r'(?m)^import\s+(\S+)', p.read_text())
        found[name] = (p, imports)
    order, seen = [], set()

    def visit(n, stack=()):
        if n in seen or n not in found:
            return
        if n in stack:
            raise SystemExit(f'import cycle at {n}')
        for dep in found[n][1]:
            visit(dep, stack + (n,))
        seen.add(n)
        order.append((n, found[n][0]))

    for n in sorted(found):
        visit(n)
    return order


def run(cmd, **kw):
    r = subprocess.run(cmd, cwd=root, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        sys.stderr.write(r.stdout + r.stderr)
        raise SystemExit(f'failed: {" ".join(map(str, cmd))}')
    return r.stdout


def audit():
    out_dir.mkdir(parents=True, exist_ok=True)
    env = {'LEAN_PATH': str(out_dir), 'PATH': subprocess.os.environ['PATH'],
           'HOME': subprocess.os.environ.get('HOME', '')}
    rows = []
    for name, path in modules():
        olean = out_dir / pathlib.Path(*name.split('.')).with_suffix('.olean')
        olean.parent.mkdir(parents=True, exist_ok=True)
        run(['lean', '-DwarningAsError=true', '-R', str(lean_root), '-o', str(olean), str(path)], env=env)
        with tempfile.NamedTemporaryFile('w', suffix='.lean', dir=out_dir, delete=False) as f:
            f.write(f'import Lean\nimport {name}\n' + AUDIT_SNIPPET.format(module=name))
            probe = f.name
        try:
            text = run(['lean', probe], env=env)
        finally:
            pathlib.Path(probe).unlink()
        rel = path.relative_to(root).as_posix()
        for line in text.splitlines():
            if line.startswith('AXIOMS\t'):
                _, thm, axs = line.split('\t', 2)
                rows.append((rel, thm, axs))
    return rows


def declared():
    if not declared_path.exists():
        return {}
    table = {}
    for line in declared_path.read_text().splitlines()[1:]:
        if not line.strip():
            continue
        cols = line.split('\t')
        if len(cols) < 3 or not cols[2].strip():
            raise SystemExit(f'declared assumption without justification: {line}')
        table[cols[0]] = cols
    return table


def main():
    rows = audit()
    decl = declared()
    errors, used = [], {}
    for module, thm, axs in rows:
        for ax in filter(None, axs.split(',')):
            if ax in FORBIDDEN:
                errors.append(f'{module}: {thm} rests on forbidden axiom {ax}')
            elif ax not in CORE:
                used.setdefault(ax, set()).add(thm)
                if ax not in decl:
                    errors.append(f'{module}: {thm} rests on undeclared axiom {ax}')
    for ax in decl:
        if ax not in used:
            errors.append(f'declared assumption {ax} is no longer used by any theorem; remove it')
    header = ['# Generated by scripts/lean_axiom_audit.py; do not edit by hand.',
              f'# Core axioms (always permitted): {", ".join(sorted(CORE))}.',
              f'# Never permitted: {", ".join(sorted(FORBIDDEN))}.',
              f'# Outside this audit: {OUTSIDE}.',
              'module\ttheorem\taxioms']
    body = [f'{m}\t{t}\t{a if a else "(none)"}' for m, t, a in sorted(rows)]
    ledger = '\n'.join(header + body) + '\n'
    summary = [f'{len(rows)} theorems audited across {len({m for m, _, _ in rows})} modules']
    for ax in sorted(used):
        summary.append(f'  {ax}: {len(used[ax])} theorem(s)')
    print('\n'.join(summary))
    if '--check' in sys.argv:
        if not ledger_path.exists() or ledger_path.read_text() != ledger:
            errors.append('LEAN_AXIOM_LEDGER.tsv is stale; regenerate and review the diff')
    else:
        ledger_path.write_text(ledger)
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
