#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check specs/requirements/CLAIM_TRACE.tsv against the proofs and the code.

Every theorem a claim names must exist in LEAN_AXIOM_LEDGER.tsv and rest on
Lean's core axioms only. Every implementation symbol (file::symbol) and test
(file::fn, or a bare file) must exist. A row naming no theorem must say why
(status starting NO THEOREM). Run after scripts/lean_axiom_audit.py.
"""
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parents[1]
req = root / 'specs' / 'requirements'
ALIASES = {'C/': 'dsm_client/deterministic_state_machine/dsm/src/',
           'S/': 'dsm_client/deterministic_state_machine/dsm_sdk/src/',
           'P/': 'crates/dsm-sphincs/src/'}
CORE = {'propext', 'Classical.choice', 'Quot.sound', '(none)'}


def rows(path):
    lines = [l for l in path.read_text().splitlines() if l and not l.startswith('#')]
    header = lines[0].split('\t')
    return [dict(zip(header, l.split('\t'))) for l in lines[1:]]


def resolve(ref):
    for a, full in ALIASES.items():
        if ref.startswith(a):
            return full + ref[len(a):]
    return ref


def main():
    ledger = {}
    for r in rows(req / 'LEAN_AXIOM_LEDGER.tsv'):
        ledger.setdefault(r['module'], {})[r['theorem']] = set(r['axioms'].split(','))
    errors, checked = [], 0
    for r in rows(req / 'CLAIM_TRACE.tsv'):
        cid = r['id']
        if r['theorems'] == '—':
            if not r['status'].startswith('NO THEOREM'):
                errors.append(f'{cid}: no theorem and status does not say NO THEOREM')
            continue
        for ref in r['theorems'].split(','):
            module, name = ref.split(':')
            thms = ledger.get(module, {})
            hits = [t for t in thms if t == name or t.endswith('.' + name)]
            if len(hits) != 1:
                errors.append(f'{cid}: theorem {ref} not found exactly once in the ledger')
                continue
            extra = thms[hits[0]] - CORE
            if extra:
                errors.append(f'{cid}: {ref} rests on non-core axioms {sorted(extra)}')
            checked += 1
        for col in ('implementation', 'tests'):
            if r[col] == '—':
                continue
            for ref in r[col].split(','):
                path, _, sym = resolve(ref).partition('::')
                f = root / path
                if not f.is_file():
                    errors.append(f'{cid}: {col} file missing: {path}')
                elif sym and not re.search(r'\b(fn|struct|enum|mod)\s+' + re.escape(sym) + r'\b', f.read_text()):
                    errors.append(f'{cid}: {col} symbol missing: {path}::{sym}')
    print(f'claim trace: {checked} theorem references checked')
    if errors:
        print('\n'.join(errors), file=sys.stderr)
        raise SystemExit(1)


if __name__ == '__main__':
    main()
