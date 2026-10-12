#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The checker must refuse changed requests, missing calls and wrong results."""
import pathlib
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
source = bytearray((root / 'target/sphincs-refinement/1-verify.bin').read_bytes())

def skip_blob(data, pos):
    size = int.from_bytes(data[pos:pos+4], 'big')
    return pos + 4 + size

pos = 9
for _ in range(4):
    pos = skip_blob(source, pos)
call_start = pos + 4
cases = {}
expected_errors = {}
changed = source.copy()
changed[8] = 1  # Rust success must not be reported as rejection.
cases['wrong-result'] = changed
changed = source.copy()
changed[call_start] = 2  # derive_key and derive-key-mode XOF are distinct.
cases['wrong-hash-mode'] = changed
changed = source.copy()
# First call: mode, context, key, input, output. Change public-seed input.
input_pos = skip_blob(changed, skip_blob(changed, call_start + 1))
changed[input_pos+4] ^= 1
cases['wrong-primitive-input'] = changed
cases['truncated'] = source[:-1]
cases['trailing'] = source + b'\x00'
expected_errors = {
    'wrong-result': 'result differs from Rust',
    'wrong-hash-mode': 'primitive request mismatch',
    'wrong-primitive-input': 'primitive request mismatch',
    'truncated': 'truncated blob',
    'trailing': 'trailing bytes',
}
with tempfile.TemporaryDirectory(prefix='dsm-sphincs-controls-') as directory:
    for name, data in cases.items():
        path = pathlib.Path(directory) / (name + '.bin')
        path.write_bytes(data)
        result = subprocess.run(
            ['lean', '--run', 'lean4/Sphincs/CrossCheck.lean', str(path)],
            cwd=root, text=True, capture_output=True, check=False)
        if result.returncode == 0:
            raise SystemExit(f'control {name} incorrectly passed')
        if expected_errors[name] not in result.stderr:
            raise SystemExit(f'control {name} failed for an unexpected reason: {result.stderr}')
        print(f'control {name}: correctly rejected: {result.stderr.strip()}')
