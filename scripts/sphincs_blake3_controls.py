#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Check that independent BLAKE3 recomputation rejects altered Rust evidence."""
import pathlib
import subprocess
import sys
import tempfile


def main():
    checker = ([sys.argv[1]] if len(sys.argv) == 2 else
               ["lean", "-DwarningAsError=true", "--run", "lean4/Sphincs/Blake3Checks.lean"])
    source = pathlib.Path("target/sphincs-refinement/wrapper-3.bin")
    data = bytearray(source.read_bytes())
    # Skip the fixed construction/variant/operation/result header and four blobs.
    pos = 9
    for _ in range(4):
        size = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4 + size
    count = int.from_bytes(data[pos:pos + 4], "big")
    if count != 1:
        raise RuntimeError("expected the one-hash wrapper fixture")
    mode_pos = pos + 4
    controls = [("altered-output", len(data) - 1, data[-1] ^ 1,
                 "BLAKE3 bytes differ"),
                ("unknown-mode", mode_pos, 99, "invalid BLAKE3 request")]
    with tempfile.TemporaryDirectory(prefix="dsm-blake3-controls-") as temp:
        for label, offset, value, expected in controls:
            mutated = data.copy()
            mutated[offset] = value
            path = pathlib.Path(temp) / (label + ".bin")
            path.write_bytes(mutated)
            run = subprocess.run(
                checker + [str(path)],
                capture_output=True, text=True, check=False)
            if run.returncode == 0 or expected not in run.stdout + run.stderr:
                raise RuntimeError(f"{label}: unexpected checker result: {run.stdout}{run.stderr}")
            print(f"BLAKE3 control {label}: correctly rejected")


if __name__ == "__main__":
    main()
