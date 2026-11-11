#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""Every command the guide shows is one the repo has, so the pages cannot drift
from what works.

For each ```bash block in guide/src/*.md:
  - it parses (`bash -n`);
  - no line ends in a `# comment`: zsh, macOS's default shell, does not take
    comments typed at its prompt, so a pasted block with one breaks;
  - every `make <target>` is a target in the Makefile;
  - every `make app ARGS=<command>` is a command of the app's command line
    (clients/typescript/src/app-cli.ts), and every `make wallet ARGS=<command>`
    or `make wallet2 ARGS=<command>` one of the terminal wallet's
    (clients/typescript/src/dev-wallet.ts);
  - every call that drives the app or a wallet (`make ... ARGS=...` or
    `make ... CODE=...`, on its own, inside `$(...)`, or in a loop that waits
    for it) appears word for word in a walkthrough tape
    (tools/walkthrough/tapes). CI's developer-path job runs every command the
    tapes type, so such a call has run as written. A call that opens a code on
    phones (`make phones-...`) is the one exception: no phone is attached to CI.

And the guide's whole programs (guide/examples) are valid as written:
`node --check` for the JavaScript, a compile for the Python.

usage: python3 guide/check_commands.py [repo-root]
"""
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent.parent)

# A make call that carries ARGS= or CODE=: its whole value, quoted or not.
DRIVING_CALL = re.compile(r"""\bmake (?:-s )?[A-Za-z0-9_.-]+ (?:ARGS|CODE)=(?:"[^"]*"|'[^']*'|[^\s|)]+)""")


def main() -> int:
    makefile = (ROOT / "Makefile").read_text()
    targets = set(re.findall(r"^([A-Za-z0-9_.-]+):", makefile, re.M))
    app_commands = set(re.findall(r'case "([a-z]+)"', (ROOT / "clients/typescript/src/app-cli.ts").read_text()))
    wallet_commands = set(re.findall(r'case "([a-z]+)"', (ROOT / "clients/typescript/src/dev-wallet.ts").read_text()))
    tapes = "\n".join(p.read_text() for p in sorted((ROOT / "tools/walkthrough/tapes").glob("*.tape")))

    problems: list[str] = []
    blocks = 0
    for page in sorted((ROOT / "guide/src").glob("*.md")):
        for block in re.findall(r"```bash\n(.*?)```", page.read_text(), re.S):
            blocks += 1
            parsed = subprocess.run(["bash", "-n"], input=block, capture_output=True, text=True)
            if parsed.returncode != 0:
                problems.append(f"{page.name}: does not parse: {parsed.stderr.strip()}")
            for line in (l.strip() for l in block.strip().splitlines()):
                where = f"{page.name}: {line}"
                if re.search(r"\s#", line):
                    problems.append(f"{where}\n    ends in a comment, which zsh does not take when pasted")
                for target in re.findall(r"\bmake (?:-s )?([A-Za-z0-9_.-]+)", line):
                    if target not in targets:
                        problems.append(f"{where}\n    no make target {target!r}")
                for command in re.findall(r"\bmake (?:-s )?app ARGS=[\"']?([a-z]+)", line):
                    if command not in app_commands:
                        problems.append(f"{where}\n    the app's command line has no {command!r}")
                for command in re.findall(r"\bmake (?:-s )?wallet2? ARGS=[\"']?([a-z]+)", line):
                    if command not in wallet_commands:
                        problems.append(f"{where}\n    the terminal wallet has no {command!r}")
                for call in DRIVING_CALL.findall(line):
                    if not call.startswith("make phones-") and call not in tapes:
                        problems.append(f"{where}\n    {call!r} is typed by no walkthrough tape, so CI has never run it")

    examples = ROOT / "guide/examples"
    programs = 0
    for program in sorted(examples.rglob("*.mjs")):
        if "node_modules" in program.parts:
            continue
        programs += 1
        node = shutil.which("node")
        if node is None:
            problems.append(f"{program.name}: no node here to check it with")
            continue
        checked = subprocess.run([node, "--check", str(program)], capture_output=True, text=True)
        if checked.returncode != 0:
            problems.append(f"{program.name}: {checked.stderr.strip()}")
    for program in sorted(examples.rglob("*.py")):
        programs += 1
        try:
            compile(program.read_text(), str(program), "exec")
        except SyntaxError as e:
            problems.append(f"{program.name}: line {e.lineno}: {e.msg}")

    if problems:
        print(f"guide: {len(problems)} problem(s) in {blocks} command blocks and {programs} programs", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(f"guide: all {blocks} command blocks are commands the repo has, and its {programs} programs are valid")
    return 0


if __name__ == "__main__":
    sys.exit(main())
