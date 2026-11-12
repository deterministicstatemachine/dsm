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
  - the installed commands (`dsm-app ...`, `dsm-dev-wallet ...`, and
    `DSM_WALLET_NAME=wallet2 dsm-dev-wallet ...`) are the same programs the
    make targets run, so each is read as its make twin (`dsm-app send $S ERA
    0.05` is `make app ARGS="send $S ERA 0.05"`, `dsm-dev-wallet up` is `make
    dev-wallet`) and held to everything above;
  - every install.sh URL and client package path names the version
    scripts/install.sh installs.

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

# An installed command: dsm-app or dsm-dev-wallet (the second wallet's with DSM_WALLET_NAME=wallet2).
INSTALLED = re.compile(r"(?:(DSM_WALLET_NAME=wallet2) )?(?<![\w/-])(dsm-app|dsm-dev-wallet)(?![\w-])")


def norm(text: str) -> str:
    """Calls as compared: `-s` dropped, and a one-word ARGS unquoted."""
    text = text.replace("make -s ", "make ")
    return re.sub(r"""\b(ARGS|CODE)=(?:"([\w$.-]+)"|'([\w$.-]+)')""", lambda m: f"{m[1]}={m[2] or m[3]}", text)


def command_args(rest: str) -> tuple[str, int]:
    """The arguments after an installed command: up to an unmatched `)`, a `|`, `;`, `&&` or the end."""
    depth, quote, i = 0, "", 0
    while i < len(rest):
        c = rest[i]
        if quote:
            if c == quote:
                quote = ""
        elif c in "\"'":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            if depth == 0:
                break
            depth -= 1
        elif depth == 0 and (c in "|;" or rest.startswith("&&", i)):
            break
        i += 1
    return rest[:i].strip(), i


def as_make(line: str) -> str:
    """The line with each installed command written as its make twin, innermost first."""
    while True:
        found = list(INSTALLED.finditer(line))
        if not found:
            return line
        m = found[-1]
        args, used = command_args(line[m.end():])
        verb = args.split(" ", 1)[0] if args else ""
        quoted = args if re.fullmatch(r"[\w$.-]+", args) else f'"{args}"'
        if m[2] == "dsm-app":
            twin = {"up": "make app-dev", "down": "make app-dev-down"}.get(args, f"make app ARGS={quoted}")
        elif m[1]:
            twin = {"up": "make dev-wallet2", "down": "make dev-down"}.get(args, f"make wallet2 ARGS={quoted}")
        elif verb == "connect" and " " in args:
            twin = f"make dev-wallet-connect CODE={args.split(' ', 1)[1]}"
        else:
            twin = {"up": "make dev-wallet", "down": "make dev-wallet-down", "pending": "make dev-wallet-pending"}.get(
                args, f"make wallet ARGS={quoted}"
            )
        after = line[m.end() + used:]
        line = line[: m.start()] + twin + (after if after.startswith(")") or not after else " " + after.lstrip())


def main() -> int:
    makefile = (ROOT / "Makefile").read_text()
    targets = set(re.findall(r"^([A-Za-z0-9_.-]+):", makefile, re.M))
    app_commands = set(re.findall(r'case "([a-z]+)"', (ROOT / "clients/typescript/src/app-cli.ts").read_text()))
    wallet_commands = set(re.findall(r'case "([a-z]+)"', (ROOT / "clients/typescript/src/dev-wallet.ts").read_text()))
    tapes = "\n".join(p.read_text() for p in sorted((ROOT / "tools/walkthrough/tapes").glob("*.tape")))
    taped = norm(tapes)
    version = re.search(r'^DSM_VERSION="(.+)"$', (ROOT / "scripts/install.sh").read_text(), re.M)[1]
    py_version = version.replace("-beta.", "b").replace("-alpha.", "a").replace("-rc.", "rc")

    problems: list[str] = []
    blocks = 0
    pages = sorted((ROOT / "guide/src").glob("*.md")) + [ROOT / "BUILDING_APPS.md", ROOT / "QUICKSTART.md"]
    for page in pages:
        text = page.read_text()
        for named in re.findall(r"releases/download/v([^/\s]+)/install\.sh", text):
            if named != version:
                problems.append(f"{page.name}: install.sh of v{named}, but scripts/install.sh installs {version}")
        for named in re.findall(r"dsm-app-client-(\d[^\s/]*?)\.tgz", text):
            if named != version:
                problems.append(f"{page.name}: dsm-app-client-{named}.tgz, but the release is {version}")
        for named in re.findall(r"dsm_app_client-(\d[^\s/-]*)-py3", text):
            if named != py_version:
                problems.append(f"{page.name}: dsm_app_client-{named}, but the release's wheel is {py_version}")
        if page.parent.name != "src":
            continue
        for block in re.findall(r"```bash\n(.*?)```", text, re.S):
            blocks += 1
            parsed = subprocess.run(["bash", "-n"], input=block, capture_output=True, text=True)
            if parsed.returncode != 0:
                problems.append(f"{page.name}: does not parse: {parsed.stderr.strip()}")
            for typed in (l.strip() for l in block.strip().splitlines()):
                where = f"{page.name}: {typed}"
                line = as_make(typed)
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
                    if not call.startswith("make phones-") and norm(call) not in taped:
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
