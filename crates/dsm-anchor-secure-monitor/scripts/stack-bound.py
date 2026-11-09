#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The deepest the Secure stack can go, read from the linked image: nothing here runs on a board.

Each function's frame comes from its own prologue in the disassembly: the registers it pushes and what
it takes from sp. Each call comes from its branch. A call through a pointer can reach any function whose
address the image holds, in its data or in its literal pools, and never one the vector table names, since
nothing calls a handler. Two families call through their own tables only. A pointer call in `core::fmt`
reaches the formatting impls, which nothing else calls by pointer, since a format string goes in through
`core::fmt::write`, a direct call this walk follows. A pointer call in `bytes` reaches `bytes`'s own vtable.

The monitor launches the Non-secure side from `main` and never returns, so every request is served on top
of the frame `main` still holds: the stack a request has is what is left under that frame.

The image does recurse, and a table cannot see how far, so each recursion is named below with the depth its
source gives, and its frame counts that many times. Any other direct recursion, outside `core::fmt` where a
nested Debug prints, fails this script. A cycle through a pointer call is an artefact of taking every target
at once (a `dyn` forward does not call its sibling method), and is cut where it closes.

Run on a production image. CI holds the stack to this bound: the trial and prepare images run less.

usage: stack-bound.py ELF [--limit BYTES] [--top N]
"""
import argparse
import os
import re
import subprocess
import sys
import tempfile

# What the board runs: its reset path, and each request on top of what `main` holds.
RESET = "dsm_anchor_secure_monitor::__cortex_m_rt_main"
HANDLER = "dsm_secure_handler"
# What a Cortex-M33 stacks taking an exception with lazy FP state, on top of whatever was running.
FAULT_FRAME = 104

# Each recursion in the image, and how deep it goes.
RECURSION = {
    # SPX128f: h = 66 over d = 22 layers, so a tree of height 3, and a node asks for its children.
    "dsm_sphincs::xmss_node": 4,
    # SPX128f: a = 6.
    "dsm_sphincs::fors_node": 7,
    # One level for each halving down to a 1 KiB chunk, from the largest message hashed: a frame of 64 KiB.
    "blake3::compress_subtree_wide": 8,
    # prost's RECURSION_LIMIT, which a hostile request of nested groups can reach.
    "prost::encoding::skip_field": 100,
    # Forwards to its own instance once.
    "<&mut &[u8] as bytes::buf::buf_impl::Buf>::copy_to_bytes": 2,
}
# These never return: a panic, on its way to the reset.
DIVERGING = ("core::str::slice_error_fail", "core::panicking", "core::slice::index")

FUNC = re.compile(r"^([0-9a-f]{8}) <(.+)>:$")
INSN = re.compile(r"^\s*([0-9a-f]+):\s+(\S+)\s*(.*)$")


def disassemble(elf):
    out = subprocess.run(
        ["arm-none-eabi-objdump", "-d", "--no-show-raw-insn", "-C", elf],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    functions = {}
    current = None
    for line in out.splitlines():
        match = FUNC.match(line)
        if match:
            address = int(match.group(1), 16)
            # Two instances of a generic can demangle to one name.
            name = match.group(2)
            if name in functions:
                name = f"{name}#{address:x}"
            current = {"addr": address, "name": name, "insns": []}
            functions[name] = current
            continue
        match = INSN.match(line)
        if match and current is not None:
            current["insns"].append((int(match.group(1), 16), match.group(2), match.group(3)))
    return functions


def register_count(operands):
    inside = re.search(r"\{(.*)\}", operands)
    if not inside:
        return 0
    count = 0
    for item in inside.group(1).split(","):
        item = item.strip()
        span = re.match(r"([a-z]+)(\d+)-[a-z]*(\d+)", item)
        count += int(span.group(3)) - int(span.group(2)) + 1 if span else 1
    return count


def immediate(text):
    match = re.search(r"#(-?(?:0x[0-9a-f]+|\d+))", text)
    return int(match.group(1), 0) if match else None


def frame_of(function):
    """Every byte this function can take from sp, counted along all its paths at once."""
    frame = 0
    loaded = {}
    for _addr, mnemonic, operands in function["insns"]:
        base = mnemonic.split(".")[0]
        if base == "push":
            frame += 4 * register_count(operands)
        elif base == "stmdb" and operands.startswith("sp!"):
            frame += 4 * register_count(operands)
        elif base == "str" and re.search(r"\[sp, #-\d+\]!", operands):
            frame += -immediate(operands.split("[")[1])
        elif base == "vpush":
            size = 8 if "d" in operands.split("{")[1][:2] else 4
            frame += size * register_count(operands)
        elif base in ("movw", "mov") and immediate(operands) is not None:
            loaded[operands.split(",")[0].strip()] = immediate(operands)
        elif base == "movt" and immediate(operands) is not None:
            register = operands.split(",")[0].strip()
            loaded[register] = loaded.get(register, 0) | (immediate(operands) << 16)
        elif base in ("sub", "subw"):
            parts = [p.strip() for p in operands.split(",")]
            if parts[0] == "sp":
                value = immediate(operands)
                if value is None:
                    value = loaded.get(parts[-1])
                if value is None:
                    raise SystemExit(f"{function['name']}: sp moved by an unknown amount: {operands}")
                frame += value
        elif base == "add" and operands.startswith("sp, #-"):
            frame += -immediate(operands)
    return frame


def calls_of(function, names_at):
    direct = set()
    indirect = 0
    start = function["addr"]
    end = function["insns"][-1][0] if function["insns"] else start
    for _addr, mnemonic, operands in function["insns"]:
        base = mnemonic.split(".")[0]
        if base in ("bl", "blx") or re.fullmatch(r"b(eq|ne|cs|cc|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|hs|lo)?", base):
            target = re.match(r"([0-9a-f]+)", operands)
            if target:
                address = int(target.group(1), 16)
                if base in ("bl", "blx") or not start <= address <= end:
                    name = names_at.get(address)
                    if name:
                        direct.add(name)
            elif base == "blx":
                indirect = 1
        elif base == "bx" and not operands.startswith("lr"):
            indirect = 1
        elif base == "tbb" or base == "tbh":
            pass
    return direct, indirect


def address_taken(elf, functions):
    """Each function whose Thumb address appears as a word in the image's loaded bytes."""
    by_address = {f["addr"] | 1: f["name"] for f in functions.values()}
    with tempfile.TemporaryDirectory() as scratch:
        image = os.path.join(scratch, "image.bin")
        subprocess.run(
            ["arm-none-eabi-objcopy", "-O", "binary", "--only-section=.vector_table", "--only-section=.text",
             "--only-section=.rodata", "--only-section=.data", elf, image],
            check=True,
        )
        with open(image, "rb") as handle:
            out = handle.read()
    taken = set()
    for offset in range(0, len(out) - 3, 4):
        word = int.from_bytes(out[offset:offset + 4], "little")
        name = by_address.get(word)
        if name:
            taken.add(name)
    return taken


def short(name):
    """A generic's name is mostly its parameters: the end of it says which function it is."""
    return name if len(name) <= 100 else name[:40] + " ... " + name[-55:]


def depth_of(name):
    for prefix, depth in RECURSION.items():
        if name.startswith(prefix):
            return depth
    return 1


def direct_recursion(functions, names_at):
    """Each direct call that closes a cycle, outside the formatting family."""
    edges = {name: calls_of(function, names_at)[0] for name, function in functions.items()}
    state = {}
    found = []

    def walk(name):
        state[name] = 1
        for child in sorted(edges.get(name, ())):
            if formatting(name) or formatting(child):
                continue
            if state.get(child) == 1:
                if depth_of(child) == 1 and not child.startswith(DIVERGING):
                    found.append((name, child))
            elif child not in state:
                walk(child)
        state[name] = 2

    for name in sorted(functions):
        if name not in state:
            walk(name)
    return found


def formatting(name):
    return "core::fmt" in name or "fmt::" in name or "::fmt" in name


def bytes_table(name):
    return name.startswith("bytes::") or "bytes::buf" in name or "::bytes::" in name


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("elf")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--top", type=int, default=12)
    parser.add_argument("--paths", action="store_true", help="print the heaviest path of each")
    args = parser.parse_args()

    functions = disassemble(args.elf)
    names_at = {f["addr"]: f["name"] for f in functions.values()}
    frames = {name: frame_of(f) * depth_of(name) for name, f in functions.items()}
    handlers = {"Reset", "main", RESET, HANDLER, "HardFaultTrampoline", "HardFault_", "DefaultHandler_", "DefaultPreInit"}
    taken = address_taken(args.elf, functions) - handlers
    fmt_targets = {name for name in taken if formatting(name)}
    bytes_targets = {name for name in taken if bytes_table(name)}
    other_targets = taken - fmt_targets - bytes_targets
    calls = {}
    pointer_callers = 0
    for name, function in functions.items():
        direct, indirect = calls_of(function, names_at)
        if indirect:
            pointer_callers += 1
            if formatting(name):
                direct = direct | fmt_targets
            elif bytes_table(name):
                direct = direct | bytes_targets
            else:
                direct = direct | other_targets
        calls[name] = direct

    memo = {}
    cycles = set()
    sys.setrecursionlimit(200000)

    def heaviest(name, on_path):
        if name in memo:
            return memo[name]
        on_path.add(name)
        best_child = 0
        best = None
        for child in sorted(calls.get(name, ())):
            if child in on_path:
                cycles.add((name, child))
                continue
            weight, _next = heaviest(child, on_path)
            if weight > best_child:
                best_child, best = weight, child
        on_path.discard(name)
        memo[name] = (frames.get(name, 0) + best_child, best)
        return memo[name]

    def trail(name):
        lines = []
        step = name
        while step:
            lines.append(f"  {frames.get(step, 0):>6}  {short(step)}")
            step = memo[step][1]
        return lines

    reset_weight, _next = heaviest(RESET, set())
    handler_weight, _next = heaviest(HANDLER, set())
    held_by_main = frames[RESET]
    serving = held_by_main + handler_weight
    print(f"reset path, up to the launch: {reset_weight} bytes (main's own frame {held_by_main})")
    print(f"a request, on top of main's frame: {handler_weight} bytes")
    if args.paths:
        print("\nthe reset path:\n" + "\n".join(trail(RESET)))
        print("\na request:\n" + "\n".join(trail(HANDLER)))
    print("\nlargest single frames:")
    for name, frame in sorted(frames.items(), key=lambda kv: -kv[1])[: args.top]:
        print(f"  {frame:>6}  {short(name)}")
    foreign = direct_recursion(functions, names_at)
    print(f"\n{len(functions)} functions, {pointer_callers} call through a pointer, {len(taken)} have their address taken")
    bound = max(reset_weight, serving) + FAULT_FRAME
    print(f"bound with a fault on top: {bound} bytes")
    failed = 0
    if foreign:
        print(f"ERROR: recursion outside core::fmt, which no bound covers: {foreign[:8]}")
        failed = 1
    if args.limit is not None and bound > args.limit:
        print(f"ERROR: over the {args.limit} bytes the stack has")
        failed = 1
    return failed


if __name__ == "__main__":
    sys.exit(main())
