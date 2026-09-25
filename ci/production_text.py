#!/usr/bin/env python3
# ci/production_text.py: a Rust file with every `#[cfg(test)]`-attributed
# item removed — what a gate over "production code" must scan.
#
# The gates used to cut a file at its FIRST `#[cfg(test)]` and scan what came
# before it. A file whose first test item sits early (a fixture, a test-only
# impl, a `#[cfg(test)] use`) then had the rest of its production code never
# scanned, and a gate over it was green on code it had not read. This removes
# each attributed item — a brace-delimited block (`mod tests { … }`, an `impl`,
# a `fn`) or a `;`-terminated statement — and keeps everything else.
#
# Exactly `#[cfg(test)]` is test-only. `#[cfg(any(test, feature = …))]` is
# compiled under the feature and ships; it stays.
#
# usage: production_text.py FILE...   (prints the production text of each)
import re
import sys

ATTR = re.compile(r"^[ \t]*#\[cfg\(test\)\][ \t]*\n?", re.M)


def _skip_ws_and_comments(text, i):
    n = len(text)
    while i < n:
        if text[i].isspace():
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j + 1
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            break
    return i


def _skip_attribute(text, i):
    """`i` at `#[`; returns the index after the matching `]`."""
    depth, j, n = 0, i + 1, len(text)
    while j < n:
        c = text[j]
        if c == "[":
            depth += 1
        elif c == "]":
            depth -= 1
            if depth == 0:
                return j + 1
        elif c == '"':
            j = _skip_string(text, j)
            continue
        j += 1
    return n


def _skip_string(text, i):
    """`i` at an opening quote; returns the index after the closing one."""
    n = len(text)
    if i > 0 and text[i - 1] == "r" or (i > 1 and text[i - 2] == "r" and text[i - 1] == "#"):
        # raw string: r"…", r#"…"#
        hashes = 0
        k = i - 1
        while k >= 0 and text[k] == "#":
            hashes += 1
            k -= 1
        close = '"' + "#" * hashes
        j = text.find(close, i + 1)
        return n if j < 0 else j + len(close)
    j = i + 1
    while j < n:
        if text[j] == "\\":
            j += 2
            continue
        if text[j] == '"':
            return j + 1
        j += 1
    return n


def _item_end(text, i):
    """`i` at the first token of an item; the index after its end."""
    n, j = len(text), i
    depth = 0
    while j < n:
        c = text[j]
        if text.startswith("//", j):
            k = text.find("\n", j)
            j = n if k < 0 else k + 1
            continue
        if text.startswith("/*", j):
            k = text.find("*/", j + 2)
            j = n if k < 0 else k + 2
            continue
        if c == '"':
            j = _skip_string(text, j)
            continue
        if c == "'":
            # a char literal ('x', '\n', '\u{..}') or a lifetime ('a)
            m = re.match(r"'(\\u\{[0-9a-fA-F]+\}|\\.|[^\\'])'", text[j:])
            j += m.end() if m else 1
            continue
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return j + 1
        elif c == ";" and depth == 0:
            return j + 1
        j += 1
    return n


def production_text(path):
    text = open(path, encoding="utf-8").read()
    out, pos = [], 0
    for m in ATTR.finditer(text):
        if m.start() < pos:
            continue
        i = _skip_ws_and_comments(text, m.end())
        while text.startswith("#[", i):
            i = _skip_ws_and_comments(text, _skip_attribute(text, i))
        end = _item_end(text, i)
        out.append(text[pos:m.start()])
        pos = end
    out.append(text[pos:])
    return "".join(out)


if __name__ == "__main__":
    for p in sys.argv[1:]:
        sys.stdout.write(production_text(p))
