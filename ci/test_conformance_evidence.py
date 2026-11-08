#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""The conformance gate's Jest evidence (ci/conformance_evidence.py) proves
what it refuses.

The Jest index is read from the test files' structure, so each case lexes a
source whose comments, strings, template literals, regular expressions or
JSX would mislead a text search, and names the tests it must find. The
negative controls run the gate itself over copies of the derived documents:
a frontend test name that exists resolves, and one misspelled, one in a file
that does not exist, and one a log does not show passing each fail it. Run
from the repository root.
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import conformance_evidence as ce  # noqa: E402

GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "conformance_evidence.py")

TRICKY = r"""
import { render } from '@testing-library/react';
// it('a comment is not a test', () => {});
/* describe('nor is a block comment', () => { it('x', () => {}); }); */
const pattern = /\(it\('a regular expression'/;
const said = "it('a string is not a test')";
const shown = `test('nor is a template ${said}')`;

describe('outer', () => {
  beforeEach(() => { pattern.test(said); });
  it("names its parent's describe", () => {
    render(<p>don't (open) a string here {"{"}</p>);
    expect(/x/.test('x')).toBe(pattern.test(said));
  });
  describe('inner', () => {
    test('nests', async () => {
      const ratio = 4 / 2 / 1;
      expect(<Box label="it('no')" />).toBeTruthy();
    });
  });
  describe.skip('skipped', () => {
    it('is not evidence', () => {});
  });
  it.todo('to do');
  it.each([[1], [2]])('row %s', () => {});
  test(`a template title`, () => {});
  test(`an interpolated ${shown}`, () => {});
  it('an escaped \'quote\'', () => {});
});
"""


def names(source, jsx=True):
    return {
        (tuple(titles), title): why
        for titles, title, _, why, _ in ce.jest_tests_in(source, jsx)
        if title is not None
    }


class Lexing(unittest.TestCase):
    def test_tests_are_found_from_the_structure(self):
        found = names(TRICKY)
        self.assertEqual(
            set(found),
            {
                (("outer",), "names its parent's describe"),
                (("outer", "inner"), "nests"),
                (("outer", "skipped"), "is not evidence"),
                (("outer",), "to do"),
                (("outer",), "row %s"),
                (("outer",), "a template title"),
                (("outer",), "an escaped 'quote'"),
            },
        )
        self.assertIsNone(found[(("outer",), "names its parent's describe")])
        self.assertIsNone(found[(("outer", "inner"), "nests")])

    def test_skipped_todo_and_table_driven_tests_are_not_evidence(self):
        found = names(TRICKY)
        self.assertEqual(found[(("outer", "skipped"), "is not evidence")], "skipped")
        self.assertEqual(found[(("outer",), "to do")], "skipped")
        self.assertIn("table-driven", found[(("outer",), "row %s")])

    def test_an_interpolated_title_has_no_name(self):
        titles = [t for _, t, _, _, _ in ce.jest_tests_in(TRICKY, True)]
        self.assertIn(None, titles, "the interpolated title is listed without a name")

    def test_a_source_that_does_not_lex_is_refused(self):
        with self.assertRaises(ValueError):
            ce.jest_tests_in("describe('open', () => {\n  it('x', () => {});\n", False)


def real_name():
    """A frontend test the repository's index holds once, and is evidence."""
    index, _ = ce.build_frontend_index()
    return sorted(n for n, found in index.items() if len(found) == 1 and found[0][1] is None)[0]


class Gate(unittest.TestCase):
    """The gate run over copies of the derived documents, one planted name in
    the §5A Evidence column of an unticked row."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.matrix = os.path.join(self.dir, "matrix.md")
        shutil.copyfile(ce.MATRIX, self.matrix)

    def gate(self, name, *extra):
        text = ce.read(ce.GAPS)
        row = next(l for l in text.splitlines() if l.startswith("| [ ] |"))
        planted = row[: -len(" |")] + f" Planted: `{name}`. |"
        gaps = os.path.join(self.dir, "gaps.md")
        with open(gaps, "w", encoding="utf-8") as f:
            f.write(text.replace(row, planted, 1))
        run = subprocess.run(
            [sys.executable, GATE, "--gaps", gaps, "--matrix", self.matrix, *extra],
            capture_output=True,
            text=True,
        )
        return run.returncode, run.stdout

    def test_a_frontend_test_that_exists_resolves(self):
        code, out = self.gate(real_name())
        self.assertEqual(code, 0, out)

    def test_a_misspelled_frontend_test_fails_the_gate(self):
        name = real_name()
        misspelled = name[:-1] + ("x" if name[-1] != "x" else "y")
        code, out = self.gate(misspelled)
        self.assertEqual(code, 1, out)
        self.assertIn(f"test {misspelled} does not exist", out)

    def test_a_frontend_test_in_no_file_fails_the_gate(self):
        missing = "frontend:src/__tests__/nothing_here.test.tsx::no such test"
        code, out = self.gate(missing)
        self.assertEqual(code, 1, out)
        self.assertIn(f"test {missing} does not exist", out)

    def test_a_frontend_test_no_log_shows_passing_fails_the_gate(self):
        name = real_name()
        rel, title = ce.FRONTEND_REF.match(name).groups()
        *ancestors, own = title.split(ce.JEST_SEP)
        log = os.path.join(self.dir, "jest.json")
        report = lambda status: {
            "testResults": [
                {
                    "name": os.path.abspath(os.path.join(ce.FRONTEND, rel)),
                    "assertionResults": [{"ancestorTitles": ancestors, "title": own, "status": status}],
                }
            ]
        }
        with open(log, "w", encoding="utf-8") as f:
            json.dump(report("failed"), f)
        code, out = self.gate(name, "--jest-log", log)
        self.assertEqual(code, 1, out)
        self.assertIn(f"test {name} failed in the given Jest logs", out)


if __name__ == "__main__":
    unittest.main()
