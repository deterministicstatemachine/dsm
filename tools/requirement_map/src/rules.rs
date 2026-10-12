// SPDX-License-Identifier: MIT OR Apache-2.0
//! The rule-coverage table, `../rules.tsv`, checked against what it names.
//! Every rule the map can apply has one row, and every row names such a rule:
//! the reason codes (`reach::code`), the edge kinds (each crate-level
//! `pub const …: &str`), the entry-point kinds (`graph::root`), the rules
//! `ci/requirement_map.py`'s check can name (its `CHECK_RULES`), the intent
//! comparator's outcomes (`ci/intent_comparator.py`'s `OUTCOMES`) and the pin
//! states (`ci/intent_pins.py`'s `PIN_STATES`), all read by running Python.
//! Every unit test, fixture reading, mutation case and sentinel a row cites
//! exists; a pin state's unit tests are in `ci/test_intent_pins.py`. A code's positive reading and sentinel read
//! that code and its negative does not; an outcome's positive is a fixture
//! manifest row (`requirement:symbol`) with that outcome and its negative one
//! without; a code's or an outcome's mutation moves a reading or an outcome
//! to or from it; a check rule's mutation is a planted case naming it. A row
//! with an empty column says why.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::visit::Visit;

const COLUMNS: [&str; 8] = [
    "rule", "kind", "unit", "positive", "negative", "mutation", "sentinel", "gap",
];

struct Row {
    rule: String,
    kind: String,
    unit: Vec<String>,
    positive: Vec<String>,
    negative: Vec<String>,
    mutation: Vec<String>,
    sentinel: Vec<String>,
    gap: String,
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))
}

/// A cell's entries: none for `-`.
fn entries(cell: &str) -> Vec<String> {
    match cell {
        "-" => Vec::new(),
        _ => cell.split(';').map(str::to_string).collect(),
    }
}

/// Lines of a committed table that are not comments.
fn table_lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
}

fn rows() -> Result<Vec<Row>, String> {
    let text = read(&crate_dir().join("rules.tsv"))?;
    let mut lines = table_lines(&text);
    let header: Vec<&str> = lines
        .next()
        .ok_or("rules.tsv has no header")?
        .split('\t')
        .collect();
    if header != COLUMNS {
        return Err(format!(
            "rules.tsv's columns are {header:?}, not {COLUMNS:?}"
        ));
    }
    lines
        .map(
            |line| match line.split('\t').collect::<Vec<_>>().as_slice() {
                [rule, kind, unit, positive, negative, mutation, sentinel, gap] => Ok(Row {
                    rule: rule.to_string(),
                    kind: kind.to_string(),
                    unit: entries(unit),
                    positive: entries(positive),
                    negative: entries(negative),
                    mutation: entries(mutation),
                    sentinel: entries(sentinel),
                    gap: gap.to_string(),
                }),
                cells => Err(format!("rules.tsv: {} cells in {line:?}", cells.len())),
            },
        )
        .collect()
}

/// Every function in `src/` under a `#[test]` attribute.
struct Tests(BTreeSet<String>);

impl<'ast> Visit<'ast> for Tests {
    fn visit_item_fn(&mut self, f: &'ast syn::ItemFn) {
        if f.attrs.iter().any(|a| a.path().is_ident("test")) {
            self.0.insert(f.sig.ident.to_string());
        }
        syn::visit::visit_item_fn(self, f);
    }
}

/// A `const NAME: &str = "value";` item's value.
fn str_constant(c: &syn::ItemConst) -> Option<String> {
    let syn::Type::Reference(r) = &*c.ty else {
        return None;
    };
    let syn::Type::Path(p) = &*r.elem else {
        return None;
    };
    if !p.path.is_ident("str") {
        return None;
    }
    match &*c.expr {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => Some(s.value()),
        _ => None,
    }
}

fn public(v: &syn::Visibility) -> bool {
    matches!(v, syn::Visibility::Public(_))
}

/// What `src/` defines: its unit tests, and the rules of each kind the code
/// names (codes in `mod code`, entry-point kinds in `mod root`, edge kinds as
/// crate-level public string constants).
fn sources() -> Result<(BTreeSet<String>, BTreeMap<&'static str, BTreeSet<String>>), String> {
    let mut tests = Tests(BTreeSet::new());
    let mut rules: BTreeMap<&'static str, BTreeSet<String>> = BTreeMap::new();
    let dir = crate_dir().join("src");
    let listing = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in listing {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let file =
            syn::parse_file(&read(&path)?).map_err(|e| format!("{}: {e}", path.display()))?;
        tests.visit_file(&file);
        for item in &file.items {
            match item {
                syn::Item::Const(c) if public(&c.vis) => {
                    if let Some(v) = str_constant(c) {
                        rules.entry("edge").or_default().insert(v);
                    }
                }
                syn::Item::Mod(m) if public(&m.vis) => {
                    let kind = match m.ident.to_string().as_str() {
                        "code" => "code",
                        "root" => "root",
                        _ => continue,
                    };
                    for inner in m.content.iter().flat_map(|(_, items)| items) {
                        if let syn::Item::Const(c) = inner {
                            let v = str_constant(c).ok_or_else(|| {
                                format!(
                                    "{}: mod {kind} holds {}, not a string",
                                    path.display(),
                                    c.ident
                                )
                            })?;
                            rules.entry(kind).or_default().insert(v);
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Ok((tests.0, rules))
}

/// A name list a `ci/` module declares (`CHECK_RULES`, `OUTCOMES`), as
/// Python reads it from the repository's root, where the module finds the
/// modules it loads.
fn python_names(module: &str, names: &str) -> Result<BTreeSet<String>, String> {
    let out = std::process::Command::new("python3")
        .arg("-c")
        .arg(format!(
            "import sys; sys.path.insert(0, 'ci'); import {module}; print('\\n'.join({module}.{names}))"
        ))
        .current_dir(crate_dir().join("../.."))
        .output()
        .map_err(|e| format!("python3: {e}"))?;
    if !out.status.success() {
        let why =
            String::from_utf8(out.stderr).map_err(|e| format!("python3's error output: {e}"))?;
        return Err(format!("python3 could not read {module}.{names}: {why}"));
    }
    let text = String::from_utf8(out.stdout).map_err(|e| format!("python3's output: {e}"))?;
    Ok(text.lines().map(str::to_string).collect())
}

/// The test methods a `ci/` Python test file defines (`def test_…`).
fn python_tests(file: &str) -> Result<BTreeSet<String>, String> {
    let text = read(&crate_dir().join("../..").join(file))?;
    Ok(text
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("def test_"))
        .filter_map(|rest| rest.split('(').next())
        .map(|name| format!("test_{name}"))
        .collect())
}

/// The fixture manifest's outcomes: `requirement:symbol` -> outcome.
fn fixture_outcomes() -> Result<BTreeMap<String, String>, String> {
    let text = read(&crate_dir().join("fixture/intent-expected.tsv"))?;
    let mut lines = table_lines(&text);
    lines.next().ok_or("intent-expected.tsv has no header")?;
    lines
        .map(
            |line| match line.split('\t').collect::<Vec<_>>().as_slice() {
                [requirement, symbol, _artifact, _reachability, _lifecycle, _root, outcome, _fails] => {
                    Ok((format!("{requirement}:{symbol}"), outcome.to_string()))
                }
                cells => Err(format!("intent-expected.tsv: {} cells in {line:?}", cells.len())),
            },
        )
        .collect()
}

/// The fixture's readings: key -> code.
fn fixture_readings() -> Result<BTreeMap<String, String>, String> {
    let text = read(&crate_dir().join("fixture/expected.tsv"))?;
    table_lines(&text)
        .map(
            |line| match line.split('\t').collect::<Vec<_>>().as_slice() {
                [key, _state, code] => Ok((key.to_string(), code.to_string())),
                cells => Err(format!("expected.tsv: {} cells in {line:?}", cells.len())),
            },
        )
        .collect()
}

/// The committed sentinels: `artifact:path` -> code.
fn sentinels() -> Result<BTreeMap<String, String>, String> {
    let text = read(&crate_dir().join("../../ci/requirement_map.sentinels.tsv"))?;
    let mut lines = table_lines(&text);
    lines.next().ok_or("the sentinels have no header")?;
    lines
        .map(
            |line| match line.split('\t').collect::<Vec<_>>().as_slice() {
                [artifact, path, _state, code, _why] => {
                    Ok((format!("{artifact}:{path}"), code.to_string()))
                }
                cells => Err(format!("sentinels: {} cells in {line:?}", cells.len())),
            },
        )
        .collect()
}

/// The mutation cases, by name.
fn cases() -> Result<BTreeMap<String, toml::Table>, String> {
    let text = read(&crate_dir().join("fixture/mutations.toml"))?;
    let table: toml::Table = text.parse().map_err(|e| format!("mutations.toml: {e}"))?;
    let list = table
        .get("case")
        .and_then(|c| c.as_array())
        .ok_or("mutations.toml holds no [[case]]")?;
    let mut out = BTreeMap::new();
    for case in list {
        let case = case.as_table().ok_or("a case is not a table")?;
        let name = case
            .get("name")
            .and_then(|n| n.as_str())
            .ok_or("a case has no name")?;
        if out.insert(name.to_string(), case.clone()).is_some() {
            return Err(format!("two cases are named {name}"));
        }
    }
    Ok(out)
}

fn text_of<'a>(case: &'a toml::Table, key: &str) -> Option<&'a str> {
    case.get(key).and_then(|v| v.as_str())
}

/// Whether a case moves some reading (or manifest row's outcome) to `code`
/// or from it: an expected value's first word is the outcome, its second the
/// reading's code.
fn moves(case: &toml::Table, code: &str, readings: &BTreeMap<String, String>) -> bool {
    let expect = case.get("expect").and_then(|e| e.as_table());
    expect
        .into_iter()
        .flat_map(|t| t.iter())
        .any(|(key, value)| {
            let words: Vec<&str> = value
                .as_str()
                .into_iter()
                .flat_map(|v| v.split(' '))
                .collect();
            words.contains(&code) || readings.get(key).map(String::as_str) == Some(code)
        })
}

#[test]
fn every_rule_has_a_row_and_every_citation_exists() -> Result<(), String> {
    let rows = rows()?;
    let (tests, mut defined) = sources()?;
    defined.insert("check", python_names("requirement_map", "CHECK_RULES")?);
    defined.insert("outcome", python_names("intent_comparator", "OUTCOMES")?);
    defined.insert("pin", python_names("intent_pins", "PIN_STATES")?);
    let pin_tests = python_tests("ci/test_intent_pins.py")?;
    let fixture_readings = fixture_readings()?;
    let outcomes = fixture_outcomes()?;
    let sentinels = sentinels()?;
    let cases = cases()?;
    let mut faults: Vec<String> = Vec::new();

    let mut seen: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for row in &rows {
        let rule = &row.rule;
        match defined.get(row.kind.as_str()) {
            None => faults.push(format!("{rule}: no such kind {}", row.kind)),
            Some(known) if !known.contains(rule) => faults.push(format!(
                "{rule}: the map applies no {} rule of this name",
                row.kind
            )),
            Some(_) => {}
        }
        if !seen
            .entry(row.kind.as_str())
            .or_default()
            .insert(rule.clone())
        {
            faults.push(format!("{rule}: two rows"));
        }
        let unit_tests = match row.kind.as_str() {
            "pin" => &pin_tests,
            _ => &tests,
        };
        for t in &row.unit {
            if !unit_tests.contains(t) {
                faults.push(format!("{rule}: no unit test {t}"));
            }
        }
        // What a row's positive and negative name: a manifest row's outcome
        // for an outcome, a fixture reading's code for anything else.
        let readings = match row.kind.as_str() {
            "outcome" => &outcomes,
            _ => &fixture_readings,
        };
        let code_row = matches!(row.kind.as_str(), "code" | "outcome");
        let what = match row.kind.as_str() {
            "outcome" => "fixture manifest row",
            _ => "fixture reading",
        };
        for key in &row.positive {
            match readings.get(key) {
                None => faults.push(format!("{rule}: no {what} {key}")),
                Some(code) if code_row && code != rule => {
                    faults.push(format!("{rule}: its positive {key} reads {code}"))
                }
                Some(_) => {}
            }
        }
        for key in &row.negative {
            match readings.get(key) {
                None => faults.push(format!("{rule}: no {what} {key}")),
                Some(code) if code_row && code == rule => {
                    faults.push(format!("{rule}: its negative {key} reads it"))
                }
                Some(_) => {}
            }
        }
        for name in &row.mutation {
            let Some(case) = cases.get(name) else {
                faults.push(format!("{rule}: no mutation case {name}"));
                continue;
            };
            let planted = text_of(case, "kind") == Some("planted");
            match row.kind.as_str() {
                "check" if !planted || text_of(case, "rule") != Some(rule.as_str()) => {
                    faults.push(format!("{rule}: {name} is not a planted case naming it"))
                }
                "code" | "outcome" if !moves(case, rule, readings) => {
                    faults.push(format!("{rule}: {name} moves no reading to or from it"))
                }
                _ => {}
            }
        }
        for s in &row.sentinel {
            match sentinels.get(s) {
                None => faults.push(format!("{rule}: no sentinel {s}")),
                Some(code) if code_row && code != rule => {
                    faults.push(format!("{rule}: its sentinel {s} reads {code}"))
                }
                Some(_) => {}
            }
        }
        let open = [
            &row.unit,
            &row.positive,
            &row.negative,
            &row.mutation,
            &row.sentinel,
        ]
        .iter()
        .any(|c| c.is_empty());
        let explained = row.gap != "-";
        if row.gap.is_empty() {
            faults.push(format!("{rule}: an empty gap cell"));
        } else if open && !explained {
            faults.push(format!("{rule}: an empty column and no gap saying why"));
        } else if explained && !open {
            faults.push(format!("{rule}: a gap with every column filled"));
        }
    }
    for (kind, known) in &defined {
        let listed = seen.get(kind);
        for missing in known
            .iter()
            .filter(|r| !listed.is_some_and(|l| l.contains(*r)))
        {
            faults.push(format!("{missing}: a {kind} rule with no row"));
        }
    }
    for (name, case) in &cases {
        if let (Some("planted"), Some(rule)) = (text_of(case, "kind"), text_of(case, "rule")) {
            if !defined.get("check").is_some_and(|c| c.contains(rule)) {
                faults.push(format!(
                    "{name}: plants {rule}, which the check does not declare"
                ));
            }
        }
    }
    match faults.as_slice() {
        [] => Ok(()),
        _ => Err(format!("rules.tsv:\n  {}", faults.join("\n  "))),
    }
}
