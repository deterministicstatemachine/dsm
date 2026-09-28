// SPDX-License-Identifier: MIT OR Apache-2.0
//! Item and closure hashes over the call graph, the production roots, and
//! what the roots reach.

use crate::hashing::{hash, Digest, CLOSURE, COMPONENT, EXTERNAL, ITEM};
use crate::index::{Definition, Edges, Position};
use crate::symbols::Kind;
use crate::tokens::{canonical, format_captures};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::Path;

/// The library and binary sources a production entry point can live in.
pub const PRODUCTION: [&str; 3] = [
    "dsm_client/deterministic_state_machine/dsm/src/",
    "dsm_client/deterministic_state_machine/dsm_sdk/src/",
    "dsm_storage_node/src/",
];

pub struct Node {
    pub item: Digest,
    pub closure: Digest,
    /// Reached from a production entry point.
    pub reached: bool,
    /// Reached from a test function.
    pub tested: bool,
    /// An impl of an outside trait on a type the index holds no symbol for.
    pub unlinked: bool,
    pub root: &'static str,
}

pub struct Graph {
    pub nodes: BTreeMap<String, Node>,
}

pub fn build(
    root: &Path,
    definitions: &[Definition],
    edges: &mut Edges,
    unlinked: &BTreeSet<String>,
) -> Result<Graph, String> {
    // Module-level constants and statics by name, for format captures.
    let mut constants: BTreeMap<&str, Vec<&Definition>> = BTreeMap::new();
    for d in definitions {
        if d.item.kind == Kind::Term && d.item.container.is_empty() {
            constants.entry(d.item.name.as_str()).or_default().push(d);
        }
    }
    let mut sources: BTreeMap<&str, String> = BTreeMap::new();
    let mut texts: BTreeMap<&str, Vec<(&str, Position, String)>> = BTreeMap::new();
    let mut roots: BTreeMap<&str, &'static str> = BTreeMap::new();
    let mut tests: BTreeMap<&str, &'static str> = BTreeMap::new();
    for d in definitions {
        if !sources.contains_key(d.file.as_str()) {
            let text = std::fs::read_to_string(root.join(&d.file))
                .map_err(|e| format!("{}: cannot read: {e}", d.file))?;
            sources.insert(d.file.as_str(), text);
        }
        let source = sources
            .get(d.file.as_str())
            .ok_or_else(|| format!("{}: not loaded", d.file))?;
        let text =
            slice(source, d.start, d.end).map_err(|e| format!("{} ({}): {e}", d.symbol, d.file))?;
        let tokens = canonical(text).map_err(|e| format!("{} ({}): {e}", d.symbol, d.file))?;
        if let Some(kind) = root_kind(d, text) {
            roots.insert(d.symbol.as_str(), kind);
        }
        if d.item.kind == Kind::Callable && is_test(text) {
            tests.insert(d.symbol.as_str(), "test");
        }
        texts
            .entry(d.symbol.as_str())
            .or_default()
            .push((d.file.as_str(), d.start, tokens));
        if d.item.kind == Kind::Callable || d.item.kind == Kind::Term {
            for name in
                format_captures(text).map_err(|e| format!("{} ({}): {e}", d.symbol, d.file))?
            {
                if let Some(target) = capture_target(&constants, d, &name) {
                    if target != d.symbol {
                        edges.insert((d.symbol.clone(), target, "format-arg"));
                    }
                }
            }
        }
    }

    // Node ids: every defined symbol, then every symbol only referenced.
    let mut ids: BTreeMap<&str, usize> = BTreeMap::new();
    let mut names: Vec<&str> = Vec::new();
    for symbol in texts
        .keys()
        .copied()
        .chain(edges.iter().map(|(_, to, _)| to.as_str()))
    {
        if !ids.contains_key(symbol) {
            ids.insert(symbol, names.len());
            names.push(symbol);
        }
    }
    let mut items: Vec<Digest> = Vec::with_capacity(names.len());
    for name in &names {
        items.push(match texts.get_mut(name) {
            Some(parts) => {
                parts.sort();
                let mut fields: Vec<&[u8]> = vec![name.as_bytes()];
                fields.extend(parts.iter().map(|(_, _, t)| t.as_bytes()));
                hash(ITEM, &fields)
            }
            None => hash(EXTERNAL, &[name.as_bytes()]),
        });
    }
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); names.len()];
    for (from, to, _) in edges.iter() {
        if let (Some(&f), Some(&t)) = (ids.get(from.as_str()), ids.get(to.as_str())) {
            adjacency[f].push(t);
        }
    }
    for list in &mut adjacency {
        list.sort_unstable();
        list.dedup();
    }

    let closures = closures(&names, &items, &adjacency)?;
    let reached = reach(&adjacency, &roots, &ids);
    let tested = reach(&adjacency, &tests, &ids);
    let mut nodes = BTreeMap::new();
    for symbol in texts.keys() {
        let id = ids[symbol];
        nodes.insert(
            symbol.to_string(),
            Node {
                item: items[id],
                closure: closures[id],
                reached: reached.contains(&id),
                tested: tested.contains(&id),
                unlinked: unlinked.contains(*symbol),
                root: match roots.get(symbol) {
                    Some(kind) => kind,
                    None => "-",
                },
            },
        );
    }
    Ok(Graph { nodes })
}

/// The constant a format capture names: one in the same file, else one in
/// the same package; a name with neither is a local variable.
fn capture_target(
    constants: &BTreeMap<&str, Vec<&Definition>>,
    d: &Definition,
    name: &str,
) -> Option<String> {
    let candidates = constants.get(name)?;
    let same_file = candidates.iter().find(|c| c.file == d.file);
    let same_package = candidates.iter().find(|c| c.item.package == d.item.package);
    same_file.or(same_package).map(|c| c.symbol.clone())
}

/// A production entry point: a JNI or C export in a production library, or
/// the `main` of a production binary.
fn root_kind(d: &Definition, text: &str) -> Option<&'static str> {
    let production = PRODUCTION.iter().any(|p| d.file.starts_with(p));
    let it = &d.item;
    if !production || it.kind != Kind::Callable || !it.container.is_empty() {
        return None;
    }
    let binary = d.file.ends_with("/src/main.rs") || d.file.contains("/src/bin/");
    if binary && it.name == "main" {
        return Some("main");
    }
    let exported =
        it.name.starts_with("Java_") || it.name == "JNI_OnLoad" || text.contains("no_mangle");
    exported.then_some("export")
}

/// A test function: `#[test]`, `#[tokio::test]` and the other test attributes
/// the evidence script recognises, on the function itself.
fn is_test(text: &str) -> bool {
    let head = match text.find("fn ") {
        Some(at) => &text[..at],
        None => text,
    };
    [
        "#[test]",
        "#[tokio::test",
        "#[rstest",
        "#[test_case",
        "#[async_std::test",
        "#[sqlx::test",
    ]
    .iter()
    .any(|attribute| head.contains(attribute))
}

fn slice(source: &str, start: Position, end: Position) -> Result<&str, String> {
    let mut offsets = vec![0usize];
    for (at, byte) in source.bytes().enumerate() {
        if byte == b'\n' {
            offsets.push(at + 1);
        }
    }
    let at = |p: Position| -> Result<usize, String> {
        let line = offsets
            .get(p.line)
            .ok_or_else(|| format!("line {} is past the end", p.line + 1))?;
        let offset = line + p.column;
        if offset > source.len() || !source.is_char_boundary(offset) {
            return Err(format!(
                "column {} of line {} is not a character boundary",
                p.column,
                p.line + 1
            ));
        }
        Ok(offset)
    };
    let (a, b) = (at(start)?, at(end)?);
    source
        .get(a..b)
        .ok_or_else(|| format!("range {a}..{b} is not in the file"))
}

/// Closure hashes: each strongly connected component is hashed once over its
/// members' items and the closures of everything it calls outside itself;
/// each member's closure is its symbol over that component hash.
fn closures(
    names: &[&str],
    items: &[Digest],
    adjacency: &[Vec<usize>],
) -> Result<Vec<Digest>, String> {
    let mut closure: Vec<Option<Digest>> = vec![None; names.len()];
    for component in components(adjacency) {
        let inside: BTreeSet<usize> = component.iter().copied().collect();
        let mut members: Vec<usize> = component.clone();
        members.sort_by_key(|&m| names[m]);
        let mut callee: BTreeSet<Digest> = BTreeSet::new();
        for &m in &members {
            for &t in &adjacency[m] {
                if !inside.contains(&t) {
                    if let Some(c) = closure[t] {
                        callee.insert(c);
                    }
                }
            }
        }
        let mut fields: Vec<&[u8]> = Vec::new();
        for &m in &members {
            fields.push(names[m].as_bytes());
            fields.push(&items[m]);
        }
        fields.extend(callee.iter().map(|c| c.as_slice()));
        let component_hash = hash(COMPONENT, &fields);
        for &m in &members {
            closure[m] = Some(hash(CLOSURE, &[names[m].as_bytes(), &component_hash]));
        }
    }
    closure
        .into_iter()
        .zip(names)
        .map(|(c, name)| c.ok_or_else(|| format!("{name} is in no component")))
        .collect()
}

/// Tarjan's strongly connected components, iteratively; components come out
/// callees first, so every callee's closure exists before its callers'.
fn components(adjacency: &[Vec<usize>]) -> Vec<Vec<usize>> {
    let n = adjacency.len();
    let mut order: Vec<Option<usize>> = vec![None; n];
    let mut low = vec![0usize; n];
    let mut on_stack: HashSet<usize> = HashSet::new();
    let mut stack: Vec<usize> = Vec::new();
    let mut out = Vec::new();
    let mut counter = 0usize;
    for start in 0..n {
        if order[start].is_some() {
            continue;
        }
        let mut calls: Vec<(usize, usize)> = vec![(start, 0)];
        order[start] = Some(counter);
        low[start] = counter;
        counter += 1;
        stack.push(start);
        on_stack.insert(start);
        while let Some(top) = calls.last_mut() {
            let v = top.0;
            if top.1 < adjacency[v].len() {
                let w = adjacency[v][top.1];
                top.1 += 1;
                match order[w] {
                    None => {
                        order[w] = Some(counter);
                        low[w] = counter;
                        counter += 1;
                        stack.push(w);
                        on_stack.insert(w);
                        calls.push((w, 0));
                    }
                    Some(ow) if on_stack.contains(&w) => low[v] = low[v].min(ow),
                    Some(_) => {}
                }
                continue;
            }
            calls.pop();
            if let Some(&(parent, _)) = calls.last() {
                low[parent] = low[parent].min(low[v]);
            }
            if order[v] == Some(low[v]) {
                let mut component = Vec::new();
                while let Some(w) = stack.pop() {
                    on_stack.remove(&w);
                    component.push(w);
                    if w == v {
                        break;
                    }
                }
                out.push(component);
            }
        }
    }
    out
}

fn reach(
    adjacency: &[Vec<usize>],
    roots: &BTreeMap<&str, &'static str>,
    ids: &BTreeMap<&str, usize>,
) -> HashSet<usize> {
    let mut seen: HashSet<usize> = HashSet::new();
    let mut queue: VecDeque<usize> = roots.keys().filter_map(|r| ids.get(r).copied()).collect();
    seen.extend(queue.iter().copied());
    while let Some(v) = queue.pop_front() {
        for &w in &adjacency[v] {
            if seen.insert(w) {
                queue.push_back(w);
            }
        }
    }
    seen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn closures_of(
        names: &[&str],
        items: &[&[u8]],
        edges: &[(usize, usize)],
    ) -> Result<Vec<Digest>, String> {
        let items: Vec<Digest> = items.iter().map(|b| hash(ITEM, &[b])).collect();
        let mut adjacency = vec![Vec::new(); names.len()];
        for &(f, t) in edges {
            adjacency[f].push(t);
        }
        closures(names, &items, &adjacency)
    }

    #[test]
    fn a_change_deep_in_the_graph_reaches_every_caller() -> Result<(), String> {
        // c -> a -> b -> a (cycle), d stands alone.
        let names = ["a", "b", "c", "d"];
        let edges = [(0, 1), (1, 0), (2, 0)];
        let before = closures_of(&names, &[b"a", b"b", b"c", b"d"], &edges)?;
        let after = closures_of(&names, &[b"a", b"b2", b"c", b"d"], &edges)?;
        assert_ne!(before[0], after[0], "a is in b's cycle");
        assert_ne!(before[1], after[1]);
        assert_ne!(before[2], after[2], "c calls into the cycle");
        assert_eq!(before[3], after[3], "d calls nothing that changed");
        Ok(())
    }

    #[test]
    fn members_of_one_cycle_keep_distinct_closures() -> Result<(), String> {
        let c = closures_of(&["a", "b"], &[b"a", b"b"], &[(0, 1), (1, 0)])?;
        assert_ne!(c[0], c[1]);
        Ok(())
    }

    #[test]
    fn a_new_callee_changes_the_caller() -> Result<(), String> {
        let without = closures_of(&["a", "b"], &[b"a", b"b"], &[])?;
        let with = closures_of(&["a", "b"], &[b"a", b"b"], &[(0, 1)])?;
        assert_ne!(without[0], with[0]);
        assert_eq!(without[1], with[1]);
        Ok(())
    }

    #[test]
    fn test_functions_are_recognised_by_their_attribute() {
        assert!(is_test("#[test]\nfn a() {}"));
        assert!(is_test(
            "#[tokio::test(flavor = \"multi_thread\")]\nasync fn b() {}"
        ));
        assert!(!is_test(
            "/// Runs the test vectors.\nfn c() { run(\"#[test]\") }"
        ));
    }

    #[test]
    fn components_come_out_callees_first() {
        let order = components(&[vec![1], vec![2], vec![]]);
        assert_eq!(order, vec![vec![2], vec![1], vec![0]]);
    }

    #[test]
    fn slicing_is_by_utf8_byte() -> Result<(), String> {
        let source = "fn é() {}\nfn g() { 1 }\n";
        let text = slice(
            source,
            Position { line: 1, column: 0 },
            Position {
                line: 1,
                column: 12,
            },
        )?;
        assert_eq!(text, "fn g() { 1 }");
        let split = slice(
            source,
            Position { line: 0, column: 4 },
            Position { line: 0, column: 5 },
        );
        assert!(
            matches!(split, Err(e) if e.contains("not a character boundary")),
            "é is two bytes"
        );
        Ok(())
    }
}
