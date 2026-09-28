// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reading a rust-analyzer SCIP index into definitions and reference edges.

use crate::symbols::{self, base_name, Item, Kind};
use protobuf::Message;
use scip::types::symbol_information::Kind as InfoKind;
use scip::types::{Index, PositionEncoding, SymbolRole};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

#[derive(Clone, Debug)]
pub struct Definition {
    /// The SCIP symbol, qualified with its file when the file is not part of a
    /// library target (a binary, an integration test, a build script), whose
    /// crate-root symbols would otherwise collide with the library's.
    pub symbol: String,
    pub item: Item,
    pub file: String,
    pub start: Position,
    pub end: Position,
}

pub type Edges = BTreeSet<(String, String, &'static str)>;

pub struct Loaded {
    pub definitions: Vec<Definition>,
    pub edges: Edges,
    /// Impl methods of outside traits whose `Self` type the index holds no
    /// symbol for (a primitive, a type it never names): nothing links them.
    pub unlinked: BTreeSet<String>,
}

/// Files that are the root of a target other than a library: symbols defined
/// there are qualified with the file.
pub fn outside_library(path: &str) -> bool {
    path.ends_with("build.rs")
        || path.ends_with("/src/main.rs")
        || path.contains("/src/bin/")
        || path.contains("/tests/")
        || path.contains("/benches/")
        || path.contains("/examples/")
}

fn qualified(symbol: &str, file: &str) -> String {
    format!("{symbol} @{file}")
}

fn range_of(range: &[i32]) -> Result<(Position, Position), String> {
    let at = |v: i32| usize::try_from(v).map_err(|e| format!("negative range value {v}: {e}"));
    match range {
        [line, start, end] => Ok((
            Position {
                line: at(*line)?,
                column: at(*start)?,
            },
            Position {
                line: at(*line)?,
                column: at(*end)?,
            },
        )),
        [line, start, end_line, end] => Ok((
            Position {
                line: at(*line)?,
                column: at(*start)?,
            },
            Position {
                line: at(*end_line)?,
                column: at(*end)?,
            },
        )),
        other => Err(format!("a range has {} values", other.len())),
    }
}

pub fn load(bytes: &[u8]) -> Result<Loaded, String> {
    let index = Index::parse_from_bytes(bytes)
        .map_err(|e| format!("the SCIP index does not parse: {e}"))?;
    let definition_role = SymbolRole::Definition as i32;
    let import_role = SymbolRole::Import as i32;

    // Pass 1: where each symbol is defined, and which type symbols are traits.
    let mut defined_in: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut traits: BTreeSet<String> = BTreeSet::new();
    for doc in &index.documents {
        match doc.position_encoding.enum_value() {
            Ok(PositionEncoding::UTF8CodeUnitOffsetFromLineStart) => {}
            other => {
                return Err(format!(
                    "{}: columns are counted as {other:?}; this tool slices source by UTF-8 byte",
                    doc.relative_path
                ))
            }
        }
        for occ in &doc.occurrences {
            if occ.symbol_roles & definition_role != 0 && !occ.symbol.starts_with("local ") {
                defined_in
                    .entry(occ.symbol.as_str())
                    .or_default()
                    .insert(doc.relative_path.as_str());
            }
        }
        for info in &doc.symbols {
            if info.kind.enum_value() == Ok(InfoKind::Trait) {
                if let Some(it) = symbols::item(&info.symbol)? {
                    traits.insert(base_name(&it.name).to_string());
                }
            }
        }
    }

    let resolve = |raw: &str, doc: &str| -> String {
        match defined_in.get(raw) {
            None => raw.to_string(),
            Some(files) if files.contains(doc) => {
                if outside_library(doc) {
                    qualified(raw, doc)
                } else {
                    raw.to_string()
                }
            }
            Some(files) => {
                let library: Vec<&&str> = files.iter().filter(|f| !outside_library(f)).collect();
                match (library.first(), files.iter().next()) {
                    (Some(_), _) => raw.to_string(),
                    (None, Some(file)) => qualified(raw, file),
                    (None, None) => raw.to_string(),
                }
            }
        }
    };

    // Pass 2: definitions, and each reference attached to the innermost
    // definition around it.
    let mut definitions = Vec::new();
    let mut edges = Edges::new();
    for doc in &index.documents {
        let path = doc.relative_path.as_str();
        let mut spans: Vec<(Position, Position, String)> = Vec::new();
        let mut refs: Vec<(Position, String)> = Vec::new();
        for occ in &doc.occurrences {
            if occ.symbol.is_empty() || occ.symbol.starts_with("local ") {
                continue;
            }
            let Some(it) = symbols::item(&occ.symbol)? else {
                continue;
            };
            if occ.symbol_roles & definition_role != 0 {
                let (start, end) = range_of(&occ.enclosing_range)
                    .map_err(|e| format!("{path}: definition {}: {e}", occ.symbol))?;
                let symbol = resolve(&occ.symbol, path);
                spans.push((start, end, symbol.clone()));
                definitions.push(Definition {
                    symbol,
                    item: it,
                    file: path.to_string(),
                    start,
                    end,
                });
            } else if occ.symbol_roles & import_role == 0 {
                let (at, _) = range_of(&occ.range)
                    .map_err(|e| format!("{path}: reference {}: {e}", occ.symbol))?;
                refs.push((at, resolve(&occ.symbol, path)));
            }
        }
        spans.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)));
        refs.sort();
        let mut open: Vec<usize> = Vec::new();
        let mut next = 0usize;
        for (at, target) in refs {
            while next < spans.len() && spans[next].0 <= at {
                open.push(next);
                next += 1;
            }
            while let Some(&top) = open.last() {
                if spans[top].1 < at {
                    open.pop();
                } else {
                    break;
                }
            }
            if let Some(&top) = open
                .iter()
                .rev()
                .find(|&&s| spans[s].0 <= at && at <= spans[s].1)
            {
                let from = &spans[top].2;
                if *from != target {
                    edges.insert((from.clone(), target, "ref"));
                }
            }
        }
    }

    let unlinked = add_impl_edges(&definitions, &traits, &mut edges)?;
    Ok(Loaded {
        definitions,
        edges,
        unlinked,
    })
}

/// A call through a trait names the trait's method, not the impl that runs:
/// each local trait method reaches every impl of it. An impl of a trait from
/// outside the index (`Drop`, `From`, `Display`, derives) runs wherever its
/// `Self` type is used, so every type of that name, in any package (an impl
/// may live in another crate than its type) or only referenced (generated
/// protobuf types), reaches it. Returns the impls no type links.
fn add_impl_edges(
    definitions: &[Definition],
    traits: &BTreeSet<String>,
    edges: &mut Edges,
) -> Result<BTreeSet<String>, String> {
    let mut trait_methods: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
    let mut types: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for d in definitions {
        let it = &d.item;
        if it.kind == Kind::Callable
            && it.trait_name.is_empty()
            && traits.contains(base_name(&it.container))
        {
            trait_methods
                .entry((base_name(&it.container), it.name.as_str()))
                .or_default()
                .push(&d.symbol);
        }
        if it.kind == Kind::Type {
            types
                .entry(base_name(&it.name))
                .or_default()
                .push(&d.symbol);
        }
    }
    let defined: BTreeSet<&str> = definitions.iter().map(|d| d.symbol.as_str()).collect();
    let mut referenced_types: Vec<(String, String)> = Vec::new();
    for (_, to, _) in edges.iter() {
        if defined.contains(to.as_str()) {
            continue;
        }
        if let Some(it) = symbols::item(to)? {
            if it.kind == Kind::Type {
                referenced_types.push((base_name(&it.name).to_string(), to.clone()));
            }
        }
    }
    for (name, symbol) in &referenced_types {
        types
            .entry(name.as_str())
            .or_default()
            .push(symbol.as_str());
    }
    // A type is in use when one of its members is: a method or associated
    // item reaches its own type (same file first, then same package, then any
    // package), and a trait impl reaches the trait it implements.
    let mut types_in: BTreeMap<(&str, &str), Vec<&Definition>> = BTreeMap::new();
    for d in definitions {
        if d.item.kind == Kind::Type {
            types_in
                .entry((d.file.as_str(), base_name(&d.item.name)))
                .or_default()
                .push(d);
        }
    }
    for d in definitions {
        let it = &d.item;
        if it.container.is_empty() || it.kind == Kind::Type {
            continue;
        }
        let owner = base_name(&it.container);
        let in_file = types_in.get(&(d.file.as_str(), owner));
        let named = types.get(owner).map(|v| v.as_slice()).into_iter().flatten();
        let targets: Vec<String> = match in_file {
            Some(found) => found.iter().map(|t| t.symbol.clone()).collect(),
            None => {
                let same_package: Vec<String> = definitions
                    .iter()
                    .filter(|t| {
                        t.item.kind == Kind::Type
                            && t.item.package == it.package
                            && base_name(&t.item.name) == owner
                    })
                    .map(|t| t.symbol.clone())
                    .collect();
                if same_package.is_empty() {
                    named.map(|s| s.to_string()).collect()
                } else {
                    same_package
                }
            }
        };
        for target in targets {
            if target != d.symbol {
                edges.insert((d.symbol.clone(), target, "member-of"));
            }
        }
        if !it.trait_name.is_empty() && traits.contains(base_name(&it.trait_name)) {
            for target in types.get(base_name(&it.trait_name)).into_iter().flatten() {
                edges.insert((d.symbol.clone(), target.to_string(), "impl-of"));
            }
        }
    }
    let mut unlinked = BTreeSet::new();
    for d in definitions {
        let it = &d.item;
        if it.kind != Kind::Callable || it.trait_name.is_empty() {
            continue;
        }
        let trait_name = base_name(&it.trait_name);
        if traits.contains(trait_name) {
            for from in trait_methods
                .get(&(trait_name, it.name.as_str()))
                .into_iter()
                .flatten()
            {
                edges.insert((from.to_string(), d.symbol.clone(), "trait-impl"));
            }
        } else {
            match types.get(base_name(&it.container)) {
                Some(owners) => {
                    for from in owners {
                        edges.insert((from.to_string(), d.symbol.clone(), "type-impl"));
                    }
                }
                None => {
                    unlinked.insert(d.symbol.clone());
                }
            }
        }
    }
    Ok(unlinked)
}
