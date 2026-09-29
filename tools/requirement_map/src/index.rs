// SPDX-License-Identifier: MIT OR Apache-2.0
//! Reading a rust-analyzer SCIP index into definitions and the edges between
//! them, each edge named by the evidence the index gives for it.
//!
//! Every item definition the index emits becomes exactly one node, and every
//! other definition occurrence is counted under what it is (a local binding,
//! a module, a parameter), so nothing is dropped unaccounted. Two definitions
//! that share a SCIP symbol stay two nodes, keyed by where each is written:
//! an item written inside a function body is named by its module's path, so
//! two `const ROUTE`s in two handlers share one symbol. A reference to such a
//! symbol is resolved by Rust's scoping (an item inside a block is visible
//! only in that block); one scoping cannot decide is an uncertain edge; two
//! module-level items with one symbol stop the map.

use crate::reach::{code, Doubt};
use crate::source::{Head, Receiver, Source, TypeShape, Use};
use crate::symbols::{self, base_name, Item, Kind};
use protobuf::Message;
use scip::types::symbol_information::Kind as InfoKind;
use scip::types::{Index, PositionEncoding, SymbolRole};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const REFERENCE: &str = "reference";
/// An associated function or constant reaches its type without making a
/// value of it.
pub use crate::reach::ASSOCIATED_OF;
/// A reference that makes a value of the type it names.
pub use crate::reach::CONSTRUCT;
pub use crate::reach::MEMBER_OF;
/// A reference that dispatches on a type without a value (`f::<T>()`,
/// `<T as Trait>::f()`).
pub use crate::reach::TYPE_ARGUMENT;
pub const IMPL_OF: &str = "impl-of";
pub use crate::reach::SELF_TYPE;
pub use crate::reach::TRAIT_DISPATCH;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Position {
    pub line: usize,
    pub column: usize,
}

impl Position {
    pub fn shown(self) -> String {
        format!("{}:{}", self.line + 1, self.column)
    }
}

#[derive(Clone, Debug)]
pub struct Definition {
    /// The node: the SCIP symbol (qualified with the file for a target other
    /// than a library), and, when another definition shares that symbol, with
    /// where this one is written.
    pub symbol: String,
    /// The SCIP symbol as the index emitted it.
    pub raw: String,
    pub item: Item,
    pub file: String,
    pub start: Position,
    pub end: Position,
    /// Where the definition's name is written.
    pub name_at: Position,
    /// The function this item is written inside, if any: the only place a
    /// block item can be named.
    pub scope: Option<(Position, Position)>,
}

/// What the index proves about an edge, and where it says so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Evidence {
    /// `file:line` of the occurrence or definition the edge is read from.
    pub at: String,
    /// Why the index does not prove this edge; `None` when it does.
    pub doubt: Option<Doubt>,
    /// Every place the edge is written: each occurrence it is read from, with
    /// that occurrence's own doubt. A build whose `cfg` turns a site off does
    /// not compile that site. Empty for an edge read from definitions (a
    /// member, an impl, a dispatch), which a gate takes out with them.
    pub sites: Vec<Site>,
}

/// One occurrence an edge is read from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Site {
    pub file: String,
    pub at: Position,
    pub doubt: Option<Doubt>,
}

pub type Edges = BTreeMap<(String, String, &'static str), Evidence>;

/// The `Self` type of an impl method.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Owner {
    Known(String),
    Unknown(Doubt),
}

/// A SCIP symbol more than one definition carries, and how the map keeps
/// them apart.
#[derive(Clone, Debug)]
pub struct Collision {
    pub symbol: String,
    /// Each definition: `file:line:column`, and whether it is written inside
    /// a function (`block`) or at module level (`module`).
    pub definitions: Vec<(String, &'static str)>,
}

/// Every definition occurrence the index emitted, accounted for.
#[derive(Clone, Debug)]
pub struct Accounting {
    pub definition_occurrences: usize,
    /// Occurrences of item definitions (functions, types, constants, macros…).
    pub item_occurrences: usize,
    /// Item occurrences that repeat one already read (same symbol, file and extent).
    pub repeated: usize,
    /// Distinct item definitions: one node each.
    pub nodes: usize,
    pub locals: usize,
    pub modules: usize,
    pub parameters: usize,
    /// Definition occurrences with no symbol at all.
    pub unnamed: usize,
    pub collisions: Vec<Collision>,
    /// Definitions whose extent the index gave wrongly and the source's tokens corrected.
    pub repaired: Vec<String>,
    /// Groups of definitions one macro invocation writes, sharing its extent.
    pub macro_groups: usize,
    /// Macro invocations whose tokens parse as no Rust (a `macro_rules!`
    /// body, a macro's own syntax), read token by token: where, and why.
    pub token_read: Vec<(String, String)>,
}

impl Accounting {
    fn new() -> Self {
        Accounting {
            definition_occurrences: 0,
            item_occurrences: 0,
            repeated: 0,
            nodes: 0,
            locals: 0,
            modules: 0,
            parameters: 0,
            unnamed: 0,
            collisions: Vec::new(),
            repaired: Vec::new(),
            macro_groups: 0,
            token_read: Vec::new(),
        }
    }

    /// Every definition occurrence is exactly one of: an item (a node or a
    /// repeat of one), a local, a module, a parameter, or unnamed.
    pub fn check(&self) -> Result<(), String> {
        let items = self.nodes + self.repeated;
        let parts =
            self.item_occurrences + self.locals + self.modules + self.parameters + self.unnamed;
        if items != self.item_occurrences || parts != self.definition_occurrences {
            return Err(format!(
                "definitions do not add up: {} occurrences, {} items ({} nodes + {} repeats), {} locals, {} modules, {} parameters, {} unnamed",
                self.definition_occurrences,
                self.item_occurrences,
                self.nodes,
                self.repeated,
                self.locals,
                self.modules,
                self.parameters,
                self.unnamed
            ));
        }
        Ok(())
    }
}

pub struct Loaded {
    /// Every document the index holds, by its path from the repository root.
    pub documents: BTreeSet<String>,
    /// One per node.
    pub definitions: Vec<Definition>,
    pub edges: Edges,
    /// The `Self` type of each impl method of a trait the index holds.
    pub self_types: BTreeMap<String, Owner>,
    /// Impl methods of outside traits whose `Self` type the index holds no
    /// symbol for, and why.
    pub unlinked: BTreeMap<String, Doubt>,
    /// Per file, each local binding: where it is defined and its name.
    pub locals: BTreeMap<String, Vec<(Position, String)>>,
    /// Methods that take `self`: they run only on a value of their type. The
    /// others (associated functions) run through the type alone.
    pub value_receivers: BTreeSet<String>,
    /// Per file, the nodes it references outside every definition: its `use`
    /// items and impl headers (rust-analyzer records them as plain references).
    pub imports: BTreeMap<String, BTreeSet<String>>,
    /// Per file, where every occurrence the index records starts: a name
    /// written where none starts is one the index did not resolve.
    pub occurrences: BTreeMap<String, BTreeSet<Position>>,
    pub accounting: Accounting,
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

fn contains(outer: (Position, Position), at: Position) -> bool {
    outer.0 <= at && at <= outer.1
}

/// What a definition occurrence that is not an item is, read from the last
/// descriptor of its symbol.
fn non_item(symbol: &str) -> &'static str {
    match symbol.chars().last() {
        Some('/') => "module",
        _ => "parameter",
    }
}

/// An item definition as read from one document, before identities are given.
struct Read {
    raw: String,
    item: Item,
    start: Position,
    end: Position,
    name_at: Position,
}

pub fn load(bytes: &[u8], root: &Path) -> Result<Loaded, String> {
    let index = Index::parse_from_bytes(bytes)
        .map_err(|e| format!("the SCIP index does not parse: {e}"))?;
    let definition_role = SymbolRole::Definition as i32;
    let import_role = SymbolRole::Import as i32;

    // Pass 1: where each symbol is defined.
    let mut defined_in: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
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
            if occ.symbol_roles & definition_role != 0
                && !occ.symbol.is_empty()
                && !occ.symbol.starts_with("local ")
            {
                defined_in
                    .entry(occ.symbol.as_str())
                    .or_default()
                    .insert(doc.relative_path.as_str());
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
                let library = files.iter().find(|f| !outside_library(f));
                match (library, files.iter().next()) {
                    (Some(_), _) => raw.to_string(),
                    (None, Some(file)) => qualified(raw, file),
                    (None, None) => raw.to_string(),
                }
            }
        }
    };
    // Traits, by their resolved symbol.
    let mut traits: BTreeMap<String, String> = BTreeMap::new();
    for doc in &index.documents {
        for info in &doc.symbols {
            if info.kind.enum_value() == Ok(InfoKind::Trait) {
                traits.insert(
                    resolve(&info.symbol, &doc.relative_path),
                    info.symbol.clone(),
                );
            }
        }
    }

    // Pass 2: each document's item definitions (extents repaired where the
    // index gave them wrongly), local bindings, references and occurrences.
    let mut accounting = Accounting::new();
    let mut read: BTreeMap<String, Vec<Read>> = BTreeMap::new();
    let mut references: BTreeMap<String, Vec<(Position, String)>> = BTreeMap::new();
    let mut locals: BTreeMap<String, Vec<(Position, String)>> = BTreeMap::new();
    let mut occurrences: BTreeMap<String, BTreeSet<Position>> = BTreeMap::new();
    for doc in &index.documents {
        let path = doc.relative_path.as_str();
        let local_names: BTreeMap<&str, &str> = doc
            .symbols
            .iter()
            .filter(|info| info.symbol.starts_with("local "))
            .map(|info| (info.symbol.as_str(), info.display_name.as_str()))
            .collect();
        let mut items = Vec::new();
        let mut refs = Vec::new();
        let positions = occurrences.entry(path.to_string()).or_default();
        for occ in &doc.occurrences {
            let (at, _) = range_of(&occ.range)
                .map_err(|e| format!("{path}: occurrence {}: {e}", occ.symbol))?;
            positions.insert(at);
            let defines = occ.symbol_roles & definition_role != 0;
            if defines {
                accounting.definition_occurrences += 1;
            }
            if occ.symbol.is_empty() {
                if defines {
                    accounting.unnamed += 1;
                }
                continue;
            }
            if occ.symbol.starts_with("local ") {
                if defines {
                    accounting.locals += 1;
                    let name = local_names.get(occ.symbol.as_str()).ok_or_else(|| {
                        format!("{path}: local {} has no recorded name", occ.symbol)
                    })?;
                    locals
                        .entry(path.to_string())
                        .or_default()
                        .push((at, name.to_string()));
                }
                continue;
            }
            let item = symbols::item(&occ.symbol)?;
            match (defines, item) {
                (_, None) if defines => match non_item(&occ.symbol) {
                    "module" => accounting.modules += 1,
                    _ => accounting.parameters += 1,
                },
                (_, None) => {}
                (_, Some(it)) if defines => {
                    accounting.item_occurrences += 1;
                    let (start, end) = range_of(&occ.enclosing_range)
                        .map_err(|e| format!("{path}: definition {}: {e}", occ.symbol))?;
                    items.push(Read {
                        raw: occ.symbol.clone(),
                        item: it,
                        start,
                        end,
                        name_at: at,
                    });
                }
                (_, Some(_)) if occ.symbol_roles & import_role == 0 => {
                    refs.push((at, occ.symbol.clone()))
                }
                (_, Some(_)) => {}
            }
        }
        repair_extents(root, path, &mut items, &mut accounting)?;
        read.insert(path.to_string(), items);
        references.insert(path.to_string(), refs);
    }

    // Identities: one node per distinct definition; a symbol several
    // definitions share is split by where each is written.
    let mut definitions: Vec<Definition> = Vec::new();
    let mut by_key: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (path, items) in &read {
        let callables: Vec<(Position, Position)> = items
            .iter()
            .filter(|r| r.item.kind == Kind::Callable)
            .map(|r| (r.start, r.end))
            .collect();
        for r in items {
            let key = resolve(&r.raw, path);
            let scope = callables
                .iter()
                .filter(|c| **c != (r.start, r.end) && c.0 <= r.start && r.end <= c.1)
                .max_by_key(|c| c.0)
                .copied();
            let same = by_key.get(&key).and_then(|ids| {
                ids.iter().copied().find(|&i| {
                    let d = &definitions[i];
                    d.file == *path && d.start == r.start && d.end == r.end
                })
            });
            if same.is_some() {
                accounting.repeated += 1;
                continue;
            }
            by_key
                .entry(key.clone())
                .or_default()
                .push(definitions.len());
            definitions.push(Definition {
                symbol: key,
                raw: r.raw.clone(),
                item: r.item.clone(),
                file: path.clone(),
                start: r.start,
                end: r.end,
                name_at: r.name_at,
                scope,
            });
        }
    }
    for (key, ids) in &by_key {
        if ids.len() < 2 {
            continue;
        }
        let module_level: Vec<usize> = ids
            .iter()
            .copied()
            .filter(|&i| definitions[i].scope.is_none())
            .collect();
        let mut shown = Vec::new();
        for &i in ids {
            let d = &definitions[i];
            let place = format!("{}:{}", d.file, d.start.shown());
            let kind = if d.scope.is_some() { "block" } else { "module" };
            shown.push((place, kind));
        }
        if module_level.len() > 1 {
            let places: Vec<String> = shown.iter().map(|(p, k)| format!("{p} ({k})")).collect();
            return Err(format!(
                "{key} names {} module-level definitions; nothing in the index tells them apart: {}",
                module_level.len(),
                places.join(", ")
            ));
        }
        for &i in ids {
            if definitions[i].scope.is_some() {
                let d = &definitions[i];
                let split = format!("{key} @{}:{}", d.file, d.start.shown());
                definitions[i].symbol = split;
            }
        }
        accounting.collisions.push(Collision {
            symbol: key.clone(),
            definitions: shown,
        });
    }
    accounting.nodes = definitions.len();
    accounting.check()?;

    // Every file a definition is written in, read once and parsed once.
    let mut texts: BTreeMap<&str, String> = BTreeMap::new();
    for d in &definitions {
        if !texts.contains_key(d.file.as_str()) {
            let text = std::fs::read_to_string(root.join(&d.file))
                .map_err(|e| format!("{}: {e}", d.file))?;
            texts.insert(d.file.as_str(), text);
        }
    }
    let mut parsed: BTreeMap<&str, Source> = BTreeMap::new();
    for (path, text) in &texts {
        parsed.insert(path, Source::lex(text).map_err(|e| format!("{path}: {e}"))?);
    }
    for (path, source) in &parsed {
        for (at, why) in source.token_read() {
            accounting
                .token_read
                .push((format!("{path}:{}", at.shown()), why.to_string()));
        }
    }
    let parsed_file = |file: &str| -> Result<&Source, String> {
        parsed
            .get(file)
            .ok_or_else(|| format!("{file}: holds no definition, so it was not parsed"))
    };

    // An impl written inside a function has its header inside that
    // function's extent: the header declares the impl, it does not use its
    // type or trait, so references written there make no edge.
    let mut headers: BTreeMap<&str, Vec<(Position, Position)>> = BTreeMap::new();
    let mut seen_headers: BTreeSet<(&str, Position)> = BTreeSet::new();
    for d in &definitions {
        if d.scope.is_none() || d.item.container.is_empty() || d.item.kind == Kind::Type {
            continue;
        }
        if let Some(header) = parsed_file(&d.file)?.impl_header_at(d.name_at)? {
            if seen_headers.insert((d.file.as_str(), header.start)) {
                headers
                    .entry(d.file.as_str())
                    .or_default()
                    .push((header.start, header.end));
            }
        }
    }

    // References, attributed to the innermost definition around each and
    // resolved to the definition Rust's scoping selects.
    let mut edges = Edges::new();
    let mut imports: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut in_file: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
    // Each defined type, for telling a value made of it from a mention.
    let type_defs: BTreeMap<&str, &Definition> = definitions
        .iter()
        .filter(|d| d.item.kind == Kind::Type)
        .map(|d| (d.symbol.as_str(), d))
        .collect();
    let mut type_refs: Vec<(String, Position, String, String, Option<Doubt>)> = Vec::new();
    for (i, d) in definitions.iter().enumerate() {
        in_file.entry(d.file.as_str()).or_default().push(i);
    }
    for (path, refs) in &references {
        let here: &[usize] = match in_file.get(path.as_str()) {
            Some(v) => v,
            None => &[],
        };
        let declared_here: &[(Position, Position)] = match headers.get(path.as_str()) {
            Some(v) => v,
            None => &[],
        };
        for (at, raw) in refs {
            if declared_here.iter().any(|h| contains(*h, *at)) {
                continue;
            }
            let key = resolve(raw, path);
            let (targets, target_doubt) = scoped_targets(&definitions, &by_key, &key, path, *at);
            let (sources, source_doubt) = enclosing(&definitions, here, *at);
            if sources.is_empty() {
                for t in targets {
                    imports.entry(path.clone()).or_default().insert(t);
                }
                continue;
            }
            let doubt = match (target_doubt, source_doubt) {
                (Some(a), _) => Some(a),
                (None, b) => b,
            };
            for from in &sources {
                for to in &targets {
                    if from != to {
                        add_edge(
                            &mut edges,
                            from,
                            to,
                            REFERENCE,
                            Evidence {
                                at: format!("{path}:{}", at.line + 1),
                                doubt: doubt.clone(),
                                sites: vec![Site {
                                    file: path.clone(),
                                    at: *at,
                                    doubt: doubt.clone(),
                                }],
                            },
                        );
                        if type_defs.contains_key(to.as_str()) {
                            type_refs.push((
                                path.clone(),
                                *at,
                                from.clone(),
                                to.clone(),
                                doubt.clone(),
                            ));
                        }
                    }
                }
            }
        }
    }

    // Where a reference to a type makes a value of it: the tokens around the
    // reference decide (a literal, a constructor, a path call, a unit value).
    let mut shapes: BTreeMap<&str, TypeShape> = BTreeMap::new();
    for (symbol, d) in &type_defs {
        let text = texts
            .get(d.file.as_str())
            .ok_or_else(|| format!("{}: not read", d.file))?;
        let whole = crate::graph::slice(text, d.start, d.end)
            .map_err(|e| format!("{} ({}): {e}", d.symbol, d.file))?;
        let shape = crate::source::struct_shape(whole)
            .map_err(|e| format!("{} ({}): {e}", d.symbol, d.file))?;
        shapes.insert(symbol, shape);
    }
    for (path, at, from, to, doubt) in &type_refs {
        let source = parsed_file(path)?;
        let shape = match shapes.get(to.as_str()) {
            Some(s) => *s,
            None => TypeShape::Other,
        };
        let kind = match source.constructs_at(*at, shape)? {
            Use::Constructs => CONSTRUCT,
            Use::TypeArgument => TYPE_ARGUMENT,
            Use::Names | Use::NoToken => continue,
        };
        add_edge(
            &mut edges,
            from,
            to,
            kind,
            Evidence {
                at: format!("{path}:{}", at.line + 1),
                doubt: doubt.clone(),
                sites: vec![Site {
                    file: path.clone(),
                    at: *at,
                    doubt: doubt.clone(),
                }],
            },
        );
    }

    // The trait an impl implements, where its name alone matches several:
    // the index's own occurrence at the trait's name in the `impl … for …`
    // header, found through the tokens.
    let mut ref_at: BTreeMap<(&str, Position), &str> = BTreeMap::new();
    for (path, refs) in &references {
        for (at, raw) in refs {
            ref_at.insert((path.as_str(), *at), raw.as_str());
        }
    }
    let mut trait_names: BTreeMap<&str, usize> = BTreeMap::new();
    for t in traits.keys() {
        *trait_names.entry(base_name_of_symbol(t)).or_default() += 1;
    }
    let mut impl_traits: BTreeMap<String, String> = BTreeMap::new();
    for d in &definitions {
        if d.item.kind != Kind::Callable || d.item.trait_name.is_empty() {
            continue;
        }
        let same_name = trait_names.get(base_name(&d.item.trait_name)).copied();
        if !same_name.is_some_and(|n| n > 1) {
            continue;
        }
        if let Some(at) = parsed_file(&d.file)?.impl_trait_at(d.name_at)? {
            if let Some(raw) = ref_at.get(&(d.file.as_str(), at)) {
                impl_traits.insert(d.symbol.clone(), resolve(raw, &d.file));
            }
        }
    }

    // Which methods take `self`; an unreadable receiver is held to the
    // stricter rule.
    let mut value_receivers: BTreeSet<String> = BTreeSet::new();
    for d in &definitions {
        if d.item.kind != Kind::Callable || d.item.container.is_empty() {
            continue;
        }
        if parsed_file(&d.file)?.receiver_at(d.name_at)? != Receiver::NoSelf {
            value_receivers.insert(d.symbol.clone());
        }
    }

    let (self_types, unlinked) = add_impl_edges(
        &definitions,
        &traits,
        &imports,
        &impl_traits,
        &value_receivers,
        &mut edges,
    )?;
    let documents = index
        .documents
        .iter()
        .map(|d| d.relative_path.clone())
        .collect();
    Ok(Loaded {
        documents,
        definitions,
        edges,
        self_types,
        unlinked,
        value_receivers,
        locals,
        imports,
        occurrences,
        accounting,
    })
}

/// Records an edge; a proven reading of it replaces an uncertain one.
/// Adds an edge, or another place it is written: the sites add up, and a
/// proven site proves an edge only doubted sites held before.
pub fn add_edge(edges: &mut Edges, from: &str, to: &str, kind: &'static str, evidence: Evidence) {
    let key = (from.to_string(), to.to_string(), kind);
    match edges.get_mut(&key) {
        Some(existing) => {
            if existing.doubt.is_some() && evidence.doubt.is_none() {
                existing.at = evidence.at;
                existing.doubt = None;
            }
            existing.sites.extend(evidence.sites);
        }
        None => {
            edges.insert(key, evidence);
        }
    }
}

/// The nodes a reference to `key` at `at` in `path` can mean: the one
/// definition carrying it; or, when several do, the block item whose function
/// holds the reference (the innermost), else the one module-level item. An
/// undecided choice is every candidate, with the doubt.
fn scoped_targets(
    definitions: &[Definition],
    by_key: &BTreeMap<String, Vec<usize>>,
    key: &str,
    path: &str,
    at: Position,
) -> (Vec<String>, Option<Doubt>) {
    let Some(ids) = by_key.get(key) else {
        return (vec![key.to_string()], None);
    };
    if let [only] = ids.as_slice() {
        return (vec![definitions[*only].symbol.clone()], None);
    }
    let visible: Vec<(usize, Position)> = ids
        .iter()
        .filter_map(|&i| {
            let d = &definitions[i];
            match d.scope {
                Some(scope) if d.file == path && contains(scope, at) => Some((i, scope.0)),
                _ => None,
            }
        })
        .collect();
    if let Some(innermost) = visible.iter().map(|(_, start)| *start).max() {
        let chosen: Vec<String> = visible
            .iter()
            .filter(|(_, start)| *start == innermost)
            .map(|(i, _)| definitions[*i].symbol.clone())
            .collect();
        let doubt = (chosen.len() > 1).then(|| {
            Doubt::new(
                code::SCOPE_UNDECIDED,
                format!("{key} names {} block items in one function; the reference's scope does not decide", chosen.len()),
            )
        });
        return (chosen, doubt);
    }
    let module_level: Vec<&Definition> = ids
        .iter()
        .map(|&i| &definitions[i])
        .filter(|d| d.scope.is_none())
        .collect();
    match module_level.as_slice() {
        [one] => (vec![one.symbol.clone()], None),
        _ => {
            let all = ids.iter().map(|&i| definitions[i].symbol.clone()).collect();
            (
                all,
                Some(Doubt::new(
                    code::SCOPE_UNDECIDED,
                    format!(
                        "{key} names {} block items, none visible where it is referenced",
                        ids.len()
                    ),
                )),
            )
        }
    }
}

/// The innermost definitions whose extent holds `at`: one, or the several one
/// macro invocation writes over the same extent (with the doubt that the
/// index does not say which of them makes the reference).
fn enclosing(
    definitions: &[Definition],
    here: &[usize],
    at: Position,
) -> (Vec<String>, Option<Doubt>) {
    let mut best: Option<(Position, Position)> = None;
    for &i in here {
        let d = &definitions[i];
        let extent = (d.start, d.end);
        if contains(extent, at) && best.is_none_or(|b| b.0 <= extent.0 && extent.1 <= b.1) {
            best = Some(extent);
        }
    }
    let Some(extent) = best else {
        return (Vec::new(), None);
    };
    let group: Vec<String> = here
        .iter()
        .map(|&i| &definitions[i])
        .filter(|d| (d.start, d.end) == extent)
        .map(|d| d.symbol.clone())
        .collect();
    let doubt = (group.len() > 1).then(|| {
        Doubt::new(
            code::MACRO_GROUP,
            format!(
                "one macro invocation writes {} items over this extent; the index does not say which of them makes the reference",
                group.len()
            ),
        )
    });
    (group, doubt)
}

/// Corrects the extents the index got wrong in one document. An attribute
/// macro (`#[async_trait]`) makes the index report its whole impl block as
/// each method's extent; the tokens give each method its own. Items that
/// still share an extent must be the ones a single macro invocation writes;
/// anything else, and any two extents that cross, stop the map.
fn repair_extents(
    root: &Path,
    path: &str,
    items: &mut [Read],
    accounting: &mut Accounting,
) -> Result<(), String> {
    let troubled = items.iter().enumerate().any(|(a, x)| {
        items.iter().enumerate().any(|(b, y)| {
            a != b
                && ((x.start, x.end) == (y.start, y.end)
                    || (x.start < y.start && y.start <= x.end && x.end < y.end))
        })
    });
    if !troubled {
        return Ok(());
    }
    let text = std::fs::read_to_string(root.join(path)).map_err(|e| format!("{path}: {e}"))?;
    let source = Source::lex(&text).map_err(|e| format!("{path}: {e}"))?;
    let names: Vec<Position> = items.iter().map(|r| r.name_at).collect();
    for r in items.iter_mut() {
        if r.item.kind != Kind::Callable {
            continue;
        }
        let Some(own) = source.fn_extent(r.name_at)? else {
            continue;
        };
        let reported = (r.start, r.end);
        let covers_another_name = names
            .iter()
            .any(|n| *n != r.name_at && contains(reported, *n) && !contains(own, *n));
        if own != reported && covers_another_name {
            accounting
                .repaired
                .push(format!("{path}:{} {}", r.name_at.shown(), r.item.name));
            r.start = own.0;
            r.end = own.1;
        }
    }
    let mut groups: BTreeMap<(Position, Position), Vec<&Read>> = BTreeMap::new();
    for r in items.iter() {
        groups.entry((r.start, r.end)).or_default().push(r);
    }
    for ((start, end), group) in &groups {
        if group.len() < 2 {
            continue;
        }
        let invocation = source.head_at(*start, *end)? == Head::MacroCall;
        if !invocation {
            let names: Vec<&str> = group.iter().map(|r| r.item.name.as_str()).collect();
            return Err(format!(
                "{path}:{}-{}: {} definitions share one extent that is not a macro invocation and the tokens do not separate: {}",
                start.shown(),
                end.shown(),
                group.len(),
                names.join(", ")
            ));
        }
        accounting.macro_groups += 1;
    }
    for x in items.iter() {
        for y in items.iter() {
            if x.start < y.start && y.start <= x.end && x.end < y.end {
                return Err(format!(
                    "{path}: the extents of {} ({}-{}) and {} ({}-{}) cross",
                    x.item.name,
                    x.start.shown(),
                    x.end.shown(),
                    y.item.name,
                    y.start.shown(),
                    y.end.shown()
                ));
            }
        }
    }
    Ok(())
}

/// The types an item's container names, resolved as the compiler would find
/// the `Self` of an impl written here: a type of that name in the same file,
/// else in the same package, else anywhere the index defines one, else one it
/// only references. More than one candidate, or only a referenced one, is a
/// doubt.
fn owners(
    d: &Definition,
    types: &[&Definition],
    referenced: &BTreeMap<String, Vec<String>>,
) -> (Vec<String>, Option<Doubt>) {
    let owner = base_name(&d.item.container);
    let named: Vec<&&Definition> = types
        .iter()
        .filter(|t| base_name(&t.item.name) == owner)
        .collect();
    let same_file: Vec<&&Definition> = named.iter().copied().filter(|t| t.file == d.file).collect();
    let same_package: Vec<&&Definition> = named
        .iter()
        .copied()
        .filter(|t| t.item.package == d.item.package)
        .collect();
    let chosen = if !same_file.is_empty() {
        same_file
    } else if !same_package.is_empty() {
        same_package
    } else {
        named
    };
    if !chosen.is_empty() {
        let symbols: Vec<String> = chosen.iter().map(|t| t.symbol.clone()).collect();
        let doubt = (symbols.len() > 1).then(|| {
            Doubt::new(
                code::AMBIGUOUS_SELF_TYPE,
                format!("`{owner}` names {} types here", symbols.len()),
            )
        });
        return (symbols, doubt);
    }
    // A type the index references but does not define: from a dependency,
    // the standard library, or generated code. One of that name is that type.
    match referenced.get(owner) {
        Some(found) => {
            let doubt = (found.len() > 1).then(|| {
                Doubt::new(
                    code::AMBIGUOUS_SELF_TYPE,
                    format!(
                        "`{owner}` names {} types defined outside the indexed workspace",
                        found.len()
                    ),
                )
            });
            (found.clone(), doubt)
        }
        None => (Vec::new(), None),
    }
}

/// Edges the index states only through symbols' shapes: a member reaches its
/// type (`member-of`); an impl of a trait the index holds reaches the trait
/// (`impl-of`) and is reached from the trait's method (`trait-dispatch`,
/// counted only once its `Self` type is reached); an impl of an outside trait
/// (`Drop`, `From` through `?`, `Display`, derives) runs wherever its `Self`
/// type is used (`self-type`). Returns each workspace-trait impl's `Self`
/// type, and the outside-trait impls no type links.
fn add_impl_edges(
    definitions: &[Definition],
    traits: &BTreeMap<String, String>,
    imports: &BTreeMap<String, BTreeSet<String>>,
    impl_traits: &BTreeMap<String, String>,
    value_receivers: &BTreeSet<String>,
    edges: &mut Edges,
) -> Result<(BTreeMap<String, Owner>, BTreeMap<String, Doubt>), String> {
    let types: Vec<&Definition> = definitions
        .iter()
        .filter(|d| d.item.kind == Kind::Type)
        .collect();
    let defined: BTreeSet<&str> = definitions.iter().map(|d| d.symbol.as_str()).collect();
    let mut referenced: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (_, to, _) in edges.keys() {
        if defined.contains(to.as_str()) {
            continue;
        }
        let unqualified = match to.split_once(" @") {
            Some((head, _)) => head,
            None => to.as_str(),
        };
        if let Some(it) = symbols::item(unqualified)? {
            if it.kind == Kind::Type {
                referenced
                    .entry(base_name(&it.name).to_string())
                    .or_default()
                    .push(to.clone());
            }
        }
    }
    // Each trait's methods, by trait and method name.
    let mut trait_methods: BTreeMap<(&str, &str), Vec<&str>> = BTreeMap::new();
    for d in definitions {
        if d.item.kind != Kind::Callable || !d.item.trait_name.is_empty() {
            continue;
        }
        for (resolved, raw) in traits {
            if d.raw.starts_with(raw.as_str())
                && base_name(&d.item.container) == base_name_of_symbol(raw)
            {
                trait_methods
                    .entry((resolved.as_str(), d.item.name.as_str()))
                    .or_default()
                    .push(d.symbol.as_str());
            }
        }
    }
    let mut self_types = BTreeMap::new();
    let mut unlinked = BTreeMap::new();
    for d in definitions {
        let it = &d.item;
        if it.container.is_empty() || it.kind == Kind::Type {
            continue;
        }
        let at = format!("{}:{}", d.file, d.start.line + 1);
        let (owner_types, owner_doubt) = owners(d, &types, &referenced);
        // A field, or a method taking `self`, means a value of the type exists;
        // an associated function, constant or type only resolves the type.
        let member_kind = match it.kind {
            // An item an impl block or a trait declares is associated; a
            // struct's field is a member.
            Kind::Term
                if it.in_impl_block
                    || traits.values().any(|raw| {
                        d.raw.starts_with(raw.as_str())
                            && base_name(&it.container) == base_name_of_symbol(raw)
                    }) =>
            {
                ASSOCIATED_OF
            }
            Kind::Term => MEMBER_OF,
            Kind::Callable if value_receivers.contains(&d.symbol) => MEMBER_OF,
            Kind::Callable | Kind::Type | Kind::Macro => ASSOCIATED_OF,
        };
        for target in &owner_types {
            if *target != d.symbol {
                add_edge(
                    edges,
                    &d.symbol,
                    target,
                    member_kind,
                    Evidence {
                        at: at.clone(),
                        doubt: owner_doubt.clone(),
                        sites: Vec::new(),
                    },
                );
            }
        }
        if it.trait_name.is_empty() || it.kind != Kind::Callable {
            continue;
        }
        let trait_base = base_name(&it.trait_name);
        let candidates: Vec<&String> = traits
            .keys()
            .filter(|t| base_name_of_symbol(t) == trait_base)
            .collect();
        if candidates.is_empty() {
            // An outside trait: the impl runs where its `Self` type is used.
            if owner_types.is_empty() {
                unlinked.insert(
                    d.symbol.clone(),
                    Doubt::new(
                        code::UNLINKED_IMPL,
                        format!(
                            "an impl of the outside trait `{trait_base}` on `{}`, a type the index has no symbol for",
                            it.container
                        ),
                    ),
                );
            }
            for from in &owner_types {
                add_edge(
                    edges,
                    from,
                    &d.symbol,
                    SELF_TYPE,
                    Evidence {
                        at: at.clone(),
                        doubt: owner_doubt.clone(),
                        sites: Vec::new(),
                    },
                );
            }
            continue;
        }
        let imported: Vec<&&String> = candidates
            .iter()
            .filter(|t| {
                imports
                    .get(&d.file)
                    .is_some_and(|set| set.contains(t.as_str()))
            })
            .collect();
        let header = impl_traits
            .get(&d.symbol)
            .and_then(|t| candidates.iter().copied().find(|c| *c == t));
        let (resolved, trait_doubt): (Vec<&String>, Option<Doubt>) =
            match (header, candidates.as_slice(), imported.as_slice()) {
                (Some(t), _, _) => (vec![t], None),
                (None, [one], _) => (vec![*one], None),
                (None, _, [one]) => (vec![**one], None),
                (None, many, _) => (
                    many.to_vec(),
                    Some(Doubt::new(
                        code::AMBIGUOUS_TRAIT,
                        format!(
                            "the trait `{trait_base}` names {} traits and {} imports {} of them",
                            many.len(),
                            d.file,
                            imported.len()
                        ),
                    )),
                ),
            };
        for t in &resolved {
            add_edge(
                edges,
                &d.symbol,
                t,
                IMPL_OF,
                Evidence {
                    at: at.clone(),
                    doubt: trait_doubt.clone(),
                    sites: Vec::new(),
                },
            );
            for from in trait_methods
                .get(&(t.as_str(), it.name.as_str()))
                .into_iter()
                .flatten()
            {
                add_edge(
                    edges,
                    from,
                    &d.symbol,
                    TRAIT_DISPATCH,
                    Evidence {
                        at: at.clone(),
                        doubt: trait_doubt.clone(),
                        sites: Vec::new(),
                    },
                );
            }
        }
        let owner = match (owner_types.as_slice(), &owner_doubt) {
            ([one], None) => Owner::Known(one.clone()),
            (_, Some(doubt)) => Owner::Unknown(Doubt::new(
                doubt.code,
                format!("the impl's Self type: {}", doubt.text),
            )),
            ([], None) => Owner::Unknown(Doubt::new(
                code::AMBIGUOUS_SELF_TYPE,
                format!(
                    "the impl's Self type `{}` is not a type the index holds",
                    base_name(&it.container)
                ),
            )),
            (many, None) => Owner::Unknown(Doubt::new(
                code::AMBIGUOUS_SELF_TYPE,
                format!("the impl's Self type names {} types", many.len()),
            )),
        };
        self_types.insert(d.symbol.clone(), owner);
    }
    Ok((self_types, unlinked))
}

/// The bare name a type or trait symbol ends in.
fn base_name_of_symbol(symbol: &str) -> &str {
    let unqualified = match symbol.split_once(" @") {
        Some((head, _)) => head,
        None => symbol,
    };
    let trimmed = unqualified.trim_end_matches('#');
    let start = trimmed.rfind(['/', '#', ' ']).map_or(0, |i| i + 1);
    base_name(trimmed[start..].trim_matches('`'))
}
