// SPDX-License-Identifier: MIT OR Apache-2.0
//! The map: every definition of every profile with its item and closure
//! hashes, and, for each shipped artifact separately, its reachability from
//! that artifact's entry points in three values, with a reason code and the
//! source of every fact. Reachability is never computed over a union of two
//! artifacts' edges: an Android build and a Linux build compile different
//! code.

use crate::hashing::{hash, Digest, CLOSURE, COMPONENT, EXTERNAL, ITEM};
use crate::index::{
    add_edge, Definition, Edges, Evidence, Loaded, Owner, Position, Site, REFERENCE,
};
use crate::reach::{self, code, Doubt, SelfType, State, Via};
use crate::source::{Form, Source};
use crate::symbols::{base_name, Kind};
use crate::tokens::{canonical, format_captures, outer_attributes, Attribute};
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
use std::path::Path;

pub const FORMAT_CAPTURE: &str = "format-capture";

/// What kind of entry point a definition is, as the map records it. `MAIN`,
/// `LOAD`, `VM` and `EXPORT` are entry points of a shipped build, and `TEST`
/// of the test build; the others say why a definition that looks like one
/// is not.
pub mod root {
    /// A binary's `main`.
    pub const MAIN: &str = "main";
    /// A load-time constructor or destructor.
    pub const LOAD: &str = "load";
    /// `JNI_OnLoad` or `JNI_OnUnload`, which the JVM calls by specification.
    pub const VM: &str = "vm";
    /// An export a Kotlin `external fun` declares.
    pub const EXPORT: &str = "export";
    /// A test function, in the host test build.
    pub const TEST: &str = "test";
    /// An export nothing declares: a dead-root candidate.
    pub const UNDECLARED_EXPORT: &str = "undeclared-export";
    /// An export only a declaration this map cannot spell could be: Indeterminate.
    pub const UNREAD_DECLARATION: &str = "unread-declaration";
    /// An entry point under a gate this map cannot decide for the build: Indeterminate.
    pub const UNDECIDED_GATE: &str = "undecided-gate";
}

/// A shipped artifact: the files its crates compile, and its index when this
/// host built one.
pub struct Artifact<'a> {
    pub name: &'static str,
    pub crates: &'a [&'a str],
    /// The artifact's index, or why this host has none.
    pub loaded: Result<&'a Loaded, String>,
    /// The build's target, and each of its packages' features: what its
    /// `cfg` decides.
    pub target: crate::cfgs::Target,
    pub features: &'a BTreeMap<String, BTreeSet<String>>,
    /// Each crate's source prefix and its package.
    pub packages: Vec<(String, String)>,
    /// A crate this artifact ships that the map cannot index here, and what
    /// its source uses from the indexed crates.
    pub unindexed: Option<&'a (String, Consumer)>,
    /// What features the index enabled and this artifact does not take out.
    pub excluded: crate::cfgs::Exclusions,
}

/// What a crate the map cannot index uses from the crates it does: every
/// name in its `use`s of and paths through them, and every call it writes in
/// method or path form.
pub struct Consumer {
    pub used: BTreeSet<String>,
    pub calls: Vec<ConsumerCall>,
    /// The functions its source writes, by name.
    pub defines: BTreeSet<String>,
}

/// A call a consumer writes to something it may take from the indexed crates.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConsumerCall {
    /// `receiver.name(…)`
    Method(String),
    /// `Qualifier::name(…)`: the qualifier, then the name.
    Path(String, String),
}

/// One artifact's reading of one node.
#[derive(Clone, Debug)]
pub struct Status {
    /// `reached`, `indeterminate`, `dead`, `not-in-artifact` or `not-built`.
    pub state: &'static str,
    /// A stable code: `REACHED` or `REACHED_VIA_DISPATCH`, an `IND_*` code,
    /// `DEAD_NO_ROOT_PATH`, `NOT_IN_ARTIFACT`.
    pub code: &'static str,
    /// Why it is in this state; none when it is Reached (the witness says how).
    pub reason: Option<String>,
    /// The node it came from, or the entry-point kind; none when nothing led
    /// to it (dead, not built, not in the artifact, or a seed).
    pub via: Option<String>,
    /// The edge kind it came over, `root`, or `seed`; none when nothing led to it.
    pub via_kind: Option<&'static str>,
    /// `file:line` of that evidence; none when there is no single place.
    pub at: Option<String>,
    /// What established the fact: `scip-occurrence`, `scip-symbol-shape`,
    /// `format-string`, `attribute`, `token-detector`, `macro-body-tokens`,
    /// `consumer-source-tokens`, `graph`, `profile`.
    pub source: &'static str,
}

pub struct Node {
    pub def: Definition,
    /// The Rust path that names it (`dsm::economic::write_set::build_write_set`,
    /// a trait method as `Type::Trait::method`); none for an item written
    /// inside a function, which no path names.
    pub path: Option<String>,
    pub item: Digest,
    pub closure: Digest,
    /// A test function reaches it (over the host test build's edges).
    pub tested: bool,
    /// What kind of entry point it is, per artifact: `export`, `vm`, `load`,
    /// `main`; `undeclared-export` for an export nothing declares;
    /// `unread-declaration` for one a declaration this map cannot spell
    /// could be.
    pub roots: BTreeMap<&'static str, &'static str>,
    /// The profiles whose index defines it.
    pub built_in: Vec<&'static str>,
    pub status: BTreeMap<&'static str, Status>,
}

/// Per artifact: its entry points and how its nodes came out, and what the
/// uncertainty detectors found.
#[derive(Clone, Debug)]
pub struct Tally {
    pub built: &'static str,
    /// Definitions the index holds that this artifact does not compile.
    pub excluded: usize,
    pub roots: usize,
    pub dead_roots: usize,
    /// Exports only a declaration this map cannot spell could be.
    pub unread_roots: usize,
    pub reached: usize,
    pub indeterminate: usize,
    pub dead: usize,
    pub unresolved_call_tokens: usize,
    /// Unresolved calls inside no definition any profile holds.
    pub unattributed_call_tokens: usize,
    /// Unresolved calls in code this build does not compile (test modules,
    /// gated-off items): not this build's calls.
    pub uncompiled_call_tokens: usize,
    /// Edges the index read only where this build's `cfg` turns the code off.
    pub uncompiled_edges: usize,
    pub unresolved_call_candidates: usize,
    pub macro_body_candidates: usize,
    pub unindexed_candidates: usize,
    /// The Kotlin-declared JNI symbols this artifact exports.
    pub exported_declarations: BTreeSet<String>,
}

pub struct Map {
    pub nodes: BTreeMap<String, Node>,
    /// Each artifact's edges as its build compiles them, and the test
    /// profile's: (profile, from, to, kind, evidence).
    pub edges: Vec<(&'static str, String, String, &'static str, Evidence)>,
    pub tallies: BTreeMap<&'static str, Tally>,
    /// Each root query's answer, in the order asked.
    pub root_answers: Vec<RootAnswer>,
}

/// A question the intent comparator asks: is `symbol` reached from the one
/// entry point `root` in `artifact`'s build? Both are Rust paths.
pub struct RootQuery {
    pub artifact: String,
    pub root: String,
    pub symbol: String,
}

/// The map's answer: the state and code `symbol` reads when `root` is the
/// build's only entry point, by the same rules as the build's own reading.
pub struct RootAnswer {
    pub artifact: String,
    pub root: String,
    pub symbol: String,
    pub state: &'static str,
    pub code: &'static str,
}

pub struct Inputs<'a> {
    pub artifacts: Vec<Artifact<'a>>,
    pub tests: &'a Loaded,
    /// JNI symbols the app's Kotlin declares, and where.
    pub declared_jni: &'a crate::jni::Declarations,
    /// The root queries asked, if any were.
    pub root_queries: Option<&'a [RootQuery]>,
}

fn in_crates(file: &str, crates: &[&str]) -> bool {
    crates.iter().any(|c| file.starts_with(c))
}

/// The Rust path that names a definition, or empty when none does.
fn rust_path(d: &Definition) -> Option<String> {
    if d.scope.is_some() {
        return None;
    }
    let mut parts: Vec<String> = vec![d.item.package.replace('-', "_")];
    parts.extend(d.item.modules.iter().cloned());
    if !d.item.container.is_empty() {
        parts.push(base_name(&d.item.container).to_string());
    }
    if !d.item.trait_name.is_empty() {
        parts.push(base_name(&d.item.trait_name).to_string());
    }
    parts.push(d.item.name.trim_matches('`').to_string());
    Some(parts.join("::"))
}

/// The symbol an exported function is linked under: its `export_name`, or
/// its own name under `no_mangle`; none when it is not exported. An
/// `export_name` without a quoted name is an error.
fn exported_name(d: &Definition, attributes: &[Attribute]) -> Result<Option<String>, String> {
    let mut exported = None;
    for a in attributes {
        match export_attribute(a).map_err(|e| format!("{} ({}): {e}", d.symbol, d.file))? {
            Some(Export::OwnName) => exported = Some(d.item.name.clone()),
            Some(Export::Named(name)) => exported = Some(name),
            None => {}
        }
    }
    Ok(exported)
}

/// What an attribute exports an item as.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Export {
    /// `#[no_mangle]`: under its own name.
    OwnName,
    /// `#[export_name = "…"]`: under that name.
    Named(String),
}

/// Reads `#[no_mangle]`, `#[export_name = "…"]` and their `#[unsafe(…)]`
/// forms by their first word; any other attribute exports nothing. A
/// `no_mangle` or `export_name` written some other way is an error.
fn export_attribute(a: &Attribute) -> Result<Option<Export>, String> {
    let words: Vec<&str> = a.args.split_whitespace().collect();
    let (attribute, rest): (&str, &[&str]) = match (a.path.as_str(), words.as_slice()) {
        ("unsafe", ["(", inner, rest @ .., ")"]) => (inner, rest),
        (path, rest) => (path, rest),
    };
    match (attribute, rest) {
        ("no_mangle", []) => Ok(Some(Export::OwnName)),
        ("export_name", ["=", literal])
            if literal.len() >= 2 && literal.starts_with('"') && literal.ends_with('"') =>
        {
            Ok(Some(Export::Named(
                literal[1..literal.len() - 1].to_string(),
            )))
        }
        ("no_mangle", _) | ("export_name", _) => Err(format!(
            "`{attribute}` written as `{}`, which this map does not read",
            a.args
        )),
        _ => Ok(None),
    }
}

/// Whether `file` is the root of a binary target: `src/main.rs`,
/// `src/bin/<name>.rs`, or `src/bin/<name>/main.rs`.
fn binary_root(file: &str) -> bool {
    file.ends_with("/src/main.rs")
        || file.split_once("/src/bin/").is_some_and(|(_, rest)| {
            let parts: Vec<&str> = rest.split('/').collect();
            matches!(parts.as_slice(), [one] if one.ends_with(".rs"))
                || matches!(parts.as_slice(), [_, "main.rs"])
        })
}

/// What kind of entry point a definition is for an artifact, if it is one:
/// the `main` of a binary; a load-time constructor; `JNI_OnLoad`, which the
/// JVM calls by specification; an exported function a Kotlin `external fun`
/// declares. An export nothing declares is `undeclared-export`: a dead-root
/// candidate, not an entry point. A `Java_…` export that only a declaration
/// this map cannot spell could be is `unread-declaration`: Indeterminate. (An
/// entry point under a gate the map cannot decide for an artifact is
/// recorded there as `undecided-gate`: Indeterminate.)
fn root_kind(
    d: &Definition,
    attributes: &[Attribute],
    declared: &crate::jni::Declarations,
) -> Result<Option<&'static str>, String> {
    let it = &d.item;
    if it.kind != Kind::Callable || !it.container.is_empty() || d.scope.is_some() {
        return Ok(None);
    }
    // A binary's `main`: at the crate root of a binary target.
    if binary_root(&d.file) && it.modules.is_empty() && it.name == "main" {
        return Ok(Some(root::MAIN));
    }
    if runs_at_load(attributes) {
        return Ok(Some(root::LOAD));
    }
    let Some(exported) = exported_name(d, attributes)? else {
        return Ok(None);
    };
    // The JVM calls these by specification when it loads and unloads the library.
    if exported == "JNI_OnLoad" || exported == "JNI_OnUnload" {
        return Ok(Some(root::VM));
    }
    if declared.symbols.contains_key(&exported) {
        return Ok(Some(root::EXPORT));
    }
    if declared.could_be(&exported).is_some() {
        return Ok(Some(root::UNREAD_DECLARATION));
    }
    Ok(Some(root::UNDECLARED_EXPORT))
}

/// Whether the `cfg` predicates around a call in `file` turn it off in the
/// artifact's build: its target, its package's features, no `test`, no
/// `debug_assertions`. A predicate the evaluator cannot decide leaves the
/// call in.
fn compiled_out(gates: &[String], file: &str, a: &Artifact) -> Result<bool, String> {
    let features = package_features(file, &a.packages, a.features)?;
    let truths = gates
        .iter()
        .map(|gate| {
            let tokens: Vec<proc_macro2::TokenTree> = gate
                .parse::<proc_macro2::TokenStream>()
                .map_err(|e| format!("{file}: `cfg({gate})`: {e}"))?
                .into_iter()
                .collect();
            crate::cfgs::evaluate_for(&tokens, features, &a.target)
        })
        .collect::<Result<Vec<_>, String>>()?;
    Ok(truths.contains(&crate::cfgs::Truth::No))
}

/// The features the build turns on for the package `file` belongs to. A file
/// of no package the build links, or a package whose features were not read,
/// is an error: evaluating its gates with no features would decide them.
fn package_features<'a>(
    file: &str,
    packages: &[(String, String)],
    features: &'a BTreeMap<String, BTreeSet<String>>,
) -> Result<&'a BTreeSet<String>, String> {
    let (_, package) = packages
        .iter()
        .find(|(prefix, _)| file.starts_with(prefix.as_str()))
        .ok_or_else(|| format!("{file}: in no package the build links"))?;
    features
        .get(&crate::cfgs::feature_key(package))
        .ok_or_else(|| format!("{package}: no features read for it"))
}

/// Whether the callable `d` can be what a call written as `form` names, from
/// a call site inside the definition `site`: none when the site is not one
/// definition (a macro's body, written once and expanded wherever it is
/// invoked). A qualifier only the site decides (`self::`, `super::`,
/// `Self::`) with no site fits every candidate of its kind: undecided, never
/// excluded.
fn call_fits(form: &Form, d: &Definition, site: Option<&Definition>) -> bool {
    let free = d.item.container.is_empty();
    match form {
        Form::Method => !free,
        Form::Bare => free,
        Form::Path(Some(q)) => match (q.as_str(), site) {
            ("Self", Some(s)) => {
                !free && base_name(&d.item.container) == base_name(&s.item.container)
            }
            ("Self", None) => !free,
            ("self", Some(s)) => free && d.item.modules == s.item.modules,
            ("super", Some(s)) => {
                free && s
                    .item
                    .modules
                    .split_last()
                    .is_some_and(|(_, parent)| d.item.modules == parent)
            }
            ("self" | "super", None) => free,
            ("crate", _) => free && d.item.modules.is_empty(),
            (q, _) => {
                base_name(&d.item.container) == q || d.item.modules.last().is_some_and(|m| m == q)
            }
        },
        // `<T as Trait>::f(…)` or `Type::<A>::f(…)`: any item of that name.
        Form::Path(None) => !free,
    }
}

fn edge_source(kind: &str) -> &'static str {
    match kind {
        k if k == REFERENCE || k == crate::reach::CONSTRUCT || k == crate::reach::TYPE_ARGUMENT => {
            "scip-occurrence"
        }
        k if k == FORMAT_CAPTURE => "format-string",
        _ => "scip-symbol-shape",
    }
}

fn seed_source(code_: &str) -> &'static str {
    match code_ {
        c if c == code::UNRESOLVED_CALL => "token-detector",
        c if c == code::MACRO_BODY => "macro-body-tokens",
        c if c == code::UNINDEXED_ARTIFACT => "consumer-source-tokens",
        c if c == code::UNLINKED_IMPL => "scip-symbol-shape",
        _ => "graph",
    }
}

pub fn build(root: &Path, inputs: &Inputs) -> Result<Map, String> {
    // The profiles whose index this host built, in order: artifacts, then tests.
    let mut profiles: Vec<(&'static str, &Loaded)> = Vec::new();
    for a in &inputs.artifacts {
        if let Ok(loaded) = &a.loaded {
            profiles.push((a.name, loaded));
        }
    }
    profiles.push(("tests", inputs.tests));

    // The node table: one entry per definition key, from the first profile
    // that defines it.
    let mut defs: BTreeMap<String, Definition> = BTreeMap::new();
    let mut built_in: BTreeMap<String, Vec<&'static str>> = BTreeMap::new();
    for (name, loaded) in &profiles {
        for d in &loaded.definitions {
            defs.entry(d.symbol.clone()).or_insert_with(|| d.clone());
            built_in.entry(d.symbol.clone()).or_default().push(name);
        }
    }

    // Each node's text: its item hash, its attributes.
    let mut sources: BTreeMap<String, String> = BTreeMap::new();
    let mut items: BTreeMap<&str, Digest> = BTreeMap::new();
    let mut attributes: BTreeMap<&str, Vec<Attribute>> = BTreeMap::new();
    for d in defs.values() {
        if !sources.contains_key(&d.file) {
            let text = std::fs::read_to_string(root.join(&d.file))
                .map_err(|e| format!("{}: cannot read: {e}", d.file))?;
            sources.insert(d.file.clone(), text);
        }
    }
    for (key, d) in &defs {
        let source = sources
            .get(&d.file)
            .ok_or_else(|| format!("{}: not loaded", d.file))?;
        let text = slice(source, d.start, d.end).map_err(|e| format!("{key} ({}): {e}", d.file))?;
        let tokens = canonical(text).map_err(|e| format!("{key} ({}): {e}", d.file))?;
        items.insert(
            key.as_str(),
            hash(ITEM, &[key.as_bytes(), tokens.as_bytes()]),
        );
        attributes.insert(
            key.as_str(),
            outer_attributes(text).map_err(|e| format!("{key} ({}): {e}", d.file))?,
        );
    }

    // Each profile's edges, with the format captures its code makes.
    let mut profile_edges: Vec<(&'static str, Edges)> = Vec::new();
    for (name, loaded) in &profiles {
        let mut edges = loaded.edges.clone();
        let mut constants: BTreeMap<&str, Vec<&Definition>> = BTreeMap::new();
        for d in &loaded.definitions {
            if d.item.kind == Kind::Term && d.item.container.is_empty() && d.scope.is_none() {
                constants.entry(d.item.name.as_str()).or_default().push(d);
            }
        }
        for d in &loaded.definitions {
            if d.item.kind != Kind::Callable && d.item.kind != Kind::Term {
                continue;
            }
            let source = sources
                .get(&d.file)
                .ok_or_else(|| format!("{}: not loaded", d.file))?;
            let text = slice(source, d.start, d.end)
                .map_err(|e| format!("{} ({}): {e}", d.symbol, d.file))?;
            for (capture, literal) in
                format_captures(text).map_err(|e| format!("{} ({}): {e}", d.symbol, d.file))?
            {
                if let Some(target) =
                    capture_target(&constants, d, &capture, &loaded.locals, &loaded.imports)
                {
                    if target != d.symbol {
                        let at = in_file(d.start, text, literal)
                            .map_err(|e| format!("{} ({}): {e}", d.symbol, d.file))?;
                        add_edge(
                            &mut edges,
                            &d.symbol,
                            &target,
                            FORMAT_CAPTURE,
                            Evidence {
                                at: format!("{}:{}", d.file, at.line + 1),
                                doubt: None,
                                sites: vec![Site {
                                    file: d.file.clone(),
                                    at,
                                    doubt: None,
                                }],
                            },
                        );
                    }
                }
            }
        }
        profile_edges.push((name, edges));
    }

    // Node ids: every definition, then every symbol only referenced.
    let mut ids: BTreeMap<String, usize> = BTreeMap::new();
    let mut names: Vec<String> = Vec::new();
    for key in defs.keys() {
        ids.insert(key.clone(), names.len());
        names.push(key.clone());
    }
    for (_, edges) in &profile_edges {
        for (from, to, _) in edges.keys() {
            for s in [from, to] {
                if !ids.contains_key(s) {
                    ids.insert(s.clone(), names.len());
                    names.push(s.clone());
                }
            }
        }
    }
    let id = |s: &str| -> Result<usize, String> {
        ids.get(s)
            .copied()
            .ok_or_else(|| format!("{s} is not a node"))
    };

    // Closure hashes over every profile's edges: a fingerprint of the code a
    // definition can lead to in any build.
    let item_of: Vec<Digest> = names
        .iter()
        .map(|n| match items.get(n.as_str()) {
            Some(d) => *d,
            None => hash(EXTERNAL, &[n.as_bytes()]),
        })
        .collect();
    let mut adjacency: Vec<Vec<usize>> = vec![Vec::new(); names.len()];
    for (_, edges) in &profile_edges {
        for (from, to, _) in edges.keys() {
            adjacency[id(from)?].push(id(to)?);
        }
    }
    for list in &mut adjacency {
        list.sort_unstable();
        list.dedup();
    }
    let name_refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    let closures = closures(&name_refs, &item_of, &adjacency)?;

    // Entry points, per artifact.
    let mut roots: BTreeMap<String, BTreeMap<&'static str, &'static str>> = BTreeMap::new();
    // The name each exported entry point is exported under.
    let mut exports: BTreeMap<String, String> = BTreeMap::new();
    for a in &inputs.artifacts {
        for (key, d) in &defs {
            if !in_crates(&d.file, a.crates) {
                continue;
            }
            let attrs = attributes
                .get(key.as_str())
                .ok_or_else(|| format!("{key}: no attributes read"))?;
            if let Some(kind) = root_kind(d, attrs, inputs.declared_jni)? {
                roots.entry(key.clone()).or_default().insert(a.name, kind);
                if kind == root::EXPORT || kind == root::UNREAD_DECLARATION {
                    let exported = exported_name(d, attrs)?
                        .ok_or_else(|| format!("{key}: an export root with no exported name"))?;
                    exports.insert(key.clone(), exported);
                }
            }
        }
    }

    // Tests: what a test function reaches over the host test build's edges.
    let tests_edges = &profile_edges
        .iter()
        .find(|(n, _)| *n == "tests")
        .ok_or("no test profile")?
        .1;
    let mut test_adjacency: Vec<Vec<usize>> = vec![Vec::new(); names.len()];
    for (from, to, _) in tests_edges.keys() {
        test_adjacency[id(from)?].push(id(to)?);
    }
    let test_starts: Vec<&str> = inputs
        .tests
        .definitions
        .iter()
        .filter(|d| {
            d.item.kind == Kind::Callable
                && attributes
                    .get(d.symbol.as_str())
                    .is_some_and(|a| is_test(a))
        })
        .map(|d| d.symbol.as_str())
        .collect();
    for t in &test_starts {
        roots
            .entry(t.to_string())
            .or_default()
            .insert("tests", root::TEST);
    }
    let id_refs: BTreeMap<&str, usize> = ids.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    let tested = reach(&test_adjacency, test_starts.into_iter(), &id_refs)?;

    let queries = || inputs.root_queries.into_iter().flatten();
    for q in queries() {
        if !inputs.artifacts.iter().any(|a| a.name == q.artifact) {
            return Err(format!(
                "a root query names the artifact {}, which this map does not read",
                q.artifact
            ));
        }
    }
    // Each answer with its query's place, so they come out in the order asked.
    let mut root_answers: Vec<(usize, RootAnswer)> = Vec::new();

    // Reachability, per artifact.
    let mut status: BTreeMap<String, BTreeMap<&'static str, Status>> = BTreeMap::new();
    let mut artifact_edges: Vec<(&'static str, String, String, &'static str, Evidence)> =
        Vec::new();
    // Entry points under a gate this map cannot decide for an artifact.
    let mut undecided_roots: Vec<(String, &'static str)> = Vec::new();
    let mut tallies: BTreeMap<&'static str, Tally> = BTreeMap::new();
    for a in &inputs.artifacts {
        let mut tally = Tally {
            built: "built",
            excluded: 0,
            roots: 0,
            dead_roots: 0,
            unread_roots: 0,
            reached: 0,
            indeterminate: 0,
            dead: 0,
            unresolved_call_tokens: 0,
            unattributed_call_tokens: 0,
            uncompiled_call_tokens: 0,
            uncompiled_edges: 0,
            unresolved_call_candidates: 0,
            macro_body_candidates: 0,
            unindexed_candidates: 0,
            exported_declarations: BTreeSet::new(),
        };
        let loaded = match &a.loaded {
            Ok(loaded) => loaded,
            Err(missing) => {
                tally.built = "not-built";
                for (key, d) in &defs {
                    if in_crates(&d.file, a.crates) {
                        status.entry(key.clone()).or_default().insert(
                            a.name,
                            Status {
                                state: "not-built",
                                code: code::PROFILE_NOT_BUILT,
                                reason: Some(missing.clone()),
                                via: None,
                                via_kind: None,
                                at: None,
                                source: "profile",
                            },
                        );
                    }
                }
                for (at, q) in queries().enumerate().filter(|(_, q)| q.artifact == a.name) {
                    root_answers.push((
                        at,
                        RootAnswer {
                            artifact: q.artifact.clone(),
                            root: q.root.clone(),
                            symbol: q.symbol.clone(),
                            state: "not-built",
                            code: code::PROFILE_NOT_BUILT,
                        },
                    ));
                }
                tallies.insert(a.name, tally);
                continue;
            }
        };
        let edges_map = &profile_edges
            .iter()
            .find(|(n, _)| *n == a.name)
            .ok_or_else(|| format!("no edges for {}", a.name))?
            .1;
        // What the index holds that this artifact does not compile.
        let mut gone: BTreeMap<&str, &str> = BTreeMap::new();
        for d in &loaded.definitions {
            if let Some(why) = a.excluded.contradiction(&d.file, d.start, d.end) {
                return Err(format!(
                    "{} ({}:{}) is in the {} index inside a gate the index's own features turn off: {why}",
                    d.symbol,
                    d.file,
                    d.start.line + 1,
                    a.name
                ));
            }
            if let Some(why) = a.excluded.excluded(&d.file, d.start, d.end) {
                gone.insert(d.symbol.as_str(), why);
            }
        }
        tally.excluded = gone.len();
        // What the index holds under a gate this map cannot decide for this
        // build: it may not be compiled at all, so nothing reaches it for certain.
        let mut undecided: BTreeMap<&str, &str> = BTreeMap::new();
        for d in &loaded.definitions {
            if gone.contains_key(d.symbol.as_str()) {
                continue;
            }
            if let Some(why) = a.excluded.undecided(&d.file, d.start, d.end) {
                undecided.insert(d.symbol.as_str(), why);
            }
        }
        let mut edges: Vec<reach::Edge> = Vec::with_capacity(edges_map.len());
        for ((from, to, kind), ev) in edges_map {
            if gone.contains_key(from.as_str()) || gone.contains_key(to.as_str()) {
                continue;
            }
            let Some(mut ev) = compiled(ev, &a.excluded) else {
                tally.uncompiled_edges += 1;
                continue;
            };
            if let (None, Some(why)) = (&ev.doubt, undecided.get(to.as_str())) {
                ev.doubt = Some(Doubt::new(code::CFG_UNDECIDED, *why));
            }
            edges.push(reach::Edge {
                from: id(from)?,
                to: id(to)?,
                kind,
                doubt: ev.doubt.clone(),
                at: ev.at.clone(),
            });
            artifact_edges.push((a.name, from.clone(), to.clone(), kind, ev));
        }
        let defined_here: HashSet<&str> = loaded
            .definitions
            .iter()
            .map(|d| d.symbol.as_str())
            .collect();
        let mut artifact_roots: Vec<(usize, &'static str)> = Vec::new();
        // Entry points this map cannot confirm, Indeterminate: an export only
        // a declaration it cannot spell could be, and one under a gate it
        // cannot decide.
        let mut doubted_roots: Vec<(usize, Doubt)> = Vec::new();
        for (key, kinds) in &roots {
            if let Some(kind) = kinds.get(a.name) {
                if !defined_here.contains(key.as_str()) || gone.contains_key(key.as_str()) {
                    continue;
                }
                if let Some(why) = undecided.get(key.as_str()) {
                    doubted_roots.push((id(key)?, Doubt::new(code::CFG_UNDECIDED, *why)));
                    undecided_roots.push((key.clone(), a.name));
                    continue;
                }
                match *kind {
                    k if k == root::UNDECLARED_EXPORT => tally.dead_roots += 1,
                    k if k == root::UNREAD_DECLARATION => {
                        let exported = exports
                            .get(key)
                            .ok_or_else(|| format!("{key}: no exported name"))?;
                        let u = inputs.declared_jni.could_be(exported).ok_or_else(|| {
                            format!("{key}: no unread declaration matches {exported}")
                        })?;
                        tally.unread_roots += 1;
                        doubted_roots.push((
                            id(key)?,
                            Doubt::new(
                                code::UNREAD_DECLARATION,
                                format!(
                                    "exported as {exported}, which the native declared at {} could be ({})",
                                    u.at, u.why
                                ),
                            ),
                        ));
                    }
                    _ => {
                        artifact_roots.push((id(key)?, kind));
                        if let Some(exported) = exports.get(key) {
                            tally.exported_declarations.insert(exported.clone());
                        }
                    }
                }
            }
        }
        tally.roots = artifact_roots.len();
        let mut self_types = reach::SelfTypes::new();
        for (m, owner) in &loaded.self_types {
            let value = match owner {
                Owner::Known(t) => SelfType::Known(id(t)?),
                Owner::Unknown(why) => SelfType::Unknown(why.clone()),
            };
            self_types.insert(id(m)?, value);
        }
        let mut takes_value: HashSet<usize> = HashSet::new();
        for m in &loaded.value_receivers {
            takes_value.insert(id(m)?);
        }
        let full = reach::reached(
            names.len(),
            &edges,
            &artifact_roots,
            &self_types,
            &takes_value,
        )?;
        // What proven references reach with no dispatch step: its witness is
        // the one shown, so a direct path is never explained by a dispatch.
        let direct = reach::reached_directly(names.len(), &edges, &artifact_roots)?;
        let via: Vec<Option<Via>> = direct
            .iter()
            .zip(full)
            .map(|(d, f)| match d {
                Some(v) => Some(v.clone()),
                None => f,
            })
            .collect();
        let reached_now: Vec<usize> = (0..names.len()).filter(|&i| via[i].is_some()).collect();
        let reached_set: HashSet<usize> = reached_now.iter().copied().collect();

        // Seeds: what the index cannot see names, and gates it cannot decide.
        let mut seeds: Vec<(usize, Doubt)> = doubted_roots;
        for d in &loaded.definitions {
            if let Some(why) = undecided.get(d.symbol.as_str()) {
                seeds.push((id(&d.symbol)?, Doubt::new(code::CFG_UNDECIDED, *why)));
            }
        }
        for (m, why) in &loaded.unlinked {
            seeds.push((id(m)?, why.clone()));
        }
        let here: Vec<&Definition> = loaded
            .definitions
            .iter()
            .filter(|d| in_crates(&d.file, a.crates) && !gone.contains_key(d.symbol.as_str()))
            .collect();
        let mut by_file: BTreeMap<&str, Vec<&Definition>> = BTreeMap::new();
        for d in &here {
            by_file.entry(d.file.as_str()).or_default().push(d);
        }
        let here_symbols: HashSet<&str> = here.iter().map(|d| d.symbol.as_str()).collect();
        let mut everywhere: BTreeMap<&str, Vec<&Definition>> = BTreeMap::new();
        for d in defs.values() {
            everywhere.entry(d.file.as_str()).or_default().push(d);
        }
        for (file, file_defs) in &by_file {
            let any_reached = file_defs
                .iter()
                .any(|d| ids.get(&d.symbol).is_some_and(|i| reached_set.contains(i)));
            if !any_reached {
                continue;
            }
            let text = sources
                .get(*file)
                .ok_or_else(|| format!("{file}: not loaded"))?;
            let lexed = Source::lex(text).map_err(|e| format!("{file}: {e}"))?;
            let end = Position {
                line: text.split('\n').count(),
                column: 0,
            };
            let occurrences = loaded.occurrences.get(*file);
            let locals = loaded.locals.get(*file);
            for call in lexed.calls(Position { line: 0, column: 0 }, end)? {
                if occurrences.is_some_and(|o| o.contains(&call.at)) {
                    continue;
                }
                // Code this build's own cfg turns off (a test, another
                // target, a feature it does not have) is not this build's
                // code, whether or not some profile indexed it.
                if compiled_out(&call.gates, file, a)? {
                    tally.uncompiled_call_tokens += 1;
                    continue;
                }
                // Place the call in the innermost definition of any profile:
                // code this build does not compile (a test module, a gated-off
                // item) is counted apart; code no definition holds (a
                // module-level macro invocation) is unattributed.
                let inner = everywhere
                    .get(*file)
                    .into_iter()
                    .flatten()
                    .filter(|d| d.start <= call.at && call.at <= d.end)
                    .max_by_key(|d| d.start);
                let (context, extent) = match inner {
                    None => {
                        tally.unattributed_call_tokens += 1;
                        ("outside every definition the index holds".to_string(), None)
                    }
                    Some(d) if !here_symbols.contains(d.symbol.as_str()) => {
                        tally.uncompiled_call_tokens += 1;
                        continue;
                    }
                    Some(d) if ids.get(&d.symbol).is_some_and(|i| reached_set.contains(i)) => (
                        format!("in reached {}", d.item.name),
                        Some((d.start, d.end)),
                    ),
                    Some(_) => continue,
                };
                let inner = inner.filter(|d| here_symbols.contains(d.symbol.as_str()));
                tally.unresolved_call_tokens += 1;
                let local = locals.is_some_and(|ls| {
                    ls.iter().any(|(at, n)| {
                        *n == call.name && extent.is_some_and(|(s0, e0)| s0 <= *at && *at <= e0)
                    })
                });
                // A name the build also uses from outside the workspace is
                // no evidence the call is to that: every workspace candidate
                // stays undecided.
                if local {
                    continue;
                }
                let candidates: Vec<&Definition> = here
                    .iter()
                    .copied()
                    .filter(|d| d.item.kind == Kind::Callable && d.item.name == call.name)
                    .filter(|d| call_fits(&call.form, d, inner.copied()))
                    .collect();
                let mut counted = 0usize;
                for c in candidates {
                    let ci = id(&c.symbol)?;
                    if reached_set.contains(&ci) {
                        continue;
                    }
                    counted += 1;
                    seeds.push((
                        ci,
                        Doubt::new(
                            code::UNRESOLVED_CALL,
                            format!(
                                "`{}` is called at {file}:{} {context}, and the index did not resolve it",
                                call.name,
                                call.at.line + 1
                            ),
                        ),
                    ));
                }
                if counted > 0 {
                    tally.unresolved_call_candidates += counted;
                }
            }
            // A reached macro's body: the index does not expand it, so what it
            // calls is undecided. Only names it writes in call position count
            // (what it defines, like the `fn new` an impl template writes, is
            // not a call), matched by the form of the call.
            for m in file_defs.iter().filter(|d| d.item.kind == Kind::Macro) {
                if !ids.get(&m.symbol).is_some_and(|i| reached_set.contains(i)) {
                    continue;
                }
                // No outside-name filter here: a handful of macros, and a
                // hidden call must stay undecided rather than read as Dead.
                for call in lexed.calls(m.start, m.end)? {
                    for d in here
                        .iter()
                        .copied()
                        .filter(|d| d.item.kind == Kind::Callable && d.item.name == call.name)
                    {
                        let fits = call_fits(&call.form, d, None);
                        let di = id(&d.symbol)?;
                        if !fits || d.item.package != m.item.package || reached_set.contains(&di) {
                            continue;
                        }
                        tally.macro_body_candidates += 1;
                        seeds.push((
                            di,
                            Doubt::new(
                                code::MACRO_BODY,
                                format!(
                                    "called as `{}` in the body of the reached macro `{}!` ({}:{}), which the index does not expand",
                                    call.name,
                                    m.item.name,
                                    m.file,
                                    call.at.line + 1
                                ),
                            ),
                        ));
                    }
                }
            }
        }
        if let Some((dir, consumer)) = a.unindexed {
            let mut named: BTreeSet<&str> = BTreeSet::new();
            for d in &here {
                let item = &d.item;
                let by_use = consumer.used.contains(&item.name);
                let by_call = item.kind == Kind::Callable
                    && consumer.calls.iter().any(|call| match call {
                        ConsumerCall::Method(name) => {
                            *name == item.name && !item.container.is_empty()
                        }
                        ConsumerCall::Path(q, name) => {
                            *name == item.name
                                && (base_name(&item.container) == q.as_str()
                                    || item.modules.last().is_some_and(|m| m == q))
                        }
                    });
                if by_use || by_call {
                    named.insert(d.symbol.as_str());
                }
            }
            for symbol in named {
                let di = id(symbol)?;
                if reached_set.contains(&di) {
                    continue;
                }
                tally.unindexed_candidates += 1;
                seeds.push((
                    di,
                    Doubt::new(
                        code::UNINDEXED_ARTIFACT,
                        format!("named by {dir}, a crate this artifact ships that the map cannot index here"),
                    ),
                ));
            }
        }

        let result = reach::classify(&edges, via, &self_types, &takes_value, &seeds, &name_refs)?;

        // The root queries: what each named entry point alone reaches, by the
        // same rules (a path through a dispatch needs its evidence reached from
        // that root too). The map's seeds are the whole build's, so they are
        // not applied here: an answer never reads Reached on their account.
        let mut compiled_paths: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        for d in &loaded.definitions {
            if gone.contains_key(d.symbol.as_str()) {
                continue;
            }
            if let Some(path) = rust_path(d) {
                compiled_paths.entry(path).or_default().push(id(&d.symbol)?);
            }
        }
        let one = |path: &str, what: &str| -> Result<usize, String> {
            match compiled_paths.get(path).map(Vec::as_slice) {
                Some([only]) => Ok(*only),
                found => Err(format!(
                    "a root query's {what} {path} names {} definitions the {} build compiles",
                    found.map_or(0, <[usize]>::len),
                    a.name
                )),
            }
        };
        let mut from_root: BTreeMap<usize, (reach::Reach, Vec<Option<Via>>)> = BTreeMap::new();
        for (at, q) in queries().enumerate().filter(|(_, q)| q.artifact == a.name) {
            let r = one(&q.root, "entry point")?;
            let s = one(&q.symbol, "symbol")?;
            if !from_root.contains_key(&r) {
                let alone = [(r, "query")];
                let via = reach::reached(names.len(), &edges, &alone, &self_types, &takes_value)?;
                let direct = reach::reached_directly(names.len(), &edges, &alone)?;
                let read =
                    reach::classify(&edges, via, &self_types, &takes_value, &[], &name_refs)?;
                from_root.insert(r, (read, direct));
            }
            let (read, direct) = &from_root[&r];
            let (state, code_) = match (read.state[s], &direct[s], &read.reason[s]) {
                (State::Reached, Some(_), _) => ("reached", code::REACHED),
                (State::Reached, None, _) => ("reached", code::REACHED_VIA_DISPATCH),
                (State::Indeterminate, _, Some(why)) => ("indeterminate", why.code),
                (State::Indeterminate, _, None) => {
                    return Err(format!(
                        "{} from {} is indeterminate with no reason",
                        q.symbol, q.root
                    ))
                }
                (State::Dead, _, _) => ("dead", code::DEAD_NO_ROOT_PATH),
            };
            root_answers.push((
                at,
                RootAnswer {
                    artifact: q.artifact.clone(),
                    root: q.root.clone(),
                    symbol: q.symbol.clone(),
                    state,
                    code: code_,
                },
            ));
        }
        for (key, d) in &defs {
            if !in_crates(&d.file, a.crates) {
                continue;
            }
            let i = id(key)?;
            let entry = if let Some(why) = gone.get(key.as_str()) {
                Status {
                    state: "not-in-artifact",
                    code: code::NOT_IN_ARTIFACT,
                    reason: Some(why.to_string()),
                    via: None,
                    via_kind: None,
                    at: None,
                    source: "cfg-evaluation",
                }
            } else if !defined_here.contains(key.as_str()) {
                Status {
                    state: "not-in-artifact",
                    code: code::NOT_IN_ARTIFACT,
                    reason: Some(format!("not compiled into the {} build", a.name)),
                    via: None,
                    via_kind: None,
                    at: None,
                    source: "profile",
                }
            } else {
                let (via, via_kind, at, source) = match &result.via[i] {
                    Some(Via::Root(kind)) => (
                        Some(kind.to_string()),
                        Some("root"),
                        Some(format!("{}:{}", d.file, d.start.line + 1)),
                        "attribute",
                    ),
                    Some(Via::Edge(e)) => {
                        let edge = &edges[*e];
                        (
                            Some(names[edge.from].clone()),
                            Some(edge.kind),
                            Some(edge.at.clone()),
                            edge_source(edge.kind),
                        )
                    }
                    Some(Via::Seed(why)) => (None, Some("seed"), None, seed_source(why.code)),
                    None => (None, None, None, "graph"),
                };
                let (state, code_, reason) = match (result.state[i], &result.reason[i]) {
                    (State::Reached, _) => (
                        "reached",
                        match direct[i] {
                            Some(_) => code::REACHED,
                            None => code::REACHED_VIA_DISPATCH,
                        },
                        None,
                    ),
                    (State::Indeterminate, Some(why)) => {
                        ("indeterminate", why.code, Some(why.text.clone()))
                    }
                    (State::Indeterminate, None) => {
                        return Err(format!("{key} is indeterminate with no reason"))
                    }
                    (State::Dead, _) => (
                        "dead",
                        code::DEAD_NO_ROOT_PATH,
                        Some(format!(
                            "no path of any kind leads to it from the {} build's entry points",
                            a.name
                        )),
                    ),
                };
                match state {
                    "reached" => tally.reached += 1,
                    "indeterminate" => tally.indeterminate += 1,
                    _ => tally.dead += 1,
                }
                Status {
                    state,
                    code: code_,
                    reason,
                    via,
                    via_kind,
                    at,
                    source,
                }
            };
            status.entry(key.clone()).or_default().insert(a.name, entry);
        }
        tallies.insert(a.name, tally);
    }
    // An entry point under a gate this map cannot decide is recorded as that,
    // not as the kind it would be if the build compiled it.
    for (key, artifact) in undecided_roots {
        roots
            .entry(key)
            .or_default()
            .insert(artifact, root::UNDECIDED_GATE);
    }

    let mut nodes = BTreeMap::new();
    for (key, d) in defs {
        let i = id(&key)?;
        let node = Node {
            path: rust_path(&d),
            item: item_of[i],
            closure: closures[i],
            tested: tested.contains(&i),
            roots: roots.remove(&key).into_iter().flatten().collect(),
            built_in: built_in.remove(&key).into_iter().flatten().collect(),
            status: status.remove(&key).into_iter().flatten().collect(),
            def: d,
        };
        nodes.insert(key, node);
    }
    // Each artifact's edges are the ones its build compiles, read above; the
    // test profile's are as the index read them.
    let artifact_names: BTreeSet<&str> = inputs.artifacts.iter().map(|a| a.name).collect();
    let mut all_edges = artifact_edges;
    for (profile, edges) in profile_edges {
        if artifact_names.contains(profile) {
            continue;
        }
        for ((from, to, kind), ev) in edges {
            all_edges.push((profile, from, to, kind, ev));
        }
    }
    Ok(Map {
        nodes,
        edges: all_edges,
        tallies,
        root_answers: {
            root_answers.sort_by_key(|(at, _)| *at);
            root_answers.into_iter().map(|(_, answer)| answer).collect()
        },
    })
}

/// An edge as a build compiles it: the sites its `cfg` turns off are not in
/// it, and with every site off the edge is not in the build (`None`). A site
/// the build compiles for certain decides: the edge is proven when one such
/// site is. With only sites under a gate this map cannot decide, it is
/// uncertain. An edge read from definitions (no sites) is as the index read
/// it: a gate takes it out with its definitions.
fn compiled(ev: &Evidence, gates: &crate::cfgs::Exclusions) -> Option<Evidence> {
    if ev.sites.is_empty() {
        return Some(ev.clone());
    }
    let live: Vec<Site> = ev
        .sites
        .iter()
        .filter(|s| gates.excluded(&s.file, s.at, s.at).is_none())
        .cloned()
        .collect();
    // Each compiled site, certain or under a gate this map cannot decide
    // (with the gate's reason), read once.
    let mut certain: Vec<&Site> = Vec::new();
    let mut undecided: Vec<(&Site, &str)> = Vec::new();
    for s in &live {
        match gates.undecided(&s.file, s.at, s.at) {
            None => certain.push(s),
            Some(why) => undecided.push((s, why)),
        }
    }
    let (chosen, doubt) = match (
        certain.iter().find(|s| s.doubt.is_none()),
        certain.first(),
        undecided.first(),
    ) {
        (Some(s), _, _) => (*s, None),
        (None, Some(s), _) => (*s, s.doubt.clone()),
        (None, None, Some((s, why))) => (*s, Some(Doubt::new(code::CFG_UNDECIDED, *why))),
        // No site compiles: the edge is not in this build.
        (None, None, None) => return None,
    };
    Some(Evidence {
        at: format!("{}:{}", chosen.file, chosen.at.line + 1),
        doubt,
        sites: live.clone(),
    })
}

/// Where a token of a definition's text (the file's text from `start`) is
/// in the file.
fn in_file(start: Position, text: &str, at: proc_macro2::LineColumn) -> Result<Position, String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let p = crate::source::position(&lines, at)?;
    Ok(match p.line {
        0 => Position {
            line: start.line,
            column: start.column + p.column,
        },
        n => Position {
            line: start.line + n,
            column: p.column,
        },
    })
}

/// The constant a format capture names, as the compiler would resolve it: a
/// local binding of that name inside the definition shadows every constant;
/// otherwise a constant defined in the same file, or one the file imports.
fn capture_target(
    constants: &BTreeMap<&str, Vec<&Definition>>,
    d: &Definition,
    name: &str,
    locals: &BTreeMap<String, Vec<(Position, String)>>,
    imports: &BTreeMap<String, BTreeSet<String>>,
) -> Option<String> {
    let shadowed = locals
        .get(&d.file)
        .into_iter()
        .flatten()
        .any(|(at, local)| local == name && d.start <= *at && *at <= d.end);
    if shadowed {
        return None;
    }
    let candidates = constants.get(name)?;
    let imported = imports.get(&d.file);
    let same_file = candidates.iter().find(|c| c.file == d.file);
    let brought_in = candidates
        .iter()
        .find(|c| imported.is_some_and(|set| set.contains(&c.symbol)));
    same_file.or(brought_in).map(|c| c.symbol.clone())
}

/// A function the loader runs when the library loads or unloads
/// (`#[ctor]`, `#[ctor::ctor]`, `#[dtor]`, `#[ctor::dtor]`): an entry point no
/// caller in the code names.
fn runs_at_load(attributes: &[Attribute]) -> bool {
    attributes
        .iter()
        .any(|a| ["ctor", "ctor::ctor", "dtor", "ctor::dtor"].contains(&a.path.as_str()))
}

/// A test function: `#[test]`, `#[tokio::test]` and the other test attributes
/// the evidence script recognises, among the function's parsed attributes.
fn is_test(attributes: &[Attribute]) -> bool {
    attributes.iter().any(|a| {
        [
            "test",
            "tokio::test",
            "rstest",
            "test_case",
            "async_std::test",
            "sqlx::test",
        ]
        .contains(&a.path.as_str())
    })
}

pub(crate) fn slice(source: &str, start: Position, end: Position) -> Result<&str, String> {
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
                    // Components come out callees first, so a callee outside
                    // this one already has its closure; its absence is a
                    // broken graph, never a callee to leave out.
                    match closure[t] {
                        Some(c) => {
                            callee.insert(c);
                        }
                        None => {
                            return Err(format!(
                                "{} calls {} before its closure exists",
                                names[m], names[t]
                            ))
                        }
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

fn reach<'a>(
    adjacency: &[Vec<usize>],
    starts: impl Iterator<Item = &'a str>,
    ids: &BTreeMap<&str, usize>,
) -> Result<HashSet<usize>, String> {
    let mut seen: HashSet<usize> = HashSet::new();
    let mut queue: VecDeque<usize> = VecDeque::new();
    for start in starts {
        let id = ids
            .get(start)
            .ok_or_else(|| format!("the start {start} is not a node"))?;
        if seen.insert(*id) {
            queue.push_back(*id);
        }
    }
    while let Some(v) = queue.pop_front() {
        for &w in &adjacency[v] {
            if seen.insert(w) {
                queue.push_back(w);
            }
        }
    }
    Ok(seen)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A callable definition read from a SCIP symbol's descriptors.
    fn callable(descriptors: &str) -> Result<Definition, String> {
        let symbol = format!("rust-analyzer cargo probe 0.1.0 {descriptors}");
        let item = crate::symbols::item(&symbol)?.ok_or("names no item")?;
        let at = Position { line: 0, column: 0 };
        Ok(Definition {
            raw: symbol.clone(),
            symbol,
            item,
            file: "probe/src/lib.rs".to_string(),
            start: at,
            end: at,
            name_at: at,
            scope: None,
        })
    }

    #[test]
    fn a_call_s_qualifier_is_decided_by_its_site_or_left_open() -> Result<(), String> {
        let root_fn = callable("f().")?;
        let in_a = callable("a/f().")?;
        let in_a_b = callable("a/b/f().")?;
        let method = callable("a/impl#[S]f().")?;
        let site_in_a_b = callable("a/b/caller().")?;
        let site_in_s = callable("a/impl#[S]caller().")?;
        let path = |q: &str| Form::Path(Some(q.to_string()));
        // `self::f` is the site's own module; `super::f` its parent's.
        assert!(call_fits(&path("self"), &in_a_b, Some(&site_in_a_b)));
        assert!(!call_fits(&path("self"), &in_a, Some(&site_in_a_b)));
        assert!(call_fits(&path("super"), &in_a, Some(&site_in_a_b)));
        assert!(!call_fits(&path("super"), &in_a_b, Some(&site_in_a_b)));
        // `crate::f` is the crate root's.
        assert!(call_fits(&path("crate"), &root_fn, None));
        assert!(!call_fits(&path("crate"), &in_a, None));
        // `Self::f` is the site's type's.
        assert!(call_fits(&path("Self"), &method, Some(&site_in_s)));
        assert!(!call_fits(&path("Self"), &in_a, Some(&site_in_s)));
        // In a macro's body no site decides: every candidate of the kind fits.
        assert!(call_fits(&path("self"), &in_a, None));
        assert!(call_fits(&path("super"), &in_a_b, None));
        assert!(call_fits(&path("Self"), &method, None));
        Ok(())
    }

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
    fn test_functions_are_recognised_by_their_attribute() -> Result<(), String> {
        assert!(is_test(&outer_attributes("#[test]\nfn a() {}")?));
        assert!(is_test(&outer_attributes(
            "/// A fn that runs\n#[tokio::test(flavor = \"multi_thread\")]\nasync fn b() {}"
        )?));
        assert!(!is_test(&outer_attributes(
            "/// Runs the test vectors.\nfn c() { run(\"#[test]\") }"
        )?));
        assert!(!is_test(&outer_attributes("// #[test]\nfn d() {}")?));
        Ok(())
    }

    #[test]
    fn load_time_constructors_are_entry_points() -> Result<(), String> {
        assert!(runs_at_load(&outer_attributes(
            "#[ctor::ctor(unsafe)]\nfn g() {}"
        )?));
        assert!(runs_at_load(&outer_attributes("#[dtor]\nfn h() {}")?));
        assert!(!runs_at_load(&outer_attributes(
            "/// Runs like a #[ctor]\nfn i() {}"
        )?));
        Ok(())
    }

    #[test]
    fn each_entry_point_kind_is_decided_by_its_rule() -> Result<(), String> {
        let mut declared = crate::jni::Declarations {
            symbols: BTreeMap::new(),
            unread: vec![crate::jni::Unread {
                prefix: "Java_p_K_hidden".to_string(),
                at: "K.kt:3".to_string(),
                why: "an `internal` member".to_string(),
            }],
        };
        declared
            .symbols
            .insert("Java_p_K_entry".to_string(), "K.kt:2".to_string());
        let kind = |descriptors: &str, file: &str, text: &str| {
            let mut d = callable(descriptors)?;
            d.file = file.to_string();
            root_kind(&d, &outer_attributes(text)?, &declared)
        };
        let lib = "p/src/lib.rs";
        assert_eq!(
            kind("main().", "n/src/main.rs", "fn main() {}")?,
            Some(root::MAIN)
        );
        assert_eq!(kind("main().", lib, "fn main() {}")?, None);
        assert_eq!(kind("g().", lib, "#[ctor]\nfn g() {}")?, Some(root::LOAD));
        assert_eq!(
            kind("JNI_OnLoad().", lib, "#[no_mangle]\nfn JNI_OnLoad() {}")?,
            Some(root::VM)
        );
        assert_eq!(
            kind(
                "Java_p_K_entry().",
                lib,
                "#[no_mangle]\nfn Java_p_K_entry() {}"
            )?,
            Some(root::EXPORT)
        );
        // Declared under the name it is exported as, not its own.
        assert_eq!(
            kind(
                "renamed().",
                lib,
                "#[export_name = \"Java_p_K_entry\"]\nfn renamed() {}"
            )?,
            Some(root::EXPORT)
        );
        assert_eq!(
            kind(
                "Java_p_K_hidden_00024m().",
                lib,
                "#[no_mangle]\nfn Java_p_K_hidden_00024m() {}"
            )?,
            Some(root::UNREAD_DECLARATION)
        );
        assert_eq!(
            kind(
                "Java_p_K_other().",
                lib,
                "#[no_mangle]\nfn Java_p_K_other() {}"
            )?,
            Some(root::UNDECLARED_EXPORT)
        );
        assert_eq!(kind("helper().", lib, "fn helper() {}")?, None);
        Ok(())
    }

    #[test]
    fn exports_are_read_by_the_attribute_not_by_a_mention() -> Result<(), String> {
        let read = |text: &str| -> Result<Vec<Option<Export>>, String> {
            outer_attributes(text)?
                .iter()
                .map(export_attribute)
                .collect()
        };
        assert_eq!(
            read("#[unsafe(no_mangle)]\nfn a() {}")?,
            vec![Some(Export::OwnName)]
        );
        assert_eq!(
            read("#[no_mangle]\nfn a() {}")?,
            vec![Some(Export::OwnName)]
        );
        assert_eq!(
            read("#[export_name = \"Java_x\"]\nfn a() {}")?,
            vec![Some(Export::Named("Java_x".to_string()))]
        );
        assert_eq!(
            read("#[unsafe(export_name = \"Java_y\")]\nfn a() {}")?,
            vec![Some(Export::Named("Java_y".to_string()))]
        );
        // A mention inside another attribute exports nothing.
        assert_eq!(
            read("#[unsafe(other(\"no_mangle\"))]\nfn a() {}")?,
            vec![None]
        );
        Ok(())
    }

    #[test]
    fn a_binary_root_is_a_target_root_not_any_file_under_bin() {
        assert!(binary_root("n/src/main.rs"));
        assert!(binary_root("n/src/bin/tool.rs"));
        assert!(binary_root("n/src/bin/tool/main.rs"));
        assert!(!binary_root("n/src/bin/tool/helpers.rs"));
        assert!(!binary_root("n/src/bin/utils/deep/mod.rs"));
        assert!(!binary_root("n/src/lib.rs"));
    }

    #[test]
    fn components_come_out_callees_first() {
        let order = components(&[vec![1], vec![2], vec![]]);
        assert_eq!(order, vec![vec![2], vec![1], vec![0]]);
    }

    #[test]
    fn a_site_the_build_turns_off_is_not_its_edge() {
        let at = |line| Position { line, column: 4 };
        let site = |line, doubt: Option<Doubt>| Site {
            file: "f.rs".to_string(),
            at: at(line),
            doubt,
        };
        let evidence = |sites: Vec<Site>| Evidence {
            at: "f.rs:1".to_string(),
            doubt: None,
            sites,
        };
        let mut gates = crate::cfgs::Exclusions::none();
        // Lines 10-19 are off in this build; lines 20-29 are undecided.
        gates.spans.insert(
            "f.rs".to_string(),
            vec![(
                at(10),
                Position {
                    line: 19,
                    column: 0,
                },
                "off".to_string(),
            )],
        );
        gates.undecided.insert(
            "f.rs".to_string(),
            vec![(
                at(20),
                Position {
                    line: 29,
                    column: 0,
                },
                "undecided".to_string(),
            )],
        );
        let doubt = |code_| Doubt::new(code_, "why");
        let code_of = |ev: Option<Evidence>| ev.map(|e| e.doubt.map(|d| d.code));

        // Every site off: no edge in this build.
        assert_eq!(
            code_of(compiled(&evidence(vec![site(12, None)]), &gates)),
            None
        );
        // A site the build compiles for certain proves it, wherever else it is written.
        assert_eq!(
            code_of(compiled(
                &evidence(vec![site(12, None), site(25, None), site(3, None)]),
                &gates
            )),
            Some(None)
        );
        // Proven only where the build turns it off, doubted where it compiles:
        // the doubt is the build's.
        let proven_off = compiled(
            &evidence(vec![
                site(12, None),
                site(3, Some(doubt(code::MACRO_GROUP))),
            ]),
            &gates,
        );
        assert_eq!(code_of(proven_off.clone()), Some(Some(code::MACRO_GROUP)));
        assert_eq!(proven_off.map(|e| e.at), Some("f.rs:4".to_string()));
        // Only undecided sites left: undecided.
        assert_eq!(
            code_of(compiled(
                &evidence(vec![site(12, None), site(25, None)]),
                &gates
            )),
            Some(Some(code::CFG_UNDECIDED))
        );
        // Read from definitions (no sites): as the index read it.
        assert_eq!(code_of(compiled(&evidence(Vec::new()), &gates)), Some(None));
    }

    #[test]
    fn a_token_s_place_in_a_definition_is_its_place_in_the_file() -> Result<(), String> {
        // The definition starts at byte 4 of line 7; its text's first line
        // is the rest of that line.
        let start = Position { line: 7, column: 4 };
        let text = "fn f() {\n    é(\"{X}\")\n}";
        let first = proc_macro2::LineColumn { line: 1, column: 3 };
        let later = proc_macro2::LineColumn { line: 2, column: 6 };
        assert_eq!(
            in_file(start, text, first)?,
            Position { line: 7, column: 7 }
        );
        // Columns count bytes: `é` is two.
        assert_eq!(
            in_file(start, text, later)?,
            Position { line: 8, column: 7 }
        );
        Ok(())
    }

    #[test]
    fn a_file_s_features_are_its_package_s_however_cargo_spells_it() -> Result<(), String> {
        // `cargo tree` prints `dsm-anchor-core`; its features are read
        // under the name the crate compiles as.
        let features = crate::cfgs::features("dsm-anchor-core v0.1.0 (/x) std\n")?;
        let packages = vec![(
            "crates/dsm-anchor-core/src/".to_string(),
            "dsm-anchor-core".to_string(),
        )];
        let std_only: BTreeSet<String> = ["std".to_string()].into_iter().collect();
        assert_eq!(
            package_features("crates/dsm-anchor-core/src/lib.rs", &packages, &features)?,
            &std_only
        );
        // A file of no package the build links is an error, never no features.
        assert!(matches!(
            package_features("elsewhere/src/lib.rs", &packages, &features),
            Err(e) if e.contains("no package")
        ));
        Ok(())
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
