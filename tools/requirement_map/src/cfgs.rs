// SPDX-License-Identifier: MIT OR Apache-2.0
//! What the index compiled that the shipped build does not. `cargo metadata`,
//! which rust-analyzer builds its view from, resolves features with every
//! workspace member's dev-dependencies, so a crate that is its own
//! dev-dependency with a test feature (`dsm_sdk = { path = ".", features =
//! ["test-utils"] }`) has that feature on in the index. The shipped build
//! never enables it. The features that differ are read from `cargo tree`
//! (the artifact's own build against the index's view), and every `cfg` that
//! names one is evaluated with the artifact's real features: what it turns
//! off is not in the artifact; what it leaves undecided is Indeterminate.

use crate::index::Position;
use proc_macro2::{Delimiter, LineColumn, Span, TokenStream, TokenTree};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::str::FromStr;
use syn::spanned::Spanned;
use syn::visit::Visit;

/// Features per package, read from `cargo tree --prefix none -f '{p} {f}'`:
/// a line is the package's name and version, then parenthesized groups (its
/// source path, which may hold spaces; `(proc-macro)`; `(*)` for a repeat)
/// and at most one bare word, the comma-separated features.
pub fn features(tree: &str) -> Result<BTreeMap<String, BTreeSet<String>>, String> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for line in tree.lines().filter(|l| !l.trim().is_empty()) {
        let malformed = || format!("{line:?} is not a `cargo tree -f '{{p}} {{f}}'` line");
        let mut words = line.trim().splitn(3, ' ');
        let (Some(package), Some(_version)) = (words.next(), words.next()) else {
            return Err(malformed());
        };
        let mut list: Option<&str> = None;
        let rest = match words.next() {
            Some(rest) => rest,
            None => "",
        };
        let chars: Vec<(usize, char)> = rest.char_indices().collect();
        let mut k = 0usize;
        while k < chars.len() {
            match chars[k].1 {
                c if c.is_whitespace() => k += 1,
                '(' => {
                    let mut depth = 0usize;
                    loop {
                        match chars.get(k).map(|(_, c)| *c) {
                            Some('(') => depth += 1,
                            Some(')') => depth -= 1,
                            Some(_) => {}
                            None => return Err(malformed()),
                        }
                        k += 1;
                        if depth == 0 {
                            break;
                        }
                    }
                }
                _ => {
                    let from = chars[k].0;
                    while k < chars.len() && !chars[k].1.is_whitespace() {
                        k += 1;
                    }
                    let to = chars.get(k).map_or(rest.len(), |(at, _)| *at);
                    if list.replace(&rest[from..to]).is_some() {
                        return Err(malformed());
                    }
                }
            }
        }
        let entry = out.entry(package.replace('-', "_")).or_default();
        if let Some(list) = list {
            entry.extend(
                list.split(',')
                    .filter(|f| !f.is_empty())
                    .map(|f| f.to_string()),
            );
        }
    }
    Ok(out)
}

/// A three-valued truth: a `cfg` the map can decide, or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Truth {
    Yes,
    No,
    Unknown,
}

impl Truth {
    fn not(self) -> Truth {
        match self {
            Truth::Yes => Truth::No,
            Truth::No => Truth::Yes,
            Truth::Unknown => Truth::Unknown,
        }
    }
}

/// Evaluates a `cfg` predicate with a package's features: `feature = "x"` is
/// decided by them, `test` is off (no shipped build is a test build), and
/// every other condition is unknown to this evaluator.
pub fn evaluate(tokens: &[TokenTree], features: &BTreeSet<String>) -> Result<Truth, String> {
    match tokens {
        [TokenTree::Ident(i)] if i == "test" => Ok(Truth::No),
        [TokenTree::Ident(i), TokenTree::Punct(eq), TokenTree::Literal(value)]
            if i == "feature" && eq.as_char() == '=' =>
        {
            let name = value.to_string().trim_matches('"').to_string();
            Ok(if features.contains(&name) {
                Truth::Yes
            } else {
                Truth::No
            })
        }
        [TokenTree::Ident(op), TokenTree::Group(g)] if g.delimiter() == Delimiter::Parenthesis => {
            let inner: Vec<TokenTree> = g.stream().into_iter().collect();
            let parts = split_commas(&inner);
            match op.to_string().as_str() {
                "not" => match parts.as_slice() {
                    [one] => Ok(evaluate(one, features)?.not()),
                    _ => Err(format!("not(…) takes one predicate, found {}", parts.len())),
                },
                "any" => {
                    let mut result = Truth::No;
                    for p in &parts {
                        match evaluate(p, features)? {
                            Truth::Yes => return Ok(Truth::Yes),
                            Truth::Unknown => result = Truth::Unknown,
                            Truth::No => {}
                        }
                    }
                    Ok(result)
                }
                "all" => {
                    let mut result = Truth::Yes;
                    for p in &parts {
                        match evaluate(p, features)? {
                            Truth::No => return Ok(Truth::No),
                            Truth::Unknown => result = Truth::Unknown,
                            Truth::Yes => {}
                        }
                    }
                    Ok(result)
                }
                _ => Ok(Truth::Unknown),
            }
        }
        _ => Ok(Truth::Unknown),
    }
}

fn split_commas(tokens: &[TokenTree]) -> Vec<Vec<TokenTree>> {
    let mut out = vec![Vec::new()];
    for t in tokens {
        match t {
            TokenTree::Punct(p) if p.as_char() == ',' => out.push(Vec::new()),
            other => {
                if let Some(last) = out.last_mut() {
                    last.push(other.clone());
                }
            }
        }
    }
    out.retain(|p| !p.is_empty());
    out
}

/// The string literals a predicate holds, at any depth.
fn literals(tokens: &[TokenTree], out: &mut Vec<String>) {
    for t in tokens {
        match t {
            TokenTree::Literal(l) => out.push(l.to_string().trim_matches('"').to_string()),
            TokenTree::Group(g) => {
                let inner: Vec<TokenTree> = g.stream().into_iter().collect();
                literals(&inner, out);
            }
            TokenTree::Ident(_) | TokenTree::Punct(_) => {}
        }
    }
}

fn mentions(tokens: &[TokenTree], names: &BTreeSet<String>) -> bool {
    let mut found = Vec::new();
    literals(tokens, &mut found);
    found.iter().any(|s| names.contains(s))
}

/// What a feature the index enabled wrongly takes out of an artifact.
pub struct Exclusions {
    /// Spans of items gated off, per file.
    pub spans: BTreeMap<String, Vec<(Position, Position, String)>>,
    /// Module files gated off whole (their `mod x;` is), with the reason.
    pub files: BTreeMap<String, String>,
    /// Gates the evaluator could not decide, per file.
    pub undecided: BTreeMap<String, Vec<(Position, Position, String)>>,
    /// Gates the index's own features turn off: no definition the index
    /// holds may lie inside one, or the evaluator and the index disagree.
    pub contradictions: BTreeMap<String, Vec<(Position, Position, String)>>,
    /// The features that differ, per package, for the accounting.
    pub extra: BTreeMap<String, BTreeSet<String>>,
}

impl Exclusions {
    pub fn none() -> Self {
        Exclusions {
            spans: BTreeMap::new(),
            files: BTreeMap::new(),
            undecided: BTreeMap::new(),
            contradictions: BTreeMap::new(),
            extra: BTreeMap::new(),
        }
    }

    /// The gate the index's own features turn off around a definition the
    /// index holds, if there is one.
    pub fn contradiction(&self, file: &str, start: Position, end: Position) -> Option<&str> {
        self.contradictions
            .get(file)?
            .iter()
            .find(|(s, e, _)| *s <= start && end <= *e)
            .map(|(_, _, why)| why.as_str())
    }

    /// Why the definition at `[start, end]` of `file` is not in the artifact, if it is not.
    pub fn excluded(&self, file: &str, start: Position, end: Position) -> Option<&str> {
        if let Some(why) = self.files.get(file) {
            return Some(why);
        }
        self.spans
            .get(file)?
            .iter()
            .find(|(s, e, _)| *s <= start && end <= *e)
            .map(|(_, _, why)| why.as_str())
    }

    /// Why a gate around the definition is undecided, if one is.
    pub fn undecided(&self, file: &str, start: Position, end: Position) -> Option<&str> {
        self.undecided
            .get(file)?
            .iter()
            .find(|(s, e, _)| *s <= start && end <= *e)
            .map(|(_, _, why)| why.as_str())
    }
}

/// The package a crate file belongs to.
fn package_of(file: &str, crates: &[(&str, &str)]) -> Option<String> {
    crates
        .iter()
        .find(|(prefix, _)| file.starts_with(prefix))
        .map(|(_, package)| package.to_string())
}

/// Reads every file of the artifact's crates for `cfg`s that name a feature
/// the index enabled and the artifact does not, and evaluates each with the
/// artifact's features.
pub fn exclusions(
    root: &Path,
    files: &[String],
    crates: &[(&str, &str)],
    built: &BTreeMap<String, BTreeSet<String>>,
    indexed: &BTreeMap<String, BTreeSet<String>>,
) -> Result<Exclusions, String> {
    let mut out = Exclusions::none();
    for (package, on) in indexed {
        let shipped = built.get(package);
        let extra: BTreeSet<String> = on
            .iter()
            .filter(|f| shipped.is_none_or(|s| !s.contains(*f)))
            .cloned()
            .collect();
        if !extra.is_empty() && crates.iter().any(|(_, p)| p == package) {
            out.extra.insert(package.clone(), extra);
        }
    }
    if out.extra.is_empty() {
        return Ok(out);
    }
    let mut gated_modules: Vec<(String, String)> = Vec::new();
    // The artifact's files in packages whose features differ; every other
    // file compiles the same in the index and in the build.
    let in_scope: Vec<(&String, String, BTreeSet<String>)> = files
        .iter()
        .filter_map(|f| package_of(f, crates).map(|p| (f, p)))
        .filter_map(|(f, p)| out.extra.get(&p).cloned().map(|e| (f, p, e)))
        .collect();
    for (file, package, extra) in in_scope {
        let extra = &extra;
        let text = std::fs::read_to_string(root.join(file)).map_err(|e| format!("{file}: {e}"))?;
        if !extra.iter().any(|f| text.contains(f.as_str())) {
            continue;
        }
        let lines: Vec<&str> = text.split('\n').collect();
        let shipped = match built.get(&package) {
            Some(f) => f.clone(),
            None => BTreeSet::new(),
        };
        let seen = match indexed.get(&package) {
            Some(f) => f.clone(),
            None => BTreeSet::new(),
        };
        for gate in gates(&text, extra).map_err(|e| format!("{file}: {e}"))? {
            let predicate = &gate.predicate;
            let (start, end) = (position(&lines, gate.start)?, position(&lines, gate.end)?);
            if let Some(why) = &gate.unread {
                out.undecided.entry(file.clone()).or_default().push((
                    start,
                    end,
                    format!(
                        "`cfg({})` names {}: {why}",
                        predicate_text(predicate),
                        extra.iter().cloned().collect::<Vec<_>>().join(", ")
                    ),
                ));
                continue;
            }
            let why_named = format!(
                "compiled only when `cfg({})` holds; the shipped build's features for {package} do not make it hold (the index enabled {} through dev-dependency feature resolution)",
                predicate_text(predicate),
                extra.iter().cloned().collect::<Vec<_>>().join(", ")
            );
            if evaluate(predicate, &seen)? == Truth::No {
                out.contradictions.entry(file.clone()).or_default().push((
                    start,
                    end,
                    format!(
                        "`cfg({})` is off even with the index's features",
                        predicate_text(predicate)
                    ),
                ));
            }
            match evaluate(predicate, &shipped)? {
                Truth::No => {
                    match &gate.module {
                        Some(module) => {
                            gated_modules.push((module_file_base(file, module), why_named.clone()))
                        }
                        None => {}
                    }
                    out.spans
                        .entry(file.clone())
                        .or_default()
                        .push((start, end, why_named));
                }
                Truth::Unknown => out.undecided.entry(file.clone()).or_default().push((
                    start,
                    end,
                    format!(
                        "`cfg({})` names {} and a condition this map does not evaluate",
                        predicate_text(predicate),
                        extra.iter().cloned().collect::<Vec<_>>().join(", ")
                    ),
                )),
                Truth::Yes => {}
            }
        }
    }
    for file in files {
        for (base, why) in &gated_modules {
            if file == &format!("{base}.rs") || file.starts_with(&format!("{base}/")) {
                out.files.insert(file.clone(), why.clone());
            }
        }
    }
    Ok(out)
}

fn predicate_text(tokens: &[TokenTree]) -> String {
    tokens
        .iter()
        .map(|t| t.to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn position(lines: &[&str], at: LineColumn) -> Result<Position, String> {
    crate::source::position(lines, at)
}

/// The path prefix of a module `name` declared in `file` (`src/lib.rs` →
/// `src/name`; `src/a.rs` or `src/a/mod.rs` → `src/a/name`).
fn module_file_base(file: &str, name: &str) -> String {
    // A raw identifier (`mod r#type;`) names the file without its `r#`.
    let name = match name.strip_prefix("r#") {
        Some(bare) => bare,
        None => name,
    };
    let (dir, stem) = match file.rsplit_once('/') {
        Some((d, f)) => (Some(d), f.trim_end_matches(".rs")),
        None => (None, file.trim_end_matches(".rs")),
    };
    // `lib.rs`, `main.rs` and `mod.rs` hold their children beside them;
    // `a.rs` holds them in `a/`.
    let beside = matches!(stem, "lib" | "main" | "mod");
    let parent: Option<String> = match (dir, beside) {
        (Some(d), here) if here => Some(d.to_string()),
        (Some(d), _) => Some(format!("{d}/{stem}")),
        (None, here) if here => None,
        (None, _) => Some(stem.to_string()),
    };
    match parent {
        Some(p) => format!("{p}/{name}"),
        None => name.to_string(),
    }
}

/// A `cfg` naming one of the features the index enabled and the build does
/// not, and what it covers.
struct Gate {
    predicate: Vec<TokenTree>,
    start: LineColumn,
    end: LineColumn,
    /// `mod x;`: the module whose file it gates.
    module: Option<String>,
    /// For a `cfg` inside a macro's tokens whose items this map does not
    /// parse: why its extent is not read.
    unread: Option<String>,
}

/// Every gate in a file, each covering the node it is written on: an outer
/// `#[cfg(…)]` (or a `cfg` inside `cfg_attr`) gates the item, field,
/// variant, arm, statement or expression it is written on; an inner
/// `#![cfg(…)]` gates the item it is written in, or the whole file. Read by
/// parsing the file as Rust.
fn gates(text: &str, features: &BTreeSet<String>) -> Result<Vec<Gate>, String> {
    let file = syn::parse_file(text).map_err(|e| {
        let at = e.span().start();
        format!("does not parse as Rust at {}:{}: {e}", at.line, at.column)
    })?;
    let mut rules = MacroRules {
        features,
        gated: BTreeMap::new(),
    };
    rules.visit_file(&file);
    let mut finder = Gates {
        features,
        gated_macros: rules.gated,
        found: Vec::new(),
        errors: Vec::new(),
    };
    finder.attributed(&file.attrs, file.span(), None);
    finder.visit_file(&file);
    if !finder.errors.is_empty() {
        return Err(finder.errors.join("; "));
    }
    Ok(finder.found)
}

/// The first gate a macro's tokens write, at any depth: `#[cfg(…)]`,
/// `#![cfg(…)]` or a `cfg` inside `cfg_attr`, naming one of the features.
fn gate_in_tokens(
    trees: &[TokenTree],
    features: &BTreeSet<String>,
) -> Result<Option<Vec<TokenTree>>, String> {
    for (k, tree) in trees.iter().enumerate() {
        if let TokenTree::Group(g) = tree {
            let inner: Vec<TokenTree> = g.stream().into_iter().collect();
            // `#[…]`, or the inner `#![…]`.
            let punct_at = |back: usize, c: char| {
                k.checked_sub(back)
                    .and_then(|j| trees.get(j))
                    .is_some_and(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == c))
            };
            let attribute = g.delimiter() == Delimiter::Bracket
                && (punct_at(1, '#') || (punct_at(1, '!') && punct_at(2, '#')));
            let call = match inner.as_slice() {
                [TokenTree::Ident(name), TokenTree::Group(args)]
                    if attribute && args.delimiter() == Delimiter::Parenthesis =>
                {
                    Some((name.to_string(), args.stream()))
                }
                _ => None,
            };
            if let Some((name, args)) = call {
                let tokens: Vec<TokenTree> = args.into_iter().collect();
                if let Some(predicate) = predicate_of_list(&name, &tokens, features)? {
                    return Ok(Some(predicate));
                }
            }
            if let Some(found) = gate_in_tokens(&inner, features)? {
                return Ok(Some(found));
            }
        }
    }
    Ok(None)
}

/// The predicate of an attribute that gates on one of the features.
fn predicate_of(
    a: &syn::Attribute,
    features: &BTreeSet<String>,
) -> Result<Option<Vec<TokenTree>>, String> {
    let syn::Meta::List(list) = &a.meta else {
        return Ok(None);
    };
    let Some(name) = list.path.get_ident() else {
        return Ok(None);
    };
    let tokens: Vec<TokenTree> = list.tokens.clone().into_iter().collect();
    predicate_of_list(&name.to_string(), &tokens, features)
}

/// The condition under which an attribute `name(tokens)` leaves its node
/// compiled, when it names one of the features: `cfg(P)` is P;
/// `cfg_attr(C, a, …)` applies its attributes only when C holds, so the node
/// is compiled when C does not hold or every gate among them holds:
/// `any(not(C), all(…))`, with a nested `cfg_attr` read the same way.
fn predicate_of_list(
    name: &str,
    tokens: &[TokenTree],
    features: &BTreeSet<String>,
) -> Result<Option<Vec<TokenTree>>, String> {
    let Some(text) = inclusion(name, tokens)? else {
        return Ok(None);
    };
    let predicate: Vec<TokenTree> = TokenStream::from_str(&text)
        .map_err(|e| format!("`{text}`: {e}"))?
        .into_iter()
        .collect();
    Ok(mentions(&predicate, features).then_some(predicate))
}

/// The inclusion condition an attribute writes, as text, if it gates at all.
fn inclusion(name: &str, tokens: &[TokenTree]) -> Result<Option<String>, String> {
    match name {
        "cfg" => Ok(Some(
            tokens.iter().cloned().collect::<TokenStream>().to_string(),
        )),
        "cfg_attr" => {
            let parts = split_commas(tokens);
            let (condition, attributes) = parts
                .split_first()
                .ok_or_else(|| "an empty `cfg_attr`".to_string())?;
            let mut gates = Vec::new();
            for attribute in attributes {
                if let [TokenTree::Ident(inner), TokenTree::Group(g)] = attribute.as_slice() {
                    if g.delimiter() == Delimiter::Parenthesis {
                        let inner_tokens: Vec<TokenTree> = g.stream().into_iter().collect();
                        if let Some(gate) = inclusion(&inner.to_string(), &inner_tokens)? {
                            gates.push(gate);
                        }
                    }
                }
            }
            if gates.is_empty() {
                return Ok(None);
            }
            Ok(Some(format!(
                "any(not({}), all({}))",
                condition.iter().cloned().collect::<TokenStream>(),
                gates.join(", ")
            )))
        }
        _ => Ok(None),
    }
}

/// The `macro_rules!` whose bodies write a gate, by name, with the gate.
struct MacroRules<'a> {
    features: &'a BTreeSet<String>,
    gated: BTreeMap<String, Result<Vec<TokenTree>, String>>,
}

impl<'ast> Visit<'ast> for MacroRules<'_> {
    fn visit_item_macro(&mut self, i: &'ast syn::ItemMacro) {
        if let Some(name) = &i.ident {
            if i.mac.path.is_ident("macro_rules") {
                let trees: Vec<TokenTree> = i.mac.tokens.clone().into_iter().collect();
                match gate_in_tokens(&trees, self.features) {
                    Ok(Some(predicate)) => {
                        self.gated.insert(name.to_string(), Ok(predicate));
                    }
                    Ok(None) => {}
                    Err(e) => {
                        self.gated.insert(name.to_string(), Err(e));
                    }
                }
            }
        }
        syn::visit::visit_item_macro(self, i);
    }
}

struct Gates<'a> {
    features: &'a BTreeSet<String>,
    gated_macros: BTreeMap<String, Result<Vec<TokenTree>, String>>,
    found: Vec<Gate>,
    errors: Vec<String>,
}

impl Gates<'_> {
    /// The gates a node's attributes write, each covering the node.
    fn attributed(&mut self, attrs: &[syn::Attribute], span: Span, module: Option<String>) {
        for a in attrs {
            match predicate_of(a, self.features) {
                Ok(Some(predicate)) => self.found.push(Gate {
                    predicate,
                    start: span.start(),
                    end: span.end(),
                    module: module.clone(),
                    unread: None,
                }),
                Ok(None) => {}
                Err(e) => self.errors.push(format!("line {}: {e}", span.start().line)),
            }
        }
    }

    /// A node syn keeps as unparsed tokens: a gate written in them leaves the
    /// node's extent undecided.
    fn unparsed(&mut self, node: &(impl quote::ToTokens + Spanned)) {
        let span = node.span();
        let trees: Vec<TokenTree> = node.to_token_stream().into_iter().collect();
        match gate_in_tokens(&trees, self.features) {
            Ok(Some(predicate)) => self.found.push(Gate {
                predicate,
                start: span.start(),
                end: span.end(),
                module: None,
                unread: Some("a `cfg` inside tokens syn keeps unparsed (Verbatim)".to_string()),
            }),
            Ok(None) => {}
            Err(e) => self.errors.push(format!("line {}: {e}", span.start().line)),
        }
    }

    /// A macro invocation whose tokens, or whose `macro_rules!` body, write a
    /// gate: when its tokens parse as items, their gates are read like any
    /// other; otherwise the invocation's extent is undecided.
    fn invocation(&mut self, mac: &syn::Macro, span: Span) {
        let trees: Vec<TokenTree> = mac.tokens.clone().into_iter().collect();
        let written = match gate_in_tokens(&trees, self.features) {
            Ok(found) => found,
            Err(e) => {
                self.errors.push(format!("line {}: {e}", span.start().line));
                return;
            }
        };
        let name = mac.path.segments.last().map(|s| s.ident.to_string());
        let by_rules = match name.as_ref().and_then(|n| self.gated_macros.get(n)) {
            Some(Ok(predicate)) => Some(predicate.clone()),
            Some(Err(e)) => {
                self.errors.push(format!("line {}: {e}", span.start().line));
                return;
            }
            None => None,
        };
        if let Some(predicate) = written {
            let items = syn::parse::Parser::parse2(
                |input: syn::parse::ParseStream| {
                    let mut items = Vec::new();
                    while !input.is_empty() {
                        items.push(input.parse::<syn::Item>()?);
                    }
                    Ok(items)
                },
                mac.tokens.clone(),
            );
            match items {
                Ok(items) => {
                    for item in &items {
                        self.visit_item(item);
                    }
                }
                Err(e) => self.found.push(Gate {
                    predicate,
                    start: span.start(),
                    end: span.end(),
                    module: None,
                    unread: Some(format!(
                        "a `cfg` inside a macro invocation whose tokens do not parse as items ({e})"
                    )),
                }),
            }
        }
        if let (Some(predicate), Some(name)) = (by_rules, name) {
            self.found.push(Gate {
                predicate,
                start: span.start(),
                end: span.end(),
                module: None,
                unread: Some(format!(
                    "`{name}!` writes a `cfg` from its `macro_rules!` body, which this map does not expand"
                )),
            });
        }
    }
}

/// A node's attributes, for the node kinds that carry them; `None` for a
/// node syn keeps as unparsed tokens (`Verbatim`), whose gates are read from
/// its tokens instead.
macro_rules! attrs_of {
    ($node:expr, $($variant:path),+ $(,)?) => {
        match $node {
            $($variant(n) => Some(&n.attrs[..]),)+
            _ => None,
        }
    };
}

fn item_attrs(i: &syn::Item) -> Option<&[syn::Attribute]> {
    use syn::Item as I;
    attrs_of!(
        i,
        I::Const,
        I::Enum,
        I::ExternCrate,
        I::Fn,
        I::ForeignMod,
        I::Impl,
        I::Macro,
        I::Mod,
        I::Static,
        I::Struct,
        I::Trait,
        I::TraitAlias,
        I::Type,
        I::Union,
        I::Use
    )
}

fn impl_item_attrs(i: &syn::ImplItem) -> Option<&[syn::Attribute]> {
    use syn::ImplItem as I;
    attrs_of!(i, I::Const, I::Fn, I::Type, I::Macro)
}

fn trait_item_attrs(i: &syn::TraitItem) -> Option<&[syn::Attribute]> {
    use syn::TraitItem as I;
    attrs_of!(i, I::Const, I::Fn, I::Type, I::Macro)
}

fn foreign_item_attrs(i: &syn::ForeignItem) -> Option<&[syn::Attribute]> {
    use syn::ForeignItem as I;
    attrs_of!(i, I::Fn, I::Static, I::Type, I::Macro)
}

fn expr_attrs(e: &syn::Expr) -> Option<&[syn::Attribute]> {
    use syn::Expr as E;
    attrs_of!(
        e,
        E::Array,
        E::Assign,
        E::Async,
        E::Await,
        E::Binary,
        E::Block,
        E::Break,
        E::Call,
        E::Cast,
        E::Closure,
        E::Const,
        E::Continue,
        E::Field,
        E::ForLoop,
        E::Group,
        E::If,
        E::Index,
        E::Infer,
        E::Let,
        E::Lit,
        E::Loop,
        E::Macro,
        E::Match,
        E::MethodCall,
        E::Paren,
        E::Path,
        E::Range,
        E::RawAddr,
        E::Reference,
        E::Repeat,
        E::Return,
        E::Struct,
        E::Try,
        E::TryBlock,
        E::Tuple,
        E::Unary,
        E::Unsafe,
        E::While,
        E::Yield
    )
}

impl<'ast> Visit<'ast> for Gates<'_> {
    fn visit_item(&mut self, i: &'ast syn::Item) {
        match item_attrs(i) {
            Some(attrs) => {
                let module = match i {
                    syn::Item::Mod(m) if m.content.is_none() => Some(m.ident.to_string()),
                    _ => None,
                };
                self.attributed(attrs, i.span(), module);
            }
            None => self.unparsed(i),
        }
        if let syn::Item::Macro(m) = i {
            if !m.mac.path.is_ident("macro_rules") {
                self.invocation(&m.mac, i.span());
            }
        }
        syn::visit::visit_item(self, i);
    }

    fn visit_impl_item(&mut self, i: &'ast syn::ImplItem) {
        match impl_item_attrs(i) {
            Some(attrs) => self.attributed(attrs, i.span(), None),
            None => self.unparsed(i),
        }
        if let syn::ImplItem::Macro(m) = i {
            self.invocation(&m.mac, i.span());
        }
        syn::visit::visit_impl_item(self, i);
    }

    fn visit_trait_item(&mut self, i: &'ast syn::TraitItem) {
        match trait_item_attrs(i) {
            Some(attrs) => self.attributed(attrs, i.span(), None),
            None => self.unparsed(i),
        }
        if let syn::TraitItem::Macro(m) = i {
            self.invocation(&m.mac, i.span());
        }
        syn::visit::visit_trait_item(self, i);
    }

    fn visit_foreign_item(&mut self, i: &'ast syn::ForeignItem) {
        match foreign_item_attrs(i) {
            Some(attrs) => self.attributed(attrs, i.span(), None),
            None => self.unparsed(i),
        }
        if let syn::ForeignItem::Macro(m) = i {
            self.invocation(&m.mac, i.span());
        }
        syn::visit::visit_foreign_item(self, i);
    }

    fn visit_field(&mut self, f: &'ast syn::Field) {
        self.attributed(&f.attrs, f.span(), None);
        syn::visit::visit_field(self, f);
    }

    fn visit_variant(&mut self, v: &'ast syn::Variant) {
        self.attributed(&v.attrs, v.span(), None);
        syn::visit::visit_variant(self, v);
    }

    fn visit_arm(&mut self, a: &'ast syn::Arm) {
        self.attributed(&a.attrs, a.span(), None);
        syn::visit::visit_arm(self, a);
    }

    fn visit_local(&mut self, l: &'ast syn::Local) {
        self.attributed(&l.attrs, l.span(), None);
        syn::visit::visit_local(self, l);
    }

    fn visit_stmt_macro(&mut self, s: &'ast syn::StmtMacro) {
        self.attributed(&s.attrs, s.span(), None);
        self.invocation(&s.mac, s.span());
        syn::visit::visit_stmt_macro(self, s);
    }

    fn visit_expr(&mut self, e: &'ast syn::Expr) {
        match expr_attrs(e) {
            Some(attrs) => self.attributed(attrs, e.span(), None),
            None => self.unparsed(e),
        }
        if let syn::Expr::Macro(m) = e {
            self.invocation(&m.mac, e.span());
        }
        syn::visit::visit_expr(self, e);
    }

    fn visit_field_value(&mut self, f: &'ast syn::FieldValue) {
        self.attributed(&f.attrs, f.span(), None);
        syn::visit::visit_field_value(self, f);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn predicate(text: &str) -> Result<Vec<TokenTree>, String> {
        let stream = TokenStream::from_str(text).map_err(|e| e.to_string())?;
        Ok(stream.into_iter().collect())
    }

    #[test]
    fn a_test_feature_gate_is_off_in_the_shipped_build() -> Result<(), String> {
        let p = predicate("any(test, feature = \"test-utils\")")?;
        assert_eq!(evaluate(&p, &set(&["jni", "bluetooth"]))?, Truth::No);
        assert_eq!(evaluate(&p, &set(&["test-utils"]))?, Truth::Yes);
        Ok(())
    }

    #[test]
    fn an_unknown_condition_leaves_the_gate_undecided() -> Result<(), String> {
        let p = predicate("all(feature = \"test-utils\", target_os = \"android\")")?;
        assert_eq!(evaluate(&p, &set(&["test-utils"]))?, Truth::Unknown);
        assert_eq!(evaluate(&p, &set(&[]))?, Truth::No);
        Ok(())
    }

    #[test]
    fn features_are_read_per_package_from_cargo_tree() -> Result<(), String> {
        let tree = "dsm_sdk v0.1.0 (/r/dsm_sdk) bluetooth,jni,test-utils\n\ndsm v0.1.0 (/r/dsm)\nserde v1.0.1 derive,std\n";
        let f = features(tree)?;
        assert_eq!(
            f.get("dsm_sdk"),
            Some(&set(&["bluetooth", "jni", "test-utils"]))
        );
        assert_eq!(f.get("dsm"), Some(&set(&[])));
        // A source path holding spaces and parentheses, a proc-macro marker
        // and a repeat marker are groups, not the feature list.
        let tree = "probe v0.1.0 (/home/a b (c)/probe) leak\nderive v1.0.0 (proc-macro) default (*)\nserde v1.0.1 (*)\n";
        let f = features(tree)?;
        assert_eq!(f.get("probe"), Some(&set(&["leak"])));
        assert_eq!(f.get("derive"), Some(&set(&["default"])));
        assert_eq!(f.get("serde"), Some(&set(&[])));
        // A line that is not a package line is refused, never skipped.
        for malformed in ["dsm_sdk\n", "a v1 (/open path\n", "a v1 one two\n"] {
            match features(malformed) {
                Err(e) => assert!(e.contains("cargo tree"), "{e}"),
                Ok(read) => return Err(format!("{malformed:?} was read as {read:?}")),
            }
        }
        Ok(())
    }

    #[test]
    fn a_gated_module_and_a_gated_fn_are_found() -> Result<(), String> {
        let text = "#[cfg(any(test, feature = \"test-utils\"))]\npub mod fixtures;\nimpl S {\n    #[cfg(any(test, feature = \"test-utils\"))]\n    pub(crate) fn reset() { }\n    fn kept() {}\n}\n";
        let found = gates(text, &set(&["test-utils"]))?;
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].module.as_deref(), Some("fixtures"));
        assert_eq!(found[1].start.line, 4);
        assert_eq!(
            module_file_base("a/src/lib.rs", "fixtures"),
            "a/src/fixtures"
        );
        assert_eq!(module_file_base("a/src/db/mod.rs", "x"), "a/src/db/x");
        assert_eq!(module_file_base("a/src/db.rs", "x"), "a/src/db/x");
        assert_eq!(module_file_base("a/src/lib.rs", "r#type"), "a/src/type");
        assert_eq!(module_file_base("lib.rs", "fixtures"), "fixtures");
        Ok(())
    }

    /// Each gate's first and last line, and whether its extent is read.
    fn found(text: &str) -> Result<Vec<(usize, usize, Option<String>)>, String> {
        Ok(gates(text, &set(&["test-utils"]))?
            .into_iter()
            .map(|g| (g.start.line, g.end.line, g.unread))
            .collect())
    }

    #[test]
    fn an_inner_cfg_gates_what_it_is_written_in() -> Result<(), String> {
        // At a file's top: the whole file.
        assert_eq!(
            found("#![cfg(feature = \"test-utils\")]\nfn a() {}\n\nfn b() {}\n")?,
            vec![(1, 4, None)]
        );
        // In a module's body: the module, from its `mod`.
        assert_eq!(
            found("fn keep() {}\nmod m {\n    #![cfg(feature = \"test-utils\")]\n    fn gone() {}\n}\nfn after() {}\n")?,
            vec![(2, 5, None)]
        );
        Ok(())
    }

    #[test]
    fn generics_and_where_clauses_do_not_end_a_gated_item() -> Result<(), String> {
        let text = "#[cfg(feature = \"test-utils\")]\nimpl<T, U> Tr for S<T, U>\nwhere\n    T: A,\n    U: B,\n{\n    fn f() {}\n}\nstruct F {\n    #[cfg(feature = \"test-utils\")]\n    map: Map<K, fn() -> V>,\n    kept: u8,\n}\n";
        assert_eq!(found(text)?, vec![(1, 8, None), (10, 11, None)]);
        // A comparison in a gated item's expression ends nothing early or late.
        let text = "#[cfg(feature = \"test-utils\")]\nconst A: bool = 1 < 2;\nfn kept() {}\nfn g(x: u8) -> u8 {\n    match x {\n        #[cfg(feature = \"test-utils\")]\n        n if n < 3 => n,\n        n => n,\n    }\n}\n";
        assert_eq!(found(text)?, vec![(1, 2, None), (6, 7, None)]);
        Ok(())
    }

    #[test]
    fn a_gate_covers_the_doc_comment_its_item_starts_at() -> Result<(), String> {
        // rust-analyzer's extent of an item starts at its doc comment; a gate
        // that started at the `cfg` line would not contain the definition.
        let text = "/// Reset (for testing only)\n#[cfg(any(test, feature = \"test-utils\"))]\npub fn reset() {}\n";
        assert_eq!(found(text)?, vec![(1, 3, None)]);
        Ok(())
    }

    #[test]
    fn positions_count_characters_not_bytes() -> Result<(), String> {
        // proc-macro2 counts a column in characters; the map's positions are
        // bytes. `é` is two bytes.
        let text = "const É: u8 = 1; #[cfg(feature = \"test-utils\")] fn g() {}\n";
        let gate = &gates(text, &set(&["test-utils"]))?[0];
        let lines: Vec<&str> = text.split('\n').collect();
        let byte = text.find("#[cfg").ok_or("no gate in the text")?;
        assert_eq!(gate.start.column, 17);
        assert_eq!(
            position(&lines, gate.start)?,
            Position {
                line: 0,
                column: byte
            }
        );
        assert_eq!(byte, 18);
        Ok(())
    }

    #[test]
    fn gates_in_macros_are_read_or_left_undecided() -> Result<(), String> {
        // Items a macro invocation holds are parsed and read.
        let text = "wrap! {\n    #[cfg(feature = \"test-utils\")]\n    fn inside() {}\n}\n";
        assert_eq!(found(text)?, vec![(2, 3, None)]);
        // A `macro_rules!` body that writes a gate: each invocation is undecided.
        let text = "macro_rules! m {\n    ($n:ident) => {\n        #[cfg(feature = \"test-utils\")]\n        fn $n() {}\n    };\n}\nm!(made);\n";
        let got = found(text)?;
        assert_eq!(got.len(), 1);
        assert_eq!((got[0].0, got[0].1), (7, 7));
        assert!(got[0]
            .2
            .as_deref()
            .is_some_and(|why| why.contains("macro_rules")));
        // `cfg_attr(C, cfg(P))` gates on all(C, P).
        let gated = gates(
            "#[cfg_attr(unix, cfg(feature = \"test-utils\"))]\nfn f() {}\n",
            &set(&["test-utils"]),
        )?;
        let text: Vec<String> = gated.iter().map(|g| predicate_text(&g.predicate)).collect();
        assert_eq!(
            text,
            vec!["any (not (unix) , all (feature = \"test-utils\"))"]
        );
        // Compiled when C does not hold or P does: excluded only when C holds
        // and P does not.
        let predicate = &gates(
            "#[cfg_attr(feature = \"x\", cfg(feature = \"test-utils\"))]\nfn f() {}\n",
            &set(&["test-utils"]),
        )?[0]
            .predicate;
        assert_eq!(evaluate(predicate, &set(&[]))?, Truth::Yes);
        assert_eq!(evaluate(predicate, &set(&["x"]))?, Truth::No);
        assert_eq!(evaluate(predicate, &set(&["x", "test-utils"]))?, Truth::Yes);
        // Nested: compiled unless x and y hold and test-utils does not.
        let predicate = &gates(
            "#[cfg_attr(feature = \"x\", cfg_attr(feature = \"y\", cfg(feature = \"test-utils\")))]\nfn f() {}\n",
            &set(&["test-utils"]),
        )?[0]
            .predicate;
        assert_eq!(evaluate(predicate, &set(&["x"]))?, Truth::Yes);
        assert_eq!(evaluate(predicate, &set(&["x", "y"]))?, Truth::No);
        assert_eq!(
            evaluate(predicate, &set(&["x", "y", "test-utils"]))?,
            Truth::Yes
        );
        Ok(())
    }
}
