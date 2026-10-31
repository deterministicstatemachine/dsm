// SPDX-License-Identifier: MIT OR Apache-2.0
//! Every outcome program a verifier registers is bounded and deterministic,
//! shown from its source and by running it to the end of the longest match
//! its rules allow (DSM Amendment A23; G3 rulings B3 and B4, owner
//! 2026-10-28: "Require each registered program's allowed operations and
//! deterministic behaviour to be explicitly verified", and "Each active
//! program must have a demonstrable execution bound. Don't pretend the
//! general language's static-budget guarantee exists when it doesn't.").
//!
//! A verifier runs a registered program as compiled Rust, so nothing meters it
//! while it runs: its bound is a property of its source, and this holds the
//! source to it. Every function the program's evaluation can reach — the whole
//! `wildstate-duel` crate, and the adapter's functions reachable from
//! `WildstateDuel::outcome` — is parsed, and none may:
//! - loop except over a collection or a range with an end: no `loop`, no
//!   `while`, no range without an end as an iterator, and no iterator that
//!   never ends (`iter::repeat`, `repeat_with`, `successors`, `iter::from_fn`,
//!   `cycle`);
//! - recurse, directly or through other functions of the program, with each
//!   call resolved by the type it is made on;
//! - dispatch dynamically (`dyn`);
//! - read a clock, randomness, the environment, a file, the network or a
//!   thread; keep state between evaluations (a `static`, a cell, a lock, an
//!   atomic, a thread local); or run `unsafe` code;
//! - compute in floating point.
//!
//! What is left terminates on every input. Each loop runs over a collection
//! whose length the inputs bound — the opened entries, at most
//! `TRANSCRIPT_MAX_ENTRIES`; the decoded setup, whose counts the codec bounds;
//! the constant tables — and the rules end every match by their turn cap, so
//! the work is bounded by those sizes. Integer arithmetic panics on overflow in
//! every build the workspace makes (both release profiles turn
//! `overflow-checks` on), so no build computes a wrapped value another would
//! not.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use syn::visit::Visit;

use dsm::sofi::computed::{OutcomeProgram, ProgramOutcome};
use dsm_sdk::sdk::outcome_programs::{opened_of_turns, WildstateDuel};

/// The `wildstate-duel` crate's sources.
fn duel_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../crates/wildstate-duel/src")
}

/// The adapter that makes the duel Core's outcome program.
fn adapter_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/sdk/outcome_programs.rs")
}

fn parse(path: &Path) -> syn::File {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => panic!("read {}: {e}", path.display()),
    };
    match syn::parse_file(&text) {
        Ok(file) => file,
        Err(e) => panic!("parse {}: {e}", path.display()),
    }
}

fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) => panic!("read {}: {e}", dir.display()),
    };
    let mut out: Vec<PathBuf> = entries
        .map(|entry| match entry {
            Ok(entry) => entry.path(),
            Err(e) => panic!("an entry of {}: {e}", dir.display()),
        })
        .filter(|path| path.extension().and_then(|e| e.to_str()) == Some("rs"))
        .collect();
    out.sort();
    out
}

/// Whether an item is compiled only for tests.
fn test_only(attrs: &[syn::Attribute]) -> bool {
    attrs
        .iter()
        .filter_map(|attr| match &attr.meta {
            syn::Meta::List(list) if list.path.is_ident("cfg") => Some(list.tokens.to_string()),
            _ => None,
        })
        .any(|predicate| {
            predicate
                .split(|c: char| !(c.is_alphanumeric() || c == '_'))
                .any(|word| word == "test")
        })
}

// ── the program's code ─────────────────────────────────────────────────────

/// One function of the program: where it is, the type its `impl` is for (a
/// free function has none), its name, and the function.
#[derive(Clone)]
struct ProgramFn {
    at: String,
    owner: Option<String>,
    name: String,
    item: syn::ItemFn,
}

impl ProgramFn {
    /// How a call names it: `Type::name`, or `name` for a free function.
    fn key(&self) -> String {
        match &self.owner {
            Some(owner) => format!("{owner}::{}", self.name),
            None => self.name.clone(),
        }
    }
}

/// The program's code: its functions, the field types of its structs, and
/// its `static` items (which it may not hold).
#[derive(Default)]
struct Code {
    fns: Vec<ProgramFn>,
    fields: BTreeMap<(String, String), syn::Type>,
    consts: BTreeMap<String, syn::Type>,
    statics: Vec<String>,
}

/// The type named `name`.
fn named(name: &str) -> syn::Type {
    match syn::parse_str::<syn::Type>(name) {
        Ok(ty) => ty,
        Err(e) => panic!("{name} names a type: {e}"),
    }
}

/// The last segment of a type's path, through references and parentheses.
fn type_name(ty: &syn::Type) -> Option<String> {
    match ty {
        syn::Type::Reference(r) => type_name(&r.elem),
        syn::Type::Paren(p) => type_name(&p.elem),
        syn::Type::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

/// The element type of a collection type (`Vec<T>`, `[T]`, `[T; N]`,
/// `Option<T>`, `Box<T>`), through references.
fn element_type(ty: &syn::Type) -> Option<syn::Type> {
    match ty {
        syn::Type::Reference(r) => element_type(&r.elem),
        syn::Type::Slice(s) => Some((*s.elem).clone()),
        syn::Type::Array(a) => Some((*a.elem).clone()),
        syn::Type::Path(p) => match &p.path.segments.last()?.arguments {
            syn::PathArguments::AngleBracketed(args) => args.args.iter().find_map(|a| match a {
                syn::GenericArgument::Type(t) => Some(t.clone()),
                _ => None,
            }),
            _ => None,
        },
        _ => None,
    }
}

fn collect(items: &[syn::Item], file: &str, code: &mut Code) {
    for item in items {
        match item {
            syn::Item::Fn(f) if !test_only(&f.attrs) => code.fns.push(ProgramFn {
                at: file.to_string(),
                owner: None,
                name: f.sig.ident.to_string(),
                item: f.clone(),
            }),
            syn::Item::Impl(imp) if !test_only(&imp.attrs) => {
                let owner = type_name(&imp.self_ty);
                for inner in &imp.items {
                    if let syn::ImplItem::Fn(f) = inner {
                        if !test_only(&f.attrs) {
                            code.fns.push(ProgramFn {
                                at: file.to_string(),
                                owner: owner.clone(),
                                name: f.sig.ident.to_string(),
                                item: syn::ItemFn {
                                    attrs: f.attrs.clone(),
                                    vis: f.vis.clone(),
                                    sig: f.sig.clone(),
                                    block: Box::new(f.block.clone()),
                                },
                            });
                        }
                    }
                }
            }
            syn::Item::Struct(s) if !test_only(&s.attrs) => {
                for field in &s.fields {
                    if let Some(name) = &field.ident {
                        code.fields
                            .insert((s.ident.to_string(), name.to_string()), field.ty.clone());
                    }
                }
            }
            syn::Item::Mod(m) if !test_only(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    collect(inner, file, code);
                }
            }
            syn::Item::Static(s) if !test_only(&s.attrs) => {
                code.statics.push(format!("{file}: static {}", s.ident));
            }
            syn::Item::Const(c) if !test_only(&c.attrs) => {
                code.consts.insert(c.ident.to_string(), (*c.ty).clone());
            }
            _ => {}
        }
    }
}

// ── what a program may not do ──────────────────────────────────────────────

/// Names only a clock, randomness, the outside world, shared state or a
/// thread needs.
const WORLD: [&str; 18] = [
    "Instant",
    "SystemTime",
    "rand",
    "thread_rng",
    "getrandom",
    "OsRng",
    "thread_local",
    "Cell",
    "RefCell",
    "UnsafeCell",
    "Mutex",
    "RwLock",
    "OnceCell",
    "OnceLock",
    "LazyLock",
    "lazy_static",
    "f32",
    "f64",
];

/// Modules of `std` the program may not name.
const STD_WORLD: [&str; 6] = ["time", "env", "fs", "net", "thread", "process"];

/// Constructors of iterators that never end (`core::array::from_fn`, which
/// builds a fixed-size array, is not one).
const ENDLESS_CALLS: [&str; 4] = ["repeat", "repeat_with", "successors", "from_fn"];

fn endless_range(expr: &syn::Expr) -> bool {
    match expr {
        syn::Expr::Paren(inner) => endless_range(&inner.expr),
        other => matches!(other, syn::Expr::Range(range) if range.end.is_none()),
    }
}

#[derive(Default)]
struct Forbidden {
    found: Vec<String>,
}

impl<'ast> Visit<'ast> for Forbidden {
    fn visit_expr_loop(&mut self, e: &'ast syn::ExprLoop) {
        self.found.push("loop".to_string());
        syn::visit::visit_expr_loop(self, e);
    }

    fn visit_expr_while(&mut self, e: &'ast syn::ExprWhile) {
        self.found.push("while".to_string());
        syn::visit::visit_expr_while(self, e);
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        if endless_range(&e.expr) {
            self.found
                .push("a for over a range with no end".to_string());
        }
        syn::visit::visit_expr_for_loop(self, e);
    }

    fn visit_expr_method_call(&mut self, e: &'ast syn::ExprMethodCall) {
        if e.method == "cycle" {
            self.found.push(".cycle()".to_string());
        }
        if endless_range(&e.receiver) {
            self.found
                .push("an iterator over a range with no end".to_string());
        }
        syn::visit::visit_expr_method_call(self, e);
    }

    fn visit_expr_call(&mut self, e: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = &*e.func {
            let segments: Vec<String> = path
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            if let Some(last) = segments.last() {
                if ENDLESS_CALLS.contains(&last.as_str()) && !segments.iter().any(|s| s == "array")
                {
                    self.found.push(format!("{last}()"));
                }
            }
        }
        syn::visit::visit_expr_call(self, e);
    }

    fn visit_type_trait_object(&mut self, t: &'ast syn::TypeTraitObject) {
        self.found.push("dyn".to_string());
        syn::visit::visit_type_trait_object(self, t);
    }

    fn visit_expr_unsafe(&mut self, e: &'ast syn::ExprUnsafe) {
        self.found.push("unsafe".to_string());
        syn::visit::visit_expr_unsafe(self, e);
    }

    fn visit_signature(&mut self, s: &'ast syn::Signature) {
        if s.unsafety.is_some() {
            self.found.push("unsafe fn".to_string());
        }
        syn::visit::visit_signature(self, s);
    }

    fn visit_lit_float(&mut self, l: &'ast syn::LitFloat) {
        self.found.push(format!("the float {}", l.base10_digits()));
        syn::visit::visit_lit_float(self, l);
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        for name in &segments {
            if WORLD.contains(&name.as_str()) || name.starts_with("Atomic") {
                self.found.push(name.clone());
            }
        }
        for pair in segments.windows(2) {
            if pair[0] == "std" && STD_WORLD.contains(&pair[1].as_str()) {
                self.found.push(format!("std::{}", pair[1]));
            }
        }
        syn::visit::visit_path(self, path);
    }
}

// ── the call graph, by the type each call is made on ───────────────────────

/// The program functions one function calls. A call through a path names its
/// type (`Self::f`, `Type::f`) or is a free function. A method call is
/// resolved by its receiver's type where that is known — `self`, a
/// parameter, a `let` with a type or a constructor, a loop variable over a
/// known collection, a field of a known type — and otherwise could be any
/// program type's method of that name.
struct Calls<'c> {
    code: &'c Code,
    owner: Option<String>,
    locals: Vec<BTreeMap<String, syn::Type>>,
    out: BTreeSet<String>,
}

impl<'c> Calls<'c> {
    fn of(code: &'c Code, f: &ProgramFn) -> BTreeSet<String> {
        let mut params = BTreeMap::new();
        for input in &f.item.sig.inputs {
            if let syn::FnArg::Typed(typed) = input {
                if let syn::Pat::Ident(name) = &*typed.pat {
                    params.insert(name.ident.to_string(), (*typed.ty).clone());
                }
            }
        }
        let mut calls = Calls {
            code,
            owner: f.owner.clone(),
            locals: vec![params],
            out: BTreeSet::new(),
        };
        calls.visit_block(&f.item.block);
        calls.out
    }

    fn defined(&self, key: &str) -> bool {
        self.code.fns.iter().any(|f| f.key() == key)
    }

    /// `Self` read as the type the `impl` is for.
    fn concrete(&self, name: String) -> Option<String> {
        match name.as_str() {
            "Self" => self.owner.clone(),
            _ => Some(name),
        }
    }

    fn local(&self, name: &str) -> Option<syn::Type> {
        match name {
            "self" => self.owner.as_deref().map(named),
            _ => self
                .locals
                .iter()
                .rev()
                .find_map(|scope| scope.get(name).cloned())
                .or_else(|| self.code.consts.get(name).cloned()),
        }
    }

    /// The type of what iterating `expr` yields, where it is known: an array
    /// literal's element, a collection's element, through `.iter()`.
    fn element_of(&self, expr: &syn::Expr) -> Option<syn::Type> {
        match expr {
            syn::Expr::Array(a) => self.type_of(a.elems.first()?),
            syn::Expr::Reference(r) => self.element_of(&r.expr),
            syn::Expr::Paren(p) => self.element_of(&p.expr),
            syn::Expr::MethodCall(m)
                if m.method == "iter" || m.method == "iter_mut" || m.method == "into_iter" =>
            {
                self.element_of(&m.receiver)
            }
            other => self.type_of(other).as_ref().and_then(element_type),
        }
    }

    /// Bind what `pat` names, matched against a value of type `ty`: a name
    /// is the value; `Some(x)` and `Ok(x)` name its element.
    fn bind_matched(&mut self, pat: &syn::Pat, ty: Option<syn::Type>) {
        match pat {
            syn::Pat::TupleStruct(t) if t.elems.len() == 1 => {
                let element = ty.as_ref().and_then(element_type);
                if let Some(inner) = t.elems.first() {
                    self.bind_matched(inner, element);
                }
            }
            other => self.bind(other, ty),
        }
    }

    /// The type of `expr`, where it is known.
    fn type_of(&self, expr: &syn::Expr) -> Option<syn::Type> {
        match expr {
            syn::Expr::Path(p) => match p.path.segments.len() {
                1 => self.local(&p.path.segments[0].ident.to_string()),
                _ => p
                    .path
                    .segments
                    .last()
                    .and_then(|last| self.code.consts.get(&last.ident.to_string()).cloned()),
            },
            syn::Expr::Index(i) => self.element_of(&i.expr),
            syn::Expr::Field(f) => {
                let base = self.concrete(type_name(&self.type_of(&f.base)?)?)?;
                match &f.member {
                    syn::Member::Named(name) => {
                        self.code.fields.get(&(base, name.to_string())).cloned()
                    }
                    syn::Member::Unnamed(_) => None,
                }
            }
            syn::Expr::Reference(r) => self.type_of(&r.expr),
            syn::Expr::Paren(p) => self.type_of(&p.expr),
            syn::Expr::Try(t) => self.type_of(&t.expr),
            syn::Expr::Struct(s) => {
                let name = self.concrete(s.path.segments.last()?.ident.to_string())?;
                Some(named(&name))
            }
            // A constructor, `Type::new(..)` and the like, names its type.
            syn::Expr::Call(c) => match &*c.func {
                syn::Expr::Path(p) if p.path.segments.len() >= 2 => {
                    let ty = p.path.segments[p.path.segments.len() - 2].ident.to_string();
                    Some(named(&self.concrete(ty)?))
                }
                _ => None,
            },
            _ => None,
        }
    }

    fn method_on(&mut self, receiver: Option<syn::Type>, method: &str) {
        match receiver
            .as_ref()
            .and_then(type_name)
            .and_then(|t| self.concrete(t))
        {
            Some(ty) => {
                let key = format!("{ty}::{method}");
                if self.defined(&key) {
                    self.out.insert(key);
                }
            }
            None => {
                let named: Vec<String> = self
                    .code
                    .fns
                    .iter()
                    .filter(|f| f.owner.is_some() && f.name == method)
                    .map(ProgramFn::key)
                    .collect();
                self.out.extend(named);
            }
        }
    }

    fn bind(&mut self, pat: &syn::Pat, ty: Option<syn::Type>) {
        let Some(ty) = ty else { return };
        match pat {
            syn::Pat::Ident(name) => {
                if let Some(scope) = self.locals.last_mut() {
                    scope.insert(name.ident.to_string(), ty);
                }
            }
            syn::Pat::Type(typed) => self.bind(&typed.pat, Some(ty)),
            syn::Pat::Reference(r) => self.bind(&r.pat, Some(ty)),
            _ => {}
        }
    }
}

impl<'ast> Visit<'ast> for Calls<'_> {
    fn visit_block(&mut self, b: &'ast syn::Block) {
        self.locals.push(BTreeMap::new());
        syn::visit::visit_block(self, b);
        self.locals.pop();
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(init) = &local.init {
            self.visit_expr(&init.expr);
            if let Some((_, diverge)) = &init.diverge {
                self.visit_expr(diverge);
            }
        }
        let ty = match &local.pat {
            syn::Pat::Type(typed) => Some((*typed.ty).clone()),
            _ => local
                .init
                .as_ref()
                .and_then(|init| self.type_of(&init.expr)),
        };
        self.bind(&local.pat, ty);
    }

    fn visit_expr_for_loop(&mut self, e: &'ast syn::ExprForLoop) {
        self.visit_expr(&e.expr);
        self.locals.push(BTreeMap::new());
        let element = self.element_of(&e.expr);
        self.bind(&e.pat, element);
        self.visit_block(&e.body);
        self.locals.pop();
    }

    fn visit_expr_method_call(&mut self, e: &'ast syn::ExprMethodCall) {
        let receiver = self.type_of(&e.receiver);
        self.method_on(receiver, &e.method.to_string());
        syn::visit::visit_expr_method_call(self, e);
    }

    fn visit_expr_match(&mut self, e: &'ast syn::ExprMatch) {
        self.visit_expr(&e.expr);
        let scrutinee = self.type_of(&e.expr);
        for arm in &e.arms {
            self.locals.push(BTreeMap::new());
            self.bind_matched(&arm.pat, scrutinee.clone());
            if let Some((_, guard)) = &arm.guard {
                self.visit_expr(guard);
            }
            self.visit_expr(&arm.body);
            self.locals.pop();
        }
    }

    fn visit_expr_let(&mut self, e: &'ast syn::ExprLet) {
        self.visit_expr(&e.expr);
        let matched = self.type_of(&e.expr);
        self.bind_matched(&e.pat, matched);
    }

    fn visit_expr_call(&mut self, e: &'ast syn::ExprCall) {
        if let syn::Expr::Path(p) = &*e.func {
            let segments: Vec<String> = p
                .path
                .segments
                .iter()
                .map(|s| s.ident.to_string())
                .collect();
            let key = match segments.as_slice() {
                [.., ty, name] => match self.concrete(ty.clone()) {
                    Some(ty) if self.defined(&format!("{ty}::{name}")) => {
                        Some(format!("{ty}::{name}"))
                    }
                    _ => Some(name.clone()),
                },
                [name] => Some(name.clone()),
                [] => None,
            };
            if let Some(key) = key.filter(|k| self.defined(k)) {
                self.out.insert(key);
            }
        }
        syn::visit::visit_expr_call(self, e);
    }
}

/// The program: every shipped function of the duel crate, and the adapter's
/// functions reachable from `WildstateDuel::outcome`.
fn program() -> Code {
    let mut code = Code::default();
    for path in rust_files(&duel_src()) {
        let at = match path.file_name().and_then(|n| n.to_str()) {
            Some(name) => format!("wildstate-duel/src/{name}"),
            None => panic!("{} has a name", path.display()),
        };
        collect(&parse(&path).items, &at, &mut code);
    }
    let mut adapter = Code::default();
    collect(
        &parse(&adapter_path()).items,
        "outcome_programs.rs",
        &mut adapter,
    );
    code.fields.extend(adapter.fields.clone());
    code.consts.extend(adapter.consts.clone());
    let whole = Code {
        fns: code.fns.iter().chain(adapter.fns.iter()).cloned().collect(),
        fields: code.fields.clone(),
        consts: code.consts.clone(),
        statics: Vec::new(),
    };
    let mut reached: BTreeSet<String> = BTreeSet::new();
    let mut pending = vec!["WildstateDuel::outcome".to_string()];
    while let Some(key) = pending.pop() {
        if reached.insert(key.clone()) {
            for f in adapter.fns.iter().filter(|f| f.key() == key) {
                pending.extend(Calls::of(&whole, f));
            }
        }
    }
    code.fns.extend(
        adapter
            .fns
            .into_iter()
            .filter(|f| reached.contains(&f.key())),
    );
    code
}

/// Every function that reaches itself through calls to functions of the
/// program.
fn recursion(code: &Code) -> Vec<String> {
    let graph: BTreeMap<String, BTreeSet<String>> = code
        .fns
        .iter()
        .map(|f| (f.key(), Calls::of(code, f)))
        .collect();
    let mut cycles = Vec::new();
    for start in graph.keys() {
        let mut seen = BTreeSet::new();
        let mut pending: Vec<&String> = graph[start].iter().collect();
        while let Some(next) = pending.pop() {
            if next == start {
                cycles.push(start.clone());
                break;
            }
            if seen.insert(next.clone()) {
                if let Some(onward) = graph.get(next) {
                    pending.extend(onward.iter());
                }
            }
        }
    }
    cycles
}

/// Everything `code` may not do, each named where it is.
fn forbidden(code: &Code) -> Vec<String> {
    let mut found = code.statics.clone();
    for f in &code.fns {
        let mut v = Forbidden::default();
        v.visit_item_fn(&f.item);
        found.extend(
            v.found
                .into_iter()
                .map(|what| format!("{}: {}: {what}", f.at, f.key())),
        );
    }
    found.extend(
        recursion(code)
            .into_iter()
            .map(|key| format!("{key} recurses")),
    );
    found
}

fn forbidden_in(source: &str) -> Vec<String> {
    let file = match syn::parse_file(source) {
        Ok(file) => file,
        Err(e) => panic!("parse a sample: {e}"),
    };
    let mut code = Code::default();
    collect(&file.items, "sample", &mut code);
    forbidden(&code)
}

#[test]
fn what_a_program_may_not_do_is_found() {
    let samples: [(&str, &str); 13] = [
        ("fn f() { loop {} }", "sample: f: loop"),
        (
            "fn f(n: u32) { let mut i = 0; while i < n { i += 1; } }",
            "sample: f: while",
        ),
        (
            "fn f() { for _ in 0.. {} }",
            "sample: f: a for over a range with no end",
        ),
        (
            "fn f(v: &[u8]) { for _ in v.iter().cycle() {} }",
            "sample: f: .cycle()",
        ),
        (
            "fn f() { std::iter::repeat(1).take(2); }",
            "sample: f: repeat()",
        ),
        ("fn f(x: &dyn Fn()) { x() }", "sample: f: dyn"),
        (
            "fn f() -> std::time::Instant { std::time::Instant::now() }",
            "sample: f: std::time",
        ),
        ("fn f() -> f64 { 0.5 }", "sample: f: f64"),
        ("static mut N: u32 = 0; fn f() {}", "sample: static N"),
        (
            "fn f(n: u32) -> u32 { g(n) } fn g(n: u32) -> u32 { f(n) }",
            "f recurses",
        ),
        (
            "struct T; impl T { fn walk(&self, other: &T) { other.walk(self) } }",
            "T::walk recurses",
        ),
        (
            "struct T { next: U } struct U; impl T { fn go(&self) { self.next.go() } } \
             impl U { fn go(&self) { let t = T { next: U }; t.go() } }",
            "T::go recurses",
        ),
        (
            "struct T; impl T { fn step(&self) { let s = Self::new(); s.step() } \
             fn new() -> T { T } }",
            "T::step recurses",
        ),
    ];
    for (sample, expected) in samples {
        let found = forbidden_in(sample);
        assert!(
            found.iter().any(|f| f == expected),
            "{sample}: expected {expected}, found {found:?}"
        );
    }
    let allowed = "struct T { body: U } struct U; \
                   impl T { fn encode(&self) -> u32 { self.body.encode() } } \
                   impl U { fn encode(&self) -> u32 { 1 } } \
                   fn f(v: &[u8]) -> u32 { let mut n = 0u32; \
                   for b in v { n = n.checked_add(u32::from(*b)).expect(\"bounded\"); } \
                   for _ in 0..v.len() {} let a: [u8; 4] = core::array::from_fn(|k| v[k]); \
                   (0u8..=u8::MAX).zip(v.iter()).map(|(_, b)| u32::from(*b)).sum::<u32>() \
                   + n + u32::from(a[0]) }\n\
                   #[cfg(test)] mod tests { fn t() { loop {} } }";
    assert_eq!(forbidden_in(allowed), Vec::<String>::new());
}

/// MUTATION CONTROL: a `loop`, a `while`, a recursion, a `dyn`, a clock or a
/// `static` added to the duel crate or to the adapter's evaluation turns this
/// red.
#[test]
fn every_registered_program_is_bounded_by_its_source() {
    let code = program();
    let keys: BTreeSet<String> = code.fns.iter().map(ProgramFn::key).collect();
    for expected in [
        "WildstateDuel::outcome",
        "DuelProgress::apply",
        "start",
        "step",
    ] {
        assert!(keys.contains(expected), "{expected} not swept: {keys:?}");
    }
    assert_eq!(
        forbidden(&code),
        Vec::<String>::new(),
        "unbounded or nondeterministic program code"
    );
}

/// The longest match the duel's rules allow, played to its end: every opened
/// entry is a pass (a garbled reveal plays as one, owner ruling 2026-10-06),
/// so no creature takes damage and only the turn cap ends the match. The
/// program reads every entry up to that end, within the transcript Core
/// admits, decides the match there, and refuses any entry after it.
#[test]
fn a_registered_program_decides_the_longest_match_its_rules_allow() {
    let set = match wildstate_duel::vectors::DuelVectorSetV1::decode(wildstate_duel::VECTORS_V1) {
        Ok(set) => set,
        Err(e) => panic!("the frozen vectors: {e}"),
    };
    let Some(vector) = set.vectors.first() else {
        panic!("the frozen set holds a vector");
    };
    let setup = wildstate_duel::DuelSetupV1 {
        program: WildstateDuel.id(),
        body: vector.body.clone(),
    }
    .encode();
    let longest_move = vec![0xFFu8; dsm::sofi::wire::TRANSCRIPT_MAX_MOVE_BYTES];
    let turns = dsm::sofi::wire::TRANSCRIPT_MAX_ENTRIES / 4;
    let opened = opened_of_turns(&vec![
        wildstate_duel::DuelOpenedTurnV1 {
            a: longest_move.clone(),
            b: longest_move,
        };
        turns
    ]);
    let decided = (1..=opened.len()).find(|&n| {
        matches!(
            WildstateDuel.outcome(&setup, &opened[..n]),
            Ok(ProgramOutcome::Done(_))
        )
    });
    let Some(ended) = decided else {
        panic!("no match of passes is decided within the transcript Core admits");
    };
    let cap = usize::from(wildstate_duel::TABLES.constants.turn_cap);
    assert_eq!(ended, cap * 2, "only the turn cap ends a match of passes");
    for n in 1..ended {
        assert!(
            matches!(
                WildstateDuel.outcome(&setup, &opened[..n]),
                Ok(ProgramOutcome::Incomplete)
            ),
            "the match of passes is undecided before its last turn: {n}"
        );
    }
    match WildstateDuel.outcome(&setup, &opened[..ended + 1]) {
        Err(fault) => assert!(
            fault.reason.contains("follows the end of the match"),
            "an entry after the end is refused as one: {}",
            fault.reason
        ),
        other => panic!("an entry after the end is refused: {other:?}"),
    }
}
