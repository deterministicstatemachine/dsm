// SPDX-License-Identifier: MIT OR Apache-2.0
//! What a source file's production code does, read with syn: every call by
//! its path, every method call, every field read, in the order they appear in
//! the source. Shared by the tests that hold production paths to the order,
//! the doors and the inputs of what they call.

use std::path::{Path, PathBuf};
use syn::{Attribute, Block, Expr, ImplItem, Item, Stmt, TraitItem};

/// One thing an expression does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// A call through a path: every segment, `["SystemTime", "now"]`.
    Call(Vec<String>),
    /// A method call, by the method's name.
    Method(String),
    /// A field read: the binding or field it is read from, when that is a
    /// name (`evidence` in `evidence.setups`), and the field's name.
    Field { base: Option<String>, name: String },
}

/// The source file at `path`, parsed.
pub fn parse(path: &Path) -> syn::File {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => panic!("read {}: {e}", path.display()),
    };
    match syn::parse_file(&text) {
        Ok(file) => file,
        Err(e) => panic!("parse {}: {e}", path.display()),
    }
}

/// `rel`, under this crate's `src`, parsed.
pub fn sdk_source(rel: &str) -> syn::File {
    parse(
        &PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("src")
            .join(rel),
    )
}

/// Core's source directory.
pub fn core_src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../dsm/src")
}

/// Every `.rs` file under `dir`, in a stable order.
pub fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(next) = pending.pop() {
        let entries = match std::fs::read_dir(&next) {
            Ok(entries) => entries,
            Err(e) => panic!("read {}: {e}", next.display()),
        };
        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(e) => panic!("an entry of {}: {e}", next.display()),
            };
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// Whether an item is compiled only under a `cfg` (tests, features).
pub fn cfg_gated(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("cfg"))
}

/// Every production function body in `file` — free functions, methods,
/// trait default methods, and those of inline modules — with the name it is
/// defined under, skipping every item under a `cfg` attribute.
pub fn production_fns(file: &syn::File) -> Vec<(String, Block)> {
    let mut out = Vec::new();
    collect_fns(&file.items, &mut out);
    out
}

fn collect_fns(items: &[Item], out: &mut Vec<(String, Block)>) {
    for item in items {
        match item {
            Item::Fn(f) if !cfg_gated(&f.attrs) => {
                out.push((f.sig.ident.to_string(), (*f.block).clone()));
            }
            Item::Impl(i) if !cfg_gated(&i.attrs) => {
                for inner in &i.items {
                    if let ImplItem::Fn(f) = inner {
                        if !cfg_gated(&f.attrs) {
                            out.push((f.sig.ident.to_string(), f.block.clone()));
                        }
                    }
                }
            }
            Item::Trait(t) if !cfg_gated(&t.attrs) => {
                for inner in &t.items {
                    if let TraitItem::Fn(f) = inner {
                        if let Some(block) = f.default.as_ref().filter(|_| !cfg_gated(&f.attrs)) {
                            out.push((f.sig.ident.to_string(), block.clone()));
                        }
                    }
                }
            }
            Item::Mod(m) if !cfg_gated(&m.attrs) => {
                if let Some((_, inner)) = &m.content {
                    collect_fns(inner, out);
                }
            }
            _ => {}
        }
    }
}

/// The production function `name` in `file`.
pub fn production_fn(file: &syn::File, name: &str) -> Block {
    let found = production_fns(file)
        .into_iter()
        .find_map(|(defined, block)| (defined == name).then_some(block));
    let Some(block) = found else {
        panic!("no production fn {name}");
    };
    block
}

/// Everything `block` does, in the order it appears in the source.
pub fn events(block: &Block) -> Vec<Event> {
    let mut out = Vec::new();
    block_events(block, &mut out);
    out
}

/// Every call in `block` by the name it calls, in the order they appear in
/// the source: a function by the last segment of its path (`sign_release`),
/// a method with a leading dot (`.advance`), so a store function and a head
/// transition that share a name stay apart.
pub fn calls_in_order(block: &Block) -> Vec<String> {
    events(block)
        .into_iter()
        .filter_map(|event| match event {
            Event::Call(path) => path.last().cloned(),
            Event::Method(name) => Some(format!(".{name}")),
            Event::Field { .. } => None,
        })
        .collect()
}

fn block_events(block: &Block, out: &mut Vec<Event>) {
    for stmt in &block.stmts {
        match stmt {
            Stmt::Local(local) => {
                if let Some(init) = &local.init {
                    expr_events(&init.expr, out);
                    if let Some((_, diverge)) = &init.diverge {
                        expr_events(diverge, out);
                    }
                }
            }
            Stmt::Expr(expr, _) => expr_events(expr, out),
            Stmt::Item(_) | Stmt::Macro(_) => {}
        }
    }
}

fn expr_events(expr: &Expr, out: &mut Vec<Event>) {
    match expr {
        Expr::Call(call) => {
            match &*call.func {
                Expr::Path(path) => out.push(Event::Call(
                    path.path
                        .segments
                        .iter()
                        .map(|s| s.ident.to_string())
                        .collect(),
                )),
                other => expr_events(other, out),
            }
            for arg in &call.args {
                expr_events(arg, out);
            }
        }
        Expr::MethodCall(call) => {
            expr_events(&call.receiver, out);
            out.push(Event::Method(call.method.to_string()));
            for arg in &call.args {
                expr_events(arg, out);
            }
        }
        Expr::Field(e) => {
            expr_events(&e.base, out);
            if let syn::Member::Named(name) = &e.member {
                let base = match &*e.base {
                    Expr::Path(path) => path.path.segments.last().map(|s| s.ident.to_string()),
                    Expr::Field(inner) => match &inner.member {
                        syn::Member::Named(field) => Some(field.to_string()),
                        syn::Member::Unnamed(..) => None,
                    },
                    _ => None,
                };
                out.push(Event::Field {
                    base,
                    name: name.to_string(),
                });
            }
        }
        Expr::Try(e) => expr_events(&e.expr, out),
        Expr::Await(e) => expr_events(&e.base, out),
        Expr::Paren(e) => expr_events(&e.expr, out),
        Expr::Reference(e) => expr_events(&e.expr, out),
        Expr::Unary(e) => expr_events(&e.expr, out),
        Expr::Cast(e) => expr_events(&e.expr, out),
        Expr::Binary(e) => {
            expr_events(&e.left, out);
            expr_events(&e.right, out);
        }
        Expr::Assign(e) => {
            expr_events(&e.left, out);
            expr_events(&e.right, out);
        }
        Expr::Let(e) => expr_events(&e.expr, out),
        Expr::Return(e) => {
            if let Some(inner) = &e.expr {
                expr_events(inner, out);
            }
        }
        Expr::Break(e) => {
            if let Some(inner) = &e.expr {
                expr_events(inner, out);
            }
        }
        Expr::Closure(e) => expr_events(&e.body, out),
        Expr::Block(e) => block_events(&e.block, out),
        Expr::Async(e) => block_events(&e.block, out),
        Expr::Unsafe(e) => block_events(&e.block, out),
        Expr::Loop(e) => block_events(&e.body, out),
        Expr::While(e) => {
            expr_events(&e.cond, out);
            block_events(&e.body, out);
        }
        Expr::ForLoop(e) => {
            expr_events(&e.expr, out);
            block_events(&e.body, out);
        }
        Expr::If(e) => {
            expr_events(&e.cond, out);
            block_events(&e.then_branch, out);
            if let Some((_, otherwise)) = &e.else_branch {
                expr_events(otherwise, out);
            }
        }
        Expr::Match(e) => {
            expr_events(&e.expr, out);
            for arm in &e.arms {
                if let Some((_, guard)) = &arm.guard {
                    expr_events(guard, out);
                }
                expr_events(&arm.body, out);
            }
        }
        Expr::Struct(e) => {
            for field in &e.fields {
                expr_events(&field.expr, out);
            }
            if let Some(rest) = &e.rest {
                expr_events(rest, out);
            }
        }
        Expr::Tuple(e) => {
            for elem in &e.elems {
                expr_events(elem, out);
            }
        }
        Expr::Array(e) => {
            for elem in &e.elems {
                expr_events(elem, out);
            }
        }
        Expr::Index(e) => {
            expr_events(&e.expr, out);
            expr_events(&e.index, out);
        }
        Expr::Range(e) => {
            if let Some(start) = &e.start {
                expr_events(start, out);
            }
            if let Some(end) = &e.end {
                expr_events(end, out);
            }
        }
        _ => {}
    }
}
