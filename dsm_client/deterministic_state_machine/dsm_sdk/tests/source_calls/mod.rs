// SPDX-License-Identifier: MIT OR Apache-2.0
//! The calls a source file makes, read with syn: every call and method call
//! by the name it calls, in the order it appears in the source. Shared by the
//! tests that hold a production path to the order or the doors of its calls.

use std::path::PathBuf;
use syn::{Attribute, Block, Expr, ImplItem, Item, Stmt};

/// `rel`, under this crate's `src`, parsed.
pub fn sdk_source(rel: &str) -> syn::File {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("src")
        .join(rel);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(e) => panic!("read {}: {e}", path.display()),
    };
    match syn::parse_file(&text) {
        Ok(file) => file,
        Err(e) => panic!("parse {}: {e}", path.display()),
    }
}

fn test_only(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("cfg"))
}

/// Every production function body in `file` — free functions and methods,
/// skipping every item under a `cfg` attribute — with the name it is
/// defined under.
pub fn production_fns(file: &syn::File) -> Vec<(String, Block)> {
    let mut out = Vec::new();
    for item in &file.items {
        match item {
            Item::Fn(f) if !test_only(&f.attrs) => {
                out.push((f.sig.ident.to_string(), (*f.block).clone()));
            }
            Item::Impl(i) if !test_only(&i.attrs) => {
                for inner in &i.items {
                    if let ImplItem::Fn(f) = inner {
                        if !test_only(&f.attrs) {
                            out.push((f.sig.ident.to_string(), f.block.clone()));
                        }
                    }
                }
            }
            _ => {}
        }
    }
    out
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

/// Every call in `block` by the name it calls, in the order they appear in
/// the source: a function by the last segment of its path (`sign_release`),
/// a method with a leading dot (`.advance`), so a store function and a head
/// transition that share a name stay apart.
pub fn calls_in_order(block: &Block) -> Vec<String> {
    let mut out = Vec::new();
    for stmt in &block.stmts {
        stmt_calls(stmt, &mut out);
    }
    out
}

fn stmt_calls(stmt: &Stmt, out: &mut Vec<String>) {
    match stmt {
        Stmt::Local(local) => {
            if let Some(init) = &local.init {
                expr_calls(&init.expr, out);
                if let Some((_, diverge)) = &init.diverge {
                    expr_calls(diverge, out);
                }
            }
        }
        Stmt::Expr(expr, _) => expr_calls(expr, out),
        Stmt::Item(_) | Stmt::Macro(_) => {}
    }
}

fn expr_calls(expr: &Expr, out: &mut Vec<String>) {
    match expr {
        Expr::Call(call) => {
            if let Expr::Path(path) = &*call.func {
                if let Some(last) = path.path.segments.last() {
                    out.push(last.ident.to_string());
                }
            }
            for arg in &call.args {
                expr_calls(arg, out);
            }
        }
        Expr::MethodCall(call) => {
            expr_calls(&call.receiver, out);
            out.push(format!(".{}", call.method));
            for arg in &call.args {
                expr_calls(arg, out);
            }
        }
        Expr::Try(e) => expr_calls(&e.expr, out),
        Expr::Await(e) => expr_calls(&e.base, out),
        Expr::Paren(e) => expr_calls(&e.expr, out),
        Expr::Reference(e) => expr_calls(&e.expr, out),
        Expr::Field(e) => expr_calls(&e.base, out),
        Expr::Unary(e) => expr_calls(&e.expr, out),
        Expr::Cast(e) => expr_calls(&e.expr, out),
        Expr::Binary(e) => {
            expr_calls(&e.left, out);
            expr_calls(&e.right, out);
        }
        Expr::Assign(e) => {
            expr_calls(&e.left, out);
            expr_calls(&e.right, out);
        }
        Expr::Let(e) => expr_calls(&e.expr, out),
        Expr::Return(e) => {
            if let Some(inner) = &e.expr {
                expr_calls(inner, out);
            }
        }
        Expr::Break(e) => {
            if let Some(inner) = &e.expr {
                expr_calls(inner, out);
            }
        }
        Expr::Closure(e) => expr_calls(&e.body, out),
        Expr::Block(e) => out.extend(calls_in_order(&e.block)),
        Expr::Async(e) => out.extend(calls_in_order(&e.block)),
        Expr::Unsafe(e) => out.extend(calls_in_order(&e.block)),
        Expr::Loop(e) => out.extend(calls_in_order(&e.body)),
        Expr::While(e) => {
            expr_calls(&e.cond, out);
            out.extend(calls_in_order(&e.body));
        }
        Expr::ForLoop(e) => {
            expr_calls(&e.expr, out);
            out.extend(calls_in_order(&e.body));
        }
        Expr::If(e) => {
            expr_calls(&e.cond, out);
            out.extend(calls_in_order(&e.then_branch));
            if let Some((_, otherwise)) = &e.else_branch {
                expr_calls(otherwise, out);
            }
        }
        Expr::Match(e) => {
            expr_calls(&e.expr, out);
            for arm in &e.arms {
                if let Some((_, guard)) = &arm.guard {
                    expr_calls(guard, out);
                }
                expr_calls(&arm.body, out);
            }
        }
        Expr::Struct(e) => {
            for field in &e.fields {
                expr_calls(&field.expr, out);
            }
        }
        Expr::Tuple(e) => {
            for elem in &e.elems {
                expr_calls(elem, out);
            }
        }
        Expr::Array(e) => {
            for elem in &e.elems {
                expr_calls(elem, out);
            }
        }
        Expr::Index(e) => {
            expr_calls(&e.expr, out);
            expr_calls(&e.index, out);
        }
        _ => {}
    }
}
