// SPDX-License-Identifier: MIT OR Apache-2.0

//! A panic that unwinds across an `extern "system"` JNI export is undefined
//! behaviour, and on Android it aborts the app. Every export therefore runs
//! its work inside a panic guard: the bridge's `jni_catch_unwind_*` helpers,
//! or the standard library's panic catcher (`std::panic`) where an export
//! recovers by hand. The exports compile only for Android, so this reads
//! their source: the first statement of each, after it renames its raw
//! parameters, is the guard.

use std::path::Path;

use syn::{Expr, Item, ItemFn, Stmt};

/// Whether `expr` is a call of a panic guard, directly or as what a `match`
/// decides on.
fn is_guard_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Match(decided) if is_guard_call(&decided.expr))
        || matches!(
            expr,
            Expr::Call(call) if matches!(call.func.as_ref(), Expr::Path(path) if is_guard_path(path))
        )
}

/// Whether `path` names a panic guard: a `jni_catch_unwind_*` helper of the
/// bridge, or a function of `std::panic` (its panic catcher).
fn is_guard_path(path: &syn::ExprPath) -> bool {
    let names: Vec<String> = path
        .path
        .segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect();
    (names.len() == 3 && names[0] == "std" && names[1] == "panic")
        || names
            .last()
            .is_some_and(|last| last.starts_with("jni_catch_unwind_"))
}

/// The expression of the export's first statement past its parameter
/// renames: the export's work, or the guard it runs inside.
fn first_work(export: &ItemFn) -> Option<&Expr> {
    let first = export.block.stmts.iter().find(|stmt| {
        !matches!(
            stmt,
            Stmt::Local(local) if local
                .init
                .as_ref()
                .is_some_and(|init| matches!(init.expr.as_ref(), Expr::Path(_)))
        )
    })?;
    match first {
        Stmt::Expr(expr, _) => Some(expr),
        Stmt::Local(local) => local.init.as_ref().map(|init| init.expr.as_ref()),
        Stmt::Item(_) | Stmt::Macro(_) => None,
    }
}

/// SA-51. `clearPendingRecoveryCapsule` and `maybeRefreshNfcCapsule` ran
/// their work outside any guard. Every Java export runs inside one now.
/// MUTATION CONTROL: taking either export's work out of its guard turns
/// this red.
#[test]
fn every_java_export_runs_its_work_inside_the_unwind_guard(
) -> Result<(), Box<dyn std::error::Error>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/jni");
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().is_some_and(|ext| ext == "rs") {
            sources.push(path);
        }
    }
    sources.sort();

    let mut exports = Vec::new();
    let mut unguarded = Vec::new();
    for path in sources {
        let text = std::fs::read_to_string(&path)?;
        let file = syn::parse_file(&text)?;
        for item in &file.items {
            let Item::Fn(export) = item else { continue };
            let name = export.sig.ident.to_string();
            let is_jni = export
                .sig
                .abi
                .as_ref()
                .and_then(|abi| abi.name.as_ref())
                .is_some_and(|abi| abi.value() == "system");
            if !is_jni || !name.starts_with("Java_") {
                continue;
            }
            if !first_work(export).is_some_and(is_guard_call) {
                unguarded.push(name.clone());
            }
            exports.push(name);
        }
    }

    for named in [
        "Java_com_dsm_wallet_bridge_UnifiedNativeApi_clearPendingRecoveryCapsule",
        "Java_com_dsm_wallet_bridge_UnifiedNativeApi_maybeRefreshNfcCapsule",
    ] {
        assert!(exports.iter().any(|e| e == named), "{named} is not found");
    }
    assert_eq!(
        unguarded,
        Vec::<String>::new(),
        "of {} exports",
        exports.len()
    );
    Ok(())
}
