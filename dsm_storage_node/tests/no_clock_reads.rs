// SPDX-License-Identifier: Apache-2.0
//! No storage-node source reads a clock or runs a timer: ordering inside a
//! node is its arrival sequence, and a cycle closes when asked, never on a
//! schedule (storage spec §1 rule 4, §14). Every file under `src/` is parsed:
//! paths and `use` trees are read whole, so a grouped or renamed import is
//! seen, and an unparsed macro body is read token by token. A name in a
//! comment or a string never counts. Bounding how long a client waits for a
//! set-mate is a `Duration` handed to the HTTP client; it reads nothing.

mod common;

use proc_macro2::{TokenStream, TokenTree};
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use syn::UseTree;

/// Names only a clock read, a timestamp or a timer needs.
const CLOCK_NAMES: [&str; 4] = ["Instant", "SystemTime", "UNIX_EPOCH", "chrono"];

#[derive(Default)]
struct Clocks {
    found: Vec<String>,
}

impl Clocks {
    fn path(&mut self, segments: &[String]) {
        for name in segments {
            if CLOCK_NAMES.contains(&name.as_str()) {
                self.found.push(name.clone());
            }
        }
        if segments
            .windows(2)
            .any(|pair| pair[0] == "tokio" && pair[1] == "time")
        {
            self.found.push("tokio::time".to_string());
        }
    }
}

/// Every full path a `use` tree brings into scope. A glob ends at its
/// prefix, so `use tokio::*` is the path `tokio`, which brings `time` in.
fn use_paths(tree: &UseTree, prefix: Vec<String>, out: &mut Vec<Vec<String>>) {
    match tree {
        UseTree::Path(step) => {
            let mut next = prefix;
            next.push(step.ident.to_string());
            use_paths(&step.tree, next, out);
        }
        UseTree::Name(leaf) => {
            let mut full = prefix;
            full.push(leaf.ident.to_string());
            out.push(full);
        }
        UseTree::Rename(leaf) => {
            let mut full = prefix;
            full.push(leaf.ident.to_string());
            out.push(full);
        }
        UseTree::Glob(_) => {
            let mut full = prefix;
            if full == ["tokio"] {
                full.push("time".to_string());
            }
            out.push(full);
        }
        UseTree::Group(group) => {
            for item in &group.items {
                use_paths(item, prefix.clone(), out);
            }
        }
    }
}

/// A macro body's identifiers and punctuation in order, with every literal
/// as an empty token so nothing joins across it.
fn tokens(stream: TokenStream, out: &mut Vec<String>) {
    for tree in stream {
        match tree {
            TokenTree::Group(group) => tokens(group.stream(), out),
            TokenTree::Ident(ident) => out.push(ident.to_string()),
            TokenTree::Punct(punct) => out.push(punct.as_char().to_string()),
            TokenTree::Literal(_) => out.push(String::new()),
        }
    }
}

impl<'ast> Visit<'ast> for Clocks {
    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.path(&segments);
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        use_paths(&item.tree, Vec::new(), &mut paths);
        for path in paths {
            self.path(&path);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let mut flat = Vec::new();
        tokens(mac.tokens.clone(), &mut flat);
        let joined: Vec<String> = flat
            .split(|t| t == ":")
            .filter(|run| !run.is_empty())
            .flat_map(|run| run.iter().cloned())
            .collect();
        self.path(&joined);
        syn::visit::visit_macro(self, mac);
    }
}

fn sources(dir: &Path, found: &mut Vec<PathBuf>) {
    for entry in common::ok_or_panic(std::fs::read_dir(dir), "list a source directory") {
        let path = common::ok_or_panic(entry, "read a source directory entry").path();
        if path.is_dir() {
            sources(&path, found);
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            found.push(path);
        }
    }
}

fn clock_reads(source: &str, context: &str) -> Vec<String> {
    let file = common::ok_or_panic(syn::parse_file(source), context);
    let mut clocks = Clocks::default();
    clocks.visit_file(&file);
    clocks.found
}

#[test]
fn a_clock_read_is_found_and_a_comment_or_string_is_not() {
    let reads =
        "fn f() { let t = std::time::Instant::now(); log::info!(\"{:?}\", SystemTime::now()); }";
    assert_eq!(clock_reads(reads, "parse reads"), ["Instant", "SystemTime"]);
    let grouped = "use tokio::{sync::Mutex, time};";
    assert_eq!(
        clock_reads(grouped, "parse a grouped import"),
        ["tokio::time"]
    );
    let renamed = "use std::time::Instant as Tick; fn f() { Tick::now(); }";
    assert_eq!(clock_reads(renamed, "parse a renamed import"), ["Instant"]);
    let glob = "use tokio::*; fn f() { time::sleep(d); }";
    assert_eq!(clock_reads(glob, "parse a glob import"), ["tokio::time"]);
    let in_macro = "fn f() { tokio::select! { _ = tokio::time::sleep(d) => {} } }";
    assert_eq!(clock_reads(in_macro, "parse a macro body"), ["tokio::time"]);
    let quiet =
        "// Instant::now()\n/// SystemTime\nfn f() -> &'static str { \"tokio::time chrono\" }";
    assert_eq!(clock_reads(quiet, "parse quiet"), Vec::<String>::new());
}

#[test]
fn no_node_source_reads_a_clock() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    for expected in ["lib.rs", "main.rs", "api/transport/b0x.rs", "set_client.rs"] {
        assert!(files.contains(&root.join(expected)), "{expected} not swept");
    }
    let mut found = Vec::new();
    for file in &files {
        let source = common::ok_or_panic(std::fs::read_to_string(file), "read a node source");
        for name in clock_reads(&source, &file.display().to_string()) {
            found.push(format!("{}: {name}", file.display()));
        }
    }
    assert_eq!(
        found,
        Vec::<String>::new(),
        "node sources that read a clock"
    );
}
