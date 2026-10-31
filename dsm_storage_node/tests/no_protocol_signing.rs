// SPDX-License-Identifier: Apache-2.0
//! A storage node holds no protocol key and signs no protocol object (storage
//! spec §1 rule 1; owner decision, 2026-10-28: "Transport keys permitted,
//! protocol-signing keys prohibited. Build the CI gate. TLS authenticates
//! endpoints; nodes never sign DSM protocol objects.").
//!
//! The node's one private key is its TLS server key, which the TLS listener
//! loads from its configured path; nothing in the node's own code names it.
//! Every shipped source under `src/` is parsed, and none may name:
//! - any of DSM's cryptography but its hashing ([`HASHING`]): signing,
//!   key generation, key encapsulation and every key type live there;
//! - a signing library ([`SIGNING_CRATES`]), as a path or as a dependency;
//! - a signing call or a key, by name ([`signing_name`]), as a path, a method
//!   call or a token in a macro body.
//!
//! Paths and `use` trees are read whole, so a grouped or renamed import is
//! seen. A name in a comment or a string never counts, and an item compiled
//! only for tests is not shipped and is not read: a test module may play the
//! device that holds the keys.

mod common;

use proc_macro2::{TokenStream, TokenTree};
use std::path::{Path, PathBuf};
use syn::visit::Visit;
use syn::UseTree;

/// The modules of `dsm::crypto` a node may name: domain-separated hashing,
/// which content addressing needs. Nothing in them holds a key.
const HASHING: [&str; 3] = ["domain", "blake3", "hash"];

/// Libraries whose purpose is signing, or generating and holding signing
/// keys. TLS itself (`rustls`, `axum-server`) is the transport and is not
/// here; its key never enters the node's own code.
const SIGNING_CRATES: [&str; 16] = [
    "ed25519_dalek",
    "ed25519",
    "ecdsa",
    "p256",
    "p384",
    "k256",
    "rsa",
    "ring",
    "aws_lc_rs",
    "openssl",
    "rcgen",
    "pqcrypto",
    "pqcrypto_sphincsplus",
    "pqcrypto_traits",
    "sphincsplus",
    "signature",
];

/// Whether `name` names a signing call or a key.
fn signing_name(name: &str) -> bool {
    matches!(name, "sign" | "try_sign" | "sign_detached")
        || name.starts_with("sign_")
        || name.ends_with("_sign")
        || [
            "keypair",
            "KeyPair",
            "SecretKey",
            "secret_key",
            "Signer",
            "SigningKey",
        ]
        .iter()
        .any(|key| name.contains(key))
        || name.contains("decapsulate")
}

#[derive(Default)]
struct Signing {
    found: Vec<String>,
}

impl Signing {
    fn path(&mut self, segments: &[String]) {
        if let [root, module, rest @ ..] = segments {
            if root == "dsm" && module == "crypto" {
                match rest.first() {
                    Some(inner) if HASHING.contains(&inner.as_str()) => {}
                    Some(inner) => self.found.push(format!("dsm::crypto::{inner}")),
                    None => self.found.push("dsm::crypto".to_string()),
                }
            }
        }
        if let Some(root) = segments.first() {
            if SIGNING_CRATES.contains(&root.as_str()) {
                self.found.push(root.clone());
            }
        }
        for name in segments {
            if signing_name(name) {
                self.found.push(name.clone());
            }
        }
    }
}

/// Every full path a `use` tree brings into scope. A glob or a rename ends at
/// its prefix plus the name, so `use dsm::crypto::*` is the path
/// `dsm::crypto`, which brings every module of it in.
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
        UseTree::Glob(_) => out.push(prefix),
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

/// Whether an item is compiled only for tests (`#[cfg(test)]`, or a `cfg`
/// whose predicate names `test`).
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

impl<'ast> Visit<'ast> for Signing {
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        if !test_only(&item.attrs) {
            syn::visit::visit_item_mod(self, item);
        }
    }

    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        if !test_only(&item.attrs) {
            syn::visit::visit_item_fn(self, item);
        }
    }

    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        if !test_only(&item.attrs) {
            syn::visit::visit_item_impl(self, item);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.path(&segments);
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        if test_only(&item.attrs) {
            return;
        }
        let mut paths = Vec::new();
        use_paths(&item.tree, Vec::new(), &mut paths);
        for path in paths {
            self.path(&path);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        let method = call.method.to_string();
        if signing_name(&method) {
            self.found.push(method);
        }
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let mut flat = Vec::new();
        tokens(mac.tokens.clone(), &mut flat);
        for run in flat.split(|t| t.is_empty() || t == "(" || t == "," || t == ";") {
            let segments: Vec<String> = run.iter().filter(|t| *t != ":").cloned().collect();
            self.path(&segments);
        }
        syn::visit::visit_macro(self, mac);
    }
}

fn signing_in(source: &str, context: &str) -> Vec<String> {
    let file = common::ok_or_panic(syn::parse_file(source), context);
    let mut signing = Signing::default();
    signing.visit_file(&file);
    signing.found
}

/// The files of the modules `file` declares out of line for tests only
/// (`#[cfg(test)] mod name;`): `name.rs` or `name/mod.rs` beside a `lib.rs`,
/// `main.rs` or `mod.rs`, and under `file`'s own directory otherwise.
fn test_only_module_files(file: &Path, source: &str) -> Vec<PathBuf> {
    let parsed = common::ok_or_panic(syn::parse_file(source), &file.display().to_string());
    let dir = common::some_or_panic(file.parent(), "a source has a directory");
    let stem = common::some_or_panic(
        file.file_stem().and_then(|s| s.to_str()),
        "a source has a name",
    );
    let base = match stem {
        "lib" | "main" | "mod" => dir.to_path_buf(),
        own => dir.join(own),
    };
    parsed
        .items
        .iter()
        .filter_map(|item| match item {
            syn::Item::Mod(module) if module.content.is_none() && test_only(&module.attrs) => {
                Some(module.ident.to_string())
            }
            _ => None,
        })
        .flat_map(|name| {
            [
                base.join(format!("{name}.rs")),
                base.join(&name).join("mod.rs"),
            ]
        })
        .collect()
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

/// The crates a manifest's `[dependencies]` table names, with `-` read as
/// `_` the way a path names them. Dev-dependencies do not ship.
fn dependencies(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .skip_while(|line| line.trim() != "[dependencies]")
        .skip(1)
        .take_while(|line| !line.trim_start().starts_with('['))
        .filter_map(|line| {
            let line = line.trim();
            match line.split_once('=') {
                Some((name, _)) if !line.starts_with('#') => Some(name.trim().replace('-', "_")),
                _ => None,
            }
        })
        .collect()
}

#[test]
fn a_signing_path_is_found_and_a_comment_string_or_test_module_is_not() {
    let calls = "fn f(sk: &[u8]) { dsm::crypto::sphincs::sphincs_sign(sk, b\"m\"); }";
    assert_eq!(
        signing_in(calls, "parse a call"),
        ["dsm::crypto::sphincs", "sphincs_sign"]
    );
    let grouped = "use dsm::crypto::{domain::TaggedHashDomain, kyber};";
    assert_eq!(
        signing_in(grouped, "parse a grouped import"),
        ["dsm::crypto::kyber"]
    );
    let renamed = "use dsm::crypto as c; fn f() { c::sphincs::sign(v, k, m); }";
    assert_eq!(
        signing_in(renamed, "parse a renamed import"),
        ["dsm::crypto", "sign"]
    );
    let method = "fn f(key: &K) -> Vec<u8> { key.sign(b\"m\") }";
    assert_eq!(signing_in(method, "parse a method call"), ["sign"]);
    let library = "use ring::signature::Ed25519KeyPair;";
    assert_eq!(
        signing_in(library, "parse a library"),
        ["ring", "Ed25519KeyPair"]
    );
    let in_macro = "fn f() { log::info!(\"{:?}\", dsm::crypto::sphincs::generate_keypair(v)); }";
    assert_eq!(
        signing_in(in_macro, "parse a macro body"),
        ["dsm::crypto::sphincs", "generate_keypair"]
    );
    let quiet = "// dsm::crypto::sphincs::sign\n/// a KeyPair\n\
                 fn f() -> &'static str { \"sign_message\" }\n\
                 #[cfg(test)] mod tests { use dsm::crypto::kyber::KyberKeyPair; }\n\
                 fn g() { dsm::crypto::domain::TaggedHashDomain::new(); }";
    assert_eq!(signing_in(quiet, "parse quiet"), Vec::<String>::new());
    let manifest = "[package]\nname = \"n\"\n[dependencies]\n# ring = \"0\"\nrustls = \"0.23\"\n\
                    ed25519-dalek = \"2\"\n[dev-dependencies]\nrcgen = \"0.14\"\n";
    assert_eq!(dependencies(manifest), ["rustls", "ed25519_dalek"]);
}

/// MUTATION CONTROL: naming a signing call, a key type or any of DSM's
/// cryptography but its hashing in a shipped node source (for example
/// `dsm::crypto::sphincs::sphincs_sign` in `api/cells.rs`) turns this red.
#[test]
fn no_node_source_holds_a_protocol_key_or_signs() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&root, &mut files);
    for expected in [
        "lib.rs",
        "main.rs",
        "api/cells.rs",
        "api/transport/b0x.rs",
        "set_client.rs",
    ] {
        assert!(files.contains(&root.join(expected)), "{expected} not swept");
    }
    let read = |file: &PathBuf| -> String {
        common::ok_or_panic(std::fs::read_to_string(file), "read a node source")
    };
    let test_only_files: Vec<PathBuf> = files
        .iter()
        .flat_map(|file| test_only_module_files(file, &read(file)))
        .collect();
    assert!(
        test_only_files.contains(&root.join("db").join("test_store.rs")),
        "the test-only module files were not resolved"
    );
    let mut found = Vec::new();
    for file in files.iter().filter(|file| {
        !test_only_files
            .iter()
            .any(|test_only| *file == test_only || file.starts_with(test_only.with_extension("")))
    }) {
        for name in signing_in(&read(file), &file.display().to_string()) {
            found.push(format!("{}: {name}", file.display()));
        }
    }
    assert_eq!(
        found,
        Vec::<String>::new(),
        "node sources that hold a protocol key or sign"
    );
}

/// MUTATION CONTROL: adding a signing library to the node's
/// `[dependencies]` turns this red.
#[test]
fn the_node_depends_on_no_signing_library() {
    let manifest_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let manifest =
        common::ok_or_panic(std::fs::read_to_string(&manifest_path), "read the manifest");
    let named = dependencies(&manifest);
    for expected in ["rustls", "dsm", "axum_server"] {
        assert!(named.iter().any(|n| n == expected), "{expected} not read");
    }
    let signing: Vec<&String> = named
        .iter()
        .filter(|name| SIGNING_CRATES.contains(&name.as_str()))
        .collect();
    assert_eq!(
        signing,
        Vec::<&String>::new(),
        "signing libraries among the node's dependencies"
    );
}
