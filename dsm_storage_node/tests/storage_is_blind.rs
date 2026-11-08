// SPDX-License-Identifier: Apache-2.0
//! The storage node holds bytes and decides nothing (storage spec §1, §12):
//! it holds no signing key and signs nothing (MR-DSM-0051); it decides no
//! ownership, validates no burn, holds no mint or Bitcoin key and chooses no
//! successor (MR-STOR-0011); and it knows nothing of SoFi (MR-SOFI-0286).
//!
//! Every production item under `src/` is parsed — paths, `use` trees, method
//! calls, string literals and unparsed macro bodies — and held to three
//! rules. The node names only the Core modules that frame and address bytes:
//! cell and object addressing, its own ByteCommit tree, the storage set's id,
//! the domain-separated hasher, the wire types and the size bounds. It calls
//! nothing that signs. It names no application, economic or settlement
//! concept. The scanner is checked against injected sources of each kind
//! first, so a gate that finds nothing is a gate that would have found it.

mod common;

use proc_macro2::{TokenStream, TokenTree};
use std::path::{Path, PathBuf};
use syn::visit::Visit;

/// The Core modules that frame and address bytes, which a node may name.
const FRAMING: &[&str] = &["storage_cell", "storage_object", "merkle", "types", "utils"];

/// Whether the Core path `dsm::<rest>` is one a storage node may name: the
/// framing modules; the storage set's id and members; the domain-separated
/// hasher; and a size bound of the route-chain and spool modules, which
/// names no function either computes.
fn core_path_allowed(rest: &[String]) -> bool {
    let at = |i: usize| rest.get(i).map(String::as_str);
    let (module, item) = (at(0), at(1));
    let a_bound = item.is_some_and(|i| i.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
    module.is_some_and(|m| FRAMING.contains(&m))
        || (module == Some("ccb")
            && item.is_some_and(|i| ["storage_set_id", "StorageSetMembers"].contains(&i)))
        || (module == Some("crypto") && item == Some("domain"))
        || (matches!(module, Some("route_chain" | "spool")) && rest.len() == 2 && a_bound)
}

/// Names of application, economic and settlement concepts: what a node that
/// decided anything would have to name.
const APPLICATION: &[&str] = &[
    "economic",
    "token",
    "token_policy",
    "native_reserve",
    "bitcoin",
    "btc",
    "dlv",
    "mint",
    "burn",
    "TraderPrecommit",
    "TraderFulfillment",
    "DlvPolicyFulfillment",
    "ConditionalSofi",
    "SofiResolutionClaim",
    "FulfillmentRegistered",
    "RouteValidation",
    "ConsumedRoute",
    "check_fulfillment_against_precommit",
    "canonical_legs",
    "recompute_e",
    "resolution_claim",
    "evaluate",
    "advance_validated",
];

#[derive(Default)]
struct Forbidden {
    found: Vec<String>,
}

impl Forbidden {
    fn segments(&mut self, segments: &[String]) {
        if let [first, rest @ ..] = segments {
            if first == "dsm" && !core_path_allowed(rest) {
                self.found
                    .push(format!("Core module {}", segments.join("::")));
            }
        }
        for name in segments {
            self.name(name);
        }
    }

    fn name(&mut self, name: &str) {
        let lower = name.to_ascii_lowercase();
        if lower.contains("sofi") || APPLICATION.contains(&name) {
            self.found.push(format!("application name {name}"));
        }
        if lower.contains("sphincs") || lower == "sign" || lower.starts_with("sign_") {
            self.found.push(format!("signing {name}"));
        }
    }
}

fn cfg_gated(attrs: &[syn::Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("cfg"))
}

fn use_paths(tree: &syn::UseTree, prefix: Vec<String>, out: &mut Vec<Vec<String>>) {
    match tree {
        syn::UseTree::Path(step) => {
            let mut next = prefix;
            next.push(step.ident.to_string());
            use_paths(&step.tree, next, out);
        }
        syn::UseTree::Name(leaf) => {
            let mut full = prefix;
            full.push(leaf.ident.to_string());
            out.push(full);
        }
        syn::UseTree::Rename(leaf) => {
            let mut full = prefix;
            full.push(leaf.ident.to_string());
            out.push(full);
        }
        syn::UseTree::Glob(_) => out.push(prefix),
        syn::UseTree::Group(group) => {
            for item in &group.items {
                use_paths(item, prefix.clone(), out);
            }
        }
    }
}

fn macro_tokens(stream: TokenStream, out: &mut Vec<String>) {
    for tree in stream {
        match tree {
            TokenTree::Group(group) => macro_tokens(group.stream(), out),
            TokenTree::Ident(ident) => out.push(ident.to_string()),
            TokenTree::Punct(punct) => out.push(punct.as_char().to_string()),
            TokenTree::Literal(literal) => out.push(literal.to_string()),
        }
    }
}

impl<'ast> Visit<'ast> for Forbidden {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            _ => &[],
        };
        if !cfg_gated(attrs) {
            syn::visit::visit_item(self, item);
        }
    }

    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        if !cfg_gated(&item.attrs) {
            syn::visit::visit_impl_item_fn(self, item);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        self.segments(&segments);
        syn::visit::visit_path(self, path);
    }

    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        let mut paths = Vec::new();
        use_paths(&item.tree, Vec::new(), &mut paths);
        for path in paths {
            self.segments(&path);
        }
    }

    fn visit_expr_method_call(&mut self, call: &'ast syn::ExprMethodCall) {
        self.name(&call.method.to_string());
        syn::visit::visit_expr_method_call(self, call);
    }

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        if lit.value().to_ascii_lowercase().contains("sofi") {
            self.found
                .push(format!("application route or name {:?}", lit.value()));
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let mut flat = Vec::new();
        macro_tokens(mac.tokens.clone(), &mut flat);
        for run in flat.split(|t| t != ":" && !t.chars().all(|c| c.is_alphanumeric() || c == '_')) {
            let segments: Vec<String> = run.iter().filter(|t| *t != ":").cloned().collect();
            self.segments(&segments);
        }
        for token in &flat {
            if token.starts_with('"') && token.to_ascii_lowercase().contains("sofi") {
                self.found
                    .push(format!("application route or name {token}"));
            }
        }
        syn::visit::visit_macro(self, mac);
    }
}

fn forbidden(source: &str, context: &str) -> Vec<String> {
    let file = common::ok_or_panic(syn::parse_file(source), context);
    let mut scan = Forbidden::default();
    scan.visit_file(&file);
    scan.found
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

/// The negative control: each kind of dependency the node must not have is
/// found when injected, and what the node does name is not.
#[test]
fn the_scanner_finds_each_dependency_a_storage_node_must_not_have() {
    for (source, kind) in [
        ("use dsm::sofi::wire::TraderPrecommitBody;", "a SoFi type"),
        (
            "fn f() { dsm::economic::lineage::advance_validated(); }",
            "economic authority",
        ),
        (
            "fn f(k: &[u8]) { let _s = dsm::crypto::sphincs::sphincs_sign(k, b\"m\"); }",
            "a signature",
        ),
        ("fn f(key: &Key) { key.sign(b\"m\"); }", "a signing method"),
        ("fn f() { mint(); }", "a mint"),
        (
            "use dsm::core::token::token_state_manager::era_policy_commit;",
            "token ownership",
        ),
        ("const R: &str = \"/api/v2/sofi/fulfil\";", "a SoFi route"),
        (
            "fn f() { log::info!(\"{}\", dsm::bitcoin::exit()); }",
            "Bitcoin, inside a macro",
        ),
        (
            "fn f() { dsm::route_chain::evaluate(); }",
            "a successor choice",
        ),
    ] {
        assert!(
            !forbidden(source, kind).is_empty(),
            "the scanner misses {kind}: {source}"
        );
    }
    let allowed = "use dsm::storage_cell::entry_digest;\n\
                   const M: usize = dsm::route_chain::MAX_ENTRY_BYTES;\n\
                   fn f(p: &[(Vec<u8>, [u8; 32])]) { let _s = dsm::ccb::StorageSetMembers::new(p); }\n\
                   #[cfg(test)] mod tests { fn t() { dsm::crypto::kyber::kyber_decapsulate(); } }";
    assert_eq!(forbidden(allowed, "allowed"), Vec::<String>::new());
}

/// MR-DSM-0051, MR-STOR-0011, MR-SOFI-0286: no production source of the
/// storage node names an application, economic or settlement concept, calls
/// anything that signs, or names a Core module beyond those that frame and
/// address bytes.
///
/// MUTATION CONTROL: a production `dsm::crypto::sphincs::sphincs_sign` call,
/// a `use dsm::sofi` or a `/api/v2/sofi` route in the node turns this red.
#[test]
fn the_storage_node_signs_nothing_and_names_no_application_or_authority() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    sources(&src, &mut files);
    assert!(!files.is_empty(), "the node's sources are where they were");
    for path in files {
        let source = common::ok_or_panic(std::fs::read_to_string(&path), "read a node source");
        let found = forbidden(&source, &path.display().to_string());
        assert!(
            found.is_empty(),
            "{} has what a storage node must not: {found:?}",
            path.display()
        );
    }
}
