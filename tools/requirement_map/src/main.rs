// SPDX-License-Identifier: MIT OR Apache-2.0
//! requirement_map: the DSM backend's function-level call graph, read from a
//! rust-analyzer SCIP index and content-hashed with BLAKE3.
//!
//!   requirement_map fingerprint --root <repo> --files <list> --out <file>
//!       the BLAKE3 hash of every listed source file (one repository path per
//!       line), taken before the index is built
//!   requirement_map index --scip <index.scip> --root <repo> --files <list>
//!                         --fingerprint <file> --out <dir>
//!       refuses when the tree is no longer the one fingerprinted (the index
//!       would describe other code); writes <dir>/defs.tsv, <dir>/edges.tsv and
//!       <dir>/files.tsv (every listed file's hash and whether the index maps
//!       its symbols)

mod graph;
mod hashing;
mod index;
mod symbols;
mod tokens;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage:\n  requirement_map fingerprint --root <repo> --files <list> --out <file>\n  requirement_map index --scip <index.scip> --root <repo> --files <list> --fingerprint <file> --out <dir>";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(&args) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("requirement_map: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: &[String]) -> Result<String, String> {
    let (command, rest) = args.split_first().ok_or_else(|| USAGE.to_string())?;
    let flags = flags(rest)?;
    let flag = |name: &str| -> Result<&Path, String> {
        flags
            .get(name)
            .map(Path::new)
            .ok_or_else(|| format!("{command} needs {name}\n{USAGE}"))
    };
    match command.as_str() {
        "fingerprint" => {
            let (tree, _) = fingerprint(flag("--root")?, flag("--files")?)?;
            let out = flag("--out")?;
            std::fs::write(out, format!("{tree}\n"))
                .map_err(|e| format!("{}: {e}", out.display()))?;
            Ok(format!("tree {tree}"))
        }
        "index" => index_command(
            flag("--scip")?,
            flag("--root")?,
            flag("--files")?,
            flag("--fingerprint")?,
            flag("--out")?,
        ),
        other => Err(format!("unknown command {other:?}\n{USAGE}")),
    }
}

fn flags(rest: &[String]) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    for pair in rest.chunks(2) {
        match pair {
            [name, value] if name.starts_with("--") => {
                out.insert(name.clone(), value.clone());
            }
            other => return Err(format!("expected --flag value, found {other:?}\n{USAGE}")),
        }
    }
    Ok(out)
}

fn cell(value: &str) -> Result<&str, String> {
    if value.contains(['\t', '\n']) {
        return Err(format!("{value:?} holds a tab or a newline"));
    }
    Ok(value)
}

/// The tree hash over every listed file, and each file's own hash.
fn fingerprint(
    root: &Path,
    list: &Path,
) -> Result<(String, Vec<(String, hashing::Digest)>), String> {
    let listed = std::fs::read_to_string(list).map_err(|e| format!("{}: {e}", list.display()))?;
    let mut files = Vec::new();
    for path in listed.lines().filter(|l| !l.is_empty()) {
        let bytes = std::fs::read(root.join(path)).map_err(|e| format!("{path}: {e}"))?;
        files.push((
            path.to_string(),
            hashing::hash(hashing::FILE, &[path.as_bytes(), &bytes]),
        ));
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    for (path, digest) in &files {
        parts.push(path.as_bytes());
        parts.push(digest);
    }
    Ok((hashing::text(&hashing::hash(hashing::TREE, &parts)), files))
}

fn index_command(
    scip: &Path,
    root: &Path,
    list: &Path,
    fingerprint_file: &Path,
    out: &Path,
) -> Result<String, String> {
    let recorded = std::fs::read_to_string(fingerprint_file)
        .map_err(|e| format!("{}: {e}", fingerprint_file.display()))?;
    let (tree, files) = fingerprint(root, list)?;
    if recorded.trim() != tree {
        return Err(format!(
            "the index was built from another tree: {} says {}, the tree is {tree}; rebuild the index",
            fingerprint_file.display(),
            recorded.trim()
        ));
    }
    let bytes = std::fs::read(scip).map_err(|e| format!("{}: {e}", scip.display()))?;
    let mut loaded = index::load(&bytes)?;
    let graph = graph::build(root, &mut loaded)?;
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;

    let mut definitions: Vec<&index::Definition> = loaded.definitions.iter().collect();
    definitions.sort_by(|a, b| (&a.file, a.start, &a.symbol).cmp(&(&b.file, b.start, &b.symbol)));
    let mut defs = String::from(
        "symbol\tkind\tname\tcontainer\ttrait\tfile\tstart_line\tend_line\titem\tclosure\treached\troot\ttested\tunlinked\n",
    );
    for d in &definitions {
        let node = graph
            .nodes
            .get(&d.symbol)
            .ok_or_else(|| format!("{} has no node", d.symbol))?;
        let reached = if node.reached { "1" } else { "0" };
        let tested = if node.tested { "1" } else { "0" };
        let unlinked = if node.unlinked { "1" } else { "0" };
        let row = [
            cell(&d.symbol)?,
            d.item.kind.label(),
            cell(&d.item.name)?,
            cell(&d.item.container)?,
            cell(&d.item.trait_name)?,
            cell(&d.file)?,
            &(d.start.line + 1).to_string(),
            &(d.end.line + 1).to_string(),
            &hashing::text(&node.item),
            &hashing::text(&node.closure),
            reached,
            match node.root {
                Some(kind) => kind,
                None => "-",
            },
            tested,
            unlinked,
        ]
        .join("\t");
        defs.push_str(&row);
        defs.push('\n');
    }
    let mut edges = String::from("from\tto\tkind\n");
    for (from, to, kind) in &loaded.edges {
        edges.push_str(&format!("{}\t{}\t{kind}\n", cell(from)?, cell(to)?));
    }
    let write = |name: &str, body: &str| -> Result<(), String> {
        let path = out.join(name);
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))
    };
    write("defs.tsv", &defs)?;
    write("edges.tsv", &edges)?;

    let roots = graph.nodes.values().filter(|n| n.root.is_some()).count();
    let reached = graph.nodes.values().filter(|n| n.reached).count();
    let mut summary = format!(
        "{} definitions of {} symbols, {} edges, {} production roots, {} symbols reached from them",
        definitions.len(),
        graph.nodes.len(),
        loaded.edges.len(),
        roots,
        reached
    );
    let mut per_file: BTreeMap<&str, usize> = BTreeMap::new();
    for d in &definitions {
        *per_file.entry(d.file.as_str()).or_default() += 1;
    }
    let mut table = String::from("path\tfile\tindexed\tdefinitions\n");
    for (path, digest) in &files {
        let indexed = if loaded.documents.contains(path) {
            "1"
        } else {
            "0"
        };
        let defined = match per_file.get(path.as_str()) {
            Some(n) => n.to_string(),
            None => "0".to_string(),
        };
        table.push_str(&format!(
            "{}\t{}\t{indexed}\t{defined}\n",
            cell(path)?,
            hashing::text(digest)
        ));
    }
    write("files.tsv", &table)?;
    summary.push_str(&format!(
        ", {} source files hashed, tree {tree}",
        files.len()
    ));
    Ok(summary)
}
