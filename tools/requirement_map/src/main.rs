// SPDX-License-Identifier: MIT OR Apache-2.0
//! requirement_map: the DSM backend's function-level call graph, read from a
//! rust-analyzer SCIP index and content-hashed with BLAKE3, and the seals
//! that lock each conformance finding to the code it describes.
//!
//!   requirement_map index --scip <index.scip> --root <repo> --out <dir>
//!       writes <dir>/defs.tsv and <dir>/edges.tsv
//!   requirement_map seal --map <dir> --rows <rows.tsv> --out <seals.tsv>

mod graph;
mod hashing;
mod index;
mod seal;
mod symbols;
mod tokens;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

const USAGE: &str = "usage:\n  requirement_map index --scip <index.scip> --root <repo> --out <dir>\n  requirement_map seal --map <dir> --rows <rows.tsv> --out <seals.tsv>";

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
        "index" => index_command(flag("--scip")?, flag("--root")?, flag("--out")?),
        "seal" => seal::command(flag("--map")?, flag("--rows")?, flag("--out")?),
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

fn index_command(scip: &Path, root: &Path, out: &Path) -> Result<String, String> {
    let bytes = std::fs::read(scip).map_err(|e| format!("{}: {e}", scip.display()))?;
    let mut loaded = index::load(&bytes)?;
    let graph = graph::build(
        root,
        &loaded.definitions,
        &mut loaded.edges,
        &loaded.unlinked,
    )?;
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
            node.root,
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

    let roots = graph.nodes.values().filter(|n| n.root != "-").count();
    let reached = graph.nodes.values().filter(|n| n.reached).count();
    Ok(format!(
        "{} definitions of {} symbols, {} edges, {} production roots, {} symbols reached from them",
        definitions.len(),
        graph.nodes.len(),
        loaded.edges.len(),
        roots,
        reached
    ))
}
