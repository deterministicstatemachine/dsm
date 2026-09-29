// SPDX-License-Identifier: MIT OR Apache-2.0
//! requirement_map: the DSM backend's function-level call graph, read from
//! rust-analyzer SCIP indexes of each shipped build and content-hashed with
//! BLAKE3.
//!
//!   requirement_map fingerprint --root <repo> --files <list> --inputs <list> --out <file>
//!       the BLAKE3 hash of every listed source file and every input the
//!       indexes depend on (configurations, lockfile, toolchain, analyzer
//!       version), taken before the indexes are built
//!   requirement_map index --root <repo> --files <list> --inputs <list> --fingerprint <file>
//!                         --android <scip> --android-log <log>
//!                         [--node <scip> --node-log <log>]
//!                         --tests <scip> --tests-log <log>
//!                         --android-features <tree> --android-features-indexed <tree>
//!                         [--node-features <tree> --node-features-indexed <tree>]
//!                         --jni-declarations <dir> [--unindexed-consumer <dir>]
//!                         --out <dir>
//!       refuses when the tree is no longer the one fingerprinted, when an
//!       index's log shows a failure or a line of no known kind, or when the
//!       definitions do not add up; writes defs.tsv, reach.tsv, edges.tsv,
//!       files.tsv, accounting.tsv, health.tsv and token-read.tsv, and prints
//!       the accounting.
//!   requirement_map fixture --root <fixture> --scip <scip> --log <log>
//!                           --jni-declarations <dir> --crate <src-prefix>
//!                           --package <name> [--features <tree> --features-indexed <tree>]
//!                           --expect <tsv> [--out <dir>]
//!       reads a fixture crate's index through the same loader, cfg
//!       evaluation and graph, as one artifact whose entry points the
//!       fixture's Kotlin declares; writes defs.tsv, reach.tsv and edges.tsv
//!       to `--out`; and refuses unless every reading `--expect` lists (key,
//!       state, code) comes out as listed. A key is a Rust path, or
//!       `@file:line name` for an item written inside a function; the state
//!       `absent` says the build compiles no such definition.

mod cfgs;
mod graph;
mod hashing;
mod index;
mod jni;
mod logs;
mod reach;
#[cfg(test)]
mod rules;
mod source;
mod symbols;
mod tokens;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const USAGE: &str = "usage:\n  requirement_map fixture --root <fixture> --scip <scip> --log <log> --jni-declarations <dir> --crate <src-prefix> --package <name> [--features <tree> --features-indexed <tree>] --expect <tsv> [--out <dir>]\n  requirement_map fingerprint --root <repo> --files <list> --inputs <list> --out <file>\n  requirement_map index --root <repo> --files <list> --inputs <list> --fingerprint <file> --android <scip> --android-log <log> [--node <scip> --node-log <log>] --tests <scip> --tests-log <log> --android-features <tree> --android-features-indexed <tree> --android-packages <tree> [--node-features <tree> --node-features-indexed <tree>] --node-packages <tree> --jni-declarations <dir> [--unindexed-consumer <dir>] [--target-dir <dir>] --out <dir>";

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

struct Flags {
    command: String,
    values: BTreeMap<String, String>,
}

impl Flags {
    fn path(&self, name: &str) -> Result<&Path, String> {
        self.values
            .get(name)
            .map(Path::new)
            .ok_or_else(|| format!("{} needs {name}\n{USAGE}", self.command))
    }

    fn optional(&self, name: &str) -> Option<&Path> {
        self.values.get(name).map(Path::new)
    }

    /// A flag's value as the text it was given.
    fn text(&self, name: &str) -> Result<&str, String> {
        self.values
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| format!("{} needs {name}\n{USAGE}", self.command))
    }
}

/// A relative path as the map writes it: its components joined by `/`. A
/// name that is not UTF-8 is an error, never replaced.
pub(crate) fn path_text(path: &Path) -> Result<String, String> {
    let mut parts: Vec<&str> = Vec::new();
    for part in path.components() {
        parts.push(
            part.as_os_str()
                .to_str()
                .ok_or_else(|| format!("{}: a name that is not UTF-8", path.display()))?,
        );
    }
    Ok(parts.join("/"))
}

fn run(args: &[String]) -> Result<String, String> {
    let (command, rest) = args.split_first().ok_or_else(|| USAGE.to_string())?;
    let mut values = BTreeMap::new();
    for pair in rest.chunks(2) {
        match pair {
            [name, value] if name.starts_with("--") => {
                if values.insert(name.clone(), value.clone()).is_some() {
                    return Err(format!("{name} is given twice\n{USAGE}"));
                }
            }
            other => return Err(format!("expected --flag value, found {other:?}\n{USAGE}")),
        }
    }
    let flags = Flags {
        command: command.clone(),
        values,
    };
    match command.as_str() {
        "fingerprint" => {
            let (tree, _) = fingerprint(
                flags.path("--root")?,
                flags.path("--files")?,
                flags.path("--inputs")?,
            )?;
            let out = flags.path("--out")?;
            std::fs::write(out, format!("{tree}\n"))
                .map_err(|e| format!("{}: {e}", out.display()))?;
            Ok(format!("tree {tree}"))
        }
        "index" => index_command(&flags),
        "fixture" => fixture_command(&flags),
        other => Err(format!("unknown command {other:?}\n{USAGE}")),
    }
}

fn cell(value: &str) -> Result<&str, String> {
    if value.contains(['\t', '\n']) {
        return Err(format!("{value:?} holds a tab or a newline"));
    }
    Ok(value)
}

/// The tree hash over every listed source file and every listed input, and
/// each source file's own hash.
fn fingerprint(
    root: &Path,
    list: &Path,
    inputs: &Path,
) -> Result<(String, Vec<(String, hashing::Digest)>), String> {
    let read_list = |p: &Path| -> Result<Vec<String>, String> {
        let text = std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()))?;
        Ok(text
            .lines()
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect())
    };
    let mut files = Vec::new();
    for path in read_list(list)? {
        let bytes = std::fs::read(root.join(&path)).map_err(|e| format!("{path}: {e}"))?;
        let digest = hashing::hash(hashing::FILE, &[path.as_bytes(), &bytes]);
        files.push((path, digest));
    }
    let mut extra = Vec::new();
    for path in read_list(inputs)? {
        let bytes = std::fs::read(root.join(&path)).map_err(|e| format!("{path}: {e}"))?;
        extra.push((
            path.clone(),
            hashing::hash(hashing::FILE, &[path.as_bytes(), &bytes]),
        ));
    }
    let mut parts: Vec<&[u8]> = Vec::new();
    for (path, digest) in files.iter().chain(extra.iter()) {
        parts.push(path.as_bytes());
        parts.push(digest);
    }
    Ok((hashing::text(&hashing::hash(hashing::TREE, &parts)), files))
}

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("{}: {e}", dir.display()))?;
        let path = entry.path();
        let kind = entry
            .file_type()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        if kind.is_dir() {
            rust_files(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    Ok(())
}

/// What a crate this map cannot index uses from the crates it does: every
/// name in its `use`s of and paths through `dsm_sdk` and `dsm`, and every
/// call it writes in method or path form.
fn consumer(root: &Path, dir: &Path) -> Result<graph::Consumer, String> {
    let mut files = Vec::new();
    rust_files(&root.join(dir), &mut files)?;
    files.sort();
    let mut used = BTreeSet::new();
    let mut calls = Vec::new();
    let mut defines = BTreeSet::new();
    for path in files {
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let lexed = source::Source::lex(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        used.extend(
            lexed
                .names_used_from(&["dsm_sdk", "dsm"])
                .map_err(|e| format!("{}: {e}", path.display()))?,
        );
        defines.extend(lexed.functions_defined());
        let end = index::Position {
            line: text.split('\n').count(),
            column: 0,
        };
        for call in lexed.calls(index::Position { line: 0, column: 0 }, end)? {
            match call.form {
                source::Form::Method => calls.push(graph::ConsumerCall::Method(call.name)),
                source::Form::Path(Some(q)) => calls.push(graph::ConsumerCall::Path(q, call.name)),
                // `<T as Trait>::f(…)`: what it names is a method of some type.
                source::Form::Path(None) => calls.push(graph::ConsumerCall::Method(call.name)),
                source::Form::Bare => {}
            }
        }
    }
    calls.sort();
    calls.dedup();
    Ok(graph::Consumer {
        used,
        calls,
        defines,
    })
}

/// Refuses what this map does not read in a shipped crate, so its absence is
/// never a silent hole: assembly (`asm!`, `global_asm!`) that can call or
/// define Rust symbols the index does not see; a `#[link_section]` that puts
/// a function where the loader runs it; a build script that set a `cfg`
/// (read from what it actually printed, cargo's `output` files), which the
/// cfg evaluation does not know.
fn unreadable(
    root: &Path,
    files: &[String],
    crates: &[(&str, &str)],
    target_dir: &Path,
) -> Result<(), String> {
    for file in files
        .iter()
        .filter(|f| crates.iter().any(|(c, _)| f.starts_with(c)))
    {
        let text = std::fs::read_to_string(root.join(file)).map_err(|e| format!("{file}: {e}"))?;
        let lexed = source::Source::lex(&text).map_err(|e| format!("{file}: {e}"))?;
        if let Some(what) = lexed.unread_construct()? {
            return Err(format!(
                "{file} holds {what}, which this map does not read; teach the map before shipping it"
            ));
        }
    }
    for (crate_dir, package) in crates {
        let crate_root = crate_dir.trim_end_matches("src/");
        if !root.join(crate_root).join("build.rs").exists() {
            continue;
        }
        let outputs = build_script_outputs(target_dir, package)?;
        if outputs.is_empty() {
            return Err(format!(
                "{package} has a build script but cargo left no output for it under {}: the index did not run it",
                target_dir.display()
            ));
        }
        for output in outputs {
            let text = std::fs::read_to_string(&output)
                .map_err(|e| format!("{}: {e}", output.display()))?;
            if let Some(line) = text
                .lines()
                .find(|l| l.starts_with("cargo:rustc-cfg=") || l.starts_with("cargo::rustc-cfg="))
            {
                return Err(format!(
                    "{package}'s build script set a cfg ({line}, in {}), which this map's cfg evaluation does not know; teach the map before shipping it",
                    output.display()
                ));
            }
        }
    }
    Ok(())
}

/// Borrowed (source prefix, package) pairs.
fn as_pairs(pairs: &[(String, String)]) -> Vec<(&str, &str)> {
    pairs
        .iter()
        .map(|(prefix, package)| (prefix.as_str(), package.as_str()))
        .collect()
}

/// Every `output` file cargo left for `package`'s build script under the
/// build's target directory (each profile, each target triple): what the
/// script printed.
fn build_script_outputs(target: &Path, package: &str) -> Result<Vec<PathBuf>, String> {
    let mut build_dirs = vec![target.join("debug/build"), target.join("release/build")];
    if target.exists() {
        for entry in std::fs::read_dir(&target).map_err(|e| format!("{}: {e}", target.display()))? {
            let path = entry
                .map_err(|e| format!("{}: {e}", target.display()))?
                .path();
            build_dirs.push(path.join("debug/build"));
            build_dirs.push(path.join("release/build"));
        }
    }
    let mut out = Vec::new();
    for dir in build_dirs.into_iter().filter(|d| d.is_dir()) {
        for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
            let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .map(|n| n.to_string());
            // `<package>-<16 hex digits>`: exactly this package's build dirs.
            let ours = name
                .as_deref()
                .and_then(|n| n.rsplit_once('-'))
                .is_some_and(|(pkg, hash)| {
                    pkg == package
                        && hash.len() == 16
                        && hash.bytes().all(|b| b.is_ascii_hexdigit())
                });
            let output = path.join("output");
            if ours && output.is_file() {
                out.push(output);
            }
        }
    }
    Ok(out)
}

struct Profile {
    name: &'static str,
    loaded: index::Loaded,
    health: logs::Health,
}

fn load_profile(
    name: &'static str,
    root: &Path,
    scip: &Path,
    log: &Path,
) -> Result<Profile, String> {
    let text = std::fs::read_to_string(log).map_err(|e| format!("{}: {e}", log.display()))?;
    let health = logs::read(&text, root)?;
    if let Some(problem) = health.refusal() {
        return Err(format!("the {name} index cannot be evidence: {problem}"));
    }
    let bytes = std::fs::read(scip).map_err(|e| format!("{}: {e}", scip.display()))?;
    let loaded = index::load(&bytes, root).map_err(|e| format!("the {name} index: {e}"))?;
    Ok(Profile {
        name,
        loaded,
        health,
    })
}

fn index_command(flags: &Flags) -> Result<String, String> {
    let root = flags.path("--root")?;
    let fingerprint_file = flags.path("--fingerprint")?;
    let recorded = std::fs::read_to_string(fingerprint_file)
        .map_err(|e| format!("{}: {e}", fingerprint_file.display()))?;
    let (tree, files) = fingerprint(root, flags.path("--files")?, flags.path("--inputs")?)?;
    if recorded.trim() != tree {
        return Err(format!(
            "the indexes were built from another tree: {} says {}, the tree is {tree}; rebuild them",
            fingerprint_file.display(),
            recorded.trim()
        ));
    }
    let android = load_profile(
        "android",
        root,
        flags.path("--android")?,
        flags.path("--android-log")?,
    )?;
    let node = match (flags.optional("--node"), flags.optional("--node-log")) {
        (Some(scip), Some(log)) => Some(load_profile("node", root, scip, log)?),
        (None, None) => None,
        _ => return Err(format!("--node and --node-log go together\n{USAGE}")),
    };
    let tests = load_profile(
        "tests",
        root,
        flags.path("--tests")?,
        flags.path("--tests-log")?,
    )?;
    let declared = jni::declared(root, flags.text("--jni-declarations")?)?;
    let unindexed = match flags.values.get("--unindexed-consumer") {
        Some(dir) => Some((dir.clone(), consumer(root, Path::new(dir))?)),
        None => None,
    };
    let source_files: Vec<String> = files
        .iter()
        .map(|(p, _)| p.clone())
        .filter(|p| p.ends_with(".rs"))
        .collect();
    let exclusions = |built: &Path,
                      indexed: &Path,
                      crates: &[(&str, &str)]|
     -> Result<cfgs::Exclusions, String> {
        let read =
            |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
        cfgs::exclusions(
            root,
            &source_files,
            crates,
            &cfgs::features(&read(built)?)?,
            &cfgs::features(&read(indexed)?)?,
        )
    };
    // Each build's crates: the repository's packages its own `cargo tree`
    // links, never a list written here.
    let linked = |flag: &str| -> Result<Vec<(String, String)>, String> {
        let path = flags.path(flag)?;
        let tree = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        cfgs::linked_packages(&tree, root).map_err(|e| format!("{}: {e}", path.display()))
    };
    let android_packages = linked("--android-packages")?;
    let node_packages = linked("--node-packages")?;
    let prefixes = |packages: &[(String, String)]| -> Vec<(String, String)> {
        packages
            .iter()
            .map(|(package, prefix)| (prefix.clone(), package.clone()))
            .collect()
    };
    let android_pairs = prefixes(&android_packages);
    let node_pairs = prefixes(&node_packages);
    let android_crates: Vec<&str> = android_pairs.iter().map(|(p, _)| p.as_str()).collect();
    let node_crates: Vec<&str> = node_pairs.iter().map(|(p, _)| p.as_str()).collect();
    let target_dir = match flags.optional("--target-dir") {
        Some(dir) => dir.to_path_buf(),
        None => root.join("target"),
    };
    unreadable(root, &source_files, &as_pairs(&android_pairs), &target_dir)?;
    unreadable(root, &source_files, &as_pairs(&node_pairs), &target_dir)?;
    let android_excluded = exclusions(
        flags.path("--android-features")?,
        flags.path("--android-features-indexed")?,
        &as_pairs(&android_pairs),
    )?;
    let node_excluded = match (
        flags.optional("--node-features"),
        flags.optional("--node-features-indexed"),
        &node,
    ) {
        (Some(built), Some(indexed), Some(_)) => {
            exclusions(built, indexed, &as_pairs(&node_pairs))?
        }
        (None, None, None) => cfgs::Exclusions::none(),
        _ => {
            return Err(format!(
                "--node, --node-features and --node-features-indexed go together\n{USAGE}"
            ))
        }
    };
    let excluded_text = |e: &cfgs::Exclusions| -> String {
        e.extra
            .iter()
            .map(|(p, f)| format!("{p}/{}", f.iter().cloned().collect::<Vec<_>>().join(",")))
            .collect::<Vec<_>>()
            .join(" ")
    };
    let feature_notes = format!(
        "features the index enabled and the build does not: android [{}], node [{}]",
        excluded_text(&android_excluded),
        excluded_text(&node_excluded)
    );
    // Each build's own features, per package: what its `cfg` decides.
    let read_features = |path: &Path| -> Result<BTreeMap<String, BTreeSet<String>>, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
        cfgs::features(&text).map_err(|e| format!("{}: {e}", path.display()))
    };
    let android_features = read_features(flags.path("--android-features")?)?;
    let node_features = match flags.optional("--node-features") {
        Some(path) => read_features(path)?,
        None => BTreeMap::new(),
    };
    let artifacts = vec![
        graph::Artifact {
            name: "android",
            crates: &android_crates,
            loaded: Ok(&android.loaded),
            target: cfgs::Target::android(),
            features: &android_features,
            packages: android_pairs.clone(),
            unindexed: unindexed.as_ref(),
            excluded: android_excluded,
        },
        graph::Artifact {
            name: "node",
            crates: &node_crates,
            loaded: node.as_ref().map(|p| &p.loaded).ok_or_else(|| {
                "no storage-node index was given to this map (make requirement-map builds it on a Linux host only; CI's map is canonical)".to_string()
            }),
            target: cfgs::Target::node(),
            features: &node_features,
            packages: node_pairs.clone(),
            unindexed: None,
            excluded: node_excluded,
        },
    ];
    let the_map = graph::build(
        root,
        &graph::Inputs {
            artifacts,
            tests: &tests.loaded,
            declared_jni: &declared,
        },
    )?;
    let out = flags.path("--out")?;
    std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
    let write = |name: &str, body: &str| -> Result<(), String> {
        let path = out.join(name);
        std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))
    };
    write_defs(&the_map, &write)?;
    write_reach(&the_map, &write)?;
    write_edges(&the_map, &write)?;

    let profiles: Vec<&Profile> = [Some(&android), node.as_ref(), Some(&tests)]
        .into_iter()
        .flatten()
        .collect();
    let mut documents: BTreeSet<&str> = BTreeSet::new();
    for p in &profiles {
        documents.extend(p.loaded.documents.iter().map(|s| s.as_str()));
    }
    let mut per_file: BTreeMap<&str, usize> = BTreeMap::new();
    for n in the_map.nodes.values() {
        *per_file.entry(n.def.file.as_str()).or_default() += 1;
    }
    let mut table = String::from("path\tfile\tindexed\tdefinitions\n");
    for (path, digest) in &files {
        let indexed = if documents.contains(path.as_str()) {
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

    let (accounting, health, summary) =
        accounting_tables(&profiles, &the_map, &declared, unindexed.as_ref());
    write("accounting.tsv", &accounting)?;
    write("health.tsv", &health)?;
    let mut token_read = String::from("profile\twhere\twhy\n");
    for p in &profiles {
        for (place, why) in &p.loaded.accounting.token_read {
            token_read.push_str(&format!("{}\t{}\t{}\n", p.name, cell(place)?, cell(why)?));
        }
    }
    write("token-read.tsv", &token_read)?;
    // Each artifact's crates, as its build's `cargo tree` gave them.
    let mut crates_table = String::from("artifact\tpackage\tsource\n");
    for (artifact, packages) in [("android", &android_packages), ("node", &node_packages)] {
        for (package, prefix) in packages {
            crates_table.push_str(&format!(
                "{artifact}\t{}\t{}\n",
                cell(package)?,
                cell(prefix)?
            ));
        }
    }
    write("artifacts.tsv", &crates_table)?;
    Ok(format!(
        "{summary}\n{feature_notes}\n{} source files hashed, tree {tree}",
        files.len()
    ))
}

/// Reads a fixture crate's index through the map's loader and graph, as one
/// artifact whose entry points the fixture's Kotlin declares, and checks
/// every reading the expectation file lists.
fn fixture_command(flags: &Flags) -> Result<String, String> {
    let root = flags.path("--root")?;
    let profile = load_profile("fixture", root, flags.path("--scip")?, flags.path("--log")?)?;
    let declared = jni::declared(root, flags.text("--jni-declarations")?)?;
    let crate_dir = flags
        .values
        .get("--crate")
        .ok_or_else(|| format!("fixture needs --crate\n{USAGE}"))?;
    let package = flags
        .values
        .get("--package")
        .ok_or_else(|| format!("fixture needs --package\n{USAGE}"))?;
    let crates = [crate_dir.as_str()];
    let mut files = Vec::new();
    rust_files(&root.join(crate_dir), &mut files)?;
    let source_files: Vec<String> = files
        .iter()
        .map(|f| {
            let relative = f
                .strip_prefix(root)
                .map_err(|e| format!("{}: {e}", f.display()))?;
            path_text(relative)
        })
        .collect::<Result<_, _>>()?;
    unreadable(
        root,
        &source_files,
        &[(crate_dir.as_str(), package.as_str())],
        &root.join("target"),
    )?;
    // What a feature only the fixture's dev-dependency on itself enables
    // takes out of the build, read exactly as for a shipped build.
    let read = |p: &Path| std::fs::read_to_string(p).map_err(|e| format!("{}: {e}", p.display()));
    let (excluded, built_features) = match (
        flags.optional("--features"),
        flags.optional("--features-indexed"),
    ) {
        (Some(built), Some(indexed)) => {
            let built_features = cfgs::features(&read(built)?)?;
            let excluded = cfgs::exclusions(
                root,
                &source_files,
                &[(crate_dir.as_str(), package.as_str())],
                &built_features,
                &cfgs::features(&read(indexed)?)?,
            )?;
            (excluded, built_features)
        }
        (None, None) => (cfgs::Exclusions::none(), BTreeMap::new()),
        _ => {
            return Err(format!(
                "--features and --features-indexed go together\n{USAGE}"
            ))
        }
    };
    let artifacts = vec![graph::Artifact {
        name: "fixture",
        crates: &crates,
        loaded: Ok(&profile.loaded),
        // The fixture is indexed for the host.
        target: cfgs::Target::host(),
        features: &built_features,
        packages: vec![(crate_dir.clone(), package.clone())],
        unindexed: None,
        excluded,
    }];
    let the_map = graph::build(
        root,
        &graph::Inputs {
            artifacts,
            tests: &profile.loaded,
            declared_jni: &declared,
        },
    )?;
    if let Some(out) = flags.optional("--out") {
        std::fs::create_dir_all(out).map_err(|e| format!("{}: {e}", out.display()))?;
        let write = |name: &str, body: &str| -> Result<(), String> {
            let path = out.join(name);
            std::fs::write(&path, body).map_err(|e| format!("{}: {e}", path.display()))
        };
        write_defs(&the_map, &write)?;
        write_reach(&the_map, &write)?;
        write_edges(&the_map, &write)?;
    }
    let expect_path = flags.path("--expect")?;
    let expect = std::fs::read_to_string(expect_path)
        .map_err(|e| format!("{}: {e}", expect_path.display()))?;
    let mut failures = Vec::new();
    let mut checked = 0usize;
    for line in expect
        .lines()
        .skip(1)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        let cells: Vec<&str> = line.split('\t').collect();
        let [path, state, code] = cells.as_slice() else {
            return Err(format!(
                "{}: {line:?} is not key, state, code",
                expect_path.display()
            ));
        };
        checked += 1;
        // A key is a Rust path, or `@file:line name` for an item written
        // inside a function, which no path names.
        let at_key = match path.strip_prefix('@') {
            Some(rest) => {
                let (place, name) = rest
                    .split_once(' ')
                    .ok_or_else(|| format!("{path:?} is not `@file:line name`"))?;
                let (file, line) = place
                    .rsplit_once(':')
                    .ok_or_else(|| format!("{path:?} is not `@file:line name`"))?;
                let line: usize = line.parse().map_err(|e| format!("{path:?}: {e}"))?;
                Some((file, line, name))
            }
            None => None,
        };
        // Only what the fixture build reads: a definition outside its crate
        // (the build script's `main`) may share a path with one inside.
        let found: Vec<&graph::Status> = the_map
            .nodes
            .values()
            .filter(|n| match at_key {
                Some((file, line, name)) => {
                    n.def.file == file && n.def.name_at.line + 1 == line && n.def.item.name == name
                }
                None => n.path.as_deref() == Some(*path),
            })
            .filter_map(|n| n.status.get("fixture"))
            .collect();
        match (found.as_slice(), *state) {
            // A negative fact: the build compiles no such definition.
            ([], "absent") => {}
            (many, "absent") => failures.push(format!(
                "{path}: expected absent, the build reads {} definitions",
                many.len()
            )),
            ([s], _) if s.state == *state && s.code == *code => {}
            ([s], _) => failures.push(format!(
                "{path}: expected {state} {code}, read {} {} ({})",
                s.state,
                s.code,
                absent_as_empty(s.reason.as_deref())
            )),
            ([], _) => failures.push(format!("{path}: not in the fixture build")),
            (many, _) => failures.push(format!(
                "{path}: names {} definitions the build reads",
                many.len()
            )),
        }
    }
    if !failures.is_empty() {
        return Err(format!(
            "the fixture reads wrongly:\n  {}",
            failures.join("\n  ")
        ));
    }
    Ok(format!("fixture: all {checked} readings as expected"))
}

fn overall(n: &graph::Node) -> (&'static str, &'static str) {
    let rank = |state: &str| match state {
        "reached" => 0,
        "indeterminate" => 1,
        "not-built" => 2,
        "dead" => 3,
        _ => 4,
    };
    match n.status.values().min_by_key(|s| rank(s.state)) {
        Some(s) => (s.state, s.code),
        None => ("not-shipped", reach::code::NOT_IN_ARTIFACT),
    }
}

fn write_defs(
    the_map: &graph::Map,
    write: &dyn Fn(&str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let mut defs = String::from(
        "symbol\tpath\tkind\tname\tcontainer\ttrait\tfile\tstart_line\tend_line\titem\tclosure\tstate\tcode\ttested\troot\tbuilt_in\n",
    );
    let mut nodes: Vec<&graph::Node> = the_map.nodes.values().collect();
    nodes.sort_by(|a, b| {
        (&a.def.file, a.def.start, &a.def.symbol).cmp(&(&b.def.file, b.def.start, &b.def.symbol))
    });
    for n in nodes {
        let d = &n.def;
        let (state, code_) = overall(n);
        let roots: Vec<String> = n.roots.iter().map(|(a, k)| format!("{a}:{k}")).collect();
        let row = [
            cell(&d.symbol)?,
            cell(absent_as_empty(n.path.as_deref()))?,
            d.item.kind.label(),
            cell(&d.item.name)?,
            cell(&d.item.container)?,
            cell(&d.item.trait_name)?,
            cell(&d.file)?,
            &(d.start.line + 1).to_string(),
            &(d.end.line + 1).to_string(),
            &hashing::text(&n.item),
            &hashing::text(&n.closure),
            state,
            code_,
            if n.tested { "1" } else { "0" },
            &roots.join(","),
            &n.built_in.join(","),
        ]
        .join("\t");
        defs.push_str(&row);
        defs.push('\n');
    }
    write("defs.tsv", &defs)
}

/// A value the map does not have is written as an empty cell: the tables'
/// encoding of absence, which the readers treat as "none".
fn absent_as_empty(value: Option<&str>) -> &str {
    match value {
        Some(v) => v,
        None => "",
    }
}

fn write_reach(
    the_map: &graph::Map,
    write: &dyn Fn(&str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let mut out =
        String::from("symbol\tartifact\tstate\tcode\tvia\tvia_kind\tat\tsource\treason\n");
    for (symbol, n) in &the_map.nodes {
        for (artifact, s) in &n.status {
            out.push_str(&format!(
                "{}\t{artifact}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
                cell(symbol)?,
                s.state,
                s.code,
                cell(absent_as_empty(s.via.as_deref()))?,
                absent_as_empty(s.via_kind),
                cell(absent_as_empty(s.at.as_deref()))?,
                s.source,
                cell(absent_as_empty(s.reason.as_deref()))?
            ));
        }
    }
    write("reach.tsv", &out)
}

fn write_edges(
    the_map: &graph::Map,
    write: &dyn Fn(&str, &str) -> Result<(), String>,
) -> Result<(), String> {
    let mut out = String::from("profile\tfrom\tto\tkind\tproof\tcode\tat\n");
    for (profile, from, to, kind, ev) in &the_map.edges {
        let (proof, code_) = match &ev.doubt {
            None => ("proven", ""),
            Some(d) => ("uncertain", d.code),
        };
        out.push_str(&format!(
            "{profile}\t{}\t{}\t{kind}\t{proof}\t{code_}\t{}\n",
            cell(from)?,
            cell(to)?,
            cell(&ev.at)?
        ));
    }
    write("edges.tsv", &out)
}

/// The accounting of every profile and artifact, as two tables and the text
/// printed at the end of a run.
fn accounting_tables(
    profiles: &[&Profile],
    the_map: &graph::Map,
    declared: &jni::Declarations,
    unindexed: Option<&(String, graph::Consumer)>,
) -> (String, String, String) {
    let mut accounting = String::from("profile\tmeasure\tvalue\n");
    let mut health = String::from("profile\tcategory\tcount\n");
    let mut text = String::from("profile   definition-occurrences  nodes  repeats  locals  modules  parameters  unnamed  collisions  repaired  macro-groups  unplaceable\n");
    for p in profiles {
        let a = &p.loaded.accounting;
        let unplaceable = p.health.unplaceable.len();
        for (measure, value) in [
            ("definition-occurrences", a.definition_occurrences),
            ("item-occurrences", a.item_occurrences),
            ("nodes", a.nodes),
            ("repeats", a.repeated),
            ("locals", a.locals),
            ("modules", a.modules),
            ("parameters", a.parameters),
            ("unnamed", a.unnamed),
            ("collisions", a.collisions.len()),
            ("repaired-extents", a.repaired.len()),
            ("token-read-macro-bodies", a.token_read.len()),
            ("macro-groups", a.macro_groups),
            ("unplaceable", unplaceable),
        ] {
            accounting.push_str(&format!("{}\t{measure}\t{value}\n", p.name));
        }
        for (category, count) in p.health.counts() {
            health.push_str(&format!("{}\t{category}\t{count}\n", p.name));
        }
        text.push_str(&format!(
            "{:<9} {:>22}  {:>5}  {:>7}  {:>6}  {:>7}  {:>10}  {:>7}  {:>10}  {:>8}  {:>12}  {:>11}\n",
            p.name,
            a.definition_occurrences,
            a.nodes,
            a.repeated,
            a.locals,
            a.modules,
            a.parameters,
            a.unnamed,
            a.collisions.len(),
            a.repaired.len(),
            a.macro_groups,
            unplaceable
        ));
    }
    text.push_str("\nartifact  built      roots  dead-roots  excluded  reached  indeterminate  dead  unresolved-call-tokens  unresolved-call-candidates  macro-body-candidates  unindexed-candidates\n");
    for (name, t) in &the_map.tallies {
        text.push_str(&format!(
            "{:<9} {:<9} {:>6}  {:>10}  {:>8}  {:>7}  {:>13}  {:>4}  {:>22}  {:>26}  {:>21}  {:>20}\n",
            name,
            t.built,
            t.roots,
            t.dead_roots,
            t.excluded,
            t.reached,
            t.indeterminate,
            t.dead,
            t.unresolved_call_tokens,
            t.unresolved_call_candidates,
            t.macro_body_candidates,
            t.unindexed_candidates
        ));
        for (measure, value) in [
            ("roots", t.roots),
            ("dead-roots", t.dead_roots),
            ("unread-declaration-roots", t.unread_roots),
            ("excluded-by-cfg", t.excluded),
            ("reached", t.reached),
            ("indeterminate", t.indeterminate),
            ("dead", t.dead),
            ("unresolved-call-tokens", t.unresolved_call_tokens),
            ("unattributed-call-tokens", t.unattributed_call_tokens),
            ("uncompiled-call-tokens", t.uncompiled_call_tokens),
            ("uncompiled-edges", t.uncompiled_edges),
            ("unresolved-call-candidates", t.unresolved_call_candidates),
            ("macro-body-candidates", t.macro_body_candidates),
            ("unindexed-candidates", t.unindexed_candidates),
        ] {
            accounting.push_str(&format!("{name}\t{measure}\t{value}\n"));
        }
        accounting.push_str(&format!("{name}\tbuilt\t{}\n", t.built));
    }
    text.push_str("\nanalyzer log   ");
    for p in profiles {
        let c = p.health.counts();
        let shown: Vec<String> = c
            .iter()
            .filter(|(_, v)| **v > 0)
            .map(|(k, v)| format!("{k} {v}"))
            .collect();
        text.push_str(&format!("\n  {}: {}", p.name, shown.join(", ")));
    }
    text.push_str(&format!(
        "\n\nJNI declarations read: {}, not spelled: {}",
        declared.symbols.len(),
        declared.unread.len()
    ));
    for u in &declared.unread {
        text.push_str(&format!("\n  {} {}: {}", u.prefix, u.at, u.why));
    }
    accounting.push_str(&format!(
        "all\tunread-declarations\t{}\n",
        declared.unread.len()
    ));
    // The app loads the android artifact's library: a declaration it does
    // not export fails at run time with `UnsatisfiedLinkError`, or is one this
    // map misread. Either way it is named.
    if let Some(t) = the_map.tallies.get("android") {
        let unexported: Vec<String> = declared
            .symbols
            .iter()
            .filter(|(symbol, _)| !t.exported_declarations.contains(*symbol))
            .map(|(symbol, at)| match unindexed {
                Some((dir, c)) if c.defines.contains(symbol) => {
                    format!("{symbol} ({at}): a function of this name is written in the unindexed {dir}")
                }
                _ => format!("{symbol} ({at}): written in no indexed or unindexed source"),
            })
            .collect();
        text.push_str(&format!(
            "\n  android: {} exported, {} declared but not exported",
            t.exported_declarations.len(),
            unexported.len()
        ));
        for u in &unexported {
            text.push_str(&format!("\n    {u}"));
        }
        accounting.push_str(&format!(
            "android\tunexported-declarations\t{}\n",
            unexported.len()
        ));
    }
    for p in profiles {
        for c in &p.loaded.accounting.collisions {
            let places: Vec<String> = c
                .definitions
                .iter()
                .map(|(at, k)| format!("{at} ({k})"))
                .collect();
            text.push_str(&format!(
                "\n  {} collision: {} -> {}",
                p.name,
                c.symbol,
                places.join(", ")
            ));
        }
    }
    (accounting, health, text)
}
