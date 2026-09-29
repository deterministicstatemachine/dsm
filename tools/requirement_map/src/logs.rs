// SPDX-License-Identifier: MIT OR Apache-2.0
//! The analyzer's own log for one index, classified. Every ERROR or WARN line
//! is a kind this map knows, and each kind is counted; a build-script or
//! proc-macro failure, a configuration error, a definition the analyzer could
//! not place that the source does not explain, or a line of no known kind
//! stops the map, because the index it came with may be missing code.

use crate::index::Position;
use crate::source::{AtPosition, Source};
use std::collections::BTreeMap;
use std::path::Path;

/// Why the analyzer could not place a definition in any document.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Cause {
    /// An impl a `#[derive(…)]` writes: the type it is on is the node.
    Derive,
    /// Code a build script wrote, pulled in with `include!`.
    Include,
    /// Items a macro invocation writes.
    MacroInvocation,
    /// A file several test crates each compile (`mod common;`): test code.
    SharedTestModule,
    /// Nothing in the source explains it.
    Unexplained,
}

impl Cause {
    pub fn label(self) -> &'static str {
        match self {
            Cause::Derive => "derive",
            Cause::Include => "include",
            Cause::MacroInvocation => "macro-invocation",
            Cause::SharedTestModule => "shared-test-module",
            Cause::Unexplained => "unexplained",
        }
    }
}

pub struct Health {
    pub build_script_failures: Vec<String>,
    pub proc_macro_failures: Vec<String>,
    pub config_errors: Vec<String>,
    /// The analyzer gave up searching for an import path (display only).
    pub path_search_limits: usize,
    /// Definitions inside an unnamed module (a function body): the index still
    /// holds them; their enclosing symbol is left empty.
    pub unnamed_enclosing: usize,
    /// Definitions the analyzer saw but placed in no document, and why.
    pub unplaceable: Vec<(String, Cause)>,
    pub duplicate_symbols: usize,
    /// A crate that is its own dev-dependency (to turn a test feature on for
    /// its integration tests): the analyzer drops the edge; the feature it
    /// turns on is handled by `cfgs`.
    pub self_dependencies: Vec<String>,
    pub unrecognised: Vec<String>,
}

impl Health {
    pub fn counts(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        out.insert(
            "build-script-failures".to_string(),
            self.build_script_failures.len(),
        );
        out.insert(
            "proc-macro-failures".to_string(),
            self.proc_macro_failures.len(),
        );
        out.insert("config-errors".to_string(), self.config_errors.len());
        out.insert("path-search-limits".to_string(), self.path_search_limits);
        out.insert(
            "unnamed-enclosing-module".to_string(),
            self.unnamed_enclosing,
        );
        out.insert(
            "duplicate-symbol-reports".to_string(),
            self.duplicate_symbols,
        );
        out.insert(
            "self-dev-dependencies".to_string(),
            self.self_dependencies.len(),
        );
        out.insert("unrecognised-lines".to_string(), self.unrecognised.len());
        for cause in [
            Cause::Derive,
            Cause::Include,
            Cause::MacroInvocation,
            Cause::SharedTestModule,
            Cause::Unexplained,
        ] {
            let n = self.unplaceable.iter().filter(|(_, c)| *c == cause).count();
            out.insert(format!("unplaceable-{}", cause.label()), n);
        }
        out
    }

    /// Why an index with this log cannot be the map's evidence, if it cannot.
    pub fn refusal(&self) -> Option<String> {
        let mut problems = Vec::new();
        let mut name = |what: &str, lines: &[String]| {
            if let Some(first) = lines.first() {
                problems.push(format!("{} {what} (first: {first})", lines.len()));
            }
        };
        name("build-script failures", &self.build_script_failures);
        name("proc-macro failures", &self.proc_macro_failures);
        name("configuration errors", &self.config_errors);
        name("log lines of no known kind", &self.unrecognised);
        let unexplained: Vec<String> = self
            .unplaceable
            .iter()
            .filter(|(_, c)| *c == Cause::Unexplained)
            .map(|(at, _)| at.clone())
            .collect();
        name(
            "definitions the analyzer placed in no document and the source does not explain",
            &unexplained,
        );
        (!problems.is_empty()).then(|| problems.join("; "))
    }
}

/// The first line of rust-analyzer's duplicate-symbol notice.
const DUPLICATE_NOTICE: &str =
    "Encountered duplicate scip symbols, indicating an internal rust-analyzer bug.";

/// `path:line:col-line:col`, how the notice lists each duplicate's place.
fn is_location(text: &str) -> bool {
    // From the right: the end column, `start column-end line`, the start
    // line, then the path.
    let mut parts = text.rsplitn(4, ':');
    let (end_col, middle, start_line, path) =
        (parts.next(), parts.next(), parts.next(), parts.next());
    let numeric = |part: Option<&str>| {
        part.is_some_and(|p| {
            p.split('-')
                .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
        })
    };
    path.is_some_and(|p| !p.is_empty())
        && numeric(start_line)
        && numeric(middle)
        && numeric(end_col)
}

/// `2026-09-28T12:26:58.933279-04:00 ERROR message` → (`ERROR`, `message`).
fn leveled(line: &str) -> Option<(&str, &str)> {
    let (stamp, rest) = line.split_once(' ')?;
    let dated = stamp.len() > 10
        && stamp.as_bytes()[..4].iter().all(u8::is_ascii_digit)
        && stamp.as_bytes()[4] == b'-'
        && stamp.contains('T');
    if !dated {
        return None;
    }
    let rest = rest.trim_start();
    let (level, message) = rest.split_once(' ')?;
    Some((level, message.trim()))
}

pub fn read(log: &str, root: &Path) -> Result<Health, String> {
    let mut health = Health {
        build_script_failures: Vec::new(),
        proc_macro_failures: Vec::new(),
        config_errors: Vec::new(),
        path_search_limits: 0,
        unnamed_enclosing: 0,
        unplaceable: Vec::new(),
        duplicate_symbols: 0,
        self_dependencies: Vec::new(),
        unrecognised: Vec::new(),
    };
    // rust-analyzer's duplicate-symbol notice: a fixed prose block, then a
    // listing of `file:range` / `Duplicate symbol: …` pairs, until the next
    // dated line.
    let mut in_notice = 0u8;
    for line in log.lines() {
        let trimmed = line.trim();
        let Some((level, message)) = leveled(line) else {
            if trimmed.starts_with(DUPLICATE_NOTICE) {
                in_notice = 1;
                continue;
            }
            if in_notice == 1 && trimmed == "Duplicate symbols encountered:" {
                in_notice = 2;
                continue;
            }
            match in_notice {
                // The notice's own prose.
                1 => {}
                2 if trimmed.starts_with("Duplicate symbol: ") => health.duplicate_symbols += 1,
                2 if trimmed.is_empty() || is_location(trimmed) => {}
                _ if trimmed.is_empty()
                    || trimmed.starts_with("rust-analyzer: ")
                    || trimmed == "Generating SCIP start..."
                    || trimmed.starts_with("Generating SCIP finished") => {}
                _ => {
                    let lower = trimmed.to_lowercase();
                    if lower.contains("build script") || lower.contains("custom build command") {
                        health.build_script_failures.push(trimmed.to_string());
                    } else {
                        health.unrecognised.push(trimmed.to_string());
                    }
                }
            }
            continue;
        };
        in_notice = 0;
        if level != "ERROR" && level != "WARN" {
            continue;
        }
        let lower = message.to_lowercase();
        if message.starts_with("ran out of fuel while searching for a path") {
            health.path_search_limits += 1;
        } else if message.starts_with("Encountered enclosing definition with no name") {
            health.unnamed_enclosing += 1;
        } else if let Some(at) = message
            .strip_prefix("Bug: definition at ")
            .and_then(|r| r.split(' ').next())
        {
            let cause = unplaceable_cause(root, at)?;
            health.unplaceable.push((at.to_string(), cause));
        } else if let Some(cycle) = message.strip_prefix("cyclic deps: ") {
            let crate_of = |part: &str| part.split('(').next().map(|c| c.trim().to_string());
            let mut ends = cycle.split(" -> ");
            let (from, to) = (
                ends.next().and_then(crate_of),
                ends.next()
                    .and_then(|t| t.split(',').next())
                    .and_then(crate_of),
            );
            match (from, to) {
                (Some(a), Some(b)) if a == b => health.self_dependencies.push(a),
                _ => health.unrecognised.push(format!("{level} {message}")),
            }
        } else if message.starts_with("Config Error(s)") {
            if !message.ends_with("ConfigErrors([])") {
                health.config_errors.push(message.to_string());
            }
        } else if lower.contains("build script") || lower.contains("build-script") {
            health.build_script_failures.push(message.to_string());
        } else if lower.contains("proc-macro") || lower.contains("proc macro") {
            health.proc_macro_failures.push(message.to_string());
        } else {
            health.unrecognised.push(format!("{level} {message}"));
        }
    }
    Ok(health)
}

/// What the source at `file:line:col-line:col` shows the unplaceable
/// definition to be.
fn unplaceable_cause(root: &Path, at: &str) -> Result<Cause, String> {
    let (file, range) = at
        .split_once(':')
        .ok_or_else(|| format!("{at}: no line in the location"))?;
    let mut numbers = range.split([':', '-']);
    let line: usize = numbers
        .next()
        .ok_or_else(|| format!("{at}: no line in the location"))?
        .parse()
        .map_err(|e| format!("{at}: the line: {e}"))?;
    let column: usize = numbers
        .next()
        .ok_or_else(|| format!("{at}: no column in the location"))?
        .parse()
        .map_err(|e| format!("{at}: the column: {e}"))?;
    let text = std::fs::read_to_string(root.join(file)).map_err(|e| format!("{file}: {e}"))?;
    let Some(source_line) = text.split('\n').nth(line) else {
        return Err(format!("{at}: past the end of {file}"));
    };
    if column > source_line.len() {
        return Err(format!(
            "{at}: the column is past the end of line {}",
            line + 1
        ));
    }
    // What the tokens at that position are part of.
    let lexed = Source::lex(&text).map_err(|e| format!("{file}: {e}"))?;
    match lexed.what_is_at(Position { line, column })? {
        AtPosition::InAttribute(path) if path == "derive" => Ok(Cause::Derive),
        AtPosition::MacroCall(name) if name == "include" => Ok(Cause::Include),
        AtPosition::MacroCall(_) => Ok(Cause::MacroInvocation),
        AtPosition::InAttribute(_) | AtPosition::Other | AtPosition::NoToken => {
            if let Some((tests_dir, module)) = test_module(file) {
                if crates_declaring(root, &tests_dir, &module)? >= 2 {
                    return Ok(Cause::SharedTestModule);
                }
            }
            Ok(Cause::Unexplained)
        }
    }
}

/// A module file directly under a `tests` directory, read by path
/// components (the workspace root's own `tests/` included): that directory,
/// and the module's name (`tests/common/mod.rs` and `tests/common.rs` are
/// `common`).
fn test_module(file: &str) -> Option<(std::path::PathBuf, String)> {
    let parts: Vec<&str> = Path::new(file)
        .components()
        .map(|c| c.as_os_str().to_str())
        .collect::<Option<Vec<&str>>>()?;
    let k = parts.iter().rposition(|p| *p == "tests")?;
    let tests_dir: std::path::PathBuf = parts[..=k].iter().collect();
    match &parts[k + 1..] {
        [dir, "mod.rs"] => Some((tests_dir, dir.to_string())),
        [single] => single
            .strip_suffix(".rs")
            .map(|name| (tests_dir, name.to_string())),
        _ => None,
    }
}

/// How many test crates in the `tests` directory `tests_dir` (relative to
/// the root) declare `mod <module>;`: two or more means the file is compiled
/// into several crates, which is why the analyzer places its definitions in
/// no single document.
fn crates_declaring(root: &Path, tests_dir: &Path, module: &str) -> Result<usize, String> {
    let dir = root.join(tests_dir);
    let entries = std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut declaring = 0usize;
    for entry in entries {
        let path = entry.map_err(|e| format!("{}: {e}", dir.display()))?.path();
        if path.extension().is_some_and(|e| e == "rs") {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let lexed = Source::lex(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            if lexed.declares_module(module) {
                declaring += 1;
            }
        }
    }
    Ok(declaring)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_module_is_found_by_path_components() {
        assert_eq!(
            test_module("tests/common.rs"),
            Some((std::path::PathBuf::from("tests"), "common".to_string()))
        );
        assert_eq!(
            test_module("a/b/tests/common/mod.rs"),
            Some((std::path::PathBuf::from("a/b/tests"), "common".to_string()))
        );
        // A directory named like it, or a file deeper down, is not one.
        assert_eq!(test_module("a/contests/common.rs"), None);
        assert_eq!(test_module("a/tests/x/y/z.rs"), None);
    }
}
