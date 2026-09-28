// SPDX-License-Identifier: MIT OR Apache-2.0
//! Seals: one BLAKE3 hash per conformance finding over its requirement, its
//! own row, and the closure of every code item and test it names.

use crate::hashing::{hash, text, Digest, REQUIREMENT, SEAL};
use std::collections::BTreeMap;
use std::path::Path;

pub fn seal_of(requirement: &str, row: &str, named: &[(&str, &str)]) -> Digest {
    let requirement_hash = hash(REQUIREMENT, &[requirement.as_bytes()]);
    let mut fields: Vec<&[u8]> = vec![&requirement_hash, row.as_bytes()];
    for (symbol, closure) in named {
        fields.push(symbol.as_bytes());
        fields.push(closure.as_bytes());
    }
    hash(SEAL, &fields)
}

/// `defs.tsv` of a map directory: symbol -> closure hash.
pub fn closures(map: &Path) -> Result<BTreeMap<String, String>, String> {
    let path = map.join("defs.tsv");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = BTreeMap::new();
    for (number, line) in text.lines().enumerate().skip(1) {
        let cells: Vec<&str> = line.split('\t').collect();
        match (cells.first(), cells.get(9)) {
            (Some(symbol), Some(closure)) => {
                out.insert(symbol.to_string(), closure.to_string());
            }
            _ => {
                return Err(format!(
                    "{}:{}: fewer than ten cells",
                    path.display(),
                    number + 1
                ))
            }
        }
    }
    Ok(out)
}

/// Rows: `id \t requirement \t row \t symbol…`; out: `id \t seal`.
pub fn command(map: &Path, rows: &Path, out: &Path) -> Result<String, String> {
    let closures = closures(map)?;
    let body = std::fs::read_to_string(rows).map_err(|e| format!("{}: {e}", rows.display()))?;
    let mut lines = Vec::new();
    for (number, line) in body.lines().enumerate() {
        if line.is_empty() {
            continue;
        }
        let cells: Vec<&str> = line.split('\t').collect();
        let (id, requirement, row) = match (cells.first(), cells.get(1), cells.get(2)) {
            (Some(i), Some(q), Some(r)) => (*i, *q, *r),
            _ => {
                return Err(format!(
                    "{}:{}: fewer than three cells",
                    rows.display(),
                    number + 1
                ))
            }
        };
        let mut named = Vec::new();
        for symbol in &cells[3..] {
            let closure = closures
                .get(*symbol)
                .ok_or_else(|| format!("{id}: {symbol} is not in the map"))?;
            named.push((*symbol, closure.as_str()));
        }
        lines.push(format!(
            "{id}\t{}",
            text(&seal_of(requirement, row, &named))
        ));
    }
    std::fs::write(out, lines.join("\n") + "\n").map_err(|e| format!("{}: {e}", out.display()))?;
    Ok(format!("{} seals", lines.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_part_of_a_finding_is_under_its_seal() {
        let base = seal_of("R", "| MR-1 | Met |", &[("s1", "C1"), ("s2", "C2")]);
        assert_ne!(
            base,
            seal_of("R'", "| MR-1 | Met |", &[("s1", "C1"), ("s2", "C2")]),
            "requirement text"
        );
        assert_ne!(
            base,
            seal_of("R", "| MR-1 | Partial |", &[("s1", "C1"), ("s2", "C2")]),
            "row text"
        );
        assert_ne!(
            base,
            seal_of("R", "| MR-1 | Met |", &[("s1", "C1x"), ("s2", "C2")]),
            "code beneath"
        );
        assert_ne!(
            base,
            seal_of("R", "| MR-1 | Met |", &[("s2", "C2"), ("s1", "C1")]),
            "order of what it names"
        );
        assert_ne!(
            base,
            seal_of("R", "| MR-1 | Met |", &[("s1", "C1")]),
            "a dropped item"
        );
        assert_eq!(
            base,
            seal_of("R", "| MR-1 | Met |", &[("s1", "C1"), ("s2", "C2")])
        );
    }
}
