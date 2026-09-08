// SPDX-License-Identifier: MIT OR Apache-2.0

//! Domain tag constants for BLAKE3 domain-separated hashing.
//!
//! The dsm_domain_hasher(tag) primitive appends the trailing NUL byte at
//! hash time, so constants in this module are plain tag strings unless
//! explicitly suffixed with _NUL for compatibility cases.
//!
//! This module is intentionally split into a hierarchical structure so DSM
//! and DJTE namespaces remain easy to navigate and maintain.

mod djte;
mod dsm;

pub use dsm::*;
pub use djte::*;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::domain::TaggedHashDomain;
    use std::collections::HashSet;

    fn all_tags() -> Vec<TaggedHashDomain<'static>> {
        let mut tags = dsm::all_tags();
        tags.extend_from_slice(djte::TAGS);
        tags
    }

    #[test]
    fn all_tags_are_unique() {
        let tags = all_tags();
        let set: HashSet<&[u8]> = tags.iter().map(|t| t.source_bytes()).collect();
        assert_eq!(set.len(), tags.len(), "All domain tags must be unique");
    }

    #[test]
    fn all_tags_have_expected_prefixes() {
        for tag in all_tags() {
            let b = tag.source_bytes();
            assert!(
                b.starts_with(b"DSM/") || b.starts_with(b"DJTE."),
                "Tag {:?} must use DSM/ or DJTE. prefix",
                String::from_utf8_lossy(b)
            );
        }
    }

    /// PREFIX-FREEDOM, evaluated on the bytes the hasher actually consumes.
    ///
    /// The no-length-prefix argument in `hash.rs` holds only if a tag is
    /// self-delimiting. `tagged_hasher` makes it so by writing
    /// `source_bytes() || 0x00`, so `"A"` and `"AB"` become `"A\0"` and `"AB\0"`
    /// and differ at byte 1.
    ///
    /// That reasoning used to break when a tag CONTAINED a NUL, because the
    /// hasher appended a second one and `"X\0"` became a strict prefix of
    /// `"X\0\0"`. `TaggedHashDomain` now makes such a tag unrepresentable, so
    /// this test can no longer fail that way — but it is kept, because a tag
    /// that is a plain prefix of another (`"DSM/a"` vs `"DSM/ab"`) is still
    /// expressible and still must not collide once encoded.
    #[test]
    fn no_domain_tag_is_a_prefix_of_another_as_the_hasher_sees_it() {
        let tags = all_tags();
        let hashed: Vec<(String, Vec<u8>)> = tags
            .iter()
            .map(|t| {
                let mut bytes = t.source_bytes().to_vec();
                bytes.push(0); // the separator tagged_hasher appends
                (
                    String::from_utf8_lossy(t.source_bytes()).into_owned(),
                    bytes,
                )
            })
            .collect();

        for (i, (name_a, a)) in hashed.iter().enumerate() {
            for (j, (name_b, b)) in hashed.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert!(
                    !b.starts_with(a),
                    "domain tag {name_a:?} is a prefix of {name_b:?} once the \
                     encoder's NUL separator is applied. H(tag_a || rest) can then \
                     equal H(tag_b || rest'), so the two domains are not separated."
                );
            }
        }
    }

    /// Was a runtime check; now a statement about the type.
    ///
    /// Every registered tag is a `TaggedHashDomain`, and neither constructor can
    /// produce one containing a NUL — `from_static` rejects at COMPILE time and
    /// `try_new` at construction. So "no registered tag carries a NUL" is not
    /// something this test discovers, it is something the type guarantees; the
    /// assertion below can only fail if a third constructor is ever added.
    ///
    /// That is the whole point of the cut: the invariant moved from a test that
    /// had to be remembered to a type that cannot be bypassed.
    #[test]
    fn no_registered_tag_can_carry_a_nul_by_construction() {
        for tag in all_tags() {
            assert!(
                !tag.source_bytes().contains(&0),
                "a registered tag contains a NUL, which TaggedHashDomain should \
                 have made unrepresentable — a constructor was added that does \
                 not validate"
            );
        }

        // The guarantee itself, exercised directly.
        assert!(TaggedHashDomain::try_new(b"DSM/x\0").is_err());
        assert!(TaggedHashDomain::try_new(b"DSM/a\0b").is_err());
        assert!(TaggedHashDomain::try_new(b"").is_err());
    }

    // ─── REGISTRY COMPLETENESS ──────────────────────────────────────────────
    //
    // Every check above traverses `all_tags()`. None of them can see a tag that
    // was declared and never added to a `TAGS` array — and 21 were, including
    // the two production §16.3 signing domains `DSM/add-device-admission` and
    // `DSM/add-device-self-attest`. The uniqueness and prefix-freedom tests were
    // blind to them, so "the domain tags are pairwise distinct" was a weaker
    // claim than its name.
    //
    // Three checks below, proving three different things:
    //
    //   1. declaration equality  the registry is COMPLETE for what source
    //                            declares — the load-bearing guard
    //   2. expected count        change-control tripwire, consciously bumped
    //   3. must-be-present       targeted assertions for the domains whose
    //                            distinctness a formal proof depends on
    //
    // A count alone would not close this: declare tag #348, forget the array,
    // and the total is still 347. Membership alone would not either: it only
    // covers the tags someone thought to name.

    /// The number of `TaggedHashDomain` constants this crate declares.
    ///
    /// A **source-completeness tripwire, not a protocol constant.** Bump it
    /// deliberately when adding a tag — the same idiom as the CI Lean gate's
    /// hardcoded module count. It is the weakest of the three checks and is
    /// here only to make an accidental edit to the registry loud.
    const EXPECTED_TAG_COUNT: usize = 347;

    /// Scan the crate source for every declared domain-tag constant.
    ///
    /// Deliberately INDEPENDENT of the `TAGS` arrays: the point is to compare a
    /// registry against something that did not come from it. Source-wide rather
    /// than scoped to `domain_tags/`, because nothing constrains a declaration
    /// to that directory and scoping the scan there would make the guard depend
    /// on the very convention it exists to enforce.
    ///
    /// Both declaration forms in the tree are matched: `tagged_domain!(b"..")`
    /// and `TaggedHashDomain::from_static(b"..")`.
    fn declared_tags_from_source() -> Vec<(String, Vec<u8>)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(String, Vec<u8>)>) {
            let entries = std::fs::read_dir(dir).expect("readable source dir");
            for entry in entries {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    let text = std::fs::read_to_string(&path).expect("readable source file");
                    scan(&text, out);
                }
            }
        }

        fn scan(text: &str, out: &mut Vec<(String, Vec<u8>)>) {
            // `pub const TAG_X: TaggedHashDomain<'static> = <ctor>(b"literal");`
            // The declaration may wrap across lines, so join and split on `;`.
            for stmt in text.split(';') {
                let Some(idx) = stmt.find("pub const TAG_") else {
                    continue;
                };
                let rest = &stmt[idx + "pub const ".len()..];
                let Some(colon) = rest.find(':') else {
                    continue;
                };
                let name = rest[..colon].trim().to_string();
                if !rest[colon..].contains("TaggedHashDomain") {
                    continue;
                }
                let is_decl = rest.contains("tagged_domain!(")
                    || rest.contains("TaggedHashDomain::from_static(");
                if !is_decl {
                    continue;
                }
                let Some(bstart) = rest.find("b\"") else {
                    continue;
                };
                let after = &rest[bstart + 2..];
                let Some(bend) = after.find('"') else {
                    continue;
                };
                out.push((name, after.as_bytes()[..bend].to_vec()));
            }
        }

        let mut out = Vec::new();
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        walk(&src, &mut out);
        out
    }

    /// THE COMPLETENESS GUARD. Every declared tag reaches `all_tags()`.
    ///
    /// Compared as a **multiset of tag bytes**, not a set: set equality silently
    /// absorbs a duplicate declaration or a duplicated registry entry, because
    /// multiplicity disappears. Bytes rather than `(name, bytes)` because
    /// `all_tags()` returns `TaggedHashDomain` values and does not retain the
    /// constant names — so name uniqueness is checked source-side, separately,
    /// in the test below. `all_tags()` is not redesigned merely to make a CI
    /// check expressible.
    #[test]
    fn every_declared_domain_tag_reaches_the_registry() {
        let declared = declared_tags_from_source();
        assert!(
            declared.len() >= EXPECTED_TAG_COUNT,
            "the source scan found only {} declarations; it is meant to find at \
             least {}. The scan is broken, not the registry — fix the scan before \
             trusting this test.",
            declared.len(),
            EXPECTED_TAG_COUNT
        );

        let mut declared_bytes: Vec<Vec<u8>> = declared.iter().map(|(_, b)| b.clone()).collect();
        let mut registered_bytes: Vec<Vec<u8>> = all_tags()
            .iter()
            .map(|t| t.source_bytes().to_vec())
            .collect();
        declared_bytes.sort();
        registered_bytes.sort();

        let missing: Vec<String> = declared_bytes
            .iter()
            .filter(|b| !registered_bytes.contains(b))
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .collect();
        assert!(
            missing.is_empty(),
            "declared domain tags that never reach all_tags(): {missing:?}. Every \
             uniqueness and prefix-freedom check in this module traverses that \
             registry, so an unregistered tag is a tag nothing checks."
        );

        assert_eq!(
            declared_bytes, registered_bytes,
            "declared and registered domain tags differ as MULTISETS — either a \
             registry entry has no declaration, or one side carries a duplicate"
        );
    }

    /// Constant names are unique. Checked source-side because the registry does
    /// not carry names; two constants sharing a name cannot both compile, but
    /// this catches the scan finding one twice, which would mask a real gap.
    #[test]
    fn declared_domain_tag_constant_names_are_unique() {
        let declared = declared_tags_from_source();
        let mut names: Vec<&str> = declared.iter().map(|(n, _)| n.as_str()).collect();
        names.sort_unstable();
        let unique: HashSet<&str> = names.iter().copied().collect();
        assert_eq!(
            unique.len(),
            names.len(),
            "a domain-tag constant name was declared more than once"
        );
    }

    /// Change-control tripwire. NOT a completeness guard — see the module note.
    #[test]
    fn the_declared_domain_tag_count_is_the_expected_one() {
        assert_eq!(
            all_tags().len(),
            EXPECTED_TAG_COUNT,
            "the registry size moved. If you added a domain tag, add it to the \
             appropriate TAGS array and bump EXPECTED_TAG_COUNT deliberately."
        );
    }

    /// Targeted membership for the domains a formal proof's premise rests on.
    ///
    /// The economic-SMT separation proof (lean4/DSMEconomicSmtSeparation.lean)
    /// reduces its cross-domain non-aliasing obligations to "these tags are
    /// pairwise distinct". That premise is only as strong as the registry the
    /// distinctness test traverses, so these eight are asserted present by name
    /// rather than left to the count. The two add-device signing domains are
    /// here because they are exactly what the registry was missing.
    #[test]
    fn the_domains_a_proof_depends_on_are_registered() {
        let registered: HashSet<Vec<u8>> = all_tags()
            .iter()
            .map(|t| t.source_bytes().to_vec())
            .collect();

        let required: &[&[u8]] = &[
            // The eight economic-SMT domains frozen by amendment 2c-C2.
            b"DSM/economic-balance-key/v1",
            b"DSM/economic-vault-reserve-key/v1",
            b"DSM/economic-settlement-receipt-key/v1",
            b"DSM/economic-consumed-source-key/v1",
            b"DSM/economic-smt-leaf/v1",
            b"DSM/economic-smt-node/v1",
            b"DSM/economic-leaf-state/v1",
            b"DSM/trader-economic-root-register-key/v1",
            // The two production signing domains the registry omitted.
            b"DSM/add-device-admission",
            b"DSM/add-device-self-attest",
        ];

        for tag in required {
            assert!(
                registered.contains(*tag),
                "{} is not in all_tags(), so no uniqueness or prefix-freedom \
                 check covers it",
                String::from_utf8_lossy(tag)
            );
        }
    }
}
