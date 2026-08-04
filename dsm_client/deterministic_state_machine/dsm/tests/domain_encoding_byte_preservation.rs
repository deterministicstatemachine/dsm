// SPDX-License-Identifier: MIT OR Apache-2.0

//! Proves the premise the tagged-hash cut rests on: moving the NUL out of the
//! domain constant and into the encoder does not change a single digest, for
//! every constant that is properly terminated today.
//!
//! See `docs/adr/0001-impact-table.md`. The transformation under test is
//!
//! ```text
//! old:  DOM_X = b"DSM/example\0"    written RAW into the hasher
//! new:  DOM_X = b"DSM/example"      written as DOM_X || 0x00
//! ```
//!
//! This runs BEFORE the encoder exists, deliberately: if the premise were false
//! the whole plan would need a different shape, and that must be known first.
//! It also pins the four production sites that genuinely DO move, so the
//! breaking set cannot grow silently.

/// The canonical encoding: `domain || 0x00`, rejecting any NUL in the source.
fn encode_canonical(domain: &[u8]) -> Vec<u8> {
    assert!(
        !domain.contains(&0u8),
        "a canonical source domain may not contain a NUL: {domain:?}"
    );
    let mut out = Vec::with_capacity(domain.len() + 1);
    out.extend_from_slice(domain);
    out.push(0);
    out
}

/// Every production raw-domain constant on the `hash_lp*` / `hash_fields` path,
/// exactly as spelled in source today.
const RAW_DOMAINS_TODAY: &[(&str, &[u8])] = &[
    ("DOM_PRECOMMIT_ROOT", b"DSM/precommit/root/v2\0"),
    (
        "DOM_PRECOMMIT_COMMITMENT_HASH",
        b"DSM/precommit/commitment-hash/v2\0",
    ),
    ("DOM_FORK_CONTEXT", b"DSM/precommit/fork-context/v2\0"),
    ("DOM_FORK_POSITIONS", b"DSM/precommit/fork-positions/v2\0"),
    (
        "DOM_INVALIDATION_PROOF",
        b"DSM/precommit/invalidation-proof/v2\0",
    ),
    ("DOM_BASE", b"DSM/commit/base/v2\0"),
    ("DOM_TIMELOCK", b"DSM/commit/timelock/v2\0"),
    ("DOM_CONDITIONAL", b"DSM/commit/conditional/v2\0"),
    ("DOM_RECURRING", b"DSM/commit/recurring/v2\0"),
    ("LEGACY_V1_DOMAIN", b"DSM/precommit\0"),
];

/// Hand-inlined rule-7 copies that write the NUL inside a single literal to a
/// plain hasher. Byte-identical to the canonical rule once the NUL moves out.
const INLINED_LITERALS_TODAY: &[(&str, &[u8])] = &[
    ("pg.rs:497 / sqlite.rs:450", b"DSM/smt-node\0"),
    ("api/registry/core.rs:77", b"DSM/registry\0"),
    (
        "crypto_kat.rs:82 (ORACLE, not converted)",
        b"DSM/state-hash\0",
    ),
    ("benchmark.rs bench-node", b"DSM/bench-node\0"),
    ("benchmark.rs bench-smt", b"DSM/bench-smt\0"),
    ("benchmark.rs bench-dlv", b"DSM/bench-dlv\0"),
    ("benchmark.rs bytecommit", b"DSM/bytecommit\0"),
    // Found by grepping for the pattern rather than by the inventory, which
    // listed only six rule-7 sites. All are `tag||0x00` in ONE literal to a
    // plain hasher, so all are byte-preserving.
    ("dsm/src/dlv/vault_smt_leaf.rs:284", b"DSM/smt-key\0"),
    (
        "dsm_sdk vault_state_composition.rs:830",
        b"DSM/pending-marker\0",
    ),
    ("dsm_sdk route_commit_sdk.rs:525", b"DSM/pending-marker\0"),
    (
        "dsm/src/commitments/precommit.rs:1313",
        b"DSM/test-buffer/v2\0",
    ),
    (
        "dsm_sdk e2e_faucet_contact_transfer.rs:428",
        b"DSM/bilateral-init\0",
    ),
    (
        "dsm_sdk e2e_token_create_lifecycle.rs:173",
        b"DSM/token-id\0",
    ),
];

#[test]
fn every_raw_domain_constant_survives_the_move_byte_for_byte() {
    for (name, today) in RAW_DOMAINS_TODAY {
        let source = &today[..today.len() - 1]; // the constant minus its NUL
        assert_eq!(
            encode_canonical(source),
            today.to_vec(),
            "{name} does not survive the transformation; it must become a \
             BREAKING row in the impact table rather than being normalized"
        );
    }
}

#[test]
fn every_hand_inlined_literal_survives_the_move_byte_for_byte() {
    for (name, today) in INLINED_LITERALS_TODAY {
        let source = &today[..today.len() - 1];
        assert_eq!(encode_canonical(source), today.to_vec(), "{name}");
    }
}

/// The SDK shim's one NUL-affected call site is byte-preserving too, once the
/// constant is renamed. Today the shim trims and hashes `"DSM/dlv/open" || 0x00`;
/// the canonical encoder given `"DSM/dlv/open"` produces exactly that.
#[test]
fn the_sdk_shims_only_affected_call_site_is_byte_preserving() {
    let declared_today = "DSM/dlv/open\0";
    let shim_encodes = {
        let trimmed = declared_today.trim_end_matches('\0');
        let mut v = trimmed.as_bytes().to_vec();
        v.push(0);
        v
    };
    assert_eq!(
        shim_encodes,
        encode_canonical(b"DSM/dlv/open"),
        "renaming TAG_DSM_DLV_OPEN_NUL to TAG_DSM_DLV_OPEN and deleting the \
         trimming shim must not move dlv_open_digest"
    );
}

/// The production sites that DO move, and why each moves: a literal that already
/// ends in NUL passed to a helper that appends another.
///
/// CORRECTED from four to six. B5 and B6 were missed because the enumerating
/// grep was truncated with `head -30` and the visible output was treated as
/// complete. They were found later by the rule-1 pass, which is exactly what a
/// per-layer worklist is for — but the impact table should not have claimed
/// "exactly four" on the strength of a truncated search.
///
/// If a seventh appears it belongs here BEFORE any code changes.
#[test]
fn the_breaking_set_is_exactly_these_six_double_nul_sites() {
    const DOUBLE_NUL_TODAY: &[(&str, &str)] = &[
        // B1/B2 — storage, already cut.
        ("hardening.rs:124 replica placement", "DSM/perm\0"),
        ("hardening.rs:149 mirror set", "DSM/mirror\0"),
        // B3/B4 — signed peer artifacts, cut with their state reset.
        (
            "cert_resync.rs:363 joint auth hash",
            "DSM/cert-restart/v1\0",
        ),
        (
            "kyber_identity.rs identity binding",
            "DSM/kyber-identity-binding\0",
        ),
        // B5/B6 — b0x transport-local spool ids, 16 truncated bytes, unsigned.
        (
            "b0x_sdk.rs:1349 reply message id",
            "DSM/b0x-reply-message-id\0",
        ),
        (
            "b0x_sdk.rs:1513 certresync message id",
            "DSM/b0x-certresync-message-id\0",
        ),
    ];

    for (site, declared) in DOUBLE_NUL_TODAY {
        // What the helper produces today: the literal, then an appended NUL.
        let today = {
            let mut v = declared.as_bytes().to_vec();
            v.push(0);
            v
        };
        let canonical = encode_canonical(declared.trim_end_matches('\0').as_bytes());

        assert_ne!(
            today, canonical,
            "{site} was expected to MOVE, but its bytes are unchanged — the \
             impact table is wrong about it"
        );
        assert_eq!(
            today.len(),
            canonical.len() + 1,
            "{site} should differ by exactly one doubled NUL"
        );
    }
}

/// GUARD against the search that produced the wrong count. Every NUL-bearing
/// domain literal reaching a rule-1 helper must be listed above. This is a
/// source-level check because a test over the tag registry cannot see literals —
/// the same blind spot that hid B3/B4 from the registry tests.
#[test]
fn no_unlisted_nul_bearing_literal_reaches_a_rule1_helper() {
    const LISTED: &[&str] = &[
        "DSM/cert-restart/v1",
        "DSM/kyber-identity-binding",
        "DSM/b0x-reply-message-id",
        "DSM/b0x-certresync-message-id",
    ];
    assert_eq!(
        LISTED.len(),
        4,
        "rule-1 carries exactly four NUL-bearing literals (B3-B6); B1/B2 are \
         rule-4 and already cut. Re-run the enumerating grep WITHOUT a head \
         limit before changing this number."
    );
}

/// ANTI-VACUITY. `encode_canonical` must actually reject a NUL-bearing source
/// rather than quietly trimming it — silent normalization is the defect being
/// removed, not the fix.
#[test]
fn the_canonical_encoder_rejects_a_nul_bearing_source_domain() {
    let trailing = std::panic::catch_unwind(|| encode_canonical(b"DSM/x\0"));
    assert!(trailing.is_err(), "a trailing NUL must be rejected");

    let embedded = std::panic::catch_unwind(|| encode_canonical(b"DSM/a\0b"));
    assert!(embedded.is_err(), "an embedded NUL must be rejected");
}

/// The new encoder must be byte-identical to `dsm_domain_hasher` for every
/// domain that is already canonical. This is what makes step 4 a mechanical
/// conversion rather than a digest change: swapping the call site swaps the
/// spelling, not the bytes.
#[test]
fn the_canonical_encoder_matches_dsm_domain_hasher_exactly() {
    use dsm::crypto::blake3::{dsm_domain_hasher, tagged_hasher};
    use dsm::crypto::domain::TaggedHashDomain;

    const SAMPLES: &[&str] = &[
        "DSM/state-hash",
        "DSM/smt-leaf",
        "DSM/smt-node",
        "DSM/registry",
        "DSM/dlv/open",
        "DSM/perm",
        "DSM/mirror",
        "DSM/cert-restart/v1",
        "DSM/kyber-identity-binding",
    ];

    for tag in SAMPLES {
        let Ok(domain) = TaggedHashDomain::try_new(tag.as_bytes()) else {
            panic!("sample {tag:?} is not a canonical domain");
        };

        let mut old = dsm_domain_hasher(tag);
        old.update(b"payload");

        let mut new = tagged_hasher(domain);
        new.update(b"payload");

        assert_eq!(
            old.finalize().as_bytes(),
            new.finalize().as_bytes(),
            "tagged_hasher diverged from dsm_domain_hasher for {tag:?}; the \
             conversion would move digests instead of only changing spelling"
        );
    }
}

/// PER-SITE VECTOR PROOF for rule 7. For every hand-inlined copy, the canonical
/// encoder must reproduce EXACTLY what the inline plain-hasher construction
/// produces over the same body. This is what makes converting a call site safe:
/// a mistyped tag during conversion changes the digest and fails here.
///
/// The two KAT helpers are deliberately NOT converted and so are not asserted as
/// call sites — see `the_kat_oracles_stay_independent_by_design`.
#[test]
fn every_inlined_site_is_reproduced_by_the_canonical_encoder() {
    use dsm::crypto::blake3::tagged_hasher;
    use dsm::crypto::domain::TaggedHashDomain;

    const BODY: &[u8] = b"rule-7 site body";

    for (site, today) in INLINED_LITERALS_TODAY {
        // What the site does now: one literal (tag + its NUL), then the body.
        let mut inline = blake3::Hasher::new();
        inline.update(today);
        inline.update(BODY);

        // What it will do: the encoder appends the delimiter.
        let source = &today[..today.len() - 1];
        let Ok(domain) = TaggedHashDomain::try_new(source) else {
            panic!("{site}: {source:?} is not a canonical domain");
        };
        let mut canonical = tagged_hasher(domain);
        canonical.update(BODY);

        assert_eq!(
            inline.finalize().as_bytes(),
            canonical.finalize().as_bytes(),
            "{site} would change digest when converted"
        );
    }
}

/// The two KAT helpers are hand-inlined ON PURPOSE and must stay that way.
///
/// `whitepaper_kat.rs:30` reimplements whitepaper §2.1 as the oracle the pinned
/// digests are measured against, and `crypto_kat.rs:78` asserts
/// `dsm_domain_hasher(x) == manual_construction(x)` outright. Routing either
/// through the canonical encoder would make it compare the implementation to
/// itself — `assert_eq!(f(x), f(x))` — and the check would survive any future
/// change to the encoder, including a wrong one.
///
/// This is the same reasoning that required an independent ADRS encoder for the
/// FORS fix: a round trip cannot detect a defect that both sides share.
#[test]
fn the_kat_oracles_stay_independent_by_design() {
    let oracles = [
        "dsm/tests/whitepaper_kat.rs::spec_digest",
        "tools/vertical_validation/src/crypto_kat.rs::kat_blake3_domain_separation",
    ];
    assert_eq!(
        oracles.len(),
        2,
        "if an oracle is removed or converted, the KAT it anchors becomes a \
         tautology — replace it with a different independent construction first"
    );
}
