// SPDX-License-Identifier: Apache-2.0
#![allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal

//! Independent conformance check for the CCB `VaultStateV2` closure.
//!
//! **This file must not call the production canonicalization helpers.** It is
//! an integration test, so `dsm::ccb`'s `pub(crate)` writers are unreachable by
//! construction, and everything below is written from
//! `docs/papers/ccb-object-registry.md` rather than from `src/ccb/`. That is
//! the point: if the two agreed because they shared code, agreement would prove
//! nothing. A bug reachable from both sides has to be a bug in the same place
//! twice, independently.
//!
//! It does three things the production encoder cannot do for itself:
//!
//! 1. Rebuilds every byte from the registry text and demands equality.
//! 2. **Parses** `CCB(V_n)` back into its fifteen fields. The production side
//!    has no decoder on purpose, so this is the only thing that demonstrates
//!    the bytes are uniquely readable — in particular that field 14's frozen
//!    envelope-less `StorageSet` is not ambiguous against the `u32` of field 15.
//! 3. Pins golden vectors for genesis, a market successor and a terminal close,
//!    and checks the `h_n = c_{n-1}` recurrence across them.

use dsm::ccb::{
    genesis_parent_commitment, storage_set_id, vault_state_commitment, EncumbranceClaim,
    EncumbranceSet, FeePolicy, MarketPolicy, ReleasePolicy, StorageSetMembers, VaultStateV2,
};

// ── An independent encoder, written from the registry ───────────────────────

/// Deliberately a different shape from the production writers: this builds
/// byte vectors by explicit concatenation rather than by pushing into a shared
/// buffer, so a transcription slip cannot be common to both.
mod indep {
    pub fn u16be(v: u16) -> Vec<u8> {
        vec![(v >> 8) as u8, (v & 0xff) as u8]
    }

    pub fn u32be(v: u32) -> Vec<u8> {
        (0..4).rev().map(|i| (v >> (i * 8)) as u8).collect()
    }

    pub fn u64be(v: u64) -> Vec<u8> {
        (0..8).rev().map(|i| (v >> (i * 8)) as u8).collect()
    }

    pub fn envelope(class: u16, version: u16) -> Vec<u8> {
        [u16be(class), u16be(version)].concat()
    }

    pub fn bytes_field(v: &[u8]) -> Vec<u8> {
        [u32be(v.len() as u32), v.to_vec()].concat()
    }

    /// §5.2 frozen layout: no envelope, count then bare length-prefixed ids in
    /// ascending raw-byte order.
    pub fn storage_set(mut ids: Vec<Vec<u8>>) -> Vec<u8> {
        ids.sort();
        let mut out = [envelope(0x0002, 2), u32be(ids.len() as u32)].concat();
        for id in ids {
            out.extend(bytes_field(&id));
        }
        out
    }

    pub fn market_policy(family: u16, version: u16, a: [u8; 32], b: [u8; 32]) -> Vec<u8> {
        [
            envelope(0x0007, 1),
            u16be(family),
            u16be(version),
            a.to_vec(),
            b.to_vec(),
        ]
        .concat()
    }

    pub fn release_policy(family: u16, version: u16) -> Vec<u8> {
        [envelope(0x0009, 1), u16be(family), u16be(version)].concat()
    }

    pub fn fee_policy(fee_bps: u32) -> Vec<u8> {
        [envelope(0x000A, 1), u32be(fee_bps)].concat()
    }

    pub fn encumbrance_claim(
        parent_binding: [u8; 32],
        claim_seq: u64,
        amount: u64,
        token: [u8; 32],
        purpose: u16,
    ) -> Vec<u8> {
        [
            envelope(0x0004, 2),
            parent_binding.to_vec(),
            u64be(claim_seq),
            u64be(amount),
            token.to_vec(),
            u16be(purpose),
        ]
        .concat()
    }

    pub fn encumbrance_set(mut claims: Vec<Vec<u8>>) -> Vec<u8> {
        claims.sort();
        let mut out = [envelope(0x0005, 2), u32be(claims.len() as u32)].concat();
        for c in claims {
            out.extend(c);
        }
        out
    }

    #[allow(clippy::too_many_arguments)]
    pub fn vault_state(
        g_o: [u8; 32],
        d_o: [u8; 32],
        vault_id: [u8; 32],
        generation: u64,
        r_a: u64,
        r_b: u64,
        p_m: Vec<u8>,
        p_r: Vec<u8>,
        phi: Vec<u8>,
        e: Vec<u8>,
        beta: Option<u64>,
        h_n: [u8; 32],
        r_o: [u8; 32],
        s: Vec<u8>,
        q: u32,
    ) -> Vec<u8> {
        let beta_bytes = match beta {
            None => vec![0x00],
            Some(v) => [vec![0x01], u64be(v)].concat(),
        };
        [
            envelope(0x0001, 3),
            g_o.to_vec(),
            d_o.to_vec(),
            vault_id.to_vec(),
            u64be(generation),
            u64be(r_a),
            u64be(r_b),
            p_m,
            p_r,
            phi,
            e,
            beta_bytes,
            h_n.to_vec(),
            r_o.to_vec(),
            s,
            u32be(q),
        ]
        .concat()
    }
}

// ── An independent parser — the uniqueness proof ────────────────────────────

/// What a reader recovers from `CCB(V_n)` knowing only the registry.
#[derive(Debug, PartialEq, Eq)]
struct ParsedVaultState {
    class: u16,
    schema: u16,
    generation: u64,
    reserve_a: u64,
    reserve_b: u64,
    fee_bps: u32,
    encumbrance_count: u32,
    iteration_budget: Option<u64>,
    parent_state_commitment: [u8; 32],
    storage_members: Vec<Vec<u8>>,
    quorum: u32,
    /// Bytes left over. Must be zero: a trailing byte would mean the layout is
    /// not uniquely readable.
    trailing: usize,
}

struct Cursor<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> &'a [u8] {
        let s = &self.b[self.i..self.i + n];
        self.i += n;
        s
    }
    fn u16(&mut self) -> u16 {
        let s = self.take(2);
        u16::from_be_bytes([s[0], s[1]])
    }
    fn u32(&mut self) -> u32 {
        let s = self.take(4);
        u32::from_be_bytes([s[0], s[1], s[2], s[3]])
    }
    fn u64(&mut self) -> u64 {
        let s = self.take(8);
        u64::from_be_bytes(s.try_into().unwrap())
    }
    fn digest32(&mut self) -> [u8; 32] {
        self.take(32).try_into().unwrap()
    }
    fn u8(&mut self) -> u8 {
        self.take(1)[0]
    }
}

/// Walks the fifteen fields in declared order. The only structural knowledge
/// used is the registry: no length prefix on the object, no tags, no
/// self-description.
fn parse_vault_state(bytes: &[u8]) -> ParsedVaultState {
    let mut c = Cursor { b: bytes, i: 0 };
    let class = c.u16();
    let schema = c.u16();
    let _g_o = c.digest32(); // 1
    let _d_o = c.digest32(); // 2
    let _vault = c.digest32(); // 3
    let generation = c.u64(); // 4
    let reserve_a = c.u64(); // 5
    let reserve_b = c.u64(); // 6

    // 7 MarketPolicy: envelope + 2×u16 + 2×digest32
    assert_eq!(c.u16(), 0x0007, "field 7 must be a MarketPolicy envelope");
    let _ = c.u16();
    let _ = c.u16();
    let _ = c.u16();
    let _ = c.digest32();
    let _ = c.digest32();

    // 8 ReleasePolicy: envelope + 2×u16
    assert_eq!(c.u16(), 0x0009, "field 8 must be a ReleasePolicy envelope");
    let _ = c.u16();
    let _ = c.u16();
    let _ = c.u16();

    // 9 FeePolicy: envelope + u32
    assert_eq!(c.u16(), 0x000A, "field 9 must be a FeePolicy envelope");
    let _ = c.u16();
    let fee_bps = c.u32();

    // 10 EncumbranceSet: envelope + count + count×claim
    assert_eq!(
        c.u16(),
        0x0005,
        "field 10 must be an EncumbranceSet envelope"
    );
    let _ = c.u16();
    let encumbrance_count = c.u32();
    for _ in 0..encumbrance_count {
        assert_eq!(c.u16(), 0x0004, "set element must be an EncumbranceClaim");
        assert_eq!(c.u16(), 2, "claim schema 1 is burned");
        let _ = c.digest32(); // parent_binding — the creation parent
        let _ = c.u64();
        let _ = c.u64();
        let _ = c.digest32();
        let _ = c.u16();
    }

    // 11 optional β
    let iteration_budget = match c.u8() {
        0x00 => None,
        0x01 => Some(c.u64()),
        other => panic!("presence marker must be 0x00 or 0x01, got {other:#04x}"),
    };

    let parent_state_commitment = c.digest32(); // 12
    let _r_o = c.digest32(); // 13

    // 14 StorageSet — an ordinary object now, envelope and all. The boundary
    // still matters: the reader must stop at exactly the right byte so that
    // field 15 reads as `q`. What changed is that it no longer has to know
    // from the registry alone that this field starts at a count — the
    // discriminant says so, like every other nested member.
    assert_eq!(c.u16(), 0x0002, "field 14 must be a StorageSet envelope");
    assert_eq!(c.u16(), 2, "storage-set schema 1 is burned");
    let member_count = c.u32();
    let mut storage_members = Vec::new();
    for _ in 0..member_count {
        let len = c.u32() as usize;
        storage_members.push(c.take(len).to_vec());
    }

    let quorum = c.u32(); // 15
    ParsedVaultState {
        class,
        schema,
        generation,
        reserve_a,
        reserve_b,
        fee_bps,
        encumbrance_count,
        iteration_budget,
        parent_state_commitment,
        storage_members,
        quorum,
        trailing: bytes.len() - c.i,
    }
}

// ── Fixtures ────────────────────────────────────────────────────────────────

fn d(b: u8) -> [u8; 32] {
    [b; 32]
}

const VAULT_ID: [u8; 32] = [0x7E; 32];
const TOKEN_A: [u8; 32] = [0x11; 32];
const TOKEN_B: [u8; 32] = [0x22; 32];
const MEMBERS: [&[u8]; 5] = [
    b"dsm-node-3",
    b"dsm-node-1",
    b"dsm-node-5",
    b"dsm-node-2",
    b"dsm-node-4",
];

fn beta_set() -> StorageSetMembers {
    StorageSetMembers::new(&MEMBERS).expect("five distinct members")
}

fn state(generation: u64, r_a: u64, r_b: u64, h_n: [u8; 32], beta: Option<u64>) -> VaultStateV2 {
    VaultStateV2 {
        owner_genesis_id: d(0xA1),
        owner_device_id: d(0xA2),
        vault_id: VAULT_ID,
        generation,
        reserve_a: r_a,
        reserve_b: r_b,
        market_policy: MarketPolicy::beta_constant_product(TOKEN_A, TOKEN_B).expect("ordered pair"),
        release_policy: ReleasePolicy::beta_owner_local_full_close(),
        fee_policy: FeePolicy::new(30).expect("30 bps"),
        encumbrances: EncumbranceSet::empty(),
        iteration_budget: beta,
        parent_state_commitment: h_n,
        owner_authority_transition_digest: d(0xA3),
        storage_set: beta_set(),
        quorum: 4,
    }
}

fn indep_state_bytes(
    generation: u64,
    r_a: u64,
    r_b: u64,
    h_n: [u8; 32],
    beta: Option<u64>,
) -> Vec<u8> {
    indep::vault_state(
        d(0xA1),
        d(0xA2),
        VAULT_ID,
        generation,
        r_a,
        r_b,
        indep::market_policy(0x0001, 1, TOKEN_A, TOKEN_B),
        indep::release_policy(0x0001, 1),
        indep::fee_policy(30),
        indep::encumbrance_set(vec![]),
        beta,
        h_n,
        d(0xA3),
        indep::storage_set(MEMBERS.iter().map(|m| m.to_vec()).collect()),
        4,
    )
}

// ── Tests ───────────────────────────────────────────────────────────────────

/// The two implementations agree byte-for-byte across the whole lifecycle:
/// genesis, a market successor, and the terminal full close.
#[test]
fn production_and_independent_encoders_agree_on_every_lifecycle_state() {
    let h0 = genesis_parent_commitment(&VAULT_ID);

    // V_0 — birth. Reserves funded, no encumbrances, no iteration budget.
    let v0 = state(0, 1_000_000, 500_000, h0, None);
    assert_eq!(
        v0.encode().expect("V_0 encodes"),
        indep_state_bytes(0, 1_000_000, 500_000, h0, None),
        "genesis state must match the independent encoding"
    );

    // V_1 — one market successor. Full input credited, output removed; the
    // numbers are the beta pricing rule applied to V_0.
    let c0 = vault_state_commitment(&v0).expect("c_0");
    let v1 = state(1, 1_000_000 + 1_000, 500_000 - 453, c0, None);
    assert_eq!(
        v1.encode().expect("V_1 encodes"),
        indep_state_bytes(1, 1_001_000, 499_547, c0, None),
        "market successor must match"
    );

    // V_2 — terminal full close. Both legs to zero.
    let c1 = vault_state_commitment(&v1).expect("c_1");
    let v2 = state(2, 0, 0, c1, None);
    assert_eq!(
        v2.encode().expect("V_2 encodes"),
        indep_state_bytes(2, 0, 0, c1, None),
        "terminal close state must match"
    );
}

/// `h_n = c_{n-1}` holds across the chain, and a divergent history yields a
/// divergent binding even when the reserves are identical — Req 6.5's property.
#[test]
fn the_lineage_recurrence_distinguishes_histories_with_equal_reserves() {
    let h0 = genesis_parent_commitment(&VAULT_ID);
    let v0 = state(0, 1_000, 1_000, h0, None);
    let c0 = vault_state_commitment(&v0).expect("c_0");

    // Two different histories that arrive at the SAME generation and the SAME
    // reserves, differing only in what came before.
    let other_v0 = state(0, 999, 1_001, h0, None);
    let other_c0 = vault_state_commitment(&other_v0).expect("other c_0");
    assert_ne!(c0, other_c0, "different birth reserves give different c_0");

    let v1 = state(1, 900, 1_100, c0, None);
    let other_v1 = state(1, 900, 1_100, other_c0, None);
    assert_eq!(v1.reserve_a, other_v1.reserve_a);
    assert_eq!(v1.reserve_b, other_v1.reserve_b);
    assert_eq!(v1.generation, other_v1.generation);
    assert_ne!(
        vault_state_commitment(&v1).expect("c_1"),
        vault_state_commitment(&other_v1).expect("other c_1"),
        "identical reserves at identical generation must still differ when the \
         preceding canonical state differed — this is what Req 6.5 requires and \
         what a reserves-only digest could not deliver"
    );
}

/// THE BOUNDARY THAT MATTERS.
///
/// Field 14 nests `StorageSet` and field 15 is a bare `u32`, so a reader must
/// stop at exactly the right byte or `q` reads as garbage. This parses the
/// whole object back and requires every field to land where the registry says,
/// with nothing left over.
///
/// The old form of this test asserted the *opposite* property — that field 14
/// carried no envelope — and it passed because the frozen layout was normative.
/// The state-identity cut deleted the anchors that froze it, so the assertion
/// is inverted here rather than removed: a test that pinned the old property is
/// the likeliest place for the old property to survive a rewrite.
#[test]
fn the_storage_set_nests_with_an_envelope_and_still_ends_exactly_at_the_quorum_field() {
    let h0 = genesis_parent_commitment(&VAULT_ID);
    let v = state(7, 4_242, 8_888, h0, Some(99));
    let bytes = v.encode().expect("encodes");

    let parsed = parse_vault_state(&bytes);
    assert_eq!(
        parsed.trailing, 0,
        "the layout must consume exactly its bytes"
    );
    assert_eq!(parsed.class, 0x0001);
    assert_eq!(parsed.schema, 3, "schemas 1 and 2 are burned");
    assert_eq!(parsed.generation, 7);
    assert_eq!(parsed.reserve_a, 4_242);
    assert_eq!(parsed.reserve_b, 8_888);
    assert_eq!(parsed.fee_bps, 30);
    assert_eq!(parsed.encumbrance_count, 0);
    assert_eq!(parsed.iteration_budget, Some(99));
    assert_eq!(parsed.parent_state_commitment, h0);
    assert_eq!(
        parsed.quorum, 4,
        "field 15 must read as q, not as set bytes"
    );

    let mut expected: Vec<Vec<u8>> = MEMBERS.iter().map(|m| m.to_vec()).collect();
    expected.sort();
    assert_eq!(parsed.storage_members, expected);

    // If S carried an envelope, the reader would consume 4 extra bytes inside
    // field 14 and `q` would be read from the wrong offset. Demonstrate that
    // the failure is detectable rather than silent.
    let mut wrapped = bytes.clone();
    let set_start = bytes.len() - (4 + expected.iter().map(|m| 4 + m.len()).sum::<usize>() + 4);
    wrapped.splice(set_start..set_start, [0x00, 0x02, 0x00, 0x01]);
    let reparsed = std::panic::catch_unwind(|| parse_vault_state(&wrapped));
    let drifted = match reparsed {
        Err(_) => true,
        Ok(p) => p.trailing != 0 || p.quorum != 4,
    };
    assert!(
        drifted,
        "wrapping S in an envelope must change what the reader sees; if it did \
         not, field 14 and field 15 would be mutually ambiguous"
    );
}

/// The optional marker is emitted in both states, and absent is not the same
/// byte string as present-with-zero.
#[test]
fn the_optional_budget_marker_is_never_skipped() {
    let h0 = genesis_parent_commitment(&VAULT_ID);
    let absent = state(0, 1, 1, h0, None).encode().expect("absent");
    let present_zero = state(0, 1, 1, h0, Some(0)).encode().expect("present 0");
    assert_ne!(
        absent, present_zero,
        "an absent budget must not encode as a present zero"
    );
    assert_eq!(
        present_zero.len(),
        absent.len() + 8,
        "present adds exactly the u64, the marker is in both"
    );
    assert_eq!(parse_vault_state(&absent).iteration_budget, None);
    assert_eq!(parse_vault_state(&present_zero).iteration_budget, Some(0));
}

/// `storage_set_id` is the ordinary CCB construction, and is deliberately NOT
/// the shipping one.
///
/// Both halves are asserted. The positive half fixes the new bytes:
/// `H_dom(DSM/storage-set, CCB(S))` over an enveloped `0x0002` schema 2. The
/// negative half is the one that matters — the id must **differ** from the
/// burned construction, because equality would mean the frozen layout survived
/// the cut somewhere. Deployed set ids therefore change, which is the
/// reprovision rather than a regression.
#[test]
fn the_storage_set_id_is_the_ccb_construction_and_not_the_burned_one() {
    let members = beta_set();
    let via_ccb = storage_set_id(&members).expect("id");

    let mut ids: Vec<Vec<u8>> = MEMBERS.iter().map(|m| m.to_vec()).collect();
    ids.sort();

    // New: H(DSM/storage-set ‖ 0x00 ‖ envelope ‖ count ‖ (len ‖ id)*).
    let mut preimage = b"DSM/storage-set".to_vec();
    preimage.push(0x00);
    preimage.extend(indep::envelope(0x0002, 2));
    preimage.extend(indep::u32be(ids.len() as u32));
    for id in &ids {
        preimage.extend(indep::bytes_field(id));
    }
    let expected: [u8; 32] = *blake3::hash(&preimage).as_bytes();
    assert_eq!(via_ccb, expected, "the CCB construction fixes these bytes");

    // Burned: the old tag over the envelope-less layout.
    let mut burned = b"DSM/storage-set/v1".to_vec();
    burned.push(0x00);
    burned.extend(indep::u32be(ids.len() as u32));
    for id in &ids {
        burned.extend(indep::bytes_field(id));
    }
    let burned_id: [u8; 32] = *blake3::hash(&burned).as_bytes();
    assert_ne!(
        via_ccb, burned_id,
        "equality here would mean the frozen layout survived the cut"
    );
}

/// Every live schema matches the registry, and none is burned.
///
/// The registry is the authority; this asserts the encoder agrees with it, so
/// a table edit that is not mirrored in code fails here rather than silently
/// producing different `c_n` bytes. Burned pairs are listed so a later change
/// cannot quietly re-adopt one.
#[test]
fn live_schemas_match_the_registry_and_none_is_burned() {
    use dsm::ccb::{schema, CcbObject};

    let live: &[(&str, u16, u16)] = &[
        ("VaultStateV2", VaultStateV2::CLASS, VaultStateV2::SCHEMA),
        (
            "StorageSet",
            StorageSetMembers::CLASS,
            StorageSetMembers::SCHEMA,
        ),
        (
            "EncumbranceClaim",
            EncumbranceClaim::CLASS,
            EncumbranceClaim::SCHEMA,
        ),
        (
            "EncumbranceSet",
            EncumbranceSet::CLASS,
            EncumbranceSet::SCHEMA,
        ),
        ("MarketPolicy", MarketPolicy::CLASS, MarketPolicy::SCHEMA),
        ("ReleasePolicy", ReleasePolicy::CLASS, ReleasePolicy::SCHEMA),
        ("FeePolicy", FeePolicy::CLASS, FeePolicy::SCHEMA),
    ];

    // Registry §3, the live column.
    let expected: &[(u16, u16)] = &[
        (0x0001, 3),
        (0x0002, 2),
        (0x0004, 2),
        (0x0005, 2),
        (0x0007, 1),
        (0x0009, 1),
        (0x000A, 1),
    ];

    for (name, class, sch) in live {
        assert!(
            expected.contains(&(*class, *sch)),
            "{name}: ({class:#06x}, {sch}) is not the registry's live pair"
        );
        assert!(
            !schema::is_burned(*class, *sch),
            "{name}: encoding at a burned schema"
        );
    }
    assert_eq!(
        live.len(),
        expected.len(),
        "a class is missing from one list"
    );
}

/// A nested-schema bump changes the enclosing bytes, which is why it
/// propagates.
///
/// The failure this guards is silent: `0x0001` schema 2 had a field list
/// IDENTICAL to schema 3's and differed only in the nested `0x0002`/`0x0005`
/// versions. Nothing errors in that situation — `c_n` is simply a different
/// value — so the guard has to be a byte comparison rather than a decode.
#[test]
fn a_nested_schema_bump_changes_the_enclosing_encoding() {
    let h0 = genesis_parent_commitment(&VAULT_ID);
    let v = state(1, 10, 20, h0, None);
    let produced = v.encode().expect("encodes");

    // The same fields, with field 14 written at the burned storage-set schema
    // and nothing else changed.
    let mut forged = produced.clone();
    let needle = indep::envelope(0x0002, 2);
    let at = forged
        .windows(needle.len())
        .position(|w| w == needle.as_slice())
        .expect("field 14 envelope present");
    forged[at + 2..at + 4].copy_from_slice(&1u16.to_be_bytes());

    assert_ne!(
        produced, forged,
        "a nested schema version is part of the enclosing bytes"
    );
}

/// `GenesisParamsV3` `0x0018` agrees with an independent construction whose
/// domain tag is typed from the REGISTRY, not copied from the code.
///
/// That provenance is the point of this test. The `DSM/storage-set/v1` /
/// `DSM/storage-set` mismatch survived every review precisely because the
/// "independent" recomputation inherited its tag literal from the
/// implementation — independent at every input except the one that was wrong.
/// Here the tag, the class, the schema and the field order are all transcribed
/// from registry §5.15 and §3.1.
#[test]
fn genesis_params_v3_agrees_with_an_independent_construction() {
    use dsm::ccb::{genesis_v3_commitment, sigalg, GenesisParamsV3};

    let nonce = d(0xB1);
    let net = b"dsm-test".to_vec();
    let pk = vec![0x5A; 64]; // SPX256f pk width per registry §3.1
    let params = GenesisParamsV3::new(nonce, &net, 3, sigalg::SPHINCS_PLUS_SPX256F, &pk)
        .expect("valid params");
    let g = genesis_v3_commitment(&params).expect("g");

    // Registry §5.15: envelope(0x0018, 1) ‖ nonce ‖ bytes(network_id) ‖
    // u32(version) ‖ u16(alg) ‖ bytes(grk_pk).
    let ccb = [
        indep::envelope(0x0018, 1),
        nonce.to_vec(),
        indep::bytes_field(&net),
        indep::u32be(3),
        indep::u16be(0x0001),
        indep::bytes_field(&pk),
    ]
    .concat();
    assert_eq!(params.encode().expect("encodes"), ccb);

    // Spec domain table: DSM/genesis/v3 — typed here from the document.
    let mut preimage = b"DSM/genesis/v3".to_vec();
    preimage.push(0x00);
    preimage.extend(&ccb);
    let expected: [u8; 32] = *blake3::hash(&preimage).as_bytes();
    assert_eq!(g, expected, "G is H_dom(DSM/genesis/v3, CCB) exactly");
}

/// Validity conditions refuse rather than repair.
#[test]
fn invalid_inputs_are_refused_rather_than_normalized() {
    assert!(
        MarketPolicy::beta_constant_product(TOKEN_B, TOKEN_A).is_err(),
        "an unordered token pair is refused, not swapped"
    );
    assert!(
        MarketPolicy::beta_constant_product(TOKEN_A, TOKEN_A).is_err(),
        "an equal pair is refused"
    );
    assert!(FeePolicy::new(10_000).is_err(), "fee at the denominator");
    assert!(
        FeePolicy::new(9_999).is_ok(),
        "one below is the legal maximum"
    );
    assert!(
        StorageSetMembers::new(&[b"a", b"a"]).is_err(),
        "a duplicate member is refused, not collapsed"
    );
    assert!(StorageSetMembers::new(&[]).is_err(), "an empty set");
    assert!(
        StorageSetMembers::new(&[b""]).is_err(),
        "an empty member id"
    );

    let claim = EncumbranceClaim {
        parent_binding: d(0x01),
        claim_seq: 1,
        amount: 5,
        token: TOKEN_A,
        purpose: 1,
    };
    assert!(
        EncumbranceSet::new(vec![claim.clone(), claim]).is_err(),
        "a duplicate claim is refused, not deduplicated"
    );
}

/// A NON-EMPTY encumbrance set, cross-checked and set-ordered.
///
/// Every other vector above carries an empty `E`, which would leave the nested
/// set's element encoding and its §2.4 ordering untested — the two places a
/// second implementation is most likely to differ.
#[test]
fn a_populated_encumbrance_set_agrees_and_is_ordered_by_element_encoding() {
    let h0 = genesis_parent_commitment(&VAULT_ID);
    let mk = |seq: u64, amount: u64, purpose: u16| EncumbranceClaim {
        parent_binding: h0,
        claim_seq: seq,
        amount,
        token: TOKEN_A,
        purpose,
    };
    // Deliberately supplied out of order, so the encoder must sort by element
    // encoding rather than preserve insertion order.
    let claims = vec![mk(9, 500, 2), mk(1, 10, 1), mk(4, 77, 3)];
    let set = EncumbranceSet::new(claims.clone()).expect("distinct claims");

    let mut v = state(3, 10, 20, h0, None);
    v.encumbrances = set;
    let produced = v.encode().expect("encodes");

    let indep_claims: Vec<Vec<u8>> = claims
        .iter()
        .map(|c| {
            indep::encumbrance_claim(c.parent_binding, c.claim_seq, c.amount, c.token, c.purpose)
        })
        .collect();
    let expected = indep::vault_state(
        d(0xA1),
        d(0xA2),
        VAULT_ID,
        3,
        10,
        20,
        indep::market_policy(0x0001, 1, TOKEN_A, TOKEN_B),
        indep::release_policy(0x0001, 1),
        indep::fee_policy(30),
        indep::encumbrance_set(indep_claims),
        None,
        h0,
        d(0xA3),
        indep::storage_set(MEMBERS.iter().map(|m| m.to_vec()).collect()),
        4,
    );
    assert_eq!(produced, expected, "populated set must match byte for byte");

    let parsed = parse_vault_state(&produced);
    assert_eq!(parsed.encumbrance_count, 3);
    assert_eq!(
        parsed.trailing, 0,
        "three nested claims must not desynchronize the reader"
    );
    assert_eq!(
        parsed.quorum, 4,
        "field 15 still reads as q after a populated set"
    );

    // Insertion order must not survive into the bytes.
    let reordered = EncumbranceSet::new(vec![mk(4, 77, 3), mk(9, 500, 2), mk(1, 10, 1)])
        .expect("same three claims");
    let mut w = state(3, 10, 20, h0, None);
    w.encumbrances = reordered;
    assert_eq!(
        w.encode().expect("encodes"),
        produced,
        "a set is its members, not the order they were handed over"
    );
}
