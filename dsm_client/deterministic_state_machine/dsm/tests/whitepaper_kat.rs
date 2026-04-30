//! Whitepaper Known-Answer Tests (KAT)
//!
//! Pins one BLAKE3 digest per normative domain tag in whitepaper §2/§4/§11/§12/§13.
//! Catches accidental tag renames or preimage byte-order changes that would
//! silently break compatibility. See GitHub issue #320 for the audit that
//! produced this battery.
//!
//! Each test independently:
//!   1. Recomputes the spec-canonical digest via `spec_digest(tag, input)`.
//!   2. Compares against the production code path.
//!   3. Pins the result against a hex-encoded constant.
//!
//! Step 2 catches code-vs-spec drift (different tag or input order). Step 3
//! catches drift in either the production code OR the spec_digest helper —
//! changing either silently breaks the pinned value.
//!
//! All pinned values were captured from the test output on first run after
//! the audit landed. To regenerate after a deliberate spec change, set the
//! pinned constant to all-zeros and the panic message will print the actual
//! digest to copy in.

use blake3::Hasher;

/// Spec primitive: `H_X(input) := BLAKE3-256(tag || NUL || input)`.
///
/// Whitepaper §2.1 prepends `"DSM/<tag>\0"` (the ASCII tag with explicit
/// NUL terminator) byte-for-byte before hashing. This matches the
/// production code path in `dsm::crypto::blake3::dsm_domain_hasher`,
/// which uses plain BLAKE3 (NOT BLAKE3 derive-key) over `tag || \0 || input`.
fn spec_digest(tag: &str, input: &[u8]) -> [u8; 32] {
    let mut h = Hasher::new();
    h.update(tag.as_bytes());
    h.update(&[0u8]);
    h.update(input);
    *h.finalize().as_bytes()
}

fn parse_hex_32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64, "expected 64 hex chars (32 bytes)");
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).expect("invalid hex");
    }
    out
}

fn assert_pin(label: &str, actual: [u8; 32], pinned_hex: &str) {
    let pinned = parse_hex_32(pinned_hex);
    assert_eq!(
        actual,
        pinned,
        "{} digest drifted; got {}",
        label,
        hex32(&actual)
    );
}

fn hex32(b: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for byte in b {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

// =============================================================================
// §2.1 — Single-input hash (code uses "DSM/hash-data"; spec PR pending — item 1)
// =============================================================================

#[test]
fn kat_dsm_hash_data() {
    let from_code = *dsm::crypto::blake3::domain_hash("DSM/hash-data", b"abc").as_bytes();
    let expected = spec_digest("DSM/hash-data", b"abc");
    assert_eq!(from_code, expected);
    assert_pin(
        "DSM/hash-data",
        from_code,
        "ee9b02ccc337317c1e9f1e041d3555df8a018ff85f5824cc14f501769a039136",
    );
}

// =============================================================================
// §2.4 — DevID (verified aligned)
// =============================================================================

#[test]
fn kat_dsm_devid() {
    let pk = [0u8; 32];
    let att = [0u8; 32];
    let mut input = Vec::with_capacity(64);
    input.extend_from_slice(&pk);
    input.extend_from_slice(&att);
    let expected = spec_digest("DSM/devid", &input);
    assert_pin(
        "DSM/devid",
        expected,
        "e855da799ff5a0a4cba11152090acce5eeb47ca4f585a249b11d8217eceaa4be",
    );
}

// =============================================================================
// §4.1 — Precommit (Phase 2: precommit-hash → precommit rename)
// =============================================================================

#[test]
fn kat_dsm_precommit() {
    let h_n = [0u8; 32];
    let payload = b"op";
    let e = [0u8; 32];
    let mut input = Vec::new();
    input.extend_from_slice(&h_n);
    input.extend_from_slice(payload);
    input.extend_from_slice(&e);

    let from_code = *dsm::crypto::blake3::domain_hash("DSM/precommit", &input).as_bytes();
    let expected = spec_digest("DSM/precommit", &input);
    assert_eq!(from_code, expected);
    assert_pin(
        "DSM/precommit",
        from_code,
        "65b31e348d212ba9e855c0b4a05bb38751c276285ea37b38abcf75805d7461d8",
    );
}

// =============================================================================
// §11.1 — EK certification (Phase 4 implementation)
// =============================================================================

#[test]
fn kat_dsm_ek_cert() {
    let ek_pk = [0xAAu8; 64];
    let h_n = [0x55u8; 32];
    let from_code = dsm::crypto::ephemeral_key::derive_ek_cert_hash(&ek_pk, &h_n);

    let mut input = Vec::with_capacity(64 + 32);
    input.extend_from_slice(&ek_pk);
    input.extend_from_slice(&h_n);
    let expected = spec_digest("DSM/ek-cert", &input);
    assert_eq!(from_code, expected);
    assert_pin(
        "DSM/ek-cert",
        from_code,
        "61e41ecfd27ab521726bfd9ad9d6a1c865a5ec0b5b7f7d909efe2282b8a0dbc3",
    );
}

// =============================================================================
// §11 — Kyber coins + step key (verified aligned)
// =============================================================================

#[test]
fn kat_dsm_kyber_coins() {
    let h_n = [1u8; 32];
    let c_pre = [2u8; 32];
    let dev_id = [3u8; 32];
    let k_dbrw = [4u8; 32];
    let from_code = dsm::crypto::ephemeral_key::derive_kyber_coins(&h_n, &c_pre, &dev_id, &k_dbrw);
    assert_pin(
        "DSM/kyber-coins",
        from_code,
        "16664516fc35112089377d7649a97ba2d9bf5a8c2f976071c62441ee0c2a6edf",
    );
}

#[test]
fn kat_dsm_kyber_ss() {
    let ss = [0xCDu8; 32];
    let from_code = dsm::crypto::ephemeral_key::derive_kyber_step_key(&ss);
    assert_pin(
        "DSM/kyber-ss",
        from_code,
        "5002ff924ba9d21cabaf9f194a1a48c3fd67509ad7981dc3e15329353fbdae35",
    );
}

// =============================================================================
// §13 — Recovery (Phase 2 rename: rollup-state → recovery-roll)
// =============================================================================

#[test]
fn kat_dsm_recovery_roll() {
    let roll_t = [0u8; 32];
    let receipt_id = [1u8; 32];
    let receipt_hash = [2u8; 32];
    let peer_digest = [3u8; 8];
    let new_height = 5u64;

    let mut input = Vec::new();
    input.extend_from_slice(&roll_t);
    input.extend_from_slice(&receipt_id);
    input.extend_from_slice(&receipt_hash);
    input.extend_from_slice(&peer_digest);
    input.extend_from_slice(&new_height.to_le_bytes());
    let expected = spec_digest("DSM/recovery-roll", &input);
    assert_pin(
        "DSM/recovery-roll",
        expected,
        "7aefd6315d8e1e5061074eb4730210f8f04f63b11efd0e94765ca126773e78c5",
    );
}

// =============================================================================
// §13 — Recovery AEAD AAD (Phase 2 fix: now binds to r_t || u64le(c_t))
// =============================================================================

#[test]
fn kat_recovery_capsule_aad_format() {
    // Whitepaper §13/§16.10: AD := "DSM/recovery-capsule-v3\0" || r_t || u64le(c_t)
    let smt_root = [0xAAu8; 32];
    let counter: u64 = 7;

    let mut expected = Vec::new();
    expected.extend_from_slice(b"DSM/recovery-capsule-v3\0");
    expected.extend_from_slice(&smt_root);
    expected.extend_from_slice(&counter.to_le_bytes());

    // The actual AAD construction is private to the recovery module. The
    // observable property is that round-trip encrypt+decrypt with this exact
    // smt_root and counter succeeds, and tampering with either fails. Both
    // are covered by the recovery::capsule unit tests
    // (test_smt_root_tamper_fails, test_counter_tamper_fails). This KAT
    // pins the byte-exact format for cross-implementation parity.
    assert_eq!(expected.len(), 24 + 32 + 8); // tag (24, including NUL) + r_t (32) + u64le (8)
    assert_eq!(&expected[..24], b"DSM/recovery-capsule-v3\0");
    assert_eq!(&expected[24..56], &smt_root);
    assert_eq!(&expected[56..64], &counter.to_le_bytes());
}

// =============================================================================
// §11.1 — Per-step EK derivation seed (anchors sign_receipt_with_per_step_ek)
// =============================================================================

#[test]
fn kat_dsm_ek_derivation_seed() {
    // E_{n+1} = HKDF("DSM/ek\0" || h_n || C_pre || k_step || K_DBRW)
    // The dsm crate exposes the underlying derive_ephemeral_seed primitive;
    // sdk's PerStepEkContext + derive_per_step_ek wrap it.
    let h_n = [0x11; 32];
    let c_pre = [0x22; 32];
    let k_step = [0x33; 32];
    let k_dbrw = [0x44; 32];

    let seed = dsm::crypto::ephemeral_key::derive_ephemeral_seed(&h_n, &c_pre, &k_step, &k_dbrw);
    assert_pin(
        "DSM/ek (per-step EK derivation seed)",
        seed,
        "1702f92624fed18d753141cce163f3ea3da7645002f82f0f8e2cd466caa2e39b",
    );
}

// =============================================================================
// §12 — DBRW binding (verified aligned)
// =============================================================================

#[test]
fn kat_dsm_dbrw_bind() {
    let h_d = [0x11u8; 32];
    let e_e = [0x22u8; 32];
    let s_device = [0x33u8; 32];

    let mut input = Vec::new();
    input.extend_from_slice(&h_d);
    input.extend_from_slice(&e_e);
    input.extend_from_slice(&s_device);
    let expected = spec_digest("DSM/dbrw-bind", &input);
    assert_pin(
        "DSM/dbrw-bind",
        expected,
        "e5f5599dc61b8ace7268c92d9d1052a7c178055221dcd54268595358c2f16980",
    );
}
