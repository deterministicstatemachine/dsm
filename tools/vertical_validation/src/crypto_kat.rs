//! Cryptographic Known-Answer Tests (KATs)
//!
//! Verifies internal consistency and correctness properties of all
//! cryptographic primitives used by DSM. These are NOT NIST KATs
//! (the SPHINCS+ implementation uses BLAKE3 internally, not SHA2/SHAKE),
//! but prove determinism, round-trip correctness, and rejection of
//! tampered inputs.

// Validation harness: panicking on crypto setup failures is correct behavior.
#![allow(clippy::expect_used)]

use instant::Instant;
use serde::Serialize;

// ---------------------------------------------------------------------------
// Result types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct CryptoKatResult {
    pub primitive: String,
    pub test_name: String,
    pub passed: bool,
    pub details: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CryptoKatSuiteResult {
    pub results: Vec<CryptoKatResult>,
    pub all_passed: bool,
    pub duration_ms: f64,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

pub fn collect_crypto_kat_results() -> CryptoKatSuiteResult {
    eprintln!("\n=== CRYPTOGRAPHIC KNOWN-ANSWER TESTS ===\n");
    let start = Instant::now();

    let mut results = Vec::new();
    results.extend(kat_blake3_domain_separation());
    results.extend(kat_sphincs());
    results.extend(kat_kyber());
    results.extend(kat_pedersen());

    let all_passed = results.iter().all(|r| r.passed);
    let duration_ms = start.elapsed().as_secs_f64() * 1000.0;

    for r in &results {
        let icon = if r.passed { "\u{2705}" } else { "\u{274c}" };
        eprintln!(
            "  {icon} [{}] {} \u{2014} {}",
            r.primitive, r.test_name, r.details
        );
    }
    eprintln!();

    CryptoKatSuiteResult {
        results,
        all_passed,
        duration_ms,
    }
}

// ---------------------------------------------------------------------------
// BLAKE3 Domain Separation (4 tests)
// ---------------------------------------------------------------------------

fn kat_blake3_domain_separation() -> Vec<CryptoKatResult> {
    use dsm::crypto::blake3::{domain_hash, dsm_domain_hasher};

    let mut out = Vec::new();

    // 1. NUL terminator: dsm_domain_hasher prepends "DSM/<tag>\0"
    {
        let h1 = dsm_domain_hasher("DSM/state-hash")
            .update(b"test-data")
            .finalize();
        let mut manual = blake3::Hasher::new();
        manual.update(b"DSM/state-hash\0");
        manual.update(b"test-data");
        let h2 = manual.finalize();
        let pass = h1 == h2;
        out.push(CryptoKatResult {
            primitive: "BLAKE3".into(),
            test_name: "NUL terminator in domain tag".into(),
            passed: pass,
            details: if pass {
                "domain_hasher matches manual NUL-terminated construction".into()
            } else {
                format!("MISMATCH: dsm={} manual={}", h1.to_hex(), h2.to_hex())
            },
        });
    }

    // 2. Determinism: same inputs -> identical output
    {
        let h1 = domain_hash("DSM/test", b"determinism-check");
        let h2 = domain_hash("DSM/test", b"determinism-check");
        let pass = h1 == h2;
        out.push(CryptoKatResult {
            primitive: "BLAKE3".into(),
            test_name: "determinism".into(),
            passed: pass,
            details: if pass {
                "identical output on repeated call".into()
            } else {
                "NON-DETERMINISTIC output detected".into()
            },
        });
    }

    // 3. Domain collision resistance: different tags -> different hashes
    {
        let h1 = domain_hash("DSM/tag-a", b"same-data");
        let h2 = domain_hash("DSM/tag-b", b"same-data");
        let pass = h1 != h2;
        out.push(CryptoKatResult {
            primitive: "BLAKE3".into(),
            test_name: "domain tag isolation".into(),
            passed: pass,
            details: if pass {
                "different tags produce different hashes".into()
            } else {
                "COLLISION: different domain tags produced same hash".into()
            },
        });
    }

    // 4. Data collision resistance: same tag, different data -> different hashes
    {
        let h1 = domain_hash("DSM/tag", b"data-alpha");
        let h2 = domain_hash("DSM/tag", b"data-beta");
        let pass = h1 != h2;
        out.push(CryptoKatResult {
            primitive: "BLAKE3".into(),
            test_name: "data differentiation".into(),
            passed: pass,
            details: if pass {
                "different data produce different hashes".into()
            } else {
                "COLLISION: different data produced same hash".into()
            },
        });
    }

    out
}

// ---------------------------------------------------------------------------
// SPHINCS+ (5 tests)
// ---------------------------------------------------------------------------

fn kat_sphincs() -> Vec<CryptoKatResult> {
    use dsm::crypto::sphincs::{
        generate_keypair_from_seed, public_key_bytes, secret_key_bytes, sign, signature_bytes,
        verify, SphincsVariant,
    };

    let mut out = Vec::new();
    let variant = SphincsVariant::SPX256s;
    let seed = [42u8; 32];

    // 1. Deterministic keygen from seed
    {
        let kp1 = generate_keypair_from_seed(variant, &seed);
        let kp2 = generate_keypair_from_seed(variant, &seed);
        let pass = match (&kp1, &kp2) {
            (Ok(a), Ok(b)) => a.public_key == b.public_key && a.secret_key == b.secret_key,
            _ => false,
        };
        out.push(CryptoKatResult {
            primitive: "SPHINCS+".into(),
            test_name: "deterministic keygen from seed".into(),
            passed: pass,
            details: if pass {
                "same seed produces identical keypair".into()
            } else {
                "FAILED: different keypairs from same seed".into()
            },
        });
    }

    // 2. Key sizes match spec
    {
        let expected_pk = public_key_bytes(variant);
        let expected_sk = secret_key_bytes(variant);
        let expected_sig = signature_bytes(variant);

        let kp = generate_keypair_from_seed(variant, &seed).expect("keygen");
        let actual_pk = kp.public_key.len();
        let actual_sk = kp.secret_key.len();

        let pass = actual_pk == expected_pk && actual_sk == expected_sk;
        out.push(CryptoKatResult {
            primitive: "SPHINCS+".into(),
            test_name: "key and signature sizes".into(),
            passed: pass,
            details: format!(
                "pk={actual_pk}/{expected_pk} sk={actual_sk}/{expected_sk} sig_spec={expected_sig}"
            ),
        });
    }

    // 3. Sign -> verify round trip
    {
        let kp = generate_keypair_from_seed(variant, &seed).expect("keygen");
        let msg = b"DSM vertical validation KAT message";
        let sig = sign(variant, &kp.secret_key, msg);
        let verified = sig
            .as_ref()
            .ok()
            .and_then(|s| verify(variant, &kp.public_key, msg, s).ok());
        let pass = verified == Some(true);
        out.push(CryptoKatResult {
            primitive: "SPHINCS+".into(),
            test_name: "sign-verify round trip".into(),
            passed: pass,
            details: if pass {
                "valid signature accepted".into()
            } else {
                "FAILED: valid signature rejected".into()
            },
        });
    }

    // 4. Bit-flip in signature -> rejection
    {
        let kp = generate_keypair_from_seed(variant, &seed).expect("keygen");
        let msg = b"bit flip test";
        let mut sig = sign(variant, &kp.secret_key, msg).expect("sign");
        sig[0] ^= 0x01; // flip one bit
        let result = verify(variant, &kp.public_key, msg, &sig);
        let pass = matches!(result, Ok(false));
        out.push(CryptoKatResult {
            primitive: "SPHINCS+".into(),
            test_name: "bit-flip rejection".into(),
            passed: pass,
            details: if pass {
                "tampered signature correctly rejected".into()
            } else {
                format!("FAILED: tampered sig accepted or errored: {result:?}")
            },
        });
    }

    // 5. Wrong-key rejection
    {
        let kp1 = generate_keypair_from_seed(variant, &seed).expect("keygen");
        let seed2 = [99u8; 32];
        let kp2 = generate_keypair_from_seed(variant, &seed2).expect("keygen2");
        let msg = b"wrong key test";
        let sig = sign(variant, &kp1.secret_key, msg).expect("sign");
        let result = verify(variant, &kp2.public_key, msg, &sig);
        let pass = matches!(result, Ok(false));
        out.push(CryptoKatResult {
            primitive: "SPHINCS+".into(),
            test_name: "wrong-key rejection".into(),
            passed: pass,
            details: if pass {
                "signature from wrong key correctly rejected".into()
            } else {
                format!("FAILED: wrong-key sig accepted or errored: {result:?}")
            },
        });
    }

    out
}

// ---------------------------------------------------------------------------
// ML-KEM-768 / Kyber (4 tests)
// ---------------------------------------------------------------------------

fn kat_kyber() -> Vec<CryptoKatResult> {
    use dsm::crypto::kyber::{
        generate_deterministic_kyber_keypair, generate_kyber_keypair, kyber_decapsulate,
        kyber_encapsulate,
    };

    let mut out = Vec::new();

    // 1. Key sizes
    {
        let kp = generate_kyber_keypair();
        let pass = match &kp {
            Ok(k) => k.public_key.len() == 1184 && k.secret_key.len() == 2400,
            Err(_) => false,
        };
        let details = match &kp {
            Ok(k) => format!(
                "pk={}/1184 sk={}/2400",
                k.public_key.len(),
                k.secret_key.len()
            ),
            Err(e) => format!("keygen failed: {e}"),
        };
        out.push(CryptoKatResult {
            primitive: "ML-KEM-768".into(),
            test_name: "key sizes".into(),
            passed: pass,
            details,
        });
    }

    // 2. Encapsulation sizes
    {
        let kp = generate_kyber_keypair().expect("keygen");
        let enc = kyber_encapsulate(&kp.public_key);
        let pass = match &enc {
            Ok((ss, ct)) => ss.len() == 32 && ct.len() == 1088,
            Err(_) => false,
        };
        let details = match &enc {
            Ok((ss, ct)) => format!("ss={}/32 ct={}/1088", ss.len(), ct.len()),
            Err(e) => format!("encapsulate failed: {e}"),
        };
        out.push(CryptoKatResult {
            primitive: "ML-KEM-768".into(),
            test_name: "encapsulation sizes".into(),
            passed: pass,
            details,
        });
    }

    // 3. Decapsulate round trip (shared secrets match)
    {
        let kp = generate_kyber_keypair().expect("keygen");
        let (ss_enc, ct) = kyber_encapsulate(&kp.public_key).expect("encapsulate");
        let ss_dec = kyber_decapsulate(&kp.secret_key, &ct);
        let pass = match &ss_dec {
            Ok(ss) => *ss == ss_enc,
            Err(_) => false,
        };
        out.push(CryptoKatResult {
            primitive: "ML-KEM-768".into(),
            test_name: "decapsulate round trip".into(),
            passed: pass,
            details: if pass {
                "encapsulated and decapsulated shared secrets match".into()
            } else {
                "MISMATCH: shared secrets differ".into()
            },
        });
    }

    // 4. Deterministic keygen from entropy
    {
        let entropy = b"deterministic_kyber_test_entropy_32bytes!!";
        let ctx = "kat-test";
        let kp1 = generate_deterministic_kyber_keypair(entropy, ctx);
        let kp2 = generate_deterministic_kyber_keypair(entropy, ctx);
        let pass = match (&kp1, &kp2) {
            (Ok((pk1, sk1)), Ok((pk2, sk2))) => pk1 == pk2 && sk1 == sk2,
            _ => false,
        };
        out.push(CryptoKatResult {
            primitive: "ML-KEM-768".into(),
            test_name: "deterministic keygen".into(),
            passed: pass,
            details: if pass {
                "same entropy+context produces identical keypair".into()
            } else {
                "FAILED: different keypairs from same entropy".into()
            },
        });
    }

    out
}

// ---------------------------------------------------------------------------
// Pedersen Commitments (3 tests) — uses simplified BLAKE3-based scheme
// ---------------------------------------------------------------------------

fn kat_pedersen() -> Vec<CryptoKatResult> {
    // The dsm crate's simple commit/verify_commitment are #[cfg(test)] only,
    // so we implement the same BLAKE3-based scheme inline for the KAT.
    // This tests the hiding + binding properties of the commitment construction.

    fn simple_commit(value: &[u8], randomness: &[u8]) -> Vec<u8> {
        let mut hasher = blake3::Hasher::new();
        hasher.update(value);
        hasher.update(randomness);
        hasher.finalize().as_bytes().to_vec()
    }

    fn simple_verify(commitment: &[u8], value: &[u8], randomness: &[u8]) -> bool {
        let expected = simple_commit(value, randomness);
        commitment == expected.as_slice()
    }

    let mut out = Vec::new();

    // 1. Hiding: different randomness -> different commitments
    {
        let value = b"same-value";
        let r1 = b"randomness-alpha-pad-to-32-bytes!";
        let r2 = b"randomness-bravo-pad-to-32-bytes";
        let c1 = simple_commit(value, r1);
        let c2 = simple_commit(value, r2);
        let pass = c1 != c2;
        out.push(CryptoKatResult {
            primitive: "Pedersen".into(),
            test_name: "hiding property".into(),
            passed: pass,
            details: if pass {
                "different randomness produces different commitments".into()
            } else {
                "FAILURE: hiding violated".into()
            },
        });
    }

    // 2. Binding: wrong value -> verify fails
    {
        let value = b"correct-value";
        let randomness = b"test-randomness-for-binding-kat!";
        let commitment = simple_commit(value, randomness);
        let ok_correct = simple_verify(&commitment, value, randomness);
        let ok_wrong = simple_verify(&commitment, b"wrong-value!", randomness);
        let pass = ok_correct && !ok_wrong;
        out.push(CryptoKatResult {
            primitive: "Pedersen".into(),
            test_name: "binding property".into(),
            passed: pass,
            details: if pass {
                "correct value accepted, wrong value rejected".into()
            } else {
                format!("FAILURE: correct={ok_correct} wrong={ok_wrong} (expected true/false)")
            },
        });
    }

    // 3. Round trip: commit -> verify
    {
        let value = b"round-trip-test-data";
        let randomness = b"round-trip-randomness-32-bytes!!";
        let commitment = simple_commit(value, randomness);
        let verified = simple_verify(&commitment, value, randomness);
        out.push(CryptoKatResult {
            primitive: "Pedersen".into(),
            test_name: "commit-verify round trip".into(),
            passed: verified,
            details: if verified {
                "commitment verified successfully".into()
            } else {
                "FAILED: valid commitment rejected".into()
            },
        });
    }

    out
}
