//! Known answers of the deployed Rust for `Statement/LeanVmGuest.lean`, at the guest's real shape: the
//! claim lists' digests, the DA list's, the statement's digest under the
//! deployed seed, and a batching of two children with true claims on the guest's stacked
//! bytecode (`aggregate_deferred_claims`, its sumcheck over all `bytecode_vars()` variables, then, research build,
//! the matrix batch of the children's fresh Flock claims and carried matrix claims), as
//! `tests/LeanVMTests/Spec/NodeVectors.lean`. The successor of the BLAKE2s-era
//! `node_spec_vectors`; the Lean checks (`#guard`s against the Spec definitions, and the mutations)
//! are hand-written in `tests/LeanVMTests/Spec/Node.lean`.

use super::*;
use lean_sphincs::LeanSphincsPublicKey;
use lean_xmss::LeanXmssPublicKey;
use lean_vm_core::StableProver;
use lean_vm_core::cpu::{from_scalar, to_scalar};
use primitives::field::F128;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use std::fmt::Write as _;

fn element(rng: &mut StdRng) -> F128 {
    F128::new(rng.random(), rng.random())
}

fn elements(rng: &mut StdRng, len: usize) -> Vec<F128> {
    (0..len).map(|_| element(rng)).collect()
}

fn e(x: F128) -> String {
    format!("e 0x{:x} 0x{:x}", x.c0, x.c1)
}

fn es(xs: &[F128]) -> String {
    format!("[{}]", xs.iter().map(|&x| e(x)).collect::<Vec<_>>().join(",\n    "))
}

/// A 32-byte digest as the Spec's four little-endian lanes.
fn digest(d: &[u8; 32]) -> String {
    let lanes: Vec<String> = (0..4)
        .map(|i| format!("0x{:016x}", u64::from_le_bytes(d[8 * i..8 * i + 8].try_into().unwrap())))
        .collect();
    format!("#v[{}]", lanes.join(", "))
}

/// Two cells as a digest (`digestHalves`' inverse).
fn cells_digest(c: &[F128; 2]) -> String {
    format!("#v[0x{:016x}, 0x{:016x}, 0x{:016x}, 0x{:016x}]", c[0].c0, c[0].c1, c[1].c0, c[1].c1)
}

fn le_nat(bytes: &[u8]) -> String {
    let mut hex = String::from("0x");
    for b in bytes.iter().rev() {
        write!(hex, "{b:02x}").unwrap();
    }
    hex
}

fn claim(pk: &[u8; 32], message: &[u8; 32]) -> String {
    format!(
        "(⟨BitVec.ofNat 128 {}, BitVec.ofNat 128 {}⟩, BitVec.ofNat 256 {})",
        le_nat(&pk[..16]),
        le_nat(&pk[16..]),
        le_nat(message)
    )
}

fn bytes32(rng: &mut StdRng) -> [u8; 32] {
    let mut b = [0u8; 32];
    rng.fill(&mut b);
    b
}

pub fn file() -> File {
    let mut rng = StdRng::seed_from_u64(0x6c65_616e_766d);
    let kbcv = bytecode_vars();

    // Claims as raw keys: the root and parameter halves the lists hash.
    let xmss: Vec<([u8; 32], [u8; 32])> = (0..3).map(|_| (bytes32(&mut rng), bytes32(&mut rng))).collect();
    let sphincs: Vec<([u8; 32], [u8; 32])> = (0..2).map(|_| (bytes32(&mut rng), bytes32(&mut rng))).collect();
    let xmss_typed: Vec<LeanXmssClaim> = xmss
        .iter()
        .map(|(pk, m)| {
            let key = LeanXmssPublicKey::from_bytes(pk);
            assert_eq!(&key.to_bytes(), pk);
            (key, *m)
        })
        .collect();
    let sphincs_typed: Vec<LeanSphincsClaim> = sphincs
        .iter()
        .map(|(pk, m)| {
            let key = LeanSphincsPublicKey::from_bytes(pk);
            assert_eq!(&key.to_bytes(), pk);
            (key, *m)
        })
        .collect();
    let xmss_digest = claim_list_digest(xmss_typed.iter().map(lean_xmss_claim_cells));
    let sphincs_digest = claim_list_digest(sphincs_typed.iter().map(lean_sphincs_claim_cells));
    let root = bytes32(&mut rng);
    let challenge = from_scalar(verifier::da::membership_challenge(&root));
    let da = verifier::da::digest(Some(root));

    // A deferred claim of the guest's shape, its values arbitrary (the digest does not care).
    let defer = DeferredClaim {
        bytecode: DeferredBytecodeClaim {
            bytecode_point: elements(&mut rng, kbcv),
            bytecode_value: element(&mut rng),
        },
        matrix: DeferredMatrixClaim {
            point: elements(&mut rng, MATRIX_VARS),
            a: element(&mut rng),
            b: element(&mut rng),
        },
    };
    let seed = fs_seed();
    let claims = AggregateClaims { lean_xmss: xmss_typed, lean_sphincs: sphincs_typed, da_commitment: Some(root), vault: None };
    let statement = statement_digest(&claims, &defer);

    // Two children with true claims on the stacked bytecode: each one's public input and fresh claim.
    let subproofs: Vec<([F128; 2], DeferredBytecodeClaim)> = (0..2)
        .map(|_| {
            let point = elements(&mut rng, kbcv);
            let scalars: Vec<_> = point.iter().map(to_scalar).collect();
            let value = from_scalar(unified_guest().bytecode().evaluate(&scalars).unwrap());
            let canonical = |rng: &mut StdRng| F128::new(rng.random(), rng.random());
            let public_input = [canonical(&mut rng), canonical(&mut rng)];
            (public_input, DeferredBytecodeClaim { bytecode_point: point, bytecode_value: value })
        })
        .collect();
    let carried: Vec<DeferredClaim> = (0..2)
        .map(|_| DeferredClaim::recompute(elements(&mut rng, kbcv), elements(&mut rng, MATRIX_VARS)))
        .collect();
    // Research build: each child's fresh Flock claim, random but true, its matrix part the verifier's
    // `matrix_term` at its point.
    let fresh_flock: Vec<FreshFlockClaim> = (0..2)
        .map(|_| {
            let s = |rng: &mut StdRng, n: usize| elements(rng, n).iter().map(to_scalar).collect::<Vec<_>>();
            let rounds = verifier::layout::FLOCK_NUM_LINCHECK_ROUNDS;
            let mut claims = verifier::flock::FlockClaims {
                z_skip: to_scalar(&element(&mut rng)),
                chi: s(&mut rng, rounds + 1),
                v_a: verifier::E::new(0, 0),
                v_b: verifier::E::new(0, 0),
                v_c: verifier::E::new(0, 0),
                alpha: to_scalar(&element(&mut rng)),
                round_challenges: s(&mut rng, rounds),
                s: s(&mut rng, verifier::layout::K_BITS),
                matrix: verifier::E::new(0, 0),
                terminal: verifier::E::new(0, 0),
            };
            claims.matrix = verifier::flock::matrix_term(&claims).unwrap();
            FreshFlockClaim::of(&claims)
        })
        .collect();
    let carried_matrix: Vec<DeferredMatrixClaim> = carried.iter().map(|c| c.matrix.clone()).collect();
    // Each child's fresh claim, then its carried one: the batch's order, which its sums follow.
    let public_inputs: Vec<[F128; 2]> = subproofs.iter().map(|(public_input, _)| *public_input).collect();
    let claims: Vec<DeferredBytecodeClaim> = subproofs
        .iter()
        .zip(&carried)
        .flat_map(|((_, fresh), carried)| [fresh.clone(), carried.bytecode.clone()])
        .collect();
    let points: Vec<Vec<F128>> = claims.iter().map(|claim| claim.bytecode_point.clone()).collect();
    <StableProver as isa::Prover>::init();
    let sums = bytecode_sums::<StableProver>(&points);
    let (hints, batched) =
        aggregate_deferred_claims::<StableProver>(&public_inputs, &claims, sums, &fresh_flock, &carried_matrix);
    let hint = |name: &str| &hints.iter().find(|(n, _)| *n == name).unwrap().1;
    let msgs = hint("bc_sumcheck_msgs");
    let star = hint("bc_star_hint");
    assert_eq!(star.len(), 1);
    // The batching challenge's grind nonce, then each round's `(g1, g_inf)`: a degree-two round grinds nothing.
    assert!(BATCH_LAM_GRIND_BITS > 0 && fiat_shamir_prover::grinding_bits(2) == 0);
    assert_eq!(msgs.len(), 1 + 2 * kbcv);
    let (nonce, msgs) = (msgs[0], &msgs[1..]);
    let mat_msgs = hint("mat_sumcheck_msgs");
    let mat_star = hint("mat_stars_hint");
    assert_eq!(mat_star.len(), 2);
    let mat_nonce = if MAT_LAM_GRIND_BITS > 0 { Some(mat_msgs[0]) } else { None };
    let mat_rounds = &mat_msgs[usize::from(mat_nonce.is_some())..];
    assert_eq!(mat_rounds.len(), 2 * MATRIX_VARS);

    let mut out = format!(
        "/-\n  LeanVMTests.Spec.NodeVectors\n\n  Generated by `guest-export` (lean_vm/scripts/guest-export) from leanVM; do not edit.\n  \
         The deployed Rust's encodings and batching on random inputs at the guest's shape\n  \
         (`bytecode_vars = {kbcv}`), which `Node.lean` checks against the Spec.\n-/\n\n\
         import Statement.LeanVmGuest\nimport LeanXmss.Scheme\nimport Statement.LeanSphincs\nimport Statement.Fast.Schemes\nimport LeanDa.Scheme\nimport Statement.Fast.Keccak\nimport Statement.Fast.QuadExt\nimport Statement.Fast.FieldWords\nimport LeanVM.Facts.Verifier\n\nnamespace LeanVMTests.Spec.NodeVectors\n\n\
         open LeanVM.Parameters LeanVM.Semantics LeanVM.Protocol LeanVM.Protocol.Verifier LeanVM.Node\n\n\
         /-- A field element from its limbs. -/\n\
         def e (c0 c1 : ℕ) : E := E.ofLimbs (K.ofBits c0) (K.ofBits c1)\n\n"
    );
    let list = |items: Vec<String>| format!("[{}]", items.join(",\n  "));
    writeln!(out, "/-- The deployed seed (`fs_seed`). -/\ndef seed : Digest := {}\n", cells_digest(&seed)).unwrap();
    writeln!(
        out,
        "/-- leanXMSS claims. -/\ndef xmss : List LeanXmssClaim :=\n  {}\n",
        list(xmss.iter().map(|(pk, m)| claim(pk, m)).collect())
    )
    .unwrap();
    writeln!(out, "def xmssListDigest : Digest := {}\n", cells_digest(&xmss_digest)).unwrap();
    writeln!(
        out,
        "/-- leanSPHINCS claims. -/\ndef sphincs : List LeanSphincsClaim :=\n  {}\n",
        list(sphincs.iter().map(|(pk, m)| claim(pk, m)).collect())
    )
    .unwrap();
    writeln!(out, "def sphincsListDigest : Digest := {}\n", cells_digest(&sphincs_digest)).unwrap();
    writeln!(
        out,
        "/-- A DA claim: a root with the membership challenge the Rust derives from it. -/\ndef daClaim : DaClaim := ⟨{}, {}⟩\n",
        digest(&root),
        e(challenge)
    )
    .unwrap();
    writeln!(out, "/-- The statement's DA field for it (`verifier::da::digest`). -/\ndef daDigest : Digest := {}\n", digest(&da)).unwrap();
    writeln!(out, "/-- The statement's DA field without a root. -/\ndef daNone : Digest := {}\n", digest(&verifier::da::digest(None))).unwrap();
    writeln!(
        out,
        "/-- A deferred claim of the guest's shape. -/\ndef defer : DeferredBytecodeClaim :=\n  ⟨{},\n   {}⟩\n",
        es(&defer.bytecode.bytecode_point),
        e(defer.bytecode.bytecode_value)
    )
    .unwrap();
    writeln!(
        out,
        "/-- Research build: its deferred matrix claim. -/\ndef deferMatrix : DeferredMatrixClaim :=\n  ⟨{},\n   {}, {}⟩\n",
        es(&defer.matrix.point),
        e(defer.matrix.a),
        e(defer.matrix.b)
    )
    .unwrap();
    writeln!(
        out,
        "/-- `statement_digest` of the claims, no vault chain, and `defer`, `deferMatrix` under `seed`. -/\ndef statementDigest : Digest := {}\n",
        cells_digest(&statement)
    )
    .unwrap();
    let children: Vec<String> = subproofs
        .iter()
        .zip(&carried)
        .map(|((public_input, s), c)| {
            format!(
                "⟨{},\n   ⟨{},\n    {}⟩,\n   ⟨{},\n    {}⟩⟩",
                cells_digest(public_input),
                es(&s.bytecode_point),
                e(s.bytecode_value),
                es(&c.bytecode.bytecode_point),
                e(c.bytecode.bytecode_value)
            )
        })
        .collect();
    let carried_matrices: Vec<String> = carried
        .iter()
        .map(|c| format!("⟨{},\n   {}, {}⟩", es(&c.matrix.point), e(c.matrix.a), e(c.matrix.b)))
        .collect();
    writeln!(
        out,
        "/-- Research build: the children's carried matrix claims, true (`matrix_values`). -/\ndef carriedMatrices : List DeferredMatrixClaim :=\n  {}\n",
        list(carried_matrices)
    )
    .unwrap();
    let fresh: Vec<String> = fresh_flock
        .iter()
        .map(|f| {
            let cells = f.cells();
            format!("{}", es(&cells))
        })
        .collect();
    writeln!(
        out,
        "/-- Research build: the children's fresh Flock claims' cells (`FreshFlockClaim::cells`: the matrix part, `α`, \
         `z_skip`, `χ_in`, the round challenges, the slices). -/\ndef freshFlock : List (List E) :=\n  {}\n",
        list(fresh)
    )
    .unwrap();
    writeln!(
        out,
        "/-- Two children, true claims on the guest's stacked bytecode. -/\ndef children : List ChildClaims :=\n  {}\n",
        list(children)
    )
    .unwrap();
    let rounds: Vec<String> = msgs.chunks(2).map(|p| format!("({}, {})", e(p[0]), e(p[1]))).collect();
    writeln!(
        out,
        "/-- The Rust's batching hints (`bc_sumcheck_msgs`, `bc_star_hint`, `mat_sumcheck_msgs`, `mat_stars_hint`). -/\n\
         def hints : BatchingHints where\n  lambdaGrindNonce := {}\n  sumcheckMessages :=\n  {}\n  finalBytecodeValue := {}\n  \
         matrixGrindNonce := {}\n  matrixMessages :=\n  {}\n  finalMatrixValues := ({}, {})\n",
        e(nonce),
        list(rounds),
        e(star[0]),
        e(mat_nonce.unwrap_or(F128::ZERO)),
        list(mat_rounds.chunks(2).map(|p| format!("({}, {})", e(p[0]), e(p[1]))).collect()),
        e(mat_star[0]),
        e(mat_star[1])
    )
    .unwrap();
    writeln!(
        out,
        "/-- The claim the batching defers. -/\ndef batched : DeferredBytecodeClaim :=\n  ⟨{},\n   {}⟩\n",
        es(&batched.bytecode.bytecode_point),
        e(batched.bytecode.bytecode_value)
    )
    .unwrap();
    writeln!(
        out,
        "/-- Research build: the matrix claim the batching defers. -/\ndef batchedMatrix : DeferredMatrixClaim :=\n  ⟨{},\n   {}, {}⟩\n",
        es(&batched.matrix.point),
        e(batched.matrix.a),
        e(batched.matrix.b)
    )
    .unwrap();
    out.push_str("end LeanVMTests.Spec.NodeVectors\n");
    File {
        path: "tests/LeanVMTests/Spec/NodeVectors.lean".into(),
        text: out,
    }
}
