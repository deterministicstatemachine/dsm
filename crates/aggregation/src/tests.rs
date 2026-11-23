use super::cells::{count, pack_16_bytes};
use super::deferred::{DeferredBytecodeClaim, bytecode_sums, bytecode_value, bytecode_vars};
use super::error::AggregateError;
use super::guest::{compile_guest, guest_source, unified_guest};
use super::hints::{FORGE, Forgery, Hints};
use super::placeholders::placeholder_map;
use super::proof::{AggregateProof, decode, encode};
use super::statement::{CLAIM_GROUP, claim_list_digest, list_split};
use super::*;
use fiat_shamir_prover::merkle::hash_to_scalars;
use isa::Program;
use isa::Prover;
use keccak256::{hash, hash_pair};
use lean_da::{BLOB_SYMBOLS, CELL_SYMBOLS, CELLS_PER_ROW, Codeword, DA_MAX_ROWS, Hash};
use lean_sphincs::LeanSphincsSignature;
use lean_vm_core::StableProver;
use lean_vm_core::cpu::{execute, from_scalar, to_scalar};
use lean_xmss::{LeanXmssPublicKey, LeanXmssSignature};
use primitives::field::F128;
use rand::SeedableRng;
use rand::rngs::StdRng;
use zkdsl_compiler::{compile, parse_with_replacements};

use crate::signers_cache::{
    LeanSphincsSigner, LeanXmssSigner, get_lean_sphincs_signers, get_signers, get_signers_for, message, message_for,
};

/// A second cached message, sorting after [`message`]; signer `i` holds the same
/// pubkey under both, at another leaf index.
const MESSAGE_B: u32 = 2;
const SMALL_LEAF_SIZE: usize = 6;

/// An aggregate's claims and proof.
type Node = (AggregateClaims, AggregateProof);

/// [`aggregate`](super::aggregate) on the stable prover at the test rate, without the statistics.
fn aggregate(
    children: &[Node],
    raw_lean_xmss: Vec<LeanXmssSigner>,
    raw_lean_sphincs: Vec<LeanSphincsSigner>,
    blobs: Option<&lean_da::BlobMatrix>,
    output: OutputClaims,
) -> Result<Node, AggregateError> {
    StableProver::init();
    let rate = lean_vm_core::pcs::TEST_LOG_INV_RATE;
    super::aggregate::<StableProver>(children, raw_lean_xmss, raw_lean_sphincs, blobs, output, rate)
        .map(|(claims, proof, _)| (claims, proof))
}

/// A node publishing every claim it covers, which must aggregate and verify.
fn prove(children: &[Node], raw_lean_xmss: &[LeanXmssSigner], raw_lean_sphincs: &[LeanSphincsSigner]) -> Node {
    let node = aggregate(
        children,
        raw_lean_xmss.to_vec(),
        raw_lean_sphincs.to_vec(),
        None,
        OutputClaims::All,
    )
    .expect("aggregates");
    assert!(node.1.verify(&node.0), "verifies");
    node
}

/// The blobs' matrix, `None` for no blobs.
fn matrix(blobs: &[lean_da::Blob]) -> Option<lean_da::BlobMatrix> {
    (!blobs.is_empty()).then(|| lean_da::BlobMatrix::build(blobs).unwrap())
}

fn da_rows(n_rows: usize, seed: u64) -> Vec<lean_da::Blob> {
    let mut rng = StdRng::seed_from_u64(seed);
    let symbols: Vec<u128> = (0..n_rows * BLOB_SYMBOLS)
        .map(|_| rand::Rng::random(&mut rng))
        .collect();
    symbols.as_chunks().0.to_vec()
}

/// Aggregating this fails in the guest's run once `forgery` edits the node's hints.
fn assert_forgery_rejected(
    forgery: Forgery,
    children: &[Node],
    raw: Vec<LeanXmssSigner>,
    sphincs: Vec<LeanSphincsSigner>,
    blobs: &[lean_da::Blob],
) {
    FORGE.with(|forge| *forge.borrow_mut() = Some(forgery));
    let result = aggregate(children, raw, sphincs, matrix(blobs).as_ref(), OutputClaims::All);
    assert!(
        result.err() == Some(AggregateError::ProvingFailed),
        "a forged hint is rejected"
    );
}

/// The guest's helpers under a `main` of their own, compiled at the bytecode size `2^kbc`.
fn guest_snippet(main: &str, kbc: usize) -> Program {
    let (helpers, _) = guest_source().split_once("\ndef main():").unwrap();
    let source = format!("{helpers}\ndef main():\n{main}");
    Program::from(compile(
        &parse_with_replacements(&source, &placeholder_map(kbc)).unwrap(),
    ))
}

#[test]
fn the_wire_layout_is_pinned() {
    let le = u64::to_le_bytes;
    let (point, proof) = (vec![F128::new(1, 2), F128::new(4, 5)], vec![9, 8, 7]);
    let bytes = encode(&point, &proof);
    assert_eq!(bytes, [&le(2)[..], &le(1), &le(2), &le(4), &le(5), &proof].concat());
    assert_eq!(decode(&bytes), Some((point, &proof[..])));
    // A count beyond the input, or beyond any input, fails whatever it claims.
    assert_eq!(decode(&[&le(3)[..], &bytes[8..]].concat()), None);
    assert_eq!(decode(&le(u64::MAX)), None);
}

/// The guest compiles to one program, always.
///
/// `unified_guest` finds a fixed point by compiling repeatedly and comparing
/// the result's log size, so a compiler that read a hash seed would not just
/// produce two incompatible transcripts, it could fail to converge at all.
/// The small programs in `zkdsl_compiler`'s `determinism` suite pin the
/// digests; this pins the one program large enough to hit every path that
/// walks a map. A fixed `kbc` is enough: reproducibility does not depend on
/// the size being the fixed point.
#[test]
fn guest_compiles_reproducibly() {
    let (one, two) = (compile_guest(20), compile_guest(20));
    assert_eq!(
        format!("{:?}", one.prog),
        format!("{:?}", two.prog),
        "two compilations of the guest produced different bytecode, \
             so the compiler is reading a hash seed"
    );
}

/// The guest builds a leanXMSS address as its type's cell plus `lo`,
/// `hi · 2^32` and `step · 2^61` in the low lane, and the top layer's flag, which
/// must be the native address's bytes.
#[test]
fn guest_addresses_are_the_native_ones() {
    let cell = |tw| pack_16_bytes(&lean_xmss::internals::address(&tw));
    let top = cell(lean_xmss::internals::tweak(0, lean_xmss::internals::TOP, 0));
    for tag in [
        lean_xmss::internals::TWEAK_CHAIN,
        lean_xmss::internals::TWEAK_LEAF,
        lean_xmss::internals::TWEAK_NODE,
        lean_xmss::internals::TWEAK_MSG,
    ] {
        for layer in 0..2 {
            for (hi, lo, step) in [(0u32, 0u32, 0usize), (5, 0x1234_5678, 2), (16, u32::MAX, 0)] {
                let tw = lean_xmss::internals::tweak(tag, lean_xmss::internals::layer_hi(layer, hi), lo).step(step);
                let fields = F128::new(u64::from(lo) | u64::from(hi) << 32 | (step as u64) << 61, 0);
                let guest =
                    cell(lean_xmss::internals::tweak(tag, 0, 0)) + fields + if layer == 1 { top } else { F128::ZERO };
                assert_eq!(guest, cell(tw));
            }
        }
    }
}

/// A leaf of both schemes, each list in its own region, with no blobs and so no root. One leanSPHINCS pubkey signs
/// two messages, the repeat the statement allows: two claims, ordered by the pair, each needing its own signature.
/// Generated here rather than cached, the cache holding one message per pubkey.
#[test]
fn aggregate_mixed_leaf() {
    let secret_key = [77; lean_sphincs::SECRET_KEY_LEN];
    let public_key = lean_sphincs::key_gen(&secret_key);
    let mut sphincs = get_lean_sphincs_signers::<StableProver>(3);
    for tag in [3u8, 9] {
        let signed: lean_sphincs::Message = std::array::from_fn(|i| tag.wrapping_mul(i as u8 + 1));
        sphincs.push((public_key, signed, lean_sphincs::sign(&secret_key, &signed)));
    }
    let leaf = prove(&[], &get_signers::<StableProver>(3), &sphincs);
    assert_eq!((leaf.0.lean_xmss.len(), leaf.0.lean_sphincs.len()), (3, 5));
    assert_eq!(leaf.0.lean_xmss[0].1, message());
    assert_eq!(leaf.0.da_commitment, None);
    let twice: Vec<_> = leaf.0.lean_sphincs.iter().filter(|(pk, _)| *pk == public_key).collect();
    assert!(
        twice.len() == 2 && twice[0].1 < twice[1].1,
        "the same pubkey twice, ordered by the message"
    );
}

/// A leanSPHINCS signature's digest and openings are bound in-circuit: a node whose
/// hints put the digest's unused bytes off by one, order a FORS node and its sibling
/// the other way, or give a layer another counter fails the guest's run.
#[test]
fn forged_lean_sphincs_hints_are_rejected() {
    let signers = get_lean_sphincs_signers::<StableProver>(1);
    let forgeries: [Forgery; 3] = [
        Box::new(|hints: &mut Hints| hints.entry_mut("sp_unused", 0)[0] *= count(1)),
        Box::new(|hints: &mut Hints| hints.entry_mut("sp_fors_nodes", 0).swap(0, 1)),
        Box::new(|hints: &mut Hints| hints.entry_mut("sp_counter", 1)[0] *= count(1)),
    ];
    for forgery in forgeries {
        assert_forgery_rejected(forgery, &[], vec![], signers.clone(), &[]);
    }
}

/// A leanXMSS signature's leaf index and codeword are bound in-circuit: a node whose
/// hints change the index, dispatch a path window other than the index's, or
/// dispatch a digit group other than the digest's fails the guest's run.
#[test]
fn forged_lean_xmss_hints_are_rejected() {
    let signers = get_signers::<StableProver>(1);
    let forgeries: [Forgery; 3] = [
        Box::new(|hints: &mut Hints| hints.entry_mut("lx_index", 0)[0] += F128::ONE),
        Box::new(|hints: &mut Hints| hints.entry_mut("lx_windows", 0)[0] *= count(1)),
        Box::new(|hints: &mut Hints| hints.entry_mut("lx_digits", 0)[0] *= count(1)),
    ];
    for forgery in forgeries {
        assert_forgery_rejected(forgery, &[], signers.clone(), vec![], &[]);
    }
}

/// The guest reads each child's root off its statement and publishes the one the
/// node picks, which must be its own with blobs: a child's root other than the one
/// its proof carries, a pick past the children, a child's root picked over the
/// node's blobs, or a membership challenge other than the root's fails the guest's run.
#[test]
fn forged_da_hints_are_rejected() {
    let child = aggregate(
        &[],
        get_signers::<StableProver>(SMALL_LEAF_SIZE),
        vec![],
        matrix(&da_rows(1, 7)).as_ref(),
        OutputClaims::All,
    )
    .unwrap();
    let forgeries: [(Forgery, bool); 4] = [
        (
            Box::new(|hints: &mut Hints| hints.entry_mut("child_da", 0)[0] += F128::ONE),
            false,
        ),
        (
            Box::new(|hints: &mut Hints| hints.entry_mut("da_pick", 0)[0] *= count(2)),
            false,
        ),
        (
            Box::new(|hints: &mut Hints| hints.entry_mut("da_pick", 0)[0] = count(0)),
            true,
        ),
        (
            Box::new(|hints: &mut Hints| hints.entry_mut("da_challenge", 0)[0] += F128::ONE),
            true,
        ),
    ];
    for (forgery, with_blobs) in forgeries {
        let blobs = if with_blobs { da_rows(1, 8) } else { vec![] };
        assert_forgery_rejected(forgery, std::slice::from_ref(&child), vec![], vec![], &blobs);
    }
}

/// The child's opening rides in as hints: a forged opened row or cap node fails the guest's Merkle check.
#[test]
fn forged_opening_hints_are_rejected() {
    let child = prove(&[], &get_signers::<StableProver>(SMALL_LEAF_SIZE), &[]);
    let forgeries: [Forgery; 2] = [
        Box::new(|hints: &mut Hints| hints.entry_mut("merkle_leaf_rows", 0)[0] += F128::ONE),
        Box::new(|hints: &mut Hints| hints.entry_mut("merkle_caps", 0)[4] += F128::ONE),
    ];
    for forgery in forgeries {
        assert_forgery_rejected(forgery, std::slice::from_ref(&child), vec![], vec![], &[]);
    }
}

/// Flock's part of a child's verification and the matrix batch ride in as hints: a forged lincheck matrix part, a
/// forged batch round or a forged reduced value fails the guest's run; a forged leaf matrix value changes the
/// statement, which the guest's own digest then refuses; and a proof whose deferred matrix point is moved verifies
/// for nothing, the outer verifier recomputing the values there.
#[test]
fn forged_flock_hints_are_rejected() {
    let signers = get_signers::<StableProver>(SMALL_LEAF_SIZE);
    let child = prove(&[], &signers, &[]);
    let forgeries: [Forgery; 4] = [
        Box::new(|hints: &mut Hints| hints.entry_mut("flock_matrix", 0)[0] += F128::ONE),
        Box::new(|hints: &mut Hints| hints.entry_mut("mat_stars_hint", 0)[0] += F128::ONE),
        Box::new(|hints: &mut Hints| hints.entry_mut("mat_stars_hint", 0)[1] += F128::ONE),
        Box::new(|hints: &mut Hints| hints.entry_mut("mat_sumcheck_msgs", 0)[3] += F128::ONE),
    ];
    for forgery in forgeries {
        assert_forgery_rejected(forgery, std::slice::from_ref(&child), vec![], vec![], &[]);
    }
    for value in [1, 2] {
        assert_forgery_rejected(
            Box::new(move |hints: &mut Hints| hints.entry_mut("leaf_defer", 0)[value] += F128::ONE),
            &[],
            signers.clone(),
            vec![],
            &[],
        );
    }
    // The child's own Flock words, as the guest reads them off its proof stream: each tampered one is refused.
    let defer = super::deferred::DeferredClaim::recompute(child.1.bytecode_point.clone(), child.1.matrix_point.clone());
    let pi = super::statement::statement_digest(&child.0, &defer);
    let summary = verifier::verify_execution(
        unified_guest().bytecode(),
        &lean_vm_core::cpu::public_input_bytes(&pi),
        &child.1.proof,
    )
    .expect("the child verifies");
    let flock = summary.flock_scalars;
    for at in [flock.start, flock.start + 70, (flock.start + flock.end) / 2, flock.end - 1] {
        assert_forgery_rejected(
            Box::new(move |hints: &mut Hints| hints.entry_mut("stream", 0)[at] += F128::ONE),
            std::slice::from_ref(&child),
            vec![],
            vec![],
            &[],
        );
    }
    let node = prove(std::slice::from_ref(&child), &[], &[]);
    let mut moved = node.1.clone();
    moved.matrix_point[5] += F128::ONE;
    assert!(!moved.verify(&node.0), "a moved deferred matrix point verifies nothing");
    let bytes = node.1.to_bytes();
    assert!(super::AggregateProof::from_bytes(&bytes).is_some_and(|p| p.verify(&node.0)));
}

#[test]
fn guest_column_selectors_match_native_eq() {
    let kbc = 18;
    let guest = guest_snippet(
        r#"    # The selector tables read whole nibbles of coordinates, zero past the stack.
    point = HeapBuf(4 * SEL_NIBBLES)
    hint_witness(point[0:MAX_STACK_LOG], "point")
    for k in unroll(MAX_STACK_LOG, 4 * SEL_NIBBLES):
        point[GEN ** k] = 0
    point1 = HeapBuf(4 * SEL_NIBBLES)
    for k in unroll(0, 4 * SEL_NIBBLES):
        point1[GEN ** k] = 1 + point[GEN ** k]
    sel_eq = selector_tables(point, point1)
    g_squares = exponent_tables()
    sel_g = g_squares * GEN ** SIZE_BITS
    offset = hint_witness("offset")
    kappa_g = hint_witness("kappa")
    weight = match(log(kappa_g), range(0, N_COLUMN_LOGS), lambda kappa: column_selector(offset, sel_eq, sel_g, kappa))
    public = GEN ** 0
    assert public[1] == weight
    return
"#,
        kbc,
    );
    let mut rng = StdRng::seed_from_u64(813);
    for mu in verifier::min_execution_stacked_log(kbc)..=verifier::MAX_STACKED_LOG {
        let mut point: Vec<F128> = (0..mu)
            .map(|_| {
                let (c0, c1) = rand::Rng::random(&mut rng);
                F128::new(c0, c1)
            })
            .collect();
        point.resize(verifier::MAX_STACKED_LOG, F128::ZERO);
        for kappa in 0..=mu {
            let mask = ((1usize << mu) - 1) & !((1usize << kappa) - 1);
            for offset in [0, mask, 0x0555_5555 & mask] {
                let selector: Vec<_> = (kappa..mu).map(|k| F128::new(((offset >> k) & 1) as u64, 0)).collect();
                let expected = selector
                    .iter()
                    .zip(&point[kappa..mu])
                    .fold(F128::ONE, |acc, (&s, &r)| acc * (F128::ONE + s + r));
                let mut hints = Hints::default();
                hints.push("point", point.clone());
                hints.push("offset", vec![count(offset)]);
                hints.push("kappa", vec![count(kappa)]);
                let execution = execute(&guest, &hints.0, [expected, F128::ZERO]).unwrap();
                assert!(execution.unconstrained_reads.is_empty());
            }
        }
    }
}

/// The right leaf holds more claims than one loop frame of its list hashes
/// ([`CLAIM_GROUP`]), so both that leaf and the parent rebuilding it run the
/// list's group loop and then a partial last group, while the left leaf's list is
/// a partial group alone. The leaves share three signers, so the parent rebuilds the
/// right list on the walk that allows repeated slots (`child_claim_list_any`).
#[test]
fn aggregate_two_to_one() {
    let big = 2 * CLAIM_GROUP + 3;
    let signers = get_signers::<StableProver>(SMALL_LEAF_SIZE + big);
    let left = prove(&[], &signers[..SMALL_LEAF_SIZE], &[]);
    let right = prove(&[], &signers[SMALL_LEAF_SIZE - 3..], &[]);
    let cover = super::coverage::plan_coverage(&[], &[], &[left.clone(), right.clone()], None).unwrap();
    assert!(
        !cover.lean_xmss.children[1].is_sorted_by(|a, b| a < b),
        "the right list takes the repeated-slot walk"
    );
    // A child whose claims are out of order, or whose proof the replay cannot walk, is refused before proving.
    let node_of = |left: Node| aggregate(&[left, right.clone()], vec![], vec![], None, OutputClaims::All).err();
    let mut unsorted = left.clone();
    unsorted.0.lean_xmss.reverse();
    assert_eq!(node_of(unsorted), Some(AggregateError::InvalidChild));
    let mut cut = left.clone();
    cut.1.proof.stream.truncate(cut.1.proof.stream.len() / 2);
    assert_eq!(node_of(cut), Some(AggregateError::InvalidChild));
    let node = prove(&[left, right], &[], &[]);
    assert_eq!(node.0.lean_xmss.len(), SMALL_LEAF_SIZE + big);
}

/// A LeanDA payload of the most blobs a node takes, proven without signatures and published in the statement. The
/// node has to reach the native committer's root, and the aggregate verifies against the receiver's claims only.
#[test]
fn aggregate_with_a_da_payload() {
    let rows = da_rows(DA_MAX_ROWS, 97);
    let matrix = lean_da::BlobMatrix::build(&rows).unwrap();
    let node = aggregate(&[], vec![], vec![], Some(&matrix), OutputClaims::All).expect("node aggregates");
    let expected = AggregateClaims {
        da_commitment: Some(matrix.commitment()),
        ..AggregateClaims::default()
    };
    assert_eq!(node.0, expected, "the guest committed to something else");
    // The receiver's own claims verify, any others fail.
    let bytes = node.1.to_bytes();
    let received = AggregateProof::from_bytes(&bytes).unwrap();
    assert!(received.verify(&expected));
    let other = AggregateClaims {
        da_commitment: Some([0; 32]),
        ..AggregateClaims::default()
    };
    assert!(!received.verify(&other));
    let claim = (
        LeanXmssPublicKey::from_bytes(&[0; lean_xmss::PUB_KEY_SIZE]),
        [0; lean_xmss::MESSAGE_LEN],
    );
    let unsorted = AggregateClaims {
        lean_xmss: vec![claim, claim],
        ..expected.clone()
    };
    assert!(!received.verify(&unsorted));
    let trailing = AggregateProof::from_bytes(&[&bytes[..], &[0]].concat());
    assert!(trailing.is_none());
}

/// A node publishes a root it holds, and with blobs only their matrix's.
#[test]
fn invalid_da_selections_are_rejected_before_building_the_proof() {
    let select = AggregateClaims {
        da_commitment: Some([0xa5; 32]),
        ..AggregateClaims::default()
    };
    let blobs = matrix(&da_rows(1, 3));
    let with = |blobs: Option<&lean_da::BlobMatrix>, declare: &AggregateClaims| {
        aggregate(&[], vec![], vec![], blobs, OutputClaims::Only(declare)).unwrap_err()
    };
    assert_eq!(
        with(None, &select),
        AggregateError::InvalidInput("the requested DA root is not a child's")
    );
    let blobs_root = AggregateError::InvalidInput("a node with blobs publishes their root");
    assert_eq!(with(blobs.as_ref(), &select), blobs_root);
    assert_eq!(with(blobs.as_ref(), &AggregateClaims::default()), blobs_root);
}

/// A proof carries one blob matrix. A node without blobs passes on one child's
/// root, the first's by default or the one it selects, or none; a node with blobs
/// publishes their matrix's, whatever its children hold.
#[test]
fn a_node_passes_on_one_childs_da_root() {
    let signers = get_signers::<StableProver>(SMALL_LEAF_SIZE);
    let mut children = vec![prove(&[], &signers, &[])];
    for (n_rows, seed) in [(1, 509), (2, 510)] {
        let rows = da_rows(n_rows, seed);
        children.push(aggregate(&[], signers.clone(), vec![], matrix(&rows).as_ref(), OutputClaims::All).unwrap());
    }
    let (first, second) = (
        children[1].0.da_commitment.unwrap(),
        children[2].0.da_commitment.unwrap(),
    );
    assert_ne!(first, second);
    let pass_on = |selected: Option<Option<[u8; 32]>>, blobs: &[lean_da::Blob]| {
        let declare = selected.map(|da_commitment| AggregateClaims {
            lean_xmss: children[0].0.lean_xmss.clone(),
            lean_sphincs: vec![],
            da_commitment,
            vault: None,
        });
        let node = aggregate(
            &children,
            vec![],
            vec![],
            matrix(blobs).as_ref(),
            declare.as_ref().map_or(OutputClaims::All, OutputClaims::Only),
        )
        .unwrap();
        assert!(node.1.verify(&node.0));
        node.0.da_commitment
    };
    assert_eq!(pass_on(None, &[]), Some(first));
    assert_eq!(pass_on(Some(Some(second)), &[]), Some(second));
    assert_eq!(pass_on(Some(None), &[]), None);
    let rows = da_rows(1, 511);
    assert_eq!(
        pass_on(None, &rows),
        Some(lean_da::BlobMatrix::build(&rows).unwrap().commitment())
    );

    // Passed on again, one level up.
    let middle = prove(&children[1..], &[], &[]);
    let top = prove(&[children[0].clone(), middle], &[], &[]);
    assert_eq!(top.0.da_commitment, Some(first));
}

/// A list hash's split is advice the guest then dispatches on, so the claim count
/// after the last group has to be bounded before the `match`: a negative
/// exponent that satisfies the product identity must fail the range check in
/// `list_split` itself, not reach the dispatch as a wild jump.
#[test]
fn list_split_rejects_a_negative_rest() {
    let guest = guest_snippet(
        r#"    n_g = hint_witness("n")
    bigs, body, rest = list_split(n_g)
    public = GEN ** 0
    assert public[1] == body
    assert public[GEN] == rest
    return
"#,
        20,
    );
    let split = |body: F128, rest: F128| {
        let mut hints = Hints::default();
        hints.push("n", vec![count(6)]);
        hints.push("signers_split", vec![count(0), body, rest]);
        execute(&guest, &hints.0, [body, rest])
    };
    // Six claims: no whole group, then six.
    assert!(split(count(0), count(6)).is_ok());
    // One group and -11 claims after it: the product identity holds, the range
    // check must not.
    let negative = count(11).inv();
    let Err(err) = split(count(1), negative) else {
        panic!("a negative last-block count was accepted");
    };
    assert!(err.to_string().contains("list_split"), "rejected elsewhere: {err}");
}

/// `grind_check` rebuilds a lane from bit windows: an honest run cannot show a proof of work
/// is checked, so this pins that a set bit below the window fails and one at or above it passes.
#[test]
fn grind_check_reads_the_low_bits() {
    let guest = guest_snippet(
        r#"    word = hint_witness("w")
    grind_check(word, exponent_tables() * GEN ** WIN_TAB_AT, 3)
    return
"#,
        20,
    );
    let check = |lane: u64| {
        let mut hints = Hints::default();
        hints.push("w", vec![F128::new(lane, 0x0123_4567_89AB_CDEF)]);
        execute(&guest, &hints.0, [F128::ZERO, F128::ZERO])
    };
    for lane in [0, 0b1000, 1 << 63, 0xFEDC_BA98_7654_3218] {
        assert!(check(lane).is_ok(), "{lane:#x} has its low 3 bits zero");
    }
    for lane in [1, 0b100, 0xFEDC_BA98_7654_321A] {
        assert!(check(lane).is_err(), "{lane:#x} has a low bit set");
    }
}

/// The guest accepts committed codewords, and rejects a matrix with one symbol of
/// one row flipped, in either limb, though its root and vector are that matrix's: the row is no codeword.
#[test]
fn da_guest_checks_codeword_membership() {
    let guest = guest_snippet(
        r#"    byte_bits = HeapBuf(SP_BYTE_VALUES)
    for v in unroll(0, SP_BYTE_VALUES):
        byte_bits[GEN ** v] = v
    r0, r1, z = da_verify(byte_bits)
    digest = StackBuf(2)
    keccak([r0, r1], [z, 0], digest)
    public = GEN ** 0
    assert public[1] == digest[0]
    assert public[GEN] == digest[1]
    return
"#,
        20,
    );
    let blobs = da_rows(3, 101);
    let witness = lean_da::BlobMatrix::build(&blobs).unwrap();
    let rows: Vec<Codeword> = (0..blobs.len()).map(|i| *witness.row(i).unwrap()).collect();
    assert_eq!(da_root(&rows), witness.commitment());
    let verify = |rows: &[Codeword]| {
        let commitment = da_root(rows);
        let mut hints = Hints::default();
        hints.push(
            "da_challenge",
            vec![from_scalar(verifier::da::membership_challenge(&commitment))],
        );
        hints.push("da_n_blobs", vec![count(rows.len())]);
        for row in rows {
            for j in 0..CELLS_PER_ROW {
                let cell = &row.as_chunks::<CELL_SYMBOLS>().0[j];
                hints.push("da_symbols", cell.iter().map(|&w| F128::from(w)).collect());
            }
        }
        execute(
            &guest,
            &hints.0,
            hash_to_scalars(&verifier::da::digest(Some(commitment))),
        )
    };
    assert!(verify(&rows).unwrap().unconstrained_reads.is_empty());
    for (position, flip) in [(0, 1), (BLOB_SYMBOLS + 5, 1 << 64)] {
        let mut corrupted = rows.clone();
        corrupted[1][position] ^= flip;
        assert!(verify(&corrupted).is_err(), "a flip of {flip:#x} at {position} passed");
    }
}

/// The commitment to rows that need not be codewords, rebuilt as `BlobMatrix::build` does it.
fn da_root(rows: &[Codeword]) -> Hash {
    fn root(mut level: Vec<Hash>) -> Hash {
        while level.len() > 1 {
            level = level.chunks(2).map(|pair| hash_pair(&pair[0], &pair[1])).collect();
        }
        level[0]
    }
    let cell_digest = |cell: &[u128]| hash(&cell.iter().flat_map(|w| w.to_le_bytes()).collect::<Vec<u8>>());
    let mut blob_roots: Vec<Hash> = rows
        .iter()
        .map(|row| root(row.chunks(CELL_SYMBOLS).map(cell_digest).collect()))
        .collect();
    blob_roots.resize(DA_MAX_ROWS, lean_da::root_of_padding_blob());
    let mut count = [0; 32];
    count[0] = rows.len() as u8;
    hash_pair(&root(blob_roots), &count)
}

/// Claims left undeclared take duplicate slots. The first narrowing drops every
/// claim on one message, the second all but one claim.
#[test]
fn a_node_may_publish_less_than_it_covers() {
    let at_a = get_signers::<StableProver>(3);
    let at_b = get_signers_for::<StableProver>(2, MESSAGE_B);
    let wide = prove(&[], &[at_a.clone(), at_b].concat(), &[]);
    assert_eq!(wide.0.lean_xmss.len(), 5);

    let narrowed = |declare: &AggregateClaims| {
        aggregate(
            std::slice::from_ref(&wide),
            vec![],
            vec![],
            None,
            OutputClaims::Only(declare),
        )
    };
    let only = |lean_xmss: Vec<LeanXmssClaim>| AggregateClaims {
        lean_xmss,
        ..AggregateClaims::default()
    };
    let on_b: Vec<LeanXmssClaim> = wide
        .0
        .lean_xmss
        .iter()
        .filter(|(_, message)| *message == message_for(MESSAGE_B))
        .cloned()
        .collect();
    assert_eq!(on_b.len(), 2);

    let narrow = narrowed(&only(on_b.clone())).expect("narrows to one message");
    assert!(narrow.1.verify(&narrow.0), "the one-message narrowing verifies");
    assert_eq!(narrow.0.lean_xmss, on_b);

    let one = vec![(at_a[0].0, message())];
    let part = narrowed(&only(one.clone())).expect("narrows to one claim");
    assert!(part.1.verify(&part.0), "the one-claim narrowing verifies");
    assert_eq!(part.0.lean_xmss, one);

    assert_eq!(
        narrowed(&AggregateClaims::default()).err(),
        Some(AggregateError::InvalidInput("nothing to publish")),
        "a declaration has to publish something"
    );
    let uncovered = Some(AggregateError::InvalidInput(
        "a requested claim is not covered by the inputs",
    ));
    // A pubkey that signed A only, declared on B: the cache reuses pubkeys.
    assert_eq!(
        narrowed(&only(vec![(at_a[2].0, message_for(MESSAGE_B))])).err(),
        uncovered
    );
    // A covered pubkey, against a message nobody signed.
    assert_eq!(
        narrowed(&only(vec![(at_a[0].0, message_for(MESSAGE_B + 1))])).err(),
        uncovered
    );
}

/// A raw signature whose claim goes undeclared covers a duplicate slot.
#[test]
fn raw_signatures_may_go_undeclared() {
    let b = get_signers_for::<StableProver>(1, MESSAGE_B);
    let claim_b = vec![(b[0].0, message_for(MESSAGE_B))];
    let declare = AggregateClaims {
        lean_xmss: claim_b.clone(),
        ..AggregateClaims::default()
    };
    let raw = [get_signers::<StableProver>(1), b].concat();
    let node = aggregate(&[], raw, vec![], None, OutputClaims::Only(&declare)).expect("the narrowing leaf aggregates");
    assert!(node.1.verify(&node.0), "it verifies");
    assert_eq!(node.0.lean_xmss, claim_b);
}

/// Two messages in one tree. Signer `i` holds the same pubkey under both, at
/// different leaf indices, so its claims on B are distinct from those on A; the
/// left leaf holds one message, the right both, and the node needs a duplicate
/// slot for the claim both leaves cover.
#[test]
fn aggregate_two_messages() {
    let at_a = get_signers::<StableProver>(4);
    let at_b = get_signers_for::<StableProver>(2, MESSAGE_B);
    assert_eq!(at_a[0].0, at_b[0].0, "the cache reuses pubkeys across messages");
    assert_ne!(at_a[0].2.leaf_index(), at_b[0].2.leaf_index());
    let left = prove(&[], &at_a[..3], &[]);
    let right = prove(&[], &[&at_a[2..], &at_b[..]].concat(), &[]);
    // A pubkey of `left` signing a second message is a second claim of that pubkey.
    let crossed = prove(std::slice::from_ref(&left), &at_b[..1], &[]);
    let of_first: Vec<lean_xmss::Message> = crossed
        .0
        .lean_xmss
        .iter()
        .filter(|(pubkey, _)| *pubkey == at_a[0].0)
        .map(|(_, message)| *message)
        .collect();
    assert_eq!(of_first, vec![message(), message_for(MESSAGE_B)]);
    assert_eq!(crossed.0.lean_xmss.len(), 4);
    let node = prove(&[left, right], &[], &[]);
    let mut expected: Vec<LeanXmssClaim> = [at_a, at_b]
        .concat()
        .into_iter()
        .map(|(pubkey, message, _)| (pubkey, message))
        .collect();
    expected.sort();
    assert_eq!(node.0.lean_xmss, expected);
}

/// A child list walked by gaps (`child_claim_list_mono`) moves strictly forward. A
/// child may declare a claim twice, and a gap of `g^-1` would walk the copy back onto
/// the slot it just covered, with the same coverage mark, so write-once memory alone
/// would not see it: only the gap's `assert_gpow` does.
#[test]
fn a_child_walk_cannot_step_back() {
    let guest = guest_snippet(
        r#"    n_c = hint_witness("n")
    table = HeapBuf(GEN ** 8)
    hint_witness(table[0:8], "claims")
    cover = HeapBuf(GEN ** 2)
    d0, d1 = child_claim_list_digest(table, cover, GEN ** 3, GEN ** 2, n_c)
    public = GEN ** 0
    assert public[1] == d0
    assert public[GEN] == d1
    return
"#,
        20,
    );
    let claim = |i: u64| [1, 2, 3, 4].map(|k| F128::new(i * 7919 + k, k));
    let table: Vec<F128> = [claim(0), claim(1)].concat();
    let walk = |child: &[[F128; 4]], gaps: &[F128]| {
        let mut hints = Hints::default();
        hints.push("n", vec![count(child.len())]);
        hints.push("claims", table.clone());
        hints.push("signers_split", list_split(child.len()));
        hints.push("child_mono", vec![count(1)]);
        for &gap in gaps {
            hints.push("child_claim_gap", vec![gap]);
        }
        execute(&guest, &hints.0, claim_list_digest(child.iter().copied()))
    };
    assert!(walk(&[claim(0), claim(1)], &[count(0), count(0)]).is_ok());
    let back = count(1).inv();
    assert!(
        walk(&[claim(0), claim(0)], &[count(0), back]).is_err(),
        "a walk revisited a slot"
    );
}

/// Three levels, both schemes. Each node has a child of one scheme only, so it rebuilds a list empty on one side,
/// which is the only way the guest's claim-absorbing loops run over an empty range and reach their bound `log(x) <
/// log(g^0)` (unsatisfiable, so nothing may be written there). Leaves overlap in claims of each scheme, within a node
/// and across the two nodes, so the left node needs a duplicate slot and the root one in each region, each child's two
/// lists landing in their own; the root adds a raw signature of each scheme, leanXMSS on a second message, alongside its
/// children. The root's proof goes over the wire.
#[test]
fn aggregate_three_levels() {
    let xmss = get_signers::<StableProver>(17);
    let sphincs = get_lean_sphincs_signers::<StableProver>(5);
    let left = prove(
        &[prove(&[], &xmss[..6], &sphincs[..2]), prove(&[], &xmss[5..11], &[])],
        &[],
        &[],
    );
    let right = prove(
        &[prove(&[], &xmss[10..], &sphincs[1..3]), prove(&[], &[], &sphincs[3..4])],
        &[],
        &[],
    );
    let root = prove(
        &[left, right],
        &get_signers_for::<StableProver>(2, MESSAGE_B),
        &sphincs[4..],
    );
    assert_eq!(root.0.lean_xmss.len(), 17 + 2);
    assert_eq!(root.0.lean_sphincs.len(), 5, "the repeats merged");
    let received = AggregateProof::from_bytes(&root.1.to_bytes()).expect("round trip");
    assert_eq!(received.to_bytes(), root.1.to_bytes());
    assert!(received.verify(&root.0), "the receiver's claims verify");
}

/// A claim's value, read off its sums or recomputed, is the bytecode's evaluation, at a random point and at a leaf's,
/// where both take a fast path.
#[test]
fn bytecode_values_are_the_bytecode_evaluation() {
    let mut rng = StdRng::seed_from_u64(11);
    let limbs = (0..bytecode_vars()).map(|_| rand::Rng::random::<(u64, u64)>(&mut rng));
    let points = [
        limbs.map(|(c0, c1)| F128::new(c0, c1)).collect(),
        DeferredBytecodeClaim::leaf().bytecode_point,
    ];
    StableProver::init();
    for (sums, point) in bytecode_sums::<StableProver>(&points).iter().zip(&points) {
        let scalars: Vec<_> = point.iter().map(to_scalar).collect();
        let value = from_scalar(unified_guest().bytecode().evaluate(&scalars).unwrap());
        assert_eq!(bytecode_value(sums, point), value);
        assert_eq!(DeferredBytecodeClaim::recompute(point.clone()).bytecode_value, value);
    }
}

/// A raw signature the hint builder cannot walk is a typed error, not a panic: a leanXMSS randomizer whose digest is
/// not a codeword, and a leanSPHINCS counter that does not encode.
#[test]
fn malformed_raw_signatures_are_errors() {
    let message = message();
    let pk = LeanXmssPublicKey::from_bytes(&[0; lean_xmss::PUB_KEY_SIZE]);
    let randomizer = (0..=u8::MAX)
        .map(|byte| [byte; lean_xmss::internals::RANDOMIZER_LEN])
        .find(|r| {
            let digest =
                lean_xmss::internals::message_digest(lean_xmss::internals::pk_public_param(&pk), 0, 0, r, &message);
            lean_xmss::internals::codeword(&digest).is_none()
        })
        .expect("some randomizer fails the codeword");
    // Leaf index 0, then both layers: the randomizer, zero chain values, a zero path.
    let mut bytes = [0; lean_xmss::SIG_SIZE];
    let layer_size = (lean_xmss::SIG_SIZE - 4) / 2;
    bytes[4..4 + lean_xmss::internals::RANDOMIZER_LEN].copy_from_slice(&randomizer);
    bytes[4 + layer_size..][..lean_xmss::internals::RANDOMIZER_LEN].copy_from_slice(&randomizer);
    let xmss = vec![(pk, message, LeanXmssSignature::from_bytes(&bytes))];

    let (public_key, signed, signature) = get_lean_sphincs_signers::<StableProver>(1).pop().expect("one signer");
    // The bottom layer's counter follows the randomizer and the FORS openings.
    let mut bytes = signature.to_bytes();
    bytes[lean_sphincs::internals::N
        + lean_sphincs::internals::FORS_TREES * lean_sphincs::internals::FORS_OPENING_SIZE] ^= 1;
    let signature = LeanSphincsSignature::from_bytes(&bytes);
    assert!(!lean_sphincs::verify(&public_key, &signed, &signature));
    let sphincs = vec![(public_key, signed, signature)];

    for (xmss, sphincs) in [(xmss, vec![]), (vec![], sphincs)] {
        assert_eq!(
            aggregate(&[], xmss, sphincs, None, OutputClaims::All).err(),
            Some(AggregateError::InvalidSignature)
        );
    }
}

/// Research build: one node per vault step, each verifying the node before it in the VM. A node of steps
/// `steps[..k]` of one vault, the first node without children.
fn vault_nodes(steps: &[vault_step::fixture::Fixture]) -> Vec<(AggregateClaims, AggregateProof, isa::Stats)> {
    let mut nodes: Vec<(AggregateClaims, AggregateProof, isa::Stats)> = Vec::new();
    for f in steps {
        let children: Vec<_> = nodes.last().map(|(c, p, _)| (c.clone(), p.clone())).into_iter().collect();
        let step = VaultStep {
            witness: f.witness.clone(),
            r_prev: f.r_prev,
        };
        nodes.push(
            aggregate_with_vault::<StableProver>(&children, vec![], vec![], None, OutputClaims::All, 1, Some(&step))
                .expect("a vault node"),
        );
    }
    nodes
}

/// Research build: a chain of vault-step nodes publishes the chain's first root and its last, verifies, and a node
/// whose step does not extend its child's chain, or belongs to another vault, does not prove.
#[test]
fn vault_steps_chain() {
    StableProver::init();
    let steps = vault_step::fixture::chain(11, 3);
    let nodes = vault_nodes(&steps);
    for (i, (claims, proof, _)) in nodes.iter().enumerate() {
        let chain = claims.vault.expect("a vault chain");
        assert_eq!(chain.r_first, steps[0].r_prev, "node {i} carries the first root");
        assert_eq!(chain.r_last, steps[i].public.r_next, "node {i} ends at its step's root");
        assert_eq!(chain.generation, steps[i].public.generation);
        assert!(proof.verify(claims), "node {i} verifies");
        // Its claims' byte form (the sidecar's wire) carries the chain: the decoded claims verify, the proof too.
        let wire = AggregateClaims::from_bytes(&claims.to_bytes()).expect("claims decode");
        assert_eq!(&wire, claims);
        let proof_wire = AggregateProof::from_bytes(&proof.to_bytes()).expect("proof decodes");
        assert!(proof_wire.verify(&wire), "node {i} verifies from its bytes");
        // Its statement binds the chain: any other chain is refused.
        for forge in [
            |c: &mut VaultChain| c.r_first[0] ^= 1,
            |c: &mut VaultChain| c.r_last[31] ^= 1,
            |c: &mut VaultChain| c.generation += 1,
            |c: &mut VaultChain| c.vault_id[5] ^= 1,
        ] {
            let mut other = claims.clone();
            forge(other.vault.as_mut().unwrap());
            assert!(!proof.verify(&other), "node {i} verified another chain");
        }
        let mut none = claims.clone();
        none.vault = None;
        assert!(!proof.verify(&none), "node {i} verified without its chain");
    }
    // Step 2 straight onto the node of step 0: its R_prev is not that chain's last root.
    let child = (nodes[0].0.clone(), nodes[0].1.clone());
    let skip = VaultStep {
        witness: steps[2].witness.clone(),
        r_prev: steps[2].r_prev,
    };
    let err = aggregate_with_vault::<StableProver>(&[child.clone()], vec![], vec![], None, OutputClaims::All, 1, Some(&skip));
    assert_eq!(err.err(), Some(AggregateError::ProvingFailed), "a step that skips one");
    // Another vault's step onto this chain.
    let other = vault_step::fixture::chain(12, 1);
    let foreign = VaultStep {
        witness: other[0].witness.clone(),
        r_prev: other[0].r_prev,
    };
    let err = aggregate_with_vault::<StableProver>(&[child], vec![], vec![], None, OutputClaims::All, 1, Some(&foreign));
    assert_eq!(err.err(), Some(AggregateError::ProvingFailed), "another vault's step");
}

/// Measurement, not a check (research build): the per-trade node, one vault step proven in the VM plus the node of
/// the step before verified in the VM, at rate 1/2. The whole `aggregate_with_vault` call timed, median of three; one
/// native verify; the proof's bytes; the process's peak memory.
#[test]
#[ignore = "benchmark"]
fn vault_bench() {
    StableProver::init();
    let steps = vault_step::fixture::chain(11, 2);
    let nodes = vault_nodes(&steps[..1]);
    let child = (nodes[0].0.clone(), nodes[0].1.clone());
    let step = VaultStep {
        witness: steps[1].witness.clone(),
        r_prev: steps[1].r_prev,
    };
    let mut times = Vec::new();
    let mut last = None;
    for _ in 0..3 {
        let t = std::time::Instant::now();
        let out = aggregate_with_vault::<StableProver>(
            std::slice::from_ref(&child),
            vec![],
            vec![],
            None,
            OutputClaims::All,
            1,
            Some(&step),
        )
        .expect("node");
        times.push(t.elapsed().as_secs_f64() * 1e3);
        last = Some(out);
    }
    let (claims, node, stats) = last.unwrap();
    let t = std::time::Instant::now();
    assert!(node.verify(&claims), "the node verifies");
    let verify_ms = t.elapsed().as_secs_f64() * 1e3;
    times.sort_by(f64::total_cmp);
    let hwm = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| s.lines().find(|l| l.starts_with("VmHWM:")).map(|l| l.split_whitespace().collect::<Vec<_>>().join(" ")))
        .unwrap_or_default();
    println!(
        "VAULT-NODE cycles={} blake3_rows={} keccak_rows={} prove_median_ms={:.1} verify_ms={verify_ms:.2} proof_kib={:.1} {hwm}",
        stats.cycles,
        stats.table_heights[verifier::layout::OP_BLAKE3],
        stats.table_heights[verifier::layout::OP_KECCAK],
        times[1],
        node.to_bytes().len() as f64 / 1024.0
    );
}

/// Research build: writes the Lean vectors of the vault step (`formal/Statement/VaultStepVectors.lean`, to the path in
/// `LEAN_VAULT_VECTORS`): three steps' witnesses, their keys and the hint pushes the node makes of them, and a vault
/// chain's statement cells, all from this Rust, for the Lean transcription (`Statement/VaultStep.lean`) to match.
#[test]
#[ignore]
fn write_lean_vault_vectors() {
    use std::fmt::Write;
    use vault_step::reference::{relationship_key, vault_state_key};
    let path = std::env::var("LEAN_VAULT_VECTORS").expect("LEAN_VAULT_VECTORS: where to write the Lean vectors");
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    let cells_hex = |cells: &[F128]| {
        hex(&cells.iter().flat_map(|c| [c.c0.to_le_bytes(), c.c1.to_le_bytes()].concat()).collect::<Vec<u8>>())
    };
    let bool_lean = |b: bool| if b { "true" } else { "false" };
    let mut out = String::from(
        "import Statement.VaultStep\n\n/-!\n# Research build: the vault step's vectors, from the Rust\n\n\
         Generated by `write_lean_vault_vectors` (`crates/aggregation/src/tests.rs`); not edited. Three steps' witnesses \
         (`vault_step::fixture`), their keys (the `blake3` crate) and the hint pushes the node makes of them \
         (`vault_step::program::hints`), and a vault chain's statement cells (`vault_cells`). Each `#guard` checks the \
         Lean transcription against them, cell by cell, as limbs. A plain file, not a module, so the guards may run \
         what it imports.\n-/\n\n\
         namespace LeanVM.Vault.Vectors\n\nopen LeanVM.Parameters\n\n\
         /-- A hex string's bytes. -/\ndef hexBytes (s : String) : List UInt8 :=\n  \
         let d := fun (c : Char) ↦ if c.isDigit then c.toNat - 48 else c.toNat - 87\n  \
         let cs := s.toList\n  (List.range (cs.length / 2)).map fun i ↦ (16 * d (cs.getD (2 * i) '0') + d (cs.getD (2 * i + 1) '0')).toUInt8\n\n\
         /-- A byte string's 32-byte pieces. -/\ndef chunks32 (b : List UInt8) : List (List UInt8) :=\n  \
         (List.range (b.length / 32)).map fun i ↦ (b.drop (32 * i)).take 32\n\n\
         /-- A cell's two limbs, which `K`'s equality compares. -/\ndef limbs (x : E) : K × K := (x.limb 0, x.limb 1)\n\n\
         /-- Cells written as their limbs' little-endian bytes, 16 per cell. -/\ndef hexCells (s : String) : List (K × K) :=\n  \
         let b := hexBytes s\n  (List.range (b.length / 16)).map fun i ↦ limbs (cell16 (b.drop (16 * i)))\n\n\
         /-- Pushes as limbs, for comparison. -/\ndef asLimbs (p : List (String × List E)) : List (String × List (K × K)) :=\n  \
         p.map fun e ↦ (e.1, e.2.map limbs)\n\n",
    );
    let cases = [(1u64, true, 3usize, 0u64), (2, false, 0, 5), (6, false, 2, 0)];
    let mut sides = [false; 2];
    for (n, (seed, present, others, attempt)) in cases.into_iter().enumerate() {
        let f = vault_step::fixture::fixture(seed, present, others, attempt);
        let w = &f.witness;
        sides[usize::from(w.hop.in_is_a)] = true;
        let s = &w.state;
        let path = |p: &[[u8; 32]]| hex(&p.concat());
        writeln!(
            out,
            "def witness{n} : StepWitness where\n  vaultId := hexBytes \"{}\"\n  state := {{ ownerGenesis := hexBytes \"{}\", \
             ownerDeviceId := hexBytes \"{}\", createPosition := {}, releasePolicy := hexBytes \"{}\", storageSetId := hexBytes \"{}\", \
             generation := {}, reserveA := {}, reserveB := {} }}\n  tokenA := hexBytes \"{}\"\n  tokenB := hexBytes \"{}\"\n  \
             feeBps := {}\n  inIsA := {}\n  amountIn := {}\n  amountOut := {}\n  traderGenesis := hexBytes \"{}\"\n  \
             traderDeviceId := hexBytes \"{}\"\n  relationshipBase := hexBytes \"{}\"\n  relationshipPresent := {}\n  \
             externalCommitment := hexBytes \"{}\"\n  attempt := {}\n  statePath := chunks32 (hexBytes \"{}\")\n  \
             relationshipPath := chunks32 (hexBytes \"{}\")\n  rPrev := hexBytes \"{}\"\n",
            hex(&w.vault_id),
            hex(&s.owner_genesis),
            hex(&s.owner_device_id),
            s.create_position,
            hex(&s.release_policy),
            hex(&s.storage_set_id),
            s.generation,
            s.reserve_a,
            s.reserve_b,
            hex(&w.token_a),
            hex(&w.token_b),
            w.fee_bps,
            bool_lean(w.hop.in_is_a),
            w.hop.amount_in,
            w.hop.amount_out,
            hex(&w.trader_genesis),
            hex(&w.trader_device_id),
            hex(&w.relationship_base),
            bool_lean(w.relationship_present),
            hex(&w.external_commitment),
            w.attempt,
            path(&w.state_path),
            path(&w.relationship_path),
            hex(&f.r_prev),
        )
        .unwrap();
        // The keys, by the `blake3` crate.
        writeln!(
            out,
            "#guard vaultStateKey witness{n}.vaultId == hexBytes \"{}\"\n#guard relationshipKey witness{n}.traderGenesis \
             witness{n}.traderDeviceId witness{n}.vaultId == hexBytes \"{}\"\n",
            hex(&vault_state_key(&w.vault_id)),
            hex(&relationship_key(&w.trader_genesis, &w.trader_device_id, &w.vault_id)),
        )
        .unwrap();
        // The pushes, as the node makes them: each stream's entries in order, the streams by name.
        let (streams, _) = vault_step::program::hints(w, &f.r_prev, &f.public);
        let entries: Vec<String> = streams
            .iter()
            .flat_map(|(name, entries)| entries.iter().map(move |e| (name, e)))
            .map(|(name, e)| format!("(\"{name}\", hexCells \"{}\")", cells_hex(e)))
            .collect();
        writeln!(
            out,
            "def pushes{n} : List (String × List (K × K)) :=\n  [{}]\n\n#guard asLimbs (stepPushes witness{n}) == pushes{n}\n",
            entries.join(",\n   ")
        )
        .unwrap();
    }
    assert_eq!(sides, [true, true], "both sides come in");
    // A vault chain's cells and no chain's, as the statement absorbs them.
    let f = vault_step::fixture::fixture(1, true, 3, 0);
    let chain = claims::VaultChain {
        vault_id: f.public.vault_id,
        r_first: f.public.r_prev,
        r_last: f.public.r_next,
        generation: 0xfedc_ba98_7654_3210,
        external_commitment: f.public.external_commitment,
        attempt_key: f.public.attempt_key,
    };
    writeln!(
        out,
        "def chain : VaultChain where\n  vaultId := hexBytes \"{}\"\n  rFirst := hexBytes \"{}\"\n  rLast := hexBytes \"{}\"\n  \
         generation := {}\n  externalCommitment := hexBytes \"{}\"\n  attemptKey := hexBytes \"{}\"\n\n\
         #guard (vaultCells (some chain)).map limbs == hexCells \"{}\"\n#guard (vaultCells none).map limbs == hexCells \"{}\"\n\n\
         end LeanVM.Vault.Vectors\n",
        hex(&chain.vault_id),
        hex(&chain.r_first),
        hex(&chain.r_last),
        chain.generation,
        hex(&chain.external_commitment),
        hex(&chain.attempt_key),
        cells_hex(&super::statement::vault_cells(&Some(chain))),
        cells_hex(&super::statement::vault_cells(&None)),
    )
    .unwrap();
    std::fs::write(&path, out).unwrap();
}
