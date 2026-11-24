//! The vault-step program proves a valid step, its statement the reference's, and refuses invalid ones.
//!
//! Each refusal gives the prover the attacker's own consistent statement (`statement_for`, the step's statement with
//! Core's checks skipped) and self-consistent hints for the lie, so the refusal comes from the check under test, not
//! from a mismatched public input.
//!
//! Each refusal is then tried on the verifier too: a malicious prover (`prove_forging`) runs the lie past every failed
//! check, keeping each cell's first value, and proves that run as an honest prover proves its own; the verifier must
//! refuse the proof.
use isa::Program;
use lean_vm_core::cpu::{Tactic, prove, prove_forging, verify};
use primitives::field::{F128, g_pow};
use vault_step::fixture::{Fixture, fixture};
use vault_step::program::{Witness, cells, hints, program};
use vault_step::reference::*;

fn gp(e: usize) -> F128 {
    F128::from(g_pow(e))
}

/// Prove and verify; `Err` with the reason when either refuses.
fn run(p: &Program, witness: &Witness, public: [F128; 2]) -> Result<(), String> {
    let (proof, _) = prove(p, witness, public, 1).map_err(|e| format!("prove: {e:?}"))?;
    verify(p, &public, &proof)
        .map(drop)
        .map_err(|e| format!("verify: {e:?}"))
}

fn stream<'a>(w: &'a mut Witness, name: &str) -> &'a mut Vec<Vec<F128>> {
    &mut w.iter_mut().find(|(n, _)| n == name).expect("stream").1
}

/// The honest post-state of a fixture's step.
fn post(f: &Fixture) -> VaultStateLeaf {
    swap_vault_post(&f.witness.state, f.witness.fee_bps, &f.witness.hop).unwrap()
}

/// The statement an attacker claims for witness `w` with post-state `post`, as the program's public input; where
/// the paths do not even fold together (the reference refuses them outright), the honest statement.
fn forged(w: &StepWitness, r_prev: &D32, post: &VaultStateLeaf, honest: &StepPublic) -> [F128; 2] {
    match statement_for(w, r_prev, post) {
        Ok((_, public)) => cells(&public.digest()),
        Err(why) => {
            eprintln!("  (reference refuses to fold: {why}; the honest statement)");
            cells(&honest.digest())
        }
    }
}

/// How a lie was refused: by the verifier, on a proof of the lie's run gone past its failed checks; or, where the run
/// stops at a fault no trace can carry, the fault.
enum Refusal {
    Verifier,
    NoTrace(String),
}

fn refused(p: &Program, what: &str, witness: &Witness, public: [F128; 2]) -> Refusal {
    match run(p, witness, public) {
        Ok(()) => panic!("{what}: an invalid step proved and verified"),
        Err(e) => eprintln!("REFUSED {what}: {}", &e[..e.len().min(160)]),
    }
    // Both tactics: the first value of each disputed cell kept, or the last.
    let mut refusal = Refusal::Verifier;
    for tactic in [Tactic::KeepFirst, Tactic::KeepLast] {
        match prove_forging(p, witness, public, 1, tactic) {
            Ok((proof, _, forged)) => {
                assert!(forged > 0, "{what}: the forging run went past no check");
                let why = match verify(p, &public, &proof) {
                    Ok(_) => panic!(
                        "{what} ({tactic:?}): the verifier accepted a proof of a run past {forged} failed checks"
                    ),
                    Err(e) => format!("{e:?}"),
                };
                eprintln!(
                    "  VERIFIER REFUSED {what} ({tactic:?}): past {forged} failed checks: {}",
                    &why[..why.len().min(120)]
                );
            }
            Err(e) => {
                let e = format!("{tactic:?}: {e:?}");
                eprintln!("  NO TRACE {what}: {}", &e[..e.len().min(200)]);
                refusal = Refusal::NoTrace(e);
            }
        }
    }
    refusal
}

#[test]
fn a_valid_step_proves() {
    let p = program();
    let f = fixture(1, true, 3, 0);
    let (witness, public) = hints(&f.witness, &f.r_prev, &f.public);
    let t = std::time::Instant::now();
    let (proof, stats) = match prove(&p, &witness, public, 1) {
        Ok(x) => x,
        Err(e) => panic!("proving failed: {e:?}"),
    };
    eprintln!(
        "VAULT-STEP cycles={} prove_ms={:.0} rows={:?} code={}",
        stats.cycles,
        t.elapsed().as_secs_f64() * 1e3,
        stats.table_heights,
        p.prog.len()
    );
    verify(&p, &public, &proof).expect("verifies");
    // The malicious prover on an honest run goes past no check, and its proof verifies: it is a working prover, so
    // its proofs of the lies below are refused for the lies.
    for tactic in [Tactic::KeepFirst, Tactic::KeepLast] {
        let (forged, _, gone_past) =
            prove_forging(&p, &witness, public, 1, tactic).expect("the forging prover proves an honest run");
        assert_eq!(gone_past, 0);
        verify(&p, &public, &forged).expect("the forging prover's proof of an honest run verifies");
    }
    // The same proof against any other statement is refused.
    let mut other = public;
    other[1] = other[1] + F128::from(1u128);
    assert!(
        verify(&p, &other, &proof).is_err(),
        "a proof verified against another statement"
    );
}

#[test]
fn every_kind_of_valid_step_proves() {
    let p = program();
    // Leaf present or absent, other traders or none, first attempt or a later one, either side coming in.
    let cases = [
        (1, true, 3, 0),
        (2, false, 0, 5),
        (3, false, 6, 1),
        (4, true, 0, 0),
        (5, true, 9, 2),
        (6, false, 2, 0),
    ];
    let mut sides = [false; 2];
    for (seed, present, others, attempt) in cases {
        let f = fixture(seed, present, others, attempt);
        sides[usize::from(f.witness.hop.in_is_a)] = true;
        let (witness, public) = hints(&f.witness, &f.r_prev, &f.public);
        run(&p, &witness, public).unwrap_or_else(|e| panic!("seed {seed}: {e}"));
    }
    assert_eq!(sides, [true, true], "both sides came in");
}

#[test]
fn invalid_steps_are_refused() {
    let p = program();
    let f = fixture(1, true, 3, 0);
    let w = &f.witness;
    let honest = post(&f);
    let mut seen = Vec::new();
    let take_out = |s: &mut VaultStateLeaf, in_is_a: bool, by: i64| {
        let r = if in_is_a { &mut s.reserve_b } else { &mut s.reserve_a };
        *r = (*r as i64 - by) as u64;
    };

    // The honest witness under another statement.
    let (witness, mut public) = hints(w, &f.r_prev, &f.public);
    public[0] = public[0] + F128::from(1u128);
    seen.push(refused(&p, "honest step, other statement", &witness, public));

    // 3: one unit more, or one less, out than the constant product pays.
    for by in [1i64, -1] {
        let mut bad = w.clone();
        bad.hop.amount_out = (bad.hop.amount_out as i64 + by) as u64;
        let mut s = honest.clone();
        take_out(&mut s, w.hop.in_is_a, by);
        let public = forged(&bad, &f.r_prev, &s, &f.public);
        let (witness, _) = hints(&bad, &f.r_prev, &f.public);
        seen.push(refused(&p, &format!("amount out {by:+}"), &witness, public));
    }

    // 2: a fee the state's fee policy does not address, priced at that fee.
    let mut bad = w.clone();
    bad.fee_bps = 0;
    let (r_in, r_out) = if w.hop.in_is_a {
        (w.state.reserve_a, w.state.reserve_b)
    } else {
        (w.state.reserve_b, w.state.reserve_a)
    };
    bad.hop.amount_out = constant_product_output(w.hop.amount_in, r_in, r_out, 0).unwrap();
    let mut s = honest.clone();
    take_out(
        &mut s,
        w.hop.in_is_a,
        bad.hop.amount_out as i64 - w.hop.amount_out as i64,
    );
    let (witness, _) = hints(&bad, &f.r_prev, &f.public);
    seen.push(refused(
        &p,
        "fee not the policy's",
        &witness,
        forged(&bad, &f.r_prev, &s, &f.public),
    ));

    // 5: a generation that skips.
    let mut s = honest.clone();
    s.generation += 1;
    let (witness, _) = hints(w, &f.r_prev, &f.public);
    seen.push(refused(
        &p,
        "generation skips",
        &witness,
        forged(w, &f.r_prev, &s, &f.public),
    ));

    // 4: reserves that do not move by the amounts.
    let mut s = honest.clone();
    if w.hop.in_is_a {
        s.reserve_a += 1;
    } else {
        s.reserve_b += 1;
    }
    seen.push(refused(
        &p,
        "reserve in off by one",
        &witness,
        forged(w, &f.r_prev, &s, &f.public),
    ));

    // 8: the relationship leaf claimed absent while the tree holds it.
    let mut bad = w.clone();
    bad.relationship_present = false;
    let (witness, _) = hints(&bad, &f.r_prev, &f.public);
    seen.push(refused(
        &p,
        "present leaf claimed absent",
        &witness,
        forged(&bad, &f.r_prev, &honest, &f.public),
    ));

    // 8: a path that does not fold to R_prev, each leaf's, the attacker's R_next from it.
    for which in ["state", "relationship"] {
        let mut bad = w.clone();
        let path = if which == "state" {
            &mut bad.state_path
        } else {
            &mut bad.relationship_path
        };
        path[200][3] ^= 1;
        let (witness, _) = hints(&bad, &f.r_prev, &f.public);
        seen.push(refused(
            &p,
            &format!("{which} path"),
            &witness,
            forged(&bad, &f.r_prev, &honest, &f.public),
        ));
    }

    // 8: the wrong level for where the two keys part.
    let (mut witness, public) = hints(w, &f.r_prev, &f.public);
    let d = stream(&mut witness, "vs_divergence");
    let e = (0..256).find(|&e| d[0][0] == gp(e)).unwrap();
    d[0][0] = gp(e + 1);
    seen.push(refused(&p, "divergence level", &witness, public));

    // A digit out of range (17 for 1, the next digit one less: the same value in a wider alphabet).
    let (mut witness, public) = hints(w, &f.r_prev, &f.public);
    let amount_in = &mut stream(&mut witness, "vs_digits")[4];
    let d0 = (0..16).find(|&e| amount_in[0] == gp(e)).unwrap();
    let d1 = (0..16).find(|&e| amount_in[1] == gp(e)).unwrap();
    if d1 > 0 {
        amount_in[0] = gp(d0 + 16);
        amount_in[1] = gp(d1 - 1);
        seen.push(refused(&p, "digit out of range", &witness, public));
    }

    // The price's remainder, one past the divisor.
    let (mut witness, public) = hints(w, &f.r_prev, &f.public);
    let digits = stream(&mut witness, "vs_digits");
    digits[11] = digits[11].iter().map(|_| gp(15)).collect();
    seen.push(refused(&p, "remainder slack", &witness, public));

    // 2: a token gap that does not take token_a to token_b.
    let (mut witness, public) = hints(w, &f.r_prev, &f.public);
    let digits = stream(&mut witness, "vs_digits");
    digits[8][5] = if digits[8][5] == gp(0) { gp(1) } else { gp(0) };
    seen.push(refused(&p, "token gap", &witness, public));

    // 9: a later attempt claimed as the first, under the first attempt's key.
    let f5 = fixture(2, false, 0, 5);
    let mut first = f5.public.clone();
    first.attempt_key = successor_base_key(&f5.witness.vault_id, &f5.r_prev);
    let (mut witness, _) = hints(&f5.witness, &f5.r_prev, &f5.public);
    stream(&mut witness, "vs_attempt_is_zero")[0][0] = F128::from(1u128);
    seen.push(refused(&p, "attempt 5 as attempt 0", &witness, cells(&first.digest())));

    // 9: attempt 0 claimed as a non-first attempt (the zero flag cleared).
    let (mut witness, _) = hints(w, &f.r_prev, &f.public);
    stream(&mut witness, "vs_attempt_is_zero")[0][0] = F128::from(0u128);
    let mut later = f.public.clone();
    let base = successor_base_key(&w.vault_id, &f.r_prev);
    later.attempt_key = h(TAG_SUCC_ATTEMPT, &[&base, &0u64.to_be_bytes()]);
    seen.push(refused(
        &p,
        "attempt 0 without the zero flag",
        &witness,
        cells(&later.digest()),
    ));

    // Every lie whose run leaves a trace was refused by the verifier, not only by the honest prover.
    let traced = seen.iter().filter(|r| matches!(r, Refusal::Verifier)).count();
    let untraced: Vec<_> = seen
        .iter()
        .filter_map(|r| if let Refusal::NoTrace(e) = r { Some(e) } else { None })
        .collect();
    eprintln!(
        "VERIFIER REFUSED {traced} of {} lies; no trace for {}: {untraced:?}",
        seen.len(),
        untraced.len()
    );
    assert_eq!(traced, seen.len(), "a lie the malicious prover could not even commit");
    assert_eq!(seen.len(), 15);
}

/// A lie's own fully consistent statement and root: the tree root its paths fold to with its leaves, and the statement
/// it would publish from there, so only the check under test can refuse it.
fn consistent(bad: &mut StepWitness, post: &VaultStateLeaf) -> (D32, StepPublic) {
    // The lie's own tree: its state leaf and, when present, its trader's relationship leaf.
    let mut tree = Tree::new();
    let state_key = vault_state_key(&bad.vault_id);
    tree.insert(state_key, vault_state_leaf_value(&bad.state));
    let rel_key = relationship_key(&bad.trader_genesis, &bad.trader_device_id, &bad.vault_id);
    if bad.relationship_present {
        tree.insert(
            rel_key,
            vault_relationship_leaf_value(&bad.trader_genesis, &bad.trader_device_id, &bad.relationship_base),
        );
    }
    bad.state_path = tree.path(&state_key);
    bad.relationship_path = tree.path(&rel_key);
    let pre = tree.root();
    let (folded, public) = statement_for(bad, &pre, post).expect("paths fold");
    assert_eq!(folded, pre);
    (pre, public)
}

/// Closes and releases of every kind prove and verify: the owner's close, computed terms, and signed terms of 1, 3 and
/// 16 branches (the last spanning several BLAKE3 chunks), with the trader's leaf present or absent.
#[test]
fn closes_and_releases_prove() {
    use vault_step::fixture::{Terms, terminal};
    let p = program();
    for (seed, release) in [
        (1, None),
        (2, Some(Terms::Computed)),
        (3, Some(Terms::Signed { branches: 1 })),
        (4, Some(Terms::Signed { branches: 3 })),
        (5, Some(Terms::Signed { branches: 16 })),
    ] {
        let f = terminal(seed, release, seed % 2 == 0, 2);
        let (witness, public) = hints(&f.witness, &f.r_prev, &f.public);
        let t = std::time::Instant::now();
        let (proof, stats) = prove(&p, &witness, public, 1).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        verify(&p, &public, &proof).unwrap_or_else(|e| panic!("seed {seed}: {e:?}"));
        let size = match &f.witness.kind {
            Kind::Release(r) => r.terms.len(),
            _ => 0,
        };
        eprintln!(
            "TERMINAL {release:?} terms={size}B cycles={} prove_ms={:.0}",
            stats.cycles,
            t.elapsed().as_secs_f64() * 1e3
        );
    }
}

/// Lies about a close, a release and a market vault's release policy are refused, by the prover and by the verifier.
#[test]
fn terminal_lies_are_refused() {
    use vault_step::fixture::{Terms, terminal};
    let p = program();
    let mut seen = Vec::new();
    let mut lie = |what: &str, mut bad: StepWitness, post: VaultStateLeaf| {
        let (r_prev, public) = consistent(&mut bad, &post);
        let (witness, _) = hints(&bad, &r_prev, &public);
        seen.push(refused(&p, what, &witness, cells(&public.digest())));
    };
    // A close by anyone but the origin owner; a close of a vault whose id is not the owner's derivation.
    let c = terminal(1, None, true, 2);
    let retired = retire_vault_post(&c.witness.state).unwrap();
    let mut bad = c.witness.clone();
    bad.trader_genesis[0] ^= 1;
    lie("close by a non-owner", bad, retired.clone());
    let mut bad = c.witness.clone();
    bad.state.create_position += 1;
    let post = retire_vault_post(&bad.state).unwrap();
    lie("close of a vault the owner did not derive", bad, post);
    // A release to a trader the named branch does not pay; naming another branch's outcome; a partial release; terms
    // other than the ones the slots name; the computed kind's another recipient.
    for terms in [Terms::Signed { branches: 3 }, Terms::Computed] {
        let r = terminal(4, Some(terms), true, 2);
        let retired = retire_vault_post(&r.witness.state).unwrap();
        let mut bad = r.witness.clone();
        bad.trader_device_id[7] ^= 1;
        lie(
            &format!("{terms:?} release to a trader the branch does not pay"),
            bad,
            retired.clone(),
        );
        let mut bad = r.witness.clone();
        if let Kind::Release(rel) = &mut bad.kind {
            let view = decode_escrow(&rel.terms).unwrap();
            rel.outcome = view.branches.iter().find(|b| b.0 != rel.outcome).unwrap().0.clone();
        }
        lie(
            &format!("{terms:?} release naming another branch's outcome"),
            bad,
            retired.clone(),
        );
        let mut bad = r.witness.clone();
        bad.state.reserve_b = 1;
        let post = retire_vault_post(&bad.state).unwrap();
        lie(&format!("{terms:?} release of part of the vault"), bad, post);
        let mut bad = r.witness.clone();
        if let Kind::Release(rel) = &mut bad.kind {
            let at = rel.terms.len() - 40;
            rel.terms[at] ^= 1; // a recipient's byte: still terms, not the slots'
        }
        lie(&format!("{terms:?} release under other terms"), bad, retired.clone());
    }
    // A swap on a market vault whose release policy is not the one beta profile.
    let s = fixture(1, true, 3, 0);
    let mut bad = s.witness.clone();
    bad.state.release_policy[0] ^= 1;
    let post = swap_vault_post(&bad.state, bad.fee_bps, &bad.hop).unwrap();
    lie("swap on a vault naming another release policy", bad, post);
    let traced = seen.iter().filter(|r| matches!(r, Refusal::Verifier)).count();
    eprintln!("VERIFIER REFUSED {traced} of {} terminal lies", seen.len());
    assert_eq!(traced, seen.len());
    assert_eq!(seen.len(), 11);
}
