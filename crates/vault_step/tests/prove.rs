//! The vault-step program proves a valid step, its statement the reference's, and refuses invalid ones.
//!
//! Each refusal gives the prover the attacker's own consistent statement (`statement_for`, the step's statement with
//! Core's checks skipped) and self-consistent hints for the lie, so the refusal comes from the check under test, not
//! from a mismatched public input.
use isa::Program;
use lean_vm_core::cpu::{prove, verify};
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
    verify(p, &public, &proof).map(drop).map_err(|e| format!("verify: {e:?}"))
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

fn refused(p: &Program, what: &str, witness: &Witness, public: [F128; 2]) {
    match run(p, witness, public) {
        Ok(()) => panic!("{what}: an invalid step proved and verified"),
        Err(e) => eprintln!("REFUSED {what}: {}", &e[..e.len().min(160)]),
    }
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
    // The same proof against any other statement is refused.
    let mut other = public;
    other[1] = other[1] + F128::from(1u128);
    assert!(verify(&p, &other, &proof).is_err(), "a proof verified against another statement");
}

#[test]
fn every_kind_of_valid_step_proves() {
    let p = program();
    // Leaf present or absent, other traders or none, first attempt or a later one, either side coming in.
    let cases = [(1, true, 3, 0), (2, false, 0, 5), (3, false, 6, 1), (4, true, 0, 0), (5, true, 9, 2), (6, false, 2, 0)];
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
    let take_out = |s: &mut VaultStateLeaf, in_is_a: bool, by: i64| {
        let r = if in_is_a { &mut s.reserve_b } else { &mut s.reserve_a };
        *r = (*r as i64 - by) as u64;
    };

    // The honest witness under another statement.
    let (witness, mut public) = hints(w, &f.r_prev, &f.public);
    public[0] = public[0] + F128::from(1u128);
    refused(&p, "honest step, other statement", &witness, public);

    // 3: one unit more, or one less, out than the constant product pays.
    for by in [1i64, -1] {
        let mut bad = w.clone();
        bad.hop.amount_out = (bad.hop.amount_out as i64 + by) as u64;
        let mut s = honest.clone();
        take_out(&mut s, w.hop.in_is_a, by);
        let public = forged(&bad, &f.r_prev, &s, &f.public);
        let (witness, _) = hints(&bad, &f.r_prev, &f.public);
        refused(&p, &format!("amount out {by:+}"), &witness, public);
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
    take_out(&mut s, w.hop.in_is_a, bad.hop.amount_out as i64 - w.hop.amount_out as i64);
    let (witness, _) = hints(&bad, &f.r_prev, &f.public);
    refused(&p, "fee not the policy's", &witness, forged(&bad, &f.r_prev, &s, &f.public));

    // 5: a generation that skips.
    let mut s = honest.clone();
    s.generation += 1;
    let (witness, _) = hints(w, &f.r_prev, &f.public);
    refused(&p, "generation skips", &witness, forged(w, &f.r_prev, &s, &f.public));

    // 4: reserves that do not move by the amounts.
    let mut s = honest.clone();
    if w.hop.in_is_a {
        s.reserve_a += 1;
    } else {
        s.reserve_b += 1;
    }
    refused(&p, "reserve in off by one", &witness, forged(w, &f.r_prev, &s, &f.public));

    // 8: the relationship leaf claimed absent while the tree holds it.
    let mut bad = w.clone();
    bad.relationship_present = false;
    let (witness, _) = hints(&bad, &f.r_prev, &f.public);
    refused(&p, "present leaf claimed absent", &witness, forged(&bad, &f.r_prev, &honest, &f.public));

    // 8: a path that does not fold to R_prev, each leaf's, the attacker's R_next from it.
    for which in ["state", "relationship"] {
        let mut bad = w.clone();
        let path = if which == "state" { &mut bad.state_path } else { &mut bad.relationship_path };
        path[200][3] ^= 1;
        let (witness, _) = hints(&bad, &f.r_prev, &f.public);
        refused(&p, &format!("{which} path"), &witness, forged(&bad, &f.r_prev, &honest, &f.public));
    }

    // 8: the wrong level for where the two keys part.
    let (mut witness, public) = hints(w, &f.r_prev, &f.public);
    let d = stream(&mut witness, "vs_divergence");
    let e = (0..256).find(|&e| d[0][0] == gp(e)).unwrap();
    d[0][0] = gp(e + 1);
    refused(&p, "divergence level", &witness, public);

    // A digit out of range (17 for 1, the next digit one less: the same value in a wider alphabet).
    let (mut witness, public) = hints(w, &f.r_prev, &f.public);
    let amount_in = &mut stream(&mut witness, "vs_digits")[4];
    let d0 = (0..16).find(|&e| amount_in[0] == gp(e)).unwrap();
    let d1 = (0..16).find(|&e| amount_in[1] == gp(e)).unwrap();
    if d1 > 0 {
        amount_in[0] = gp(d0 + 16);
        amount_in[1] = gp(d1 - 1);
        refused(&p, "digit out of range", &witness, public);
    }

    // The price's remainder, one past the divisor.
    let (mut witness, public) = hints(w, &f.r_prev, &f.public);
    let digits = stream(&mut witness, "vs_digits");
    digits[11] = digits[11].iter().map(|_| gp(15)).collect();
    refused(&p, "remainder slack", &witness, public);

    // 2: a token gap that does not take token_a to token_b.
    let (mut witness, public) = hints(w, &f.r_prev, &f.public);
    let digits = stream(&mut witness, "vs_digits");
    digits[8][5] = if digits[8][5] == gp(0) { gp(1) } else { gp(0) };
    refused(&p, "token gap", &witness, public);

    // 9: a later attempt claimed as the first, under the first attempt's key.
    let f5 = fixture(2, false, 0, 5);
    let mut first = f5.public.clone();
    first.attempt_key = successor_base_key(&f5.witness.vault_id, &f5.r_prev);
    let (mut witness, _) = hints(&f5.witness, &f5.r_prev, &f5.public);
    stream(&mut witness, "vs_attempt_is_zero")[0][0] = F128::from(1u128);
    refused(&p, "attempt 5 as attempt 0", &witness, cells(&first.digest()));

    // 9: attempt 0 claimed as a non-first attempt (the zero flag cleared).
    let (mut witness, _) = hints(w, &f.r_prev, &f.public);
    stream(&mut witness, "vs_attempt_is_zero")[0][0] = F128::from(0u128);
    let mut later = f.public.clone();
    let base = successor_base_key(&w.vault_id, &f.r_prev);
    later.attempt_key = h(TAG_SUCC_ATTEMPT, &[&base, &0u64.to_be_bytes()]);
    refused(&p, "attempt 0 without the zero flag", &witness, cells(&later.digest()));
}
