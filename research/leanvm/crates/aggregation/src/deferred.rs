//! The deferred claim on the stacked bytecode and the sumcheck that batches it.

use super::cells::count;
use super::guest::unified_guest;
use super::hints::SubHints;
use fiat_shamir_prover::{FiatShamirState, RATE_SCALARS, Sequential, grinding_bits};
use isa::Prover;
use lean_vm_core::cpu::{from_scalar, to_scalar};
use primitives::field::F128;
use verifier::layout::BUS_BITS;
// `eq` tables on the calling thread: the batch runs under either prover, some of it in its pool's tasks.
use primitives::multilinear::{eq_table_serial as eq_table, interp};
use std::ops::Range;

pub(super) const RECURSION_AGG_LABEL: &[u8] = b"leanvm/recursion-aggregation/v1";

/// The claim on the stacked bytecode that a node defers rather than evaluating
/// in-circuit: one point and value (`doc/leanvm/main.tex` §Deferred evaluation
/// claims).
///
/// Only the point is transmitted; the value is derived from it on receipt, so a
/// prover that lies about a value changes the statement its proof has to satisfy
/// rather than the claim anyone checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DeferredBytecodeClaim {
    pub(super) bytecode_point: Vec<F128>,
    pub(super) bytecode_value: F128,
}

impl DeferredBytecodeClaim {
    /// What a leaf defers: the all-zeros point, where the value is just the
    /// table's first entry.
    pub(super) fn leaf() -> Self {
        Self::recompute(vec![F128::ZERO; bytecode_vars()])
    }

    /// The claim at `bytecode_point`, its value read off the point's [`bytecode_sums`].
    pub(super) fn from_sums(bytecode_point: Vec<F128>, sums: &[F128]) -> Self {
        let bytecode_value = bytecode_value(sums, &bytecode_point);
        Self {
            bytecode_point,
            bytecode_value,
        }
    }

    /// The claim at `bytecode_point`, a point of [`bytecode_vars`] coordinates, evaluated by the `verifier` crate,
    /// scalar and single threaded: what a received aggregate is checked with.
    pub(super) fn recompute(bytecode_point: Vec<F128>) -> Self {
        // Every leaf defers the all-zeros point, where the bytecode polynomial is just its table's first entry: a
        // leaf is the aggregate people verify most, and the general path is a pass over the whole table.
        let bytecode_value = if bytecode_point.iter().all(|x| *x == F128::ZERO) {
            F128::new(unified_guest().stacked_bytecode()[0], 0)
        } else {
            let scalars: Vec<_> = bytecode_point.iter().map(to_scalar).collect();
            from_scalar(
                unified_guest()
                    .bytecode()
                    .evaluate(&scalars)
                    .expect("a point of bytecode_vars() coordinates"),
            )
        };
        Self {
            bytecode_point,
            bytecode_value,
        }
    }

    /// The cells the statement digest absorbs, in the guest's `defer_stmt` order.
    pub(super) fn cells(&self) -> Vec<F128> {
        let mut cells = self.bytecode_point.clone();
        cells.push(self.bytecode_value);
        cells
    }
}

/// Cells of a child's fresh Flock claim: the lincheck's matrix part, its `alpha`, the skip point, the zerocheck's
/// first `FLOCK_NUM_LINCHECK_ROUNDS` coordinates, the lincheck's round challenges, then the 64 slices.
pub(super) const FLOCK_FRESH: usize = 3 + 2 * verifier::layout::FLOCK_NUM_LINCHECK_ROUNDS + verifier::layout::K_BITS;
/// Variables of a deferred matrix claim's point: the rows', then the columns'.
pub(super) const MATRIX_VARS: usize = 2 * verifier::layout::BLAKE3_R1CS_LOG_SIZE;

/// The claim on Flock's `A0`, `B0` a child's verification raises: its lincheck's matrix part, `sum_(r, c) (A0 + alpha
/// B0)[r][c] U(r) W(c)`, `U` the quirky eq table at `(z_skip, zchi)` and `W` the slices times eq at the lincheck's
/// challenges, bound top-down (`verifier::flock::matrix_term`). A guest takes it from a hint and defers it.
#[derive(Clone, Debug)]
pub(super) struct FreshFlockClaim {
    pub(super) matrix: F128,
    pub(super) alpha: F128,
    pub(super) z_skip: F128,
    pub(super) zchi: Vec<F128>,
    pub(super) rs: Vec<F128>,
    pub(super) s: Vec<F128>,
}

impl FreshFlockClaim {
    pub(super) fn of(flock: &verifier::flock::FlockClaims) -> Self {
        let lift = |v: &[verifier::E]| v.iter().copied().map(from_scalar).collect::<Vec<_>>();
        Self {
            matrix: from_scalar(flock.matrix),
            alpha: from_scalar(flock.alpha),
            z_skip: from_scalar(flock.z_skip),
            zchi: lift(&flock.chi[..verifier::layout::FLOCK_NUM_LINCHECK_ROUNDS]),
            rs: lift(&flock.round_challenges),
            s: lift(&flock.s),
        }
    }

    /// In the guest's `defer_out` order, after the bytecode's.
    pub(super) fn cells(&self) -> Vec<F128> {
        let mut cells = vec![self.matrix, self.alpha, self.z_skip];
        cells.extend(&self.zchi);
        cells.extend(&self.rs);
        cells.extend(&self.s);
        assert_eq!(cells.len(), FLOCK_FRESH);
        cells
    }

    /// The row weights `U` and the column weights `W` of its bilinear form.
    fn weights(&self) -> (Vec<F128>, Vec<F128>) {
        let k = verifier::layout::BLAKE3_R1CS_LOG_SIZE;
        let rows = flock::lincheck::build_quirky_eq_table(self.z_skip, &self.zchi, verifier::layout::FLOCK_K_SKIP);
        let columns = (0..1usize << k)
            .map(|col| {
                let mut w = self.s[col % verifier::layout::K_BITS];
                for (j, &rj) in self.rs.iter().enumerate() {
                    w *= if (col >> (k - 1 - j)) & 1 == 1 { rj } else { F128::ONE + rj };
                }
                w
            })
            .collect();
        (rows, columns)
    }
}

/// The claim on Flock's matrices a node defers: their multilinear extensions at one point. Only the point is
/// transmitted; the values are recomputed from it on receipt, as the bytecode's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DeferredMatrixClaim {
    pub(super) point: Vec<F128>,
    pub(super) a: F128,
    pub(super) b: F128,
}

impl DeferredMatrixClaim {
    /// What a leaf defers: the all-zeros point.
    pub(super) fn leaf() -> Self {
        Self::recompute(vec![F128::ZERO; MATRIX_VARS])
    }

    /// The claim at `point`, evaluated by the `verifier` crate (a forward walk of the BLAKE3 circuit).
    pub(super) fn recompute(point: Vec<F128>) -> Self {
        let scalars: Vec<_> = point.iter().map(to_scalar).collect();
        let (a, b) = verifier::flock::matrix_values(&scalars).expect("a point of MATRIX_VARS coordinates");
        Self {
            point,
            a: from_scalar(a),
            b: from_scalar(b),
        }
    }

    pub(super) fn cells(&self) -> Vec<F128> {
        let mut cells = self.point.clone();
        cells.extend([self.a, self.b]);
        cells
    }
}

/// Everything a node defers: the bytecode claim, then the matrix claim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DeferredClaim {
    pub(super) bytecode: DeferredBytecodeClaim,
    pub(super) matrix: DeferredMatrixClaim,
}

impl DeferredClaim {
    pub(super) fn leaf() -> Self {
        Self {
            bytecode: DeferredBytecodeClaim::leaf(),
            matrix: DeferredMatrixClaim::leaf(),
        }
    }

    pub(super) fn recompute(bytecode_point: Vec<F128>, matrix_point: Vec<F128>) -> Self {
        Self {
            bytecode: DeferredBytecodeClaim::recompute(bytecode_point),
            matrix: DeferredMatrixClaim::recompute(matrix_point),
        }
    }

    /// The cells the statement digest absorbs, in the guest's `defer_stmt` order.
    pub(super) fn cells(&self) -> Vec<F128> {
        let mut cells = self.bytecode.cells();
        cells.extend(self.matrix.cells());
        cells
    }
}

/// The rows of [`BLOCK`] entries of the stacked bytecode that hold its populated slots: every other row is
/// structurally zero.
fn bytecode_rows() -> Range<usize> {
    static ROWS: std::sync::OnceLock<Range<usize>> = std::sync::OnceLock::new();
    ROWS.get_or_init(|| {
        let rows = unified_guest().stacked_bytecode().as_chunks::<BLOCK>().0;
        let per_slot = rows.len() >> BUS_BITS;
        assert!(
            per_slot.is_multiple_of(8),
            "a slot is whole groups of rows, as `Prover::combine_rows` may require"
        );
        let live = |s: &usize| rows[s * per_slot..(s + 1) * per_slot].iter().flatten().any(|&v| v != 0);
        let slots = || 0..1 << BUS_BITS;
        let start = slots().find(live).expect("the bytecode is not all zero");
        let end = slots().rfind(live).expect("the bytecode is not all zero") + 1;
        start * per_slot..end * per_slot
    })
    .clone()
}

/// Low row variables of the stacked bytecode, which the batch binds first.
const BLOCK_VARS: usize = 10;
const BLOCK: usize = 1 << BLOCK_VARS;

/// Per claim point, the stacked bytecode with the point's weight on all but the low `BLOCK_VARS` variables summed
/// out: `G(low) = Σ_r eq(point[BLOCK_VARS..], r) · row_r[low]`, over rows `r` of `BLOCK` entries. The weight
/// `eq(point, ·)` is a product of a factor on the low variables and one on the rest, so the batch's low rounds run
/// on these, and a point's value is read off its own ([`bytecode_value`]).
pub(super) fn bytecode_sums<P: Prover>(points: &[Vec<F128>]) -> Vec<Vec<F128>> {
    let _span = tracing::info_span!("Bytecode sums").entered();
    let (table, live) = (unified_guest().stacked_bytecode(), bytecode_rows());
    points
        .iter()
        .map(|point| {
            // A leaf's claim weighs the first row alone.
            if point.iter().all(|&x| x == F128::ZERO) {
                return table[..BLOCK].iter().map(|&w| F128::new(w, 0)).collect();
            }
            let eq: Vec<_> = eq_table(&point[BLOCK_VARS..])[live.clone()]
                .iter()
                .map(to_scalar)
                .collect();
            let sums = P::combine_rows(&table[live.start * BLOCK..live.end * BLOCK], &eq);
            sums.into_iter().map(from_scalar).collect()
        })
        .collect()
}

/// The stacked bytecode at `point`, from its [`bytecode_sums`].
pub(super) fn bytecode_value(sums: &[F128], point: &[F128]) -> F128 {
    eq_table(&point[..BLOCK_VARS])
        .iter()
        .zip(sums)
        .map(|(&eq, &sum)| eq * sum)
        .sum()
}

/// Variables of a bytecode claim's point: the log row count plus the stacking
/// selectors.
pub(super) fn bytecode_vars() -> usize {
    unified_guest().stacked_bytecode().len().trailing_zeros() as usize
}

fn fold_lsb(table: &mut Vec<F128>, challenge: F128) {
    let half = table.len() / 2;
    for i in 0..half {
        table[i] = interp(table[2 * i], table[2 * i + 1], challenge);
    }
    table.truncate(half);
}

/// Compressed product-sumcheck round message of `u·m`: (g1, g∞) with g0 recovered from the
/// running claim.
fn round_msg(u: &[F128], m: &[F128]) -> (F128, F128) {
    (0..u.len() / 2).fold((F128::ZERO, F128::ZERO), |acc, i| {
        let (u0, u1) = (u[2 * i], u[2 * i + 1]);
        let (m0, m1) = (m[2 * i], m[2 * i + 1]);
        (acc.0 + u1 * m1, acc.1 + (u0 + u1) * (m0 + m1))
    })
}

/// The grind before the batching challenge, whose powers weigh at most `2 MAX_RECURSIONS` claims.
pub(super) const BATCH_LAM_GRIND_BITS: u32 = grinding_bits(2 * super::MAX_RECURSIONS as u128 - 1);
/// The grind before the matrix batch's challenge, whose powers weigh at most `3 MAX_RECURSIONS` claims.
pub(super) const MAT_LAM_GRIND_BITS: u32 = grinding_bits(3 * super::MAX_RECURSIONS as u128 - 1);

/// One round of a batching sumcheck, in the transcript order the guest mirrors
/// word for word: observe `(g1, g_inf)`, grind for the round's degree two, squeeze the fold challenge, record
/// the two words and the nonce, if the grind sends one, and advance the running claim through the compressed round polynomial.
/// Returns the challenge, which the caller folds its tables with.
fn absorb_round(
    transcript: &mut FiatShamirState<F128>,
    messages: &mut Vec<F128>,
    challenges: &mut Vec<F128>,
    claim: &mut F128,
    (g1, gi): (F128, F128),
) -> F128 {
    transcript.observe(g1);
    transcript.observe(gi);
    let nonce = transcript.grind::<Sequential>(grinding_bits(2));
    let challenge = transcript.sample();
    messages.extend([g1, gi]);
    messages.extend(nonce.map(|nonce| F128::new(nonce, 0)));
    challenges.push(challenge);
    let g0 = *claim + g1;
    let c1 = g0 + g1 + gi;
    *claim = (gi * challenge + c1) * challenge + g0;
    challenge
}

/// Mirror the guest's `aggregate_claims` transcript and prove the batching
/// sumcheck over the stacked bytecode.
///
/// Each child brings its public input and two claims, the fresh one its verification raised and the one it deferred:
/// `claims` holds them child by child in that order, and `sums` their [`bytecode_sums`]. A child's fresh claim is
/// batched with its carried one at every child count, one included. Returns the guest hints and the single claim they
/// reduce to.
pub(super) fn aggregate_deferred_claims<P: Prover>(
    public_inputs: &[[F128; 2]],
    claims: &[DeferredBytecodeClaim],
    mut sums: Vec<Vec<F128>>,
    fresh_flock: &[FreshFlockClaim],
    carried_matrix: &[DeferredMatrixClaim],
) -> (SubHints, DeferredClaim) {
    let kbcv = bytecode_vars();

    // The count and each child's words are padded with zeros to whole rates, so the
    // guest's loop over the children finds every child starting the same way.
    let mut transcript = FiatShamirState::from_label(RECURSION_AGG_LABEL);
    let pad = |transcript: &mut FiatShamirState<F128>, n: usize| {
        for _ in 0..n.next_multiple_of(RATE_SCALARS) - n {
            transcript.observe(F128::ZERO);
        }
    };
    transcript.observe(count(public_inputs.len()));
    pad(&mut transcript, 1);
    for (((public_input, pair), fresh), carried) in public_inputs
        .iter()
        .zip(claims.chunks(2))
        .zip(fresh_flock)
        .zip(carried_matrix)
    {
        // The guest's order: the statement, the fresh region (bytecode, then Flock), the carried region (bytecode,
        // then matrices).
        let words: Vec<F128> = public_input
            .iter()
            .copied()
            .chain(pair[0].cells())
            .chain(fresh.cells())
            .chain(pair[1].cells())
            .chain(carried.cells())
            .collect();
        for &value in &words {
            transcript.observe(value);
        }
        pad(&mut transcript, words.len());
    }

    let _span = tracing::info_span!("Bytecode batch", vars = kbcv).entered();
    // Powers of one challenge: child i's fresh claim takes lam^(2i), its carried one lam^(2i+1). The batch's grinds
    // are short, so they search on the calling thread, under either prover.
    let nonce = transcript.grind::<Sequential>(BATCH_LAM_GRIND_BITS);
    let lam = transcript.sample();
    let powers: Vec<F128> = std::iter::successors(Some(F128::ONE), |&power| Some(power * lam))
        .take(claims.len())
        .collect();
    // The running claim: the claims' values weighed by their powers.
    let mut claim: F128 = powers.iter().zip(claims).map(|(&g, c)| g * c.bytecode_value).sum();
    let mut messages: Vec<F128> = nonce.map(|nonce| F128::new(nonce, 0)).into_iter().collect();
    let mut challenges = Vec::new();
    // The low rounds, on each claim's sums against its `eq` on the low rows, scaled by its power of `lam`.
    let mut low_weights: Vec<Vec<F128>> = claims
        .iter()
        .zip(&powers)
        .map(|(c, &power)| {
            eq_table(&c.bytecode_point[..BLOCK_VARS])
                .into_iter()
                .map(|eq| power * eq)
                .collect()
        })
        .collect();
    for _ in 0..BLOCK_VARS {
        let msg = sums
            .iter()
            .zip(&low_weights)
            .fold((F128::ZERO, F128::ZERO), |acc, (sums, weights)| {
                let (g1, gi) = round_msg(sums, weights);
                (acc.0 + g1, acc.1 + gi)
            });
        let r = absorb_round(&mut transcript, &mut messages, &mut challenges, &mut claim, msg);
        for table in sums.iter_mut().chain(&mut low_weights) {
            fold_lsb(table, r);
        }
    }
    // The rest: every row against the low challenges, zero outside the populated ones, and each claim's `eq` on
    // the rows, scaled by what its low rows left.
    let (table, live) = (unified_guest().stacked_bytecode(), bytecode_rows());
    let mut rows = vec![F128::ZERO; table.len() / BLOCK];
    let low_eq: Vec<_> = eq_table(&challenges).iter().map(to_scalar).collect();
    let dots = P::dot_rows(&table[live.start * BLOCK..live.end * BLOCK], &low_eq);
    for (row, dot) in rows[live].iter_mut().zip(dots) {
        *row = from_scalar(dot);
    }
    let mut weights = vec![F128::ZERO; rows.len()];
    for (c, low_weight) in claims.iter().zip(&low_weights) {
        for (weight, eq) in weights.iter_mut().zip(eq_table(&c.bytecode_point[BLOCK_VARS..])) {
            *weight += low_weight[0] * eq;
        }
    }
    for _ in BLOCK_VARS..kbcv {
        let msg = round_msg(&rows, &weights);
        let r = absorb_round(&mut transcript, &mut messages, &mut challenges, &mut claim, msg);
        fold_lsb(&mut rows, r);
        fold_lsb(&mut weights, r);
    }
    let value = rows[0];
    assert_eq!(
        claim,
        value * weights[0],
        "every claim's value is the bytecode's evaluation"
    );

    drop(_span);
    let (mat_messages, matrix) = matrix_batch(&mut transcript, fresh_flock, carried_matrix);
    let hints = vec![
        ("bc_sumcheck_msgs", messages),
        ("bc_star_hint", vec![value]),
        ("mat_sumcheck_msgs", mat_messages),
        ("mat_stars_hint", vec![matrix.a, matrix.b]),
    ];
    let reduced = DeferredClaim {
        bytecode: DeferredBytecodeClaim {
            bytecode_point: challenges,
            bytecode_value: value,
        },
        matrix,
    };
    (hints, reduced)
}

/// The matrix batch, after the bytecode's, in the transcript order the guest mirrors: a grind and one challenge
/// `lam`, child `i`'s fresh claim taking `lam^(3i)` (its `B0` part times its `alpha`) and its carried `A0` and `B0`
/// claims `lam^(3i + 1)`, `lam^(3i + 2)`; then one sumcheck over the `MATRIX_VARS` variables of `A0` and `B0`, rows
/// first, its rounds those of [`absorb_round`]. The row rounds run on each claim's row tables `(A0 W, B0 W)`, the
/// circuit walked forward once per claim; the column rounds on the column marginals at the row challenges, walked
/// backward once. Returns the hints (the nonce, if the grind sends one, then the rounds) and the claim they reduce to.
fn matrix_batch(
    transcript: &mut FiatShamirState<F128>,
    fresh: &[FreshFlockClaim],
    carried: &[DeferredMatrixClaim],
) -> (Vec<F128>, DeferredMatrixClaim) {
    let _span = tracing::info_span!("Matrix batch").entered();
    let k = verifier::layout::BLAKE3_R1CS_LOG_SIZE;
    let nonce = transcript.grind::<Sequential>(MAT_LAM_GRIND_BITS);
    let lam = transcript.sample();
    let mut messages: Vec<F128> = nonce.map(|nonce| F128::new(nonce, 0)).into_iter().collect();
    // One group per claim: its row weights, its column weights, and the coefficient each matrix enters with.
    let (mut us, mut ws, mut ga, mut gb) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    let mut claim = F128::ZERO;
    let mut power = F128::ONE;
    for (f, c) in fresh.iter().zip(carried) {
        let (u, w) = f.weights();
        us.push(u);
        ws.push(w);
        ga.push(power);
        gb.push(power * f.alpha);
        us.push(eq_table(&c.point[..k]));
        ws.push(eq_table(&c.point[k..]));
        ga.push(power * lam);
        gb.push(power * lam * lam);
        claim += power * (f.matrix + lam * (c.a + lam * c.b));
        power *= lam * lam * lam;
    }
    // Each claim's row tables, `(A0 W, B0 W)`, by one forward walk of the circuit.
    let mut ms: Vec<(Vec<F128>, Vec<F128>)> = ws.iter().map(|w| flock::hash::row_values_walk(w)).collect();
    // A fresh claim's value is its bilinear form: the hint the guest took is this.
    for (t, f) in fresh.iter().enumerate() {
        let (u, (ma, mb)) = (&us[2 * t], &ms[2 * t]);
        let form: F128 = u.iter().zip(ma.iter().zip(mb)).map(|(&u, (&a, &b))| u * (a + f.alpha * b)).sum();
        assert_eq!(form, f.matrix, "a child's fresh matrix claim is its bilinear form");
    }
    let mut challenges = Vec::new();
    for _ in 0..k {
        let msg = (0..us.len()).fold((F128::ZERO, F128::ZERO), |acc, t| {
            let (a1, ai) = round_msg(&us[t], &ms[t].0);
            let (b1, bi) = round_msg(&us[t], &ms[t].1);
            (acc.0 + ga[t] * a1 + gb[t] * b1, acc.1 + ga[t] * ai + gb[t] * bi)
        });
        let r = absorb_round(transcript, &mut messages, &mut challenges, &mut claim, msg);
        for u in us.iter_mut() {
            fold_lsb(u, r);
        }
        for (ma, mb) in ms.iter_mut() {
            fold_lsb(ma, r);
            fold_lsb(mb, r);
        }
    }
    // The column marginals at the row challenges, `A0^T eq` and `B0^T eq`, by one backward walk.
    let (mut acol, mut bcol) = flock::hash::marginal_walk_pair(&eq_table(&challenges));
    let (mut wa, mut wb) = (vec![F128::ZERO; 1 << k], vec![F128::ZERO; 1 << k]);
    for t in 0..us.len() {
        let (sa, sb) = (ga[t] * us[t][0], gb[t] * us[t][0]);
        for j in 0..1 << k {
            wa[j] += sa * ws[t][j];
            wb[j] += sb * ws[t][j];
        }
    }
    for _ in 0..k {
        let (a1, ai) = round_msg(&acol, &wa);
        let (b1, bi) = round_msg(&bcol, &wb);
        let r = absorb_round(transcript, &mut messages, &mut challenges, &mut claim, (a1 + b1, ai + bi));
        for table in [&mut acol, &mut bcol, &mut wa, &mut wb] {
            fold_lsb(table, r);
        }
    }
    let (a, b) = (acol[0], bcol[0]);
    assert_eq!(claim, a * wa[0] + b * wb[0], "the matrix batch's terminal");
    (messages, DeferredMatrixClaim { point: challenges, a, b })
}
