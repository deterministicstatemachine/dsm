//! Flock's reduction of the `BLAKE3` table's validity (Succinct Labs' Flock, carried from leanVM 4242200163b0 to this
//! tree's `E`): the zerocheck, then the lincheck, whose 64 slice claims ring switching binds to `q_flock`.
//!
//! Scratch research port. The fixed zerocheck coordinates' soundness lemma was stated for the old 192-bit field; here
//! only its F2-independence premise is re-checked in 128 bits (the prover's `friendly_challenges_f2_independent`).

use crate::blake3::{G_LANES, IV, SIGMA};
use crate::field::{E, ONE, Scaled, ZERO};
use crate::layout::{BLAKE3_CONSTANT_COLUMN, BLAKE3_R1CS_LOG_SIZE, FLOCK_K_SKIP, FLOCK_NUM_LINCHECK_ROUNDS, K_BITS};
use crate::multilinear::{dot, eq_eval, eq_kernel, multilinear_eval};
use crate::transcript::{Transcript, grinding_bits, sumcheck};
use crate::{VerifierError, require};

const PHI_BASIS: [u64; 8] = [
    0x0000000000000001,
    0x033CE8BEDDC8A656,
    0x512620375ED2A108,
    0x0C9E636090AAFC01,
    0xBA4F3CD82801769C,
    0xBA26E7904ADB4A47,
    0x467698598926DC01,
    0x4418AE808B28BDD0,
];

/// `PHI[value]`: the F2-linear image of the byte `value` in the PHI basis.
pub fn phi(value: usize) -> E {
    let bits = (0..8).filter(|bit| value >> bit & 1 == 1);
    E::new(bits.fold(0, |acc, bit| acc ^ PHI_BASIS[bit]), 0)
}

/// The old generator's first two limbs (hex digits of pi), as the prover's `medium_generator`.
const MEDIUM_GENERATOR: E = E::new(0x243F6A8885A308D3, 0x13198A2E03707344);
pub const N_FIXED_CHALLENGES: usize = 7;
/// The grind before the zerocheck's sampled coordinates: their count is at most 32.
pub const FLOCK_POINT_GRIND_BITS: u32 = grinding_bits(32);
const _: () = assert!(BLAKE3_R1CS_LOG_SIZE + crate::layout::MAX_TABLE_LOG - FLOCK_K_SKIP - N_FIXED_CHALLENGES <= 32);
/// The grind before the univariate-skip challenge: P is of degree 2 (2^k_skip - 1) in it.
pub const FLOCK_SKIP_GRIND_BITS: u32 = grinding_bits(2 * (K_BITS as u128 - 1));

pub fn fixed_challenges() -> [E; N_FIXED_CHALLENGES] {
    let medium = |power: u32| {
        let value = MEDIUM_GENERATOR.pow(1 << power);
        value * (ONE + value).inv()
    };
    [
        phi(0xF7),
        phi(0x53),
        phi(0xB5),
        medium(0),
        medium(1),
        medium(2),
        medium(3),
    ]
}

/// The one barycentric denominator `PHI[:count]` has: `prod_(k != 0) PHI[k]`, inverted.
///
/// PHI is F2-linear in its index, so `PHI[i] + PHI[j] = PHI[i ^ j]`, and over a power-of-two prefix
/// `j -> i ^ j` only permutes the block. Every node is left the same product.
pub fn window_denominator(count: usize) -> E {
    (1..count).fold(ONE, |acc, k| acc * phi(k)).inv()
}

/// The barycentric weights of `PHI[:count]` at `point`, by prefix and suffix numerator products.
fn lagrange_weights(count: usize, point: E) -> Vec<E> {
    let differences: Vec<E> = (0..count).map(|node| point + phi(node)).collect();
    let mut prefix = vec![ONE; count + 1];
    let mut suffix = vec![ONE; count + 1];
    for i in 0..count {
        prefix[i + 1] = prefix[i] * differences[i];
        suffix[count - 1 - i] = suffix[count - i] * differences[count - 1 - i];
    }
    let denominator = window_denominator(count);
    (0..count).map(|i| prefix[i] * suffix[i + 1] * denominator).collect()
}

fn lagrange_interpolate(count: usize, values: &[E], point: E) -> E {
    dot(&lagrange_weights(count, point), values)
}

struct ZerocheckResult {
    z_skip: E,
    chi: Vec<E>,
    v_a: E,
    v_b: E,
    v_c: E,
}

/// The zerocheck: one univariate skip round, then nflock quadratic ones.
/// C rides those rounds with AB, so all three claims come out at one point.
fn verify_flock_zerocheck(log_n: usize, transcript: &mut Transcript) -> Result<ZerocheckResult, VerifierError> {
    // The point r: seven fixed coordinates, the rest sampled.
    let mut r: Vec<Option<E>> = fixed_challenges().map(Some).into();
    // The sampled coordinates, degree one each in the eq sum: their count over |E|, at most 32 for every announced
    // height (log_n <= BLAKE3_R1CS_LOG_SIZE + MAX_TABLE_LOG), so one grind fits every proof.
    let n_sampled = log_n - FLOCK_K_SKIP - N_FIXED_CHALLENGES;
    if n_sampled > 0 {
        transcript.grind_check(FLOCK_POINT_GRIND_BITS)?;
    }
    let sampled = transcript.samples(n_sampled);
    r.extend(sampled.into_iter().map(Some));

    // P = P^AB + P^C on the coset, then z_skip; the 64 zeros on Lambda are assumed.
    let p_coset = transcript.next_scalars(K_BITS)?;
    transcript.grind_check(FLOCK_SKIP_GRIND_BITS)?;
    let z_skip = transcript.sample();
    let v_p = lagrange_interpolate(2 * K_BITS, &[vec![ZERO; K_BITS], p_coset].concat(), z_skip);

    // nflock quadratic rounds on P, closed by v_a, v_b.
    let (chi, running) = sumcheck(transcript, v_p, 3, &r)?;
    let (v_a, v_b) = (transcript.next_scalar()?, transcript.next_scalar()?);
    let v_c = running + v_a * v_b;
    Ok(ZerocheckResult {
        z_skip,
        chi,
        v_a,
        v_b,
        v_c,
    })
}

/// What the reduction leaves: the zerocheck's point and its three claims there, then the lincheck's
/// batching challenge, its round challenges in round order, and the 64 slices it closes on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlockClaims {
    pub z_skip: E,
    pub chi: Vec<E>,
    pub v_a: E,
    pub v_b: E,
    pub v_c: E,
    pub alpha: E,
    pub round_challenges: Vec<E>,
    pub s: Vec<E>,
    /// The terminal's matrix part ([`matrix_term`]), and the claim the lincheck's rounds leave.
    pub matrix: E,
    pub terminal: E,
}

impl FlockClaims {
    /// The point the slices are claims at: the lincheck's challenges in coordinate order, then the rest of chi.
    pub(crate) fn point(&self) -> Vec<E> {
        let chi_in_prime = self.round_challenges.iter().rev().copied();
        let rest = self.chi[FLOCK_NUM_LINCHECK_ROUNDS..].iter().copied();
        chi_in_prime.chain(rest).collect()
    }
}

/// Lincheck at the quirky point (z_skip, chi): its 64 slices s, claims at [`FlockClaims::point`].
fn verify_flock_lincheck(zc: ZerocheckResult, transcript: &mut Transcript) -> Result<FlockClaims, VerifierError> {
    // Batches the two matrix identities, the c claim and the constant-position claim: four terms, degree 3 in alpha.
    transcript.grind_check(grinding_bits(3))?;
    let alpha = transcript.sample();

    // The 8 rounds that bind the high column coordinates, leaving 64 unfolded.
    let claim = zc.v_a + alpha * zc.v_b + alpha.pow(2) * zc.v_c + alpha.pow(3);
    let (round_challenges, r_lc) = sumcheck(transcript, claim, 3, &[None; FLOCK_NUM_LINCHECK_ROUNDS])?;

    // The residual, then the terminal identity: pin term and c term included.
    let s = transcript.next_scalars(K_BITS)?;
    let mut claims = FlockClaims {
        z_skip: zc.z_skip,
        chi: zc.chi,
        v_a: zc.v_a,
        v_b: zc.v_b,
        v_c: zc.v_c,
        alpha,
        round_challenges,
        s,
        matrix: ZERO,
        terminal: r_lc,
    };
    // A guest defers the matrix part, so a replay computes it too: it is a witness of the guest's.
    claims.matrix = matrix_term(&claims)?;
    if transcript.checked() {
        let skip_weights = lagrange_weights(K_BITS, claims.z_skip);
        let chi_in = &claims.chi[..FLOCK_NUM_LINCHECK_ROUNDS];
        // C = I, so the c weight is e_row itself, and both sides being tensors it
        // collapses to eq(chi_in, chi_in_prime) times a 64-term Lagrange combination.
        let chi_in_prime: Vec<E> = claims.round_challenges.iter().rev().copied().collect();
        // The constant column's weight: its slice, times its high bits' eq.
        let pin = claims.s[BLAKE3_CONSTANT_COLUMN % K_BITS]
            * eq_kernel(&chi_in_prime)[BLAKE3_CONSTANT_COLUMN / K_BITS];
        let terminal = claims.matrix
            + alpha.pow(2) * eq_eval(chi_in, &chi_in_prime) * dot(&skip_weights, &claims.s)
            + alpha.pow(3) * pin;
        require(terminal == r_lc, VerifierError::FlockLincheckTerminal)?;
    }
    Ok(claims)
}

/// The lincheck terminal's matrix part, `sum_(r, c) (A0 + alpha B0)[r][c] e_row(r) w_col(c)`: `e_row` the phi8
/// Lagrange weights at the skip coordinate times eq at the zerocheck's first coordinates, `w_col` the 64 slices times
/// eq at the lincheck's challenges (bound top-down). A recursion guest defers it.
pub fn matrix_term(claims: &FlockClaims) -> Result<E, VerifierError> {
    let skip_weights = lagrange_weights(K_BITS, claims.z_skip);
    let chi_in = &claims.chi[..FLOCK_NUM_LINCHECK_ROUNDS];
    let chi_in_prime: Vec<E> = claims.round_challenges.iter().rev().copied().collect();
    // w_col = eq(chi_in_prime) ⊗ s, a column of it per slice: each slice multiplies the whole eq table.
    let high = eq_kernel(&chi_in_prime);
    let mut w_col = vec![ZERO; high.len() * K_BITS];
    for (l, &slice) in claims.s.iter().enumerate() {
        let slice = Scaled::new(slice);
        for (h, &weight) in high.iter().enumerate() {
            w_col[h * K_BITS + l] = slice.mul(weight);
        }
    }
    let (left_values, right_values) = blake3_row_values(&w_col);
    // e_row = eq(chi_in) ⊗ skip_weights, never built: each block of 64 rows meets the skip weights, a column at a
    // time, then chi_in folds the blocks.
    let (mut left_blocks, mut right_blocks) = (vec![ZERO; high.len()], vec![ZERO; high.len()]);
    for (l, &weight) in skip_weights.iter().enumerate() {
        let weight = Scaled::new(weight);
        for (h, (left, right)) in left_blocks.iter_mut().zip(&mut right_blocks).enumerate() {
            *left += weight.mul(left_values[h * K_BITS + l]);
            *right += weight.mul(right_values[h * K_BITS + l]);
        }
    }
    Ok(multilinear_eval(&left_blocks, chi_in)? + claims.alpha * multilinear_eval(&right_blocks, chi_in)?)
}

/// The multilinear extensions of `A0` and `B0` at `point`: the row coordinates, then the column coordinates. What
/// the outermost verifier of an aggregate checks a deferred matrix claim with.
pub fn matrix_values(point: &[E]) -> Result<(E, E), VerifierError> {
    require(point.len() == 2 * BLAKE3_R1CS_LOG_SIZE, VerifierError::MultilinearSize)?;
    let (row, column) = point.split_at(BLAKE3_R1CS_LOG_SIZE);
    let (left_values, right_values) = blake3_row_values(&eq_kernel(column));
    Ok((multilinear_eval(&left_values, row)?, multilinear_eval(&right_values, row)?))
}

type Word = [E; 32];

/// The forward walk's state: `A0 w` and `B0 w`, filled row by row.
struct RowValues<'a> {
    column_weights: &'a [E],
    left_values: Vec<E>,
    right_values: Vec<E>,
}

impl RowValues<'_> {
    fn slots(&self, base: usize) -> Word {
        std::array::from_fn(|bit| self.column_weights[base + bit])
    }

    fn literal(&self, value: u32) -> Word {
        let constant = self.column_weights[BLAKE3_CONSTANT_COLUMN];
        std::array::from_fn(|bit| if value >> bit & 1 == 1 { constant } else { ZERO })
    }

    fn add(&mut self, x: Word, y: Word, carry_base: usize) -> Word {
        let mut carry = ZERO;
        let mut output = [ZERO; 32];
        for bit in 0..32 {
            if bit < 31 {
                self.left_values[carry_base + bit] = x[bit] + carry;
                self.right_values[carry_base + bit] = y[bit] + carry;
            }
            output[bit] = x[bit] + y[bit] + carry;
            if bit < 31 {
                carry += self.column_weights[carry_base + bit];
            }
        }
        output
    }

    /// Fused three-operand add: 31 majority rows then 30 ripple rows.
    ///
    /// The majority of bit `i` is `maj_aux[i] + z[i]`, since over GF(2)
    /// `(x+z)(y+z) = xy + xz + yz + z`; then `x + y + z` is the ripple sum of
    /// `p = x^y^z` against `q[i] = maj[i-1]`, whose bit 0 is zero, so the
    /// ripple layer's bit 0 needs no row and slot `base + 31 + i - 1` carries
    /// bit `i`.
    fn add3(&mut self, x: Word, y: Word, z: Word, base: usize) -> Word {
        let mut majority = [ZERO; 31];
        for bit in 0..31 {
            self.left_values[base + bit] = x[bit] + z[bit];
            self.right_values[base + bit] = y[bit] + z[bit];
            majority[bit] = self.column_weights[base + bit] + z[bit];
        }
        let ripple_base = base + 31;
        let mut carry = ZERO;
        let mut output = [ZERO; 32];
        for bit in 0..32 {
            let q = if bit == 0 { ZERO } else { majority[bit - 1] };
            let left = x[bit] + y[bit] + z[bit] + carry;
            output[bit] = left + q;
            if (1..=30).contains(&bit) {
                self.left_values[ripple_base + bit - 1] = left;
                self.right_values[ripple_base + bit - 1] = q + carry;
                carry += self.column_weights[ripple_base + bit - 1];
            }
        }
        output
    }

    fn linear_rows(&mut self, values: Word, base: usize) {
        for bit in 0..32 {
            self.left_values[base + bit] = values[bit];
            self.right_values[base + bit] = self.column_weights[BLAKE3_CONSTANT_COLUMN];
        }
    }
}

fn xor(x: Word, y: Word) -> Word {
    std::array::from_fn(|bit| x[bit] + y[bit])
}

fn rotate_right(word: Word, amount: usize) -> Word {
    std::array::from_fn(|bit| word[(bit + amount) & 31])
}

/// The bit of X, Y, W (counted from X's first) the circuit places at block bit `bit`: `X` at bytes 25..57, the first 7
/// bytes of `Y` at 57..64, the last 25 of `W` at 0..25. The 25-byte prefix is a 24-byte DSM tag and its NUL, so a tree
/// node `tag ‖ 0 ‖ L ‖ R` takes `L` and `R` in their natural limbs.
pub fn relocation_source(bit: usize) -> Option<usize> {
    let (p, k) = (bit / 8, bit % 8);
    match p {
        0..25 => Some(512 + 8 * (p + 7) + k),
        25..57 => Some(8 * (p - 25) + k),
        57..64 => Some(256 + 8 * (p - 57) + k),
        _ => None,
    }
}

/// Compute `A0 w` and `B0 w` by one forward walk of the circuit.
pub fn blake3_row_values(column_weights: &[E]) -> (Vec<E>, Vec<E>) {
    let size = 1 << BLAKE3_R1CS_LOG_SIZE;
    let constant = BLAKE3_CONSTANT_COLUMN;
    let message_base = 640;
    let counter_low = 1152;
    let counter_high = 1184;
    let final_flag = 1216;
    let last_node_flag = 1248;
    let gates_base = 1280;
    let gate_stride = 184;
    // X, Y, W: three 32-byte inputs the circuit places into the block (`relocation_source`).
    let x_base = gates_base + gate_stride * SIGMA.len() * G_LANES.len();
    let mut rows = RowValues {
        column_weights,
        left_values: vec![ZERO; size],
        right_values: vec![ZERO; size],
    };

    for (base, length) in [(0, 256), (message_base, 512), (counter_low, 128), (x_base, 768)] {
        for row in base..base + length {
            rows.left_values[row] = column_weights[row];
            rows.right_values[row] = column_weights[constant];
        }
    }

    // v[0..8] = h, v[8..12] = IV[0..4], v[12..16] = IV[4..8] ^ (t_lo, t_hi, f0, f1).
    let mut state = [[ZERO; 32]; 16];
    for word in 0..8 {
        state[word] = rows.slots(32 * word);
    }
    for word in 0..4 {
        state[8 + word] = rows.literal(IV[word]);
    }
    for (word, base) in [counter_low, counter_high, final_flag, last_node_flag]
        .into_iter()
        .enumerate()
    {
        state[12 + word] = rows.slots(base);
    }

    // The effective message words: the slots, XOR the placed X/Y/W bits.
    let message: [Word; 16] = std::array::from_fn(|i| {
        let mut word = rows.slots(message_base + 32 * i);
        for (j, bit) in word.iter_mut().enumerate() {
            if let Some(source) = relocation_source(32 * i + j) {
                *bit += column_weights[x_base + source];
            }
        }
        word
    });
    for (round_index, sigma) in SIGMA.iter().enumerate() {
        for (gate_index, &[lane_a, lane_b, lane_c, lane_d]) in G_LANES.iter().enumerate() {
            let gate = round_index * 8 + gate_index;
            let gate_base = gates_base + gate_stride * gate;
            let (a, b, c, d) = (state[lane_a], state[lane_b], state[lane_c], state[lane_d]);
            let mx = message[sigma[2 * gate_index]];
            let my = message[sigma[2 * gate_index + 1]];
            let a1 = rows.add3(a, b, mx, gate_base);
            let d1 = rotate_right(xor(d, a1), 16);
            let c1 = rows.add(c, d1, gate_base + 61);
            let b1 = rotate_right(xor(b, c1), 12);
            let a2 = rows.add3(a1, b1, my, gate_base + 92);
            let d2 = rotate_right(xor(d1, a2), 8);
            let c2 = rows.add(c1, d2, gate_base + 153);
            let b2 = rotate_right(xor(b1, c2), 7);
            // Every lane cascades: this encoding materializes no intermediate word.
            state[lane_a] = a2;
            state[lane_b] = b2;
            state[lane_c] = c2;
            state[lane_d] = d2;
        }
    }

    // out[w] = h[w] ^ v[w] ^ v[w+8], the only materialized words.
    for word in 0..8 {
        let out = xor(state[word], state[word + 8]);
        rows.linear_rows(out, 256 + 32 * word);
    }

    rows.left_values[constant] = column_weights[constant];
    rows.right_values[constant] = column_weights[constant];
    (rows.left_values, rows.right_values)
}

/// The reduction in protocol order: zerocheck, then lincheck. What it leaves is the
/// point and the 64 claims s\[i\] = z(i, point), i < 64, for ring switching to bind.
pub fn verify_flock(log_n: usize, transcript: &mut Transcript) -> Result<FlockClaims, VerifierError> {
    let zc = verify_flock_zerocheck(log_n, transcript)?;
    verify_flock_lincheck(zc, transcript)
}
