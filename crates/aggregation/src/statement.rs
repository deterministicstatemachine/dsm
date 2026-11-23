//! Claim-list digests and a node's public statement.

use super::cells::{cell_bytes, count, pack_16_bytes};
use super::deferred::DeferredClaim;
use super::guest::fs_seed;
use super::{AggregateClaims, LeanSphincsClaim, LeanXmssClaim};
use fiat_shamir_prover::merkle::hash_to_scalars;
use primitives::field::F128;

/// Claims the guest hashes a loop frame: 68 cells, four whole block pairs.
pub(super) const CLAIM_GROUP: usize = 17;
const _: () = assert!((CLAIM_GROUP * 64).is_multiple_of(2 * keccak256::RATE));
/// Groups of [`CLAIM_GROUP`] the guest's main list loop hashes a frame.
pub(super) const BIG_GROUPS: usize = 8;
const CLAIM_BIG: usize = CLAIM_GROUP * BIG_GROUPS;

/// How the guest splits a list of `n` claims: the whole frames of [`CLAIM_BIG`], then
/// the whole groups of [`CLAIM_GROUP`], then the claims after them. Its own product
/// identity and range checks pin all three, so this only has to agree with them
/// (`list_split` in the guest). A list is never empty here: both claim lists are
/// guarded at the call, since the guest hashes an empty one without a split at all.
pub(super) fn list_split(n: usize) -> Vec<F128> {
    assert!(n > 0, "an empty list has no split");
    let rest = n % CLAIM_BIG;
    vec![
        count(n / CLAIM_BIG),
        count(rest / CLAIM_GROUP),
        count(rest % CLAIM_GROUP),
    ]
}

/// One scheme's declared claims, hashed plainly: 64 bytes a claim, its pubkey then
/// the message it signed, and an empty list hashes the empty string. The guest
/// computes this same digest [`CLAIM_GROUP`] claims at a time (`claim_list_digest`).
pub(super) fn claim_list_digest(claims: impl IntoIterator<Item = [F128; 4]>) -> [F128; 2] {
    cell_hash(claims.into_iter().flatten())
}

/// A claim as the four cells the guest hashes and its verifier reads: the pubkey's
/// two halves (`to_bytes`), then the message that pubkey signed.
fn claim_cells(pk: &[u8; 32], message: &[u8; 32]) -> [F128; 4] {
    [
        pack_16_bytes(&pk[..16]),
        pack_16_bytes(&pk[16..]),
        pack_16_bytes(&message[..16]),
        pack_16_bytes(&message[16..]),
    ]
}

pub(super) fn lean_xmss_claim_cells((pk, message): &LeanXmssClaim) -> [F128; 4] {
    claim_cells(&pk.to_bytes(), message)
}

pub(super) fn lean_sphincs_claim_cells((pk, message): &LeanSphincsClaim) -> [F128; 4] {
    claim_cells(&pk.to_bytes(), message)
}

/// The statement's fixed header, ahead of the deferred cells: the seed, the two
/// claim-list digests (leanXMSS then leanSPHINCS), and the DA digest ([`verifier::da::digest`]).
/// Fed to the guest as `STMT_HEADER`, which pins where its deferred cells start;
/// the header cells themselves are written out again there, and only the
/// end-to-end statement check holds the two spellings together.
pub(super) const STATEMENT_HEADER: usize = 8 + VAULT_CELLS;

/// Research build: the vault chain's cells in the statement header, after the DA digest: the vault, the first and
/// last roots, the external commitment and the attempt key (two cells each, a value's little-endian limbs), the
/// generation as one cell (`vault_step.py`'s `int_limb` of its digits), and 1 marking a chain; zeros for none.
pub(super) const VAULT_CELLS: usize = 12;

pub(super) fn vault_cells(vault: &Option<claims::VaultChain>) -> Vec<F128> {
    let Some(v) = vault else {
        return vec![F128::from(0u128); VAULT_CELLS];
    };
    use vault_step::program::cells;
    let generation = (0..16).fold(F128::from(0u128), |acc, k| {
        let digit = (v.generation >> (4 * k)) & 15;
        acc + F128::from(u128::from(digit)) * F128::from(primitives::field::g_pow(4 * k))
    });
    [cells(&v.vault_id), cells(&v.r_first), cells(&v.r_last), cells(&v.external_commitment), cells(&v.attempt_key)]
        .into_iter()
        .flatten()
        .chain([generation, F128::from(1u128)])
        .collect()
}

/// A plain hash over cells: what the guest gets from `keccak_cells` over the same cells.
fn cell_hash(cells: impl IntoIterator<Item = F128>) -> [F128; 2] {
    hash_to_scalars(&keccak256::hash(&cell_bytes(cells)))
}

/// A node's public statement, hashed to the two words the VM publishes as its public input. The
/// guest's `statement_digest` computes exactly this, both for itself and when it
/// rebuilds a child's, which is what forces a whole tree onto one bytecode and
/// each child's claims, bound by the two list digests, onto its parent's lists.
///
/// Fixed-length preimage, so a plain hash, with no domain tag of its own: every
/// field has a fixed width, and the header leads with the environment digest, which
/// binds this bytecode and the proof system's version and so already separates the
/// preimage from every other use of the hash here. The header cells, then the
/// deferred cells, each hashed as its two lanes. Each claim list's digest binds its
/// own length through the hash's padding, so the pair binds both lists whole.
pub(super) fn statement_digest(claims: &AggregateClaims, defer: &DeferredClaim) -> [F128; 2] {
    let header: [[F128; 2]; 4] = [
        fs_seed(),
        claim_list_digest(claims.lean_xmss.iter().map(lean_xmss_claim_cells)),
        claim_list_digest(claims.lean_sphincs.iter().map(lean_sphincs_claim_cells)),
        hash_to_scalars(&verifier::da::digest(claims.da_commitment)),
    ];
    cell_hash(header.into_iter().flatten().chain(vault_cells(&claims.vault)).chain(defer.cells()))
}
