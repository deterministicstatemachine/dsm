// SPDX-License-Identifier: MIT OR Apache-2.0

//! The P0–P6 owner-authority resolver.
//!
//! A foreign verifier's only a priori input is `g_o`. Everything else is
//! **presented**, and nothing presented is trusted before the stage that
//! authenticates it. The stage order is normative: a verifier that recomputes
//! the device id before authenticating the root has proven only that a
//! presented triple is internally consistent — anyone can generate a keypair
//! and a 32-byte value whose hash matches a leaf they also chose — and one
//! that checks membership against an unauthenticated root has proven
//! membership in a tree the attacker supplied.
//!
//! ```text
//! P0  recompute G from the presented parameters; GRK_pk becomes authoritative
//! P1  authenticate the delegation chain under GRK_pk (objects only —
//!     activation is RECORDED here, never evaluated)
//! P2  fold the transition chain by predecessor EDGE, evaluating activation
//!     eligibility against the already-authenticated prefix
//! P3  reach the caller's BOUND position (never "latest")
//! P4  prove d_o ∈ R_G at exactly that position's root
//! P5  recompute d_o = H(DSM/devid ‖ AK_pk ‖ AttA) from presented material
//! P6  K_cand == K_proven, byte for byte — only then is the anchor signature
//!     owner-authenticated
//! ```
//!
//! ## What this proves, and what it cannot
//!
//! The predicate proves **descent at a position**: this `AK_pk` was the owner
//! authority for `d_o` under `g_o` at the bound transition. It does **not**
//! prove frontier — no presented chain can carry "no newer position exists",
//! and nothing here implies currency. Names in this module never say
//! "latest" or "current", deliberately.
//!
//! ## Failure taxonomy
//!
//! [`ResolveFailure`] separates **absent** (a liveness condition — the
//! material may simply not have been published or presented),
//! **incomplete** (a chain exists but does not reach what was asked), and
//! **invalid** (a signature fails, a link breaks, a fork is observed — an
//! attack or a bug, never a retry). A single error conflating them would hide
//! the only one that matters.

use crate::ccb::{
    decode_vault_state, delegation_genesis_sentinel, genesis_v3_commitment, role,
    transition_genesis_sentinel, DeviceTreeRootTransition, GenesisParamsV3,
    RootProgressionDelegation,
};
use crate::common::device_tree::DevTreeProof;
use crate::core::identity::genesis_v2::derive_devid;
use crate::crypto::sphincs::sphincs_verify;
use crate::dlv::vault_state_anchor_v3::{verify_anchor_v3_candidate, SignedVaultStateAnchorV3};
use crate::storage_object::immutable_inner;

/// A delegation with the GRK signature that travels beside its CCB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedDelegation {
    pub delegation: RootProgressionDelegation,
    pub grk_signature: Vec<u8>,
}

/// A transition with the delegate signature that travels beside its CCB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTransition {
    pub transition: DeviceTreeRootTransition,
    pub delegate_signature: Vec<u8>,
}

/// Everything a stranger presents. All of it is untrusted input.
#[derive(Debug, Clone)]
pub struct PresentedIdentity<'a> {
    /// P0: the genesis parameter set whose recomputed `G` must equal `g_o`.
    pub genesis_params: &'a GenesisParamsV3,
    /// P1: delegation material, as an unordered bag — the resolver builds the
    /// unique chain or refuses.
    pub delegations: &'a [SignedDelegation],
    /// P2: transition material, as an unordered bag.
    pub transitions: &'a [SignedTransition],
    /// P4: inclusion proof for `d_o` under the bound position's root.
    pub inclusion: &'a DevTreeProof,
    /// P5: the candidate device key.
    pub ak_pk: &'a [u8],
    /// P5: the device-birth attestation digest.
    pub atta: &'a [u8; 32],
}

/// Why resolution did not produce an authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveFailure {
    /// Material is missing. A liveness condition, not an attack: the identity
    /// may be valid and simply unpublished or unpresented.
    Absent(&'static str),
    /// A chain exists but does not reach what was asked for. Usually
    /// liveness, possibly withholding — indistinguishable without a
    /// frontier, and reported as exactly that.
    Incomplete(&'static str),
    /// A signature fails, a link breaks, a recomputation mismatches, or a
    /// fork is observed. An attack or a bug; never a retry.
    Invalid(String),
}

impl core::fmt::Display for ResolveFailure {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ResolveFailure::Absent(w) => write!(f, "absent: {w}"),
            ResolveFailure::Incomplete(w) => write!(f, "incomplete: {w}"),
            ResolveFailure::Invalid(w) => write!(f, "invalid: {w}"),
        }
    }
}

impl std::error::Error for ResolveFailure {}

fn invalid(msg: impl Into<String>) -> ResolveFailure {
    ResolveFailure::Invalid(msg.into())
}

/// P0 — genesis binding, by recomputation alone.
///
/// No signature is checked here, and that is the point: the stage that
/// bootstraps authority consumes nothing but the identifier the verifier
/// already holds.
fn p0_genesis_binding(g_o: &[u8; 32], params: &GenesisParamsV3) -> Result<Vec<u8>, ResolveFailure> {
    let g = genesis_v3_commitment(params).map_err(|e| invalid(format!("P0: {e}")))?;
    if g != *g_o {
        return Err(invalid(
            "P0: presented genesis parameters do not recompute to g_o",
        ));
    }
    Ok(params.grk_pk.clone())
}

/// P1 — index the delegation bag, judging nothing.
///
/// Authentication is **lazy and relevance-driven**, performed by the fold as
/// activations become resolvable — because whether a delegation can affect
/// the authenticated prefix through the bound position is a fact about the
/// transition chain, which only the fold holds. An earlier revision
/// authenticated the whole bag up front, which let a delegation whose
/// activation lies strictly AFTER the bound position — ambiguous, forked, or
/// garbage-signed — poison a proof it could never have participated in: the
/// same contract violation the fold's stop-at-position fixed for
/// transitions, one stage up.
fn p1_index(bag: &[SignedDelegation]) -> std::collections::BTreeMap<u64, Vec<&SignedDelegation>> {
    let mut by_number: std::collections::BTreeMap<u64, Vec<&SignedDelegation>> =
        std::collections::BTreeMap::new();
    for sd in bag {
        by_number
            .entry(sd.delegation.delegation_number)
            .or_default()
            .push(sd);
    }
    by_number
}

/// The contiguous authenticated delegation prefix, grown lazily by the fold.
///
/// A number is **consulted** — fork-checked, ambiguity-checked, GRK-verified
/// — only when (a) its predecessor's activation has resolved on the chain
/// (the contiguity that makes inactivity cascade), and (b) some entry at that
/// number claims an activation the chain has actually resolved. Material
/// failing either gate is not "tolerated"; it is never examined, exactly as
/// transitions after the bound position are never examined. A forged entry
/// *claiming* an in-prefix activation does get examined and refused — a claim
/// of relevance to this prefix is the one thing that cannot be ignored
/// without verifying it, since if true it would retire the predecessor.
struct DelegationLadder<'a> {
    grk_pk: &'a [u8],
    g_o: &'a [u8; 32],
    by_number: std::collections::BTreeMap<u64, Vec<&'a SignedDelegation>>,
    /// Authenticated delegations, contiguous from number 0.
    auth: Vec<RootProgressionDelegation>,
    digests: Vec<[u8; 32]>,
    /// Chain position at which each authenticated delegation activated
    /// (0 = before `T_0`); strictly ascending, enforced on admission.
    activation_pos: Vec<usize>,
    expected_parent: [u8; 32],
}

impl<'a> DelegationLadder<'a> {
    fn new(
        grk_pk: &'a [u8],
        g_o: &'a [u8; 32],
        by_number: std::collections::BTreeMap<u64, Vec<&'a SignedDelegation>>,
    ) -> Self {
        Self {
            grk_pk,
            g_o,
            by_number,
            auth: Vec::new(),
            digests: Vec::new(),
            activation_pos: Vec::new(),
            expected_parent: delegation_genesis_sentinel(),
        }
    }

    /// Advance the ladder as far as the resolved chain permits.
    ///
    /// `position_of` maps an authenticated transition digest to the chain
    /// position at which a delegation activating there takes effect; the
    /// transition sentinel maps to 0.
    fn advance(
        &mut self,
        position_of: &std::collections::HashMap<[u8; 32], usize>,
    ) -> Result<(), ResolveFailure> {
        loop {
            let next = self.auth.len() as u64;
            let Some(candidates) = self.by_number.get(&next) else {
                return Ok(());
            };

            // Relevance gate: does any entry CLAIM an activation this chain
            // has resolved (or the sentinel, for number 0)? If none, the
            // number cannot yet participate — and is not examined.
            let resolves = |d: &RootProgressionDelegation| -> Option<usize> {
                if d.activation_transition_digest == transition_genesis_sentinel() {
                    Some(0)
                } else {
                    position_of.get(&d.activation_transition_digest).copied()
                }
            };
            if !candidates
                .iter()
                .any(|sd| resolves(&sd.delegation).is_some())
            {
                return Ok(());
            }

            // The number is relevant: NOW it is examined in full. Fork and
            // ambiguity refusal are scoped to consulted numbers, exactly as
            // the fold scopes them to walked edges.
            let sd = candidates[0];
            for other in &candidates[1..] {
                if other.delegation != sd.delegation {
                    return Err(invalid(format!(
                        "P1: delegation fork at number {next} — refused, not chosen"
                    )));
                }
                if other.grk_signature != sd.grk_signature {
                    return Err(invalid(format!(
                        "P1: delegation {next} presented with two different signatures — \
                         ambiguous, refused so the outcome cannot depend on bag order"
                    )));
                }
            }
            let d = &sd.delegation;
            if d.genesis_id != *self.g_o {
                return Err(invalid("P1: delegation bound to a different genesis"));
            }
            if d.role != role::DEVICE_TREE_ROOT_PROGRESSION
                || d.role_version != role::BETA_ROLE_VERSION
            {
                return Err(invalid(format!(
                    "P1: role {:#06x} v{} is not a supported root-progression role",
                    d.role, d.role_version
                )));
            }
            if d.parent_delegation_digest != self.expected_parent {
                return Err(invalid(format!(
                    "P1: delegation {next} does not chain its predecessor"
                )));
            }
            let pos = resolves(d).ok_or_else(|| {
                invalid(format!(
                    "P1: delegation {next} was consulted without a resolved activation"
                ))
            })?;
            if let Some(prev) = self.activation_pos.last() {
                if pos <= *prev {
                    return Err(invalid(
                        "P2: retroactive activation — a delegation activates at or before \
                         its predecessor, which is history retraction",
                    ));
                }
            }
            let msg = d
                .signing_digest()
                .map_err(|e| invalid(format!("P1: {e}")))?;
            let ok = sphincs_verify(self.grk_pk, &msg, &sd.grk_signature)
                .map_err(|e| invalid(format!("P1: {e}")))?;
            if !ok {
                return Err(invalid(format!("P1: delegation {next} is not GRK-signed")));
            }
            self.expected_parent = d.digest().map_err(|e| invalid(format!("P1: {e}")))?;
            self.digests.push(self.expected_parent);
            self.activation_pos.push(pos);
            self.auth.push(d.clone());
        }
    }

    /// The applicable delegation: the ladder top. Every admitted delegation's
    /// activation is in the current proper ancestry (it resolved on the
    /// chain, strictly ascending), so the highest number both retires every
    /// predecessor and is the one a conforming transition must bind.
    fn applicable(&self) -> Option<(usize, &RootProgressionDelegation, &[u8; 32])> {
        let i = self.auth.len().checked_sub(1)?;
        Some((i, &self.auth[i], &self.digests[i]))
    }
}

/// One authenticated position on the transition chain.
struct ChainedTransition {
    digest: [u8; 32],
    new_root: [u8; 32],
}

/// P2 — fold the transition chain by predecessor EDGE, stopping AT the bound
/// position, authenticating delegations lazily as their activations resolve.
///
/// Every fact consumed here is authenticated by P0 or by this fold's own
/// prefix. **A proof at position P depends only on material capable of
/// affecting the authenticated prefix through P** — for transitions, the fold
/// stops at P and never inspects successors; for delegations, the ladder
/// consults a number only when its predecessor's activation has resolved AND
/// some entry claims an activation the chain has resolved. Forks, ambiguity
/// and bad signatures within that scope refuse; outside it they are never
/// seen. The inactivity cascade is the contiguity gate itself: an unresolved
/// predecessor stops the ladder, so descendants are structurally
/// unconsultable rather than merely ineligible.
fn p2_fold_transitions(
    g_o: &[u8; 32],
    position: &[u8; 32],
    grk_pk: &[u8],
    delegation_bag: &[SignedDelegation],
    bag: &[SignedTransition],
) -> Result<Vec<ChainedTransition>, ResolveFailure> {
    if delegation_bag.is_empty() {
        return Err(ResolveFailure::Absent("P1: no delegations presented"));
    }
    let mut ladder = DelegationLadder::new(grk_pk, g_o, p1_index(delegation_bag));

    // Group transitions by predecessor edge. Grouping is not judging: fork
    // detection happens during the fold, only for edges actually walked.
    let mut by_predecessor: std::collections::HashMap<[u8; 32], Vec<&SignedTransition>> =
        std::collections::HashMap::new();
    for st in bag {
        by_predecessor
            .entry(st.transition.predecessor_transition_digest)
            .or_default()
            .push(st);
    }

    let mut chain: Vec<ChainedTransition> = Vec::new();
    let mut cursor = transition_genesis_sentinel();
    let mut last_version: Option<u64> = None;
    // Digest → the chain position a delegation activating there occupies.
    let mut position_of: std::collections::HashMap<[u8; 32], usize> =
        std::collections::HashMap::new();

    while let Some(candidates) = by_predecessor.get(&cursor) {
        // Fork and ambiguity, scoped to THIS edge only.
        let st = candidates[0];
        for other in &candidates[1..] {
            if other.transition != st.transition {
                return Err(invalid(
                    "P2: transition fork — two successors of one predecessor, refused",
                ));
            }
            if other.delegate_signature != st.delegate_signature {
                return Err(invalid(
                    "P2: one transition presented with two different signatures — \
                     ambiguous, refused so the outcome cannot depend on bag order",
                ));
            }
        }
        let t = &st.transition;
        if t.genesis_id != *g_o {
            return Err(invalid("P2: transition bound to a different genesis"));
        }
        if let Some(prev) = last_version {
            if t.version_number <= prev {
                return Err(invalid(format!(
                    "P2: version_number {} does not strictly increase past {}",
                    t.version_number, prev
                )));
            }
        }

        // Grow the ladder with everything the chain has resolved so far,
        // then require this transition to bind the applicable delegation.
        ladder.advance(&position_of)?;
        let Some((_, applicable, applicable_digest)) = ladder.applicable() else {
            return Err(ResolveFailure::Absent(
                "P1: no delegation at number 0 with a genesis-sentinel activation",
            ));
        };
        if t.delegation_digest != *applicable_digest {
            return Err(invalid(format!(
                "P2: transition v{} is not bound to the applicable delegation — \
                 superseded delegations are retired, and a signature by a retired \
                 key does not verify authority",
                t.version_number
            )));
        }
        let msg = t.signing_digest();
        let ok = sphincs_verify(&applicable.delegated_pk, &msg, &st.delegate_signature)
            .map_err(|e| invalid(format!("P2: {e}")))?;
        if !ok {
            return Err(invalid(format!(
                "P2: transition v{} signature does not verify under the applicable \
                 delegation's key",
                t.version_number
            )));
        }

        let digest = t.digest();
        chain.push(ChainedTransition {
            digest,
            new_root: t.new_root,
        });
        last_version = Some(t.version_number);
        position_of.insert(digest, chain.len());

        // THE STOP. The bound position is authenticated; its successors are
        // not this proof's business, and neither is any delegation whose
        // activation only a successor could resolve.
        if digest == *position {
            return Ok(chain);
        }
        cursor = digest;
    }

    if chain.is_empty() {
        return Err(ResolveFailure::Absent(
            "P2: no transition extends the genesis sentinel",
        ));
    }
    Ok(chain)
}

/// The proven result: an owner key, valid **at a position**. The name says
/// what it is — not "current", not "latest".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerAuthorityAtPosition {
    /// The proven key — equal to the presented candidate, byte for byte.
    pub ak_pk: Vec<u8>,
    /// The device whose authority was proven.
    pub device_id: [u8; 32],
    /// The exact transition digest the proof is bound to.
    pub position: [u8; 32],
}

/// P0–P6 at a caller-bound position.
///
/// `position` is the `owner_authority_transition_digest` the owner committed
/// inside `V_n` — the caller names it, and verification happens **there**,
/// never at whatever tip the presented material happens to reach. Presented
/// transitions beyond the position are ignored rather than rejected: a longer
/// authenticated chain does not invalidate a position-scoped proof.
pub fn resolve_owner_authority_at_position(
    g_o: &[u8; 32],
    position: &[u8; 32],
    presented: &PresentedIdentity<'_>,
) -> Result<OwnerAuthorityAtPosition, ResolveFailure> {
    // P0 — GRK by recomputation.
    let grk_pk = p0_genesis_binding(g_o, presented.genesis_params)?;

    // P1+P2 — the fold, delegations authenticated lazily as their
    // activations resolve, stopping at the bound position. A proof at a
    // position depends only on material capable of affecting the prefix
    // through it — for BOTH chains.
    let chain = p2_fold_transitions(
        g_o,
        position,
        &grk_pk,
        presented.delegations,
        presented.transitions,
    )?;

    // P3 — the bound position must be ON the authenticated chain.
    let at = chain
        .iter()
        .find(|c| c.digest == *position)
        .ok_or(ResolveFailure::Incomplete(
            "P3: the bound position is not on the authenticated chain — either material \
             is missing or the position was never authentic; without a frontier the two \
             are indistinguishable, and refusal is the only sound answer",
        ))?;

    // P5 — recompute the device id from independently presented material.
    // (Numbered before P4 in code order only to name the leaf; the trust
    // order is preserved because nothing is *concluded* until both hold.)
    let d_o = derive_devid(presented.ak_pk, presented.atta);

    // P4 — membership of that d_o under exactly the bound position's root.
    if !presented.inclusion.verify(&d_o, &at.new_root) {
        return Err(invalid(
            "P4: recomputed d_o is not included under the bound position's root",
        ));
    }

    // P6 — the proven key IS the presented candidate, by construction here
    // (d_o was recomputed from it); the byte equality against an anchor's
    // candidate is enforced in `authenticate_anchor_owner`.
    Ok(OwnerAuthorityAtPosition {
        ak_pk: presented.ak_pk.to_vec(),
        device_id: d_o,
        position: *position,
    })
}

/// The full staging: candidate anchor → verified `V_n` bytes → P0–P6 at the
/// state's own bound position → **`K_cand == K_proven`** → owner-authenticated.
///
/// `vn_bytes` must be the exact `CCB(V_n)` whose commitment the anchor signs;
/// they are re-hashed here against the anchor's `state_commitment` before
/// anything is read from them. No stage before the final equality calls
/// anything "owner" — the anchor's key is a candidate until the last line.
pub fn authenticate_anchor_owner(
    anchor: &SignedVaultStateAnchorV3,
    vn_bytes: &[u8],
    presented: &PresentedIdentity<'_>,
) -> Result<OwnerAuthorityAtPosition, ResolveFailure> {
    // Stage 1 — cryptographic check only: the candidate key signed this c_n.
    verify_anchor_v3_candidate(anchor).map_err(|e| invalid(format!("stage 1: {e}")))?;

    // Stage 3 — the bytes are the preimage of the signed commitment.
    let c_n = immutable_inner(crate::common::domain_tags::TAG_DSM_VAULT_STATE, vn_bytes);
    if c_n != anchor.state_commitment {
        return Err(invalid(
            "stage 3: presented bytes do not hash to the anchor's state commitment",
        ));
    }

    // Stage 4 — read the bound facts from the state the anchor commits.
    let state = decode_vault_state(vn_bytes).map_err(|e| invalid(format!("stage 4: {e}")))?;

    // Stage 5 — discharge P0–P6 at the state's own committed position.
    let proven = resolve_owner_authority_at_position(
        &state.owner_genesis_id,
        &state.owner_authority_transition_digest,
        presented,
    )?;

    // The proven device must be the one the state names.
    if proven.device_id != state.owner_device_id {
        return Err(invalid(
            "stage 5: the proven device is not the d_o this state commits",
        ));
    }

    // Stage 6 — the join. Two individually valid halves are not a whole:
    // K_anchor signed a valid c_n and K_proven passed P0–P6, and nothing
    // before this line forces them to be the same key. An implementation
    // keeping two variables would prove authority for one and reinterpret
    // the OTHER's signature. The byte equality is the predicate.
    if anchor.candidate_public_key != proven.ak_pk {
        return Err(invalid(
            "stage 6: the anchor's candidate key is not the proven owner key — \
             both halves are individually valid and the conclusion is false",
        ));
    }

    Ok(proven)
}
