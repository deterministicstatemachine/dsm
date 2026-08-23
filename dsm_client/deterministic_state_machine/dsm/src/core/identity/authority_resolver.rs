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

/// P1 — authenticate delegation OBJECTS under the GRK.
///
/// Activation digests are **recorded, never evaluated**: whether one
/// activation descends from another is a fact about the transition chain,
/// which this stage has not authenticated and must not consult — checking it
/// here would make P1 depend on P2 and break the ordering property the
/// predicate exists to guarantee.
fn p1_delegation_chain(
    g_o: &[u8; 32],
    grk_pk: &[u8],
    bag: &[SignedDelegation],
) -> Result<Vec<RootProgressionDelegation>, ResolveFailure> {
    if bag.is_empty() {
        return Err(ResolveFailure::Absent("P1: no delegations presented"));
    }
    // Forks are refused, never chosen: two delegations at one number are
    // evidence, and a verifier holding both stops.
    let mut by_number: std::collections::BTreeMap<u64, &SignedDelegation> =
        std::collections::BTreeMap::new();
    for sd in bag {
        if let Some(prev) = by_number.insert(sd.delegation.delegation_number, sd) {
            if prev.delegation != sd.delegation {
                return Err(invalid(format!(
                    "P1: delegation fork at number {} — refused, not chosen",
                    sd.delegation.delegation_number
                )));
            }
        }
    }

    let mut chain: Vec<RootProgressionDelegation> = Vec::with_capacity(by_number.len());
    let mut expected_parent = delegation_genesis_sentinel();
    for (i, (number, sd)) in by_number.iter().enumerate() {
        let d = &sd.delegation;
        if *number != i as u64 {
            return Err(ResolveFailure::Incomplete(
                "P1: delegation numbering has a gap — the chain does not reach its own tip",
            ));
        }
        if d.genesis_id != *g_o {
            return Err(invalid("P1: delegation bound to a different genesis"));
        }
        if d.role != role::DEVICE_TREE_ROOT_PROGRESSION || d.role_version != role::BETA_ROLE_VERSION
        {
            return Err(invalid(format!(
                "P1: role {:#06x} v{} is not a supported root-progression role",
                d.role, d.role_version
            )));
        }
        if d.parent_delegation_digest != expected_parent {
            return Err(invalid(format!(
                "P1: delegation {number} does not chain its predecessor"
            )));
        }
        let msg = d
            .signing_digest()
            .map_err(|e| invalid(format!("P1: {e}")))?;
        let ok = sphincs_verify(grk_pk, &msg, &sd.grk_signature)
            .map_err(|e| invalid(format!("P1: {e}")))?;
        if !ok {
            return Err(invalid(format!(
                "P1: delegation {number} is not GRK-signed"
            )));
        }
        expected_parent = d.digest().map_err(|e| invalid(format!("P1: {e}")))?;
        chain.push(d.clone());
    }
    Ok(chain)
}

/// One authenticated position on the transition chain.
struct ChainedTransition {
    digest: [u8; 32],
    new_root: [u8; 32],
}

/// P2 — fold the transition chain by predecessor EDGE, evaluating activation
/// against the already-authenticated prefix.
///
/// Every fact consumed here is authenticated by P0/P1 or by this fold's own
/// prefix. Activation eligibility is the **contiguous resolved prefix** rule:
/// `D_i` (`i > 0`) is eligible only if every predecessor activation through
/// `act(D_{i−1})` resolves on the chain and each strictly descends its
/// predecessor — an unresolved predecessor blocks all descendants, so the
/// lineage can never skip an edge it did not prove. The failure mode of that
/// rule is liveness (an older delegation stays applicable), never safety —
/// a property that holds precisely because ancestry is the signed edge.
fn p2_fold_transitions(
    g_o: &[u8; 32],
    delegations: &[RootProgressionDelegation],
    bag: &[SignedTransition],
) -> Result<Vec<ChainedTransition>, ResolveFailure> {
    // Digests and signing material, precomputed once.
    let del_digests: Vec<[u8; 32]> = delegations
        .iter()
        .map(|d| d.digest().map_err(|e| invalid(format!("P2: {e}"))))
        .collect::<Result<_, _>>()?;

    // Index transitions by the predecessor edge they bind. Two transitions
    // binding one predecessor are a fork: refused, never ordered — taking the
    // higher version would convert equivocation into a selection rule.
    let mut by_predecessor: std::collections::HashMap<[u8; 32], &SignedTransition> =
        std::collections::HashMap::new();
    for st in bag {
        if let Some(prev) = by_predecessor.insert(st.transition.predecessor_transition_digest, st) {
            if prev.transition != st.transition {
                return Err(invalid(
                    "P2: transition fork — two successors of one predecessor, refused",
                ));
            }
        }
    }

    let mut chain: Vec<ChainedTransition> = Vec::new();
    let mut cursor = transition_genesis_sentinel();
    let mut last_version: Option<u64> = None;

    // Position (index into `chain`) at which each delegation's activation
    // resolved, if it has. The genesis sentinel resolves "before T_0".
    let mut resolved_at: Vec<Option<usize>> = delegations
        .iter()
        .map(|d| {
            if d.activation_transition_digest == transition_genesis_sentinel() {
                Some(0)
            } else {
                None
            }
        })
        .collect();

    while let Some(st) = by_predecessor.get(&cursor) {
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

        // Activation eligibility: contiguous resolved prefix, strictly
        // ascending positions. Evaluated against `resolved_at` as it stands —
        // i.e. against the chain authenticated SO FAR, which is what makes
        // "act(D) resolves in this transition's PROPER ancestry" exact: a
        // digest can only have resolved at an index < chain.len() + 1.
        let mut applicable: Option<usize> = None;
        let mut prefix_ok = true;
        let mut last_pos: Option<usize> = None;
        for (i, pos) in resolved_at.iter().enumerate() {
            match pos {
                Some(p) if prefix_ok => {
                    if let Some(lp) = last_pos {
                        if *p <= lp && i > 0 {
                            return Err(invalid(
                                "P2: retroactive activation — a delegation activates at or \
                                 before its predecessor, which is history retraction",
                            ));
                        }
                    }
                    last_pos = Some(*p);
                    applicable = Some(i);
                }
                Some(_) => {
                    // Resolved, but a predecessor has not: the lineage skipped
                    // an edge it never proved. Inactivity cascades — this
                    // delegation neither activates nor retires.
                }
                None => {
                    prefix_ok = false;
                }
            }
        }
        let applicable_idx = applicable.ok_or(ResolveFailure::Incomplete(
            "P2: no activation-eligible delegation for this position",
        ))?;

        if t.delegation_digest != del_digests[applicable_idx] {
            return Err(invalid(format!(
                "P2: transition v{} is not bound to the applicable delegation \
                 (expected delegation {}, and superseded delegations are retired — \
                 a signature by a retired key does not verify authority)",
                t.version_number, applicable_idx
            )));
        }
        let msg = t.signing_digest();
        let ok = sphincs_verify(
            &delegations[applicable_idx].delegated_pk,
            &msg,
            &st.delegate_signature,
        )
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

        // A newly authenticated transition may resolve later delegations'
        // activations — at the position AFTER this transition.
        for (i, d) in delegations.iter().enumerate() {
            if resolved_at[i].is_none() && d.activation_transition_digest == digest {
                resolved_at[i] = Some(chain.len());
            }
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

    // P1 — delegation objects.
    let delegations = p1_delegation_chain(g_o, &grk_pk, presented.delegations)?;

    // P2 — transition chain, activation evaluated against the fold's prefix.
    let chain = p2_fold_transitions(g_o, &delegations, presented.transitions)?;

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
