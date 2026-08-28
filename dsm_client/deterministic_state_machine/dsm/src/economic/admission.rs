// SPDX-License-Identifier: Apache-2.0

//! The economic admission lifecycle and the pending fence.
//!
//! ## Why there is a fence at all
//!
//! Both naive orderings are wrong. **Register first** burns a write-once
//! position on something that may never validate — and the cell can never be
//! reused. **Locally accept first** advances value that nothing may yet treat
//! as economic ancestry. The lifecycle therefore has a window where local
//! acceptance has happened and registration has not, and the fence is what
//! makes that window safe rather than merely brief.
//!
//! ```text
//! ECON_PREPARED
//!    -> LOCAL_ACCEPTED_PENDING_ECON   // substrate-neutral:
//!                                     //   DSM      : exact C_dsm+ / sigma_dsm accepted
//!                                     //   boundary : exact OfflineBoundaryAttestationV1 accepted
//!    -> ECON_EVIDENCE_PUBLISHED
//!    -> ECON_REGISTERED
//!    -> ECON_ADMITTED                 // LOCAL terminal state
//! ```
//!
//! `ECON_ADMITTED` is where the *local lifecycle* ends. It is not a claim that
//! the root is valid: `ValidatedEconomicRoot` is the **verifier's** result and
//! there is no network event that produces one.
//!
//! ## The fence predicate is the economic classifier, not `is_value_bearing`
//!
//! ```text
//! while pending:
//!   EconomicEffect::None                       => ALLOW
//!   EconomicEffect::ClosedWriteSet             => BLOCK
//!   EconomicEffect::UnsupportedValueTransition => BLOCK
//!   EconomicEffect::OfflineAccountOnly         => depends on the pending SUBSTRATE
//! ```
//!
//! `Operation::is_value_bearing` is the wrong predicate here and the
//! divergence is not hypothetical: `DlvUnlock` is value-egress by that measure
//! yet produces no `R_econ` mutation at all, so fencing on it would block an
//! operation the economic root does not care about.
//!
//! `OfflineAccountOnly` is **not blanket-allowed**. Bearer activity unrelated
//! to a pending DSM-backed transition neither consumes nor mutates `R_econ`,
//! so it continues. But when the pending admission *is* an offline boundary,
//! the allocation it moves is precisely what must not be spent yet:
//!
//! ```text
//! pending load:   block bearer use of the newly increased allocation
//! pending unload: block descendant progression from the not-yet-admitted
//!                 new checkpoint
//! ```
//!
//! ## Ordinary non-value activity continues
//!
//! The fence is not a freeze. Relationship activity that touches no economic
//! leaf runs normally throughout, because blocking it would make an economic
//! publication delay look like a device fault.

use crate::economic::classifier::EconomicEffect;
use crate::types::operations::Operation;

/// Which substrate carried the local acceptance, and therefore what kind of
/// pending state the fence is protecting.
///
/// The offline variants carry the asset because the fence has to know *what*
/// not to spend. A kind without its asset would force the fence to block all
/// bearer activity or none, and both are wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingAdmissionKind {
    /// An ordinary DSM successor. Unrelated bearer activity is unaffected.
    DsmBacked,
    /// A load boundary: online balance debited, allocation increased. The new
    /// allocation is not bearer-spendable until admitted.
    OfflineLoad { asset_policy_commit: [u8; 32] },
    /// An unload boundary: allocation decreased, online balance to be
    /// credited. The new checkpoint cannot parent further progression until
    /// admitted.
    OfflineUnload { asset_policy_commit: [u8; 32] },
}

impl PendingAdmissionKind {
    /// The asset whose bearer use is fenced, if any.
    pub fn fenced_asset(&self) -> Option<[u8; 32]> {
        match self {
            Self::DsmBacked => None,
            Self::OfflineLoad {
                asset_policy_commit,
            }
            | Self::OfflineUnload {
                asset_policy_commit,
            } => Some(*asset_policy_commit),
        }
    }
}

/// Where an admission has reached. Advances only forward, and **no timeout
/// ever aborts one**: a pending admission is finished, never abandoned,
/// because abandoning it would leave locally-accepted value with no economic
/// ancestry and a burned position behind it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EconomicAdmissionState {
    /// Evidence assembled, nothing durable yet. Before this point nothing
    /// changed, so recovery has nothing to finish.
    Prepared,
    /// The substrate acceptance is durable. From here recovery MUST finish
    /// this exact admission and may not start a different one.
    LocalAcceptedPendingEcon,
    /// The evidence DAG is durably present on a quorum.
    EvidencePublished,
    /// The claim occupies its register cell.
    Registered,
    /// Local terminal state.
    Admitted,
}

impl EconomicAdmissionState {
    /// Whether the fence is active. It engages the moment local acceptance
    /// becomes durable and releases only at the terminal state.
    pub fn is_fencing(&self) -> bool {
        matches!(
            self,
            Self::LocalAcceptedPendingEcon | Self::EvidencePublished | Self::Registered
        )
    }
}

/// The coordinates that exist only once the substrate acceptance exists.
///
/// Under the v2 operation identity (`EconOpId_v2 = H(G ‖ DevID ‖ C_dsm+)`)
/// none of these are computable before the DSM successor is prepared: the
/// witness commits the economic operation id (and, for operations that
/// consume sources, the id enters leaf VALUES and therefore the post-root),
/// and the manifest addresses the witness. A `Prepared` admission that
/// claimed to know them would be carrying placeholders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcceptedAdmissionCoords {
    pub post_economic_root: [u8; 32],
    /// The exact accepted substrate artifact: the successor evidence for a
    /// DSM admission, or the `OfflineBoundaryAttestationV1` for a boundary.
    pub accepted_substrate_addr: [u8; 32],
    pub admission_manifest_addr: [u8; 32],
    /// The accepted successor's chain-state commitment — the `C_dsm+` the v2
    /// economic operation id binds. Recovery cannot re-derive it from the
    /// head (unrelated non-economic activity may advance other tips), so it
    /// is durable admission state like everything else here. For an offline
    /// boundary this is the boundary attestation's commitment (Step 5).
    pub c_dsm_plus: [u8; 32],
    /// The accepted successor's own parent tip — with `c_dsm_plus` this is
    /// the successor's `(embedded_parent, tip)` pair, which acceptance
    /// evidence binds its countersigned B-side pair to. Durable for the same
    /// reason as `c_dsm_plus`: recovery cannot re-derive it from the head.
    /// Zero for an offline boundary (Step 5).
    pub embedded_parent: [u8; 32],
}

/// The durable record of an admission in flight.
///
/// Every field is something recovery needs to reconstruct the **exact,
/// byte-identical** evidence without new private or user-supplied material.
/// That is the durability invariant: a value-bearing local acceptance must not
/// become durable unless this record is too, in the same transaction.
///
/// ## The `Prepared` ⇔ no-coordinates invariant
///
/// `acceptance` is `Some` exactly when `state != Prepared`, enforced by the
/// constructors — the field is private so a literal cannot break it. A
/// `Prepared` admission authorizes exactly one operation (its digest) and
/// nothing more; the acceptance coordinates come into existence together with
/// the prepared successor and are installed by [`Self::into_locally_accepted`]
/// in the same atomic commit that makes the acceptance durable. `Prepared`
/// is therefore never a durable row: recovery has nothing to finish before
/// acceptance, so a stored `Prepared` record would be a contradiction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEconomicAdmission {
    pub kind: PendingAdmissionKind,
    pub state: EconomicAdmissionState,
    /// The position this admission will occupy. It cannot advance while
    /// pending, and it may not be reused for a different admission.
    pub economic_position: u64,
    pub pre_economic_root: [u8; 32],
    /// Binds this admission to the operation the witness describes. Without
    /// it, a valid successor and a valid economic transition could describe
    /// **different operations**.
    pub operation_digest: [u8; 32],
    acceptance: Option<AcceptedAdmissionCoords>,
}

impl PendingEconomicAdmission {
    /// A new admission, before anything durable exists. Knows WHAT it
    /// authorizes (the digest) but not yet the coordinates of an acceptance
    /// that has not happened.
    pub fn prepared(
        kind: PendingAdmissionKind,
        economic_position: u64,
        pre_economic_root: [u8; 32],
        operation_digest: [u8; 32],
    ) -> Self {
        Self {
            kind,
            state: EconomicAdmissionState::Prepared,
            economic_position,
            pre_economic_root,
            operation_digest,
            acceptance: None,
        }
    }

    /// Install the acceptance coordinates, moving `Prepared` →
    /// `LocalAcceptedPendingEcon`. The only way an admission starts fencing.
    pub fn into_locally_accepted(
        self,
        coords: AcceptedAdmissionCoords,
    ) -> Result<Self, &'static str> {
        if self.state != EconomicAdmissionState::Prepared {
            return Err(
                "admission: acceptance coordinates can be installed exactly once, from Prepared",
            );
        }
        Ok(Self {
            state: EconomicAdmissionState::LocalAcceptedPendingEcon,
            acceptance: Some(coords),
            ..self
        })
    }

    /// Move forward through the post-acceptance lifecycle. Refuses `Prepared`
    /// (that transition installs coordinates and has its own constructor) and
    /// refuses going backward.
    pub fn advanced_to(self, state: EconomicAdmissionState) -> Result<Self, &'static str> {
        if state == EconomicAdmissionState::Prepared {
            return Err("admission: cannot return to Prepared");
        }
        if self.acceptance.is_none() {
            return Err("admission: cannot advance past Prepared without acceptance coordinates");
        }
        if state < self.state {
            return Err("admission: lifecycle only advances forward");
        }
        Ok(Self { state, ..self })
    }

    /// Rebuild from durable parts. A stored admission is post-acceptance by
    /// construction — `Prepared` is never durable — so the coordinates are
    /// REQUIRED here, and a caller holding a fencing state without them has
    /// corrupt storage, not a default.
    pub fn from_durable_parts(
        kind: PendingAdmissionKind,
        state: EconomicAdmissionState,
        economic_position: u64,
        pre_economic_root: [u8; 32],
        operation_digest: [u8; 32],
        coords: AcceptedAdmissionCoords,
    ) -> Result<Self, &'static str> {
        if state == EconomicAdmissionState::Prepared {
            return Err("admission: a Prepared admission is never durable");
        }
        Ok(Self {
            kind,
            state,
            economic_position,
            pre_economic_root,
            operation_digest,
            acceptance: Some(coords),
        })
    }

    /// The acceptance coordinates, present exactly when `state != Prepared`.
    pub fn acceptance(&self) -> Option<&AcceptedAdmissionCoords> {
        self.acceptance.as_ref()
    }

    /// The acceptance coordinates of a post-`Prepared` admission. The error
    /// is a state machine violation, not an expected branch.
    pub fn accepted_coords(&self) -> Result<&AcceptedAdmissionCoords, &'static str> {
        self.acceptance
            .as_ref()
            .ok_or("admission: no acceptance coordinates while Prepared")
    }
}

/// Why the fence refused an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceBlock {
    /// The operation writes economic leaves while an admission is pending.
    EconomicWriteWhilePending { position: u64 },
    /// The operation touches online economic value with no defined
    /// foreign-verifiable source predicate. Refused independently of the
    /// fence, and refused here too.
    UnsupportedValueWhilePending { position: u64 },
    /// Bearer use of the very allocation a pending boundary is moving.
    BearerUseOfPendingAllocation {
        position: u64,
        asset_policy_commit: [u8; 32],
    },
}

impl core::fmt::Display for FenceBlock {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EconomicWriteWhilePending { position } => write!(
                f,
                "economic admission at position {position} is pending: this operation writes \
                 economic leaves, and value accepted before its economic ancestry is registered \
                 must not be spendable"
            ),
            Self::UnsupportedValueWhilePending { position } => write!(
                f,
                "economic admission at position {position} is pending: this operation touches \
                 online economic value with no defined foreign-verifiable source predicate"
            ),
            Self::BearerUseOfPendingAllocation {
                position,
                asset_policy_commit: _,
            } => write!(
                f,
                "economic admission at position {position} is a pending offline boundary for \
                 this asset: the allocation it moves is not bearer-spendable until admitted"
            ),
        }
    }
}

impl std::error::Error for FenceBlock {}

/// The fence.
///
/// Takes the pending record, the operation's classified economic effect, and
/// the operation itself — the third because `OfflineAccountOnly` is decided
/// against the pending substrate and the operation's asset, not by the effect
/// alone.
pub fn fence_allows(
    pending: &PendingEconomicAdmission,
    effect: EconomicEffect,
    operation: &Operation,
) -> Result<(), FenceBlock> {
    if !pending.state.is_fencing() {
        return Ok(());
    }
    // Deliberately NO "matching operation" exception here. The operation an
    // admission authorizes is accepted while the admission is still
    // `Prepared` — which does not fence — so it never needs a doorway; and a
    // doorway would let the SAME operation re-advance after acceptance
    // (states that DO fence), double-crediting locally. While fencing, every
    // economic write is blocked, including a replay of the admitted one.
    let position = pending.economic_position;
    match effect {
        EconomicEffect::None => Ok(()),
        EconomicEffect::ClosedWriteSet => Err(FenceBlock::EconomicWriteWhilePending { position }),
        EconomicEffect::UnsupportedValueTransition => {
            Err(FenceBlock::UnsupportedValueWhilePending { position })
        }
        EconomicEffect::OfflineAccountOnly => match pending.kind.fenced_asset() {
            // A DSM-backed admission does not touch the offline regime, so
            // unrelated bearer activity neither consumes nor mutates R_econ.
            None => Ok(()),
            Some(fenced) => match bearer_asset(operation) {
                // Same asset as the pending boundary: this is exactly the
                // allocation that is not yet admitted.
                Some(asset) if asset == fenced => Err(FenceBlock::BearerUseOfPendingAllocation {
                    position,
                    asset_policy_commit: fenced,
                }),
                // A different asset's allocation is untouched by this
                // boundary, so it stays spendable.
                Some(_) => Ok(()),
                // Classified OfflineAccountOnly but carrying no identifiable
                // asset. Fail closed: an unidentifiable bearer operation
                // during a boundary fence cannot be shown to be unrelated.
                None => Err(FenceBlock::BearerUseOfPendingAllocation {
                    position,
                    asset_policy_commit: fenced,
                }),
            },
        },
    }
}

/// The asset a bearer operation moves, when it names one.
fn bearer_asset(operation: &Operation) -> Option<[u8; 32]> {
    match operation {
        Operation::Transfer { policy_commit, .. } => Some(*policy_commit),
        _ => None,
    }
}

/// The durable head and the durable pending row must agree about whether the
/// device is fenced.
///
/// Checked before an atomic commit, because the failure it prevents is silent:
/// a head written WITHOUT the admission it is supposed to carry is a head that
/// reloads unfenced, while the pending row sits beside it claiming otherwise.
/// The device would then spend value whose economic ancestry is unregistered,
/// and nothing at read time could detect the disagreement — both rows are
/// individually well-formed.
pub fn head_carries_admission(
    head_pending: Option<&PendingEconomicAdmission>,
    committing: &PendingEconomicAdmission,
) -> bool {
    head_pending == Some(committing)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PendingEconomicAdmission {
        PendingEconomicAdmission::prepared(PendingAdmissionKind::DsmBacked, 2, [1; 32], [3; 32])
            .into_locally_accepted(AcceptedAdmissionCoords {
                post_economic_root: [2; 32],
                accepted_substrate_addr: [4; 32],
                admission_manifest_addr: [5; 32],
                c_dsm_plus: [6; 32],
                embedded_parent: [7; 32],
            })
            .expect("prepared -> accepted")
    }

    #[test]
    fn a_head_that_does_not_carry_the_admission_is_refused() {
        let a = sample();
        assert!(head_carries_admission(Some(&a), &a));

        // The dangerous case: the head reloads UNFENCED while the pending row
        // claims an admission is in flight. Nothing at read time could detect
        // it — both rows are individually well-formed.
        assert!(!head_carries_admission(None, &a));

        // A head carrying a DIFFERENT admission is equally wrong: the fence
        // would be enforced against the wrong position and asset.
        let mut b = sample();
        b.economic_position = 3;
        assert!(!head_carries_admission(Some(&b), &a));
    }
}
