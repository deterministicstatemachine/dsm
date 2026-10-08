// SPDX-License-Identifier: Apache-2.0

//! Part II §13 and §17.4, rebuild step R10: `FulfillmentRegistered(F)`,
//! derived by Core from raw reads of the two position cells.
//!
//! ```text
//! FulfillmentRegistered(F) ⟺ Final(K_ful(q), F) ∧ Final(K_root(q), C_q)
//! ```
//!
//! It is a conclusion, never a record: no member computes it, no member
//! writes it, and nothing here consults anything but what the members hold.
//! `Final` at each cell is the route-chain rule of storage spec §9 over the
//! recognized view. An object naming `K_ful(q)` is a fulfillment envelope at
//! position `q` under a key that derives the trader's device; an object
//! naming `K_root(q)` is a registered claim whose coordinates derive that
//! key. Both are decided from the bytes alone (SoFi Amendment S20), so what
//! holds each cell, and whether the pair is registered, is the same for every
//! reader at every time. Bytes that are neither count as nothing anywhere.
//!
//! Because at most one value has a valid leader link at `K_ful(q)`, at most
//! one fulfillment is registered per position. Registered is not conforming
//! and not valid (Section 20.2): what this module answers is only whether the
//! exercise happened. Whether the claim at `K_root(q)` is exactly
//! `derive(P, F)` is checked where `P` is in hand ([`RegistrationRead::standing_of`]).

use crate::economic::claim_envelope::RegisteredEconomicClaim;
use crate::economic::register::{position_seed, read_root_cell, RootCell};
use crate::route_chain::{
    check_completion_proof, completion_proof, evaluate, CellError, CellEvidence, CellReading,
    ChainState, CompletionProof, Missing, ProofRefusal, RoutedCell,
};
use super::derive;
use super::publication::{recognize_fulfillment, Signed};
use super::wire::{TraderFulfillmentBody, TraderPrecommitBody};

type D32 = [u8; 32];

/// Whether `F` proves its own authority for a cell of `device_id` (DSM
/// Amendment A10, SoFi Amendment S20): its key, with the `AttA` it carries,
/// derives that device. Decided from `F`'s bytes alone.
pub fn fulfillment_proves_the_device(body: &TraderFulfillmentBody, device_id: &D32) -> bool {
    crate::core::identity::genesis_v2::derive_devid(
        body.claimant_public_key(),
        body.claimant_att_a(),
    ) == *device_id
}

/// An object naming `K_ful(q)` of the trader whose device is `device_id`
/// (SoFi Amendment S20): a fulfillment envelope that recognizes under its own
/// key (R8), whose body's position is `q`, and whose key and `AttA` derive
/// `device_id` ([`fulfillment_proves_the_device`]). Decided from `F`'s bytes
/// alone: `P` is never read here. `F` carries no genesis; the cell's key is
/// derived from `(G, DevID, q)`, and only the holder of `DevID`'s key can
/// write an `F` that passes, so whatever holds the trader's `K_ful(q)` is the
/// trader's own act. Anything else written at this key is nothing: neither a
/// rival nor a winner, however early it arrived.
pub fn names_fulfillment_key(
    bytes: &[u8],
    device_id: &D32,
    position: u64,
) -> Option<Signed<TraderFulfillmentBody>> {
    let signed = recognize_fulfillment(bytes)?.1;
    (signed.body.position() == position && fulfillment_proves_the_device(&signed.body, device_id))
        .then_some(signed)
}

/// The two cells of trader `(G, DevID)`'s position `q` as Core derives them
/// (Sections 7.2, 17.4): `K_ful(q)` and `K_root(q)`, both routed by `s(q)`
/// over the register's committed set, so one route serves both and a writer
/// puts the pair at each seat in one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PositionCells {
    fulfillment: RoutedCell,
    root: RootCell,
    parent_root: D32,
}

impl PositionCells {
    /// `parent_root` is `R_p`, the root the verifier validated at `q - 1`.
    /// `members` must re-derive `committed_set_id`, the register's pinned
    /// set id.
    pub fn new(
        genesis: &D32,
        device_id: &D32,
        position: u64,
        parent_root: &D32,
        members: &crate::ccb::StorageSetMembers,
        committed_set_id: &D32,
    ) -> Result<Self, CellError> {
        let root = RootCell::new(
            genesis,
            device_id,
            position,
            parent_root,
            members,
            committed_set_id,
        )?;
        let fulfillment = RoutedCell::new(
            crate::common::domain_tags::TAG_DSM_SOFI_FULFILLMENT.source_bytes(),
            derive::fulfillment_register_key(genesis, device_id, position),
            &position_seed(genesis, device_id, position, parent_root),
            members,
            committed_set_id,
        )?;
        Ok(Self {
            fulfillment,
            root,
            parent_root: *parent_root,
        })
    }

    /// `K_ful(q)`.
    pub fn fulfillment(&self) -> &RoutedCell {
        &self.fulfillment
    }

    /// `K_root(q)`.
    pub fn root(&self) -> &RootCell {
        &self.root
    }

    /// `R_p`, the root the pair is routed by.
    pub fn parent_root(&self) -> &D32 {
        &self.parent_root
    }
}

/// `FulfillmentRegistered` at one position as the reads established it,
/// bound to the position it is about: the trader, the position, and the
/// root `R_p` the pair was routed by. Built by [`fulfillment_registered`]
/// over the seats' reads and by nothing else, so the registration a verdict
/// stands on is always one Core derived at that very pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationRead {
    genesis: D32,
    device_id: D32,
    position: u64,
    parent_root: D32,
    registration: Registration,
    /// The id of the claim holding `K_root(q)`'s leader link, in any state:
    /// the entry digest of its exact bytes, or of its derived body for a
    /// conditional claim (SoFi Amendment S20). `None` while the leader holds
    /// no claim.
    root_claim: Option<D32>,
    /// The exact bytes final at `K_root(q)`: the trader's signed `C_q` when
    /// the position is registered, which a position's exercise carries and a
    /// verifier rebuilding it takes from here (SoFi Amendment S25). `None`
    /// while no claim is final there.
    root_claim_final: Option<Vec<u8>>,
}

impl RegistrationRead {
    pub fn genesis(&self) -> &D32 {
        &self.genesis
    }

    pub fn device_id(&self) -> &D32 {
        &self.device_id
    }

    pub fn position(&self) -> u64 {
        self.position
    }

    pub fn parent_root(&self) -> &D32 {
        &self.parent_root
    }

    pub fn registration(&self) -> &Registration {
        &self.registration
    }

    pub fn into_registration(self) -> Registration {
        self.registration
    }

    /// The id of the claim holding `K_root(q)`'s leader link, if any.
    pub fn root_claim(&self) -> Option<&D32> {
        self.root_claim.as_ref()
    }

    /// The exact bytes final at `K_root(q)`, if a claim is final there.
    pub fn root_claim_final(&self) -> Option<&[u8]> {
        self.root_claim_final.as_deref()
    }

    /// Whether this read is of the position `fulfillment` claims for
    /// `precommit`'s trader, routed by the root `precommit` was built on.
    pub fn is_of(
        &self,
        precommit: &TraderPrecommitBody,
        fulfillment: &TraderFulfillmentBody,
    ) -> bool {
        self.genesis == *precommit.genesis()
            && self.device_id == *precommit.device_id()
            && self.position == fulfillment.position()
            && self.parent_root == *precommit.void_root()
    }

    /// Where `fulfillment`, of `precommit`, stands at this pair, with `P` in
    /// hand (SoFi Amendments S14 and S20). `F` is lost when another
    /// fulfillment holds `K_ful(q)`'s leader link, in any state (§23.1: once
    /// the leader keeps a value, no other is ever final there), or when
    /// `K_root(q)`'s leader link is held by a claim other than
    /// `derive(P, F)`: another fulfillment's, an ordinary transition's, or
    /// one naming `F` whose body is not `F`'s. When that last one is final
    /// with `F` final at `K_ful(q)`, the pair is matched by `F`'s id and its
    /// body is not `F`'s claim: misbodied, which loses `F` and makes the
    /// position Invalid for the trader's lineage (S20). Registered when the
    /// pair is final on `F` and on exactly `derive(P, F)`. All but Pending
    /// are permanent.
    pub fn standing_of(
        &self,
        precommit: &TraderPrecommitBody,
        fulfillment: &TraderFulfillmentBody,
    ) -> PairStanding {
        let own = crate::storage_cell::entry_digest(
            &derive::resolution_claim(precommit, fulfillment).encode(),
        );
        let root_is_another = self.root_claim.is_some_and(|claim| claim != own);
        if root_is_another
            && matches!(&self.registration, Registration::Registered(held) if held.body == *fulfillment)
        {
            return PairStanding::Misbodied;
        }
        let holder = match &self.registration {
            Registration::Registered(signed)
            | Registration::Held(signed)
            | Registration::NeverRegistered {
                fulfillment: signed,
                ..
            } => Some(&signed.body),
            Registration::RootTaken { .. } | Registration::Unresolved => None,
        };
        if root_is_another || holder.is_some_and(|held| held != fulfillment) {
            return PairStanding::Lost;
        }
        match self.registration {
            Registration::Registered(..) => PairStanding::Registered,
            Registration::Held(..)
            | Registration::NeverRegistered { .. }
            | Registration::RootTaken { .. }
            | Registration::Unresolved => PairStanding::Pending,
        }
    }
}

/// Where one fulfillment stands at its position pair, with its `P` in hand
/// ([`RegistrationRead::standing_of`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PairStanding {
    /// `FulfillmentRegistered(F)`, the pair's claim being exactly
    /// `derive(P, F)`.
    Registered,
    /// Not yet: `F` may still register.
    Pending,
    /// `F` can never register at `q` (SoFi Amendments S14, S20). Permanent.
    Lost,
    /// The pair is final on `F`, matched by its id, but the claim at
    /// `K_root(q)` is not `derive(P, F)`: it names `F` under another body.
    /// `F` is lost there (S14's skip, no Void) and the position is Invalid
    /// for the trader's lineage (S20). Permanent.
    Misbodied,
}

impl PairStanding {
    /// `F` can never register at `q`: lost to another claim, or to its own
    /// pair under another body. What the S14 skip reads.
    pub fn is_lost(self) -> bool {
        matches!(self, Self::Lost | Self::Misbodied)
    }
}

/// Which of the two cells settled the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionCell {
    Fulfillment,
    Root,
}

/// `FulfillmentRegistered` at position `q`, as the reads establish it from
/// the two cells' bytes alone (SoFi Amendment S20).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// `Final(K_ful(q), F)` and `Final(K_root(q), C_q)`, the claim naming
    /// `FulfillmentId(F)`: the exercise. The registered fulfillment, in the
    /// envelope the members hold. Whether that claim is exactly
    /// `derive(P, F)` is checked where `P` is in hand.
    Registered(Signed<TraderFulfillmentBody>),
    /// `F` holds `K_ful(q)`'s leader link, and `K_root(q)`'s leader link is
    /// held by a claim that does not name it: an ordinary transition, or
    /// another fulfillment's claim, got to the leader first. This `F` is not
    /// registered and never will be (PairMutualExclusion): the position went
    /// to the other claim.
    NeverRegistered {
        fulfillment: Signed<TraderFulfillmentBody>,
        settled_at: PositionCell,
    },
    /// `F` holds `K_ful(q)`'s leader link, leader-held, preserved or final,
    /// and the pair is not final on it yet. `F` may still register, and no
    /// other fulfillment ever will (§23.1).
    Held(Signed<TraderFulfillmentBody>),
    /// No fulfillment holds `K_ful(q)`'s leader link, and `K_root(q)`'s is
    /// held by the claim whose id is `claim`. An `F` at `q` whose own `C_q`
    /// it is not can never register (SoFi Amendment S14); one whose `C_q` it
    /// is waits for its fulfillment to be relayed.
    RootTaken { claim: D32 },
    /// Neither cell's leader holds a recognized value yet.
    Unresolved,
}

/// The recognizer of `K_ful(q)`: fulfillment envelopes naming the key
/// ([`names_fulfillment_key`]), identified by the entry digest of their exact
/// bytes.
fn fulfillment_at(
    cells: &PositionCells,
) -> impl Fn(&[u8]) -> Option<(D32, Signed<TraderFulfillmentBody>)> + '_ {
    move |bytes| {
        let signed = names_fulfillment_key(
            bytes,
            cells.root.device_id(),
            cells.root.economic_position(),
        )?;
        Some((crate::storage_cell::entry_digest(bytes), signed))
    }
}

/// The completion proof of the fulfillment final at `K_ful(q)` (storage spec
/// §9; SoFi Amendment S10), with the fulfillment; `None` while no chain of
/// the fulfillment holding the cell has three links.
pub fn fulfillment_completion(
    cells: &PositionCells,
    evidence: &CellEvidence,
) -> Result<Option<(Signed<TraderFulfillmentBody>, CompletionProof)>, Missing> {
    completion_proof(&cells.fulfillment, evidence, fulfillment_at(cells))
}

/// Check a kept completion proof of `K_ful(q)` against the reads in
/// `evidence`: the fulfillment it proves final.
pub fn check_fulfillment_completion(
    cells: &PositionCells,
    evidence: &CellEvidence,
    proof: &CompletionProof,
) -> Result<Signed<TraderFulfillmentBody>, ProofRefusal> {
    check_completion_proof(&cells.fulfillment, evidence, proof, fulfillment_at(cells))
}

/// Derive `FulfillmentRegistered(q)` from the route-chain evidence of the
/// two position cells: `K_ful(q)` over [`names_fulfillment_key`], `K_root(q)`
/// over the register reader's rule
/// ([`crate::economic::register::root_claim_naming`]; `C_q` is one such
/// claim), the pair matched by `FulfillmentId(F)`. `Err` names what the
/// evidence does not yet show at a cell whose answer is needed: a network
/// status, never an answer about the position.
pub fn fulfillment_registered(
    cells: &PositionCells,
    fulfillment_evidence: &CellEvidence,
    root_evidence: &CellEvidence,
) -> Result<RegistrationRead, Missing> {
    let root = read_root_cell(&cells.root, root_evidence)?;
    let (root_claim, root_claim_final) = match &root {
        CellReading::Held {
            id, value, state, ..
        } => (
            Some(*id),
            matches!(state, ChainState::Final).then(|| value.clone()),
        ),
        CellReading::Open => (None, None),
    };
    let registration = match evaluate(
        &cells.fulfillment,
        fulfillment_evidence,
        fulfillment_at(cells),
    )? {
        CellReading::Open => match root {
            CellReading::Held { id, .. } => Registration::RootTaken { claim: id },
            CellReading::Open => Registration::Unresolved,
        },
        CellReading::Held {
            object: signed,
            state,
            ..
        } => match root {
            CellReading::Held {
                object: claim,
                state: root_state,
                ..
            } if names_the_fulfillment(&claim, &signed.body) => {
                if matches!(state, ChainState::Final) && matches!(root_state, ChainState::Final) {
                    Registration::Registered(signed)
                } else {
                    Registration::Held(signed)
                }
            }
            // Another claim holds the leader link at K_root(q): final or not
            // yet, no other value will ever be final there (§9 finality 2).
            CellReading::Held { .. } => Registration::NeverRegistered {
                fulfillment: signed,
                settled_at: PositionCell::Root,
            },
            CellReading::Open => Registration::Held(signed),
        },
    };
    Ok(RegistrationRead {
        genesis: *cells.root.genesis(),
        device_id: *cells.root.device_id(),
        position: cells.root.economic_position(),
        parent_root: cells.parent_root,
        registration,
        root_claim,
        root_claim_final,
    })
}

/// Whether the claim at `K_root(q)` names `fulfillment` (SoFi Amendment
/// S20): a conditional claim whose `fulfillment_id` is `FulfillmentId(F)`.
fn names_the_fulfillment(
    claim: &RegisteredEconomicClaim,
    fulfillment: &TraderFulfillmentBody,
) -> bool {
    matches!(
        claim,
        RegisteredEconomicClaim::ConditionalSofi(c)
            if c.fulfillment_id == derive::fulfillment_id(fulfillment)
    )
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use crate::sofi::publication::Publication;
    use crate::sofi::validation::fixtures::{signed_c_q, swap_fixture_n, trader_keys, dev, G};
    use crate::route_chain::fixtures::{committed_set, committed_set_id, Cell};
    use crate::route_chain::ROUTE_LEN;
    use crate::sofi::wire::{AttemptEntry, SofiResolutionClaim};

    /// The trader's key, as every fixture `P` commits it.
    fn key() -> &'static [u8] {
        &trader_keys().0
    }

    /// The trader's signature over `digest`.
    fn signed(digest: D32) -> Vec<u8> {
        crate::crypto::sphincs::sphincs_sign(&trader_keys().1, &digest).unwrap()
    }

    fn fulfillment(p: &TraderPrecommitBody, position: u64) -> TraderFulfillmentBody {
        TraderFulfillmentBody::new(
            derive::precommit_id(p),
            vec![[0x01; 32], [0x02; 32]],
            p.legs()
                .iter()
                .map(|l| AttemptEntry {
                    vault_id: l.vault_id,
                    attempt: 0,
                })
                .collect(),
            position,
            ALG,
            key(),
            crate::sofi::validation::fixtures::TRADER_ATT_A,
        )
        .unwrap()
    }

    fn envelope(f: &TraderFulfillmentBody) -> Vec<u8> {
        Publication::Fulfillment {
            body: f,
            signature: &signed(derive::fulfillment_signing_digest(f)),
        }
        .object_bytes()
        .unwrap()
    }

    /// The key is `(G, DevID, q)`, and what names it is decided from `F`'s
    /// bytes alone (SoFi Amendment S20): an envelope at another position, or
    /// under a key that does not derive this device, is nothing, and no `P`
    /// is read to decide it, so whether the `P` it names is published yet
    /// changes nothing.
    #[test]
    fn only_a_fulfillment_of_this_trader_at_this_position_names_the_key() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let f = fulfillment(&p, q);
        let bytes = envelope(&f);
        assert_eq!(
            names_fulfillment_key(&bytes, &dev(), q).map(|s| s.body),
            Some(f.clone())
        );
        assert!(names_fulfillment_key(&bytes, &dev(), q + 1).is_none());
        assert!(names_fulfillment_key(&bytes, &[0x33; 32], q).is_none());
        assert!(names_fulfillment_key(b"not an envelope", &dev(), q).is_none());
    }

    /// DSM Amendment A10, SoFi Amendment S20: `F` proves its own authority
    /// for `K_ful(q)`. A squatter that publishes its own `P` naming the
    /// victim's device, and an `F` of it — each verifying under the
    /// squatter's key — names no cell of the victim's, with the squatter's
    /// `AttA` or the victim's, even with that `P` in hand: the key does not
    /// derive the victim's device, decided from `F`'s bytes alone.
    #[test]
    fn a_fulfillment_under_a_key_that_does_not_derive_the_trader_names_no_cell() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let (squatter_pk, squatter_sk) =
            crate::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let squatters_p = TraderPrecommitBody::new(
            *p.genesis(),
            *p.device_id(),
            p.position(),
            *p.parent_claim_ref(),
            *p.external_commitment(),
            p.legs().to_vec(),
            *p.realize_root(),
            *p.void_root(),
            *p.storage_set_id(),
            ALG,
            &squatter_pk,
        )
        .unwrap();
        for att_a in [[0x5A; 32], crate::sofi::validation::fixtures::TRADER_ATT_A] {
            let squat = TraderFulfillmentBody::new(
                derive::precommit_id(&squatters_p),
                vec![[0x01; 32], [0x02; 32]],
                squatters_p
                    .legs()
                    .iter()
                    .map(|l| AttemptEntry {
                        vault_id: l.vault_id,
                        attempt: 0,
                    })
                    .collect(),
                q,
                ALG,
                &squatter_pk,
                att_a,
            )
            .unwrap();
            assert!(!fulfillment_proves_the_device(&squat, &dev()));
            let bytes = Publication::Fulfillment {
                body: &squat,
                signature: &crate::crypto::sphincs::sphincs_sign(
                    &squatter_sk,
                    &derive::fulfillment_signing_digest(&squat),
                )
                .unwrap(),
            }
            .object_bytes()
            .unwrap();
            assert!(
                names_fulfillment_key(&bytes, &dev(), q).is_none(),
                "a squatter's F names no cell of the victim's"
            );
        }
        // The trader's own F of its own P names the cell.
        let f = fulfillment(&p, q);
        assert!(fulfillment_proves_the_device(&f, &dev()));
        assert!(names_fulfillment_key(&envelope(&f), &dev(), q).is_some());
    }

    /// `K_ful(q)` is named only by a fulfillment the trader signed: its
    /// signature verifies under the key its body commits, and that key, with
    /// the `AttA` it carries, derives the trader's device (SoFi Amendment
    /// S20). An unsigned or foreign-key `F` naming the right position and
    /// `P` is nothing, so first at the leader it holds nothing.
    #[test]
    fn only_a_fulfillment_signed_under_a_key_of_this_device_names_the_key() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let f = fulfillment(&p, q);
        let unsigned = Publication::Fulfillment {
            body: &f,
            signature: &[0x77; 8],
        }
        .object_bytes()
        .unwrap();
        assert!(names_fulfillment_key(&unsigned, &dev(), q).is_none());

        let (other_pk, other_sk) = crate::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let foreign = TraderFulfillmentBody::new(
            *f.precommit_id(),
            f.policy_fulfillment_set().to_vec(),
            f.attempts().to_vec(),
            q,
            ALG,
            &other_pk,
            crate::sofi::validation::fixtures::TRADER_ATT_A,
        )
        .unwrap();
        let foreign_bytes = Publication::Fulfillment {
            body: &foreign,
            signature: &crate::crypto::sphincs::sphincs_sign(
                &other_sk,
                &derive::fulfillment_signing_digest(&foreign),
            )
            .unwrap(),
        }
        .object_bytes()
        .unwrap();
        assert!(names_fulfillment_key(&foreign_bytes, &dev(), q).is_none());

        // First at the leader, the unsigned F blocks nothing.
        let cells = PositionCells::new(
            &G,
            &dev(),
            q,
            &[0x5E; 32],
            &committed_set(),
            &committed_set_id(),
        )
        .expect("the committed set");
        let claim = signed_c_q(derive::resolution_claim(&p, &f));
        let mut ful = Cell::at(cells.fulfillment());
        ful.write(&unsigned, ROUTE_LEN - 1, &[]);
        ful.write(&envelope(&f), ROUTE_LEN - 1, &[]);
        let mut root = Cell::at(cells.root().routed());
        root.write(&claim, ROUTE_LEN - 1, &[]);
        assert!(matches!(
            fulfillment_registered(&cells, &ful.evidence(), &root.evidence())
                .map(|r| r.into_registration()),
            Ok(Registration::Registered(ref s)) if s.body == f
        ));
    }

    /// A fulfillment final at `K_ful(q)` has a completion proof built from
    /// the reads, and the proof checks against them.
    #[test]
    fn a_final_fulfillment_has_a_completion_proof_that_checks() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let f = fulfillment(&p, q);
        let bytes = envelope(&f);
        let cells = PositionCells::new(
            &G,
            &dev(),
            q,
            &[0x5E; 32],
            &committed_set(),
            &committed_set_id(),
        )
        .expect("the committed set");
        let mut seats = Cell::at(cells.fulfillment());
        seats.write(&bytes, 1, &[]);
        assert!(matches!(
            fulfillment_completion(&cells, &seats.evidence()),
            Ok(None)
        ));
        let mut seats = Cell::at(cells.fulfillment());
        seats.write(&bytes, ROUTE_LEN - 1, &[]);
        let Ok(Some((proven, proof))) = fulfillment_completion(&cells, &seats.evidence()) else {
            panic!("a final fulfillment has a completion proof")
        };
        assert_eq!(proven.body, f);
        let checked = check_fulfillment_completion(&cells, &seats.evidence(), &proof)
            .expect("the kept proof checks");
        assert_eq!(checked.body, f);
    }

    /// The predicate over the two cells, from their bytes alone (SoFi
    /// Amendment S20): both final, the root on a claim naming this `F` —
    /// registered; the root held by a claim naming another fulfillment,
    /// final or not — never; this `F` holding the fulfillment cell's leader
    /// link with the pair not final on it — held; no fulfillment holding it
    /// — the root cell's claim named, or nothing decided; an unread leader —
    /// not decided on this evidence.
    #[test]
    fn registration_needs_both_cells_final_and_the_root_on_this_claim() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let f = fulfillment(&p, q);
        let bytes = envelope(&f);
        let claim = signed_c_q(derive::resolution_claim(&p, &f));
        let rival = rival_of(&p, &f);
        let other_claim = signed_c_q(derive::resolution_claim(&p, &rival));
        let cells = cells_at(q);
        let written = |at: &RoutedCell, value: &[u8], last: usize| {
            let mut c = Cell::at(at);
            c.write(value, last, &[]);
            c.evidence()
        };
        let ful_cell = |value: &[u8], last: usize| written(cells.fulfillment(), value, last);
        let root_cell = |value: &[u8], last: usize| written(cells.root().routed(), value, last);
        let reg = |ful: &CellEvidence, root: &CellEvidence| {
            fulfillment_registered(&cells, ful, root).map(|r| r.into_registration())
        };
        let registered = Signed {
            body: f.clone(),
            signature: signed(derive::fulfillment_signing_digest(&f)),
        };
        let final_ful = ful_cell(&bytes, ROUTE_LEN - 1);
        assert_eq!(
            reg(&final_ful, &root_cell(&claim, ROUTE_LEN - 1)),
            Ok(Registration::Registered(registered.clone()))
        );
        for last in [0, ROUTE_LEN - 1] {
            assert_eq!(
                reg(&final_ful, &root_cell(&other_claim, last)),
                Ok(Registration::NeverRegistered {
                    fulfillment: registered.clone(),
                    settled_at: PositionCell::Root,
                }),
                "another claim of this position holds K_root(q) through position {last}"
            );
        }
        assert_eq!(
            reg(&final_ful, &root_cell(&claim, 1)),
            Ok(Registration::Held(registered.clone())),
            "the claim is preserved, not final"
        );
        assert_eq!(
            reg(&final_ful, &root_cell(b"not a claim", ROUTE_LEN - 1)),
            Ok(Registration::Held(registered.clone())),
            "no claim yet at K_root(q)"
        );
        assert_eq!(
            reg(&ful_cell(&bytes, 1), &root_cell(&claim, ROUTE_LEN - 1)),
            Ok(Registration::Held(registered.clone())),
            "the fulfillment is preserved, not final"
        );
        // No fulfillment holds K_ful(q): the root cell's claim is named, and
        // weighed by each F against its own C_q (SoFi Amendment S14). A
        // conditional claim is named by its derived body (SoFi Amendment S20).
        let claim_id =
            crate::storage_cell::entry_digest(&derive::resolution_claim(&p, &f).encode());
        let other_id =
            crate::storage_cell::entry_digest(&derive::resolution_claim(&p, &rival).encode());
        assert_eq!(
            reg(
                &ful_cell(b"garbage", ROUTE_LEN - 1),
                &root_cell(&claim, ROUTE_LEN - 1)
            ),
            Ok(Registration::RootTaken { claim: claim_id })
        );
        for last in [0, ROUTE_LEN - 1] {
            assert_eq!(
                reg(
                    &ful_cell(b"garbage", ROUTE_LEN - 1),
                    &root_cell(&other_claim, last)
                ),
                Ok(Registration::RootTaken { claim: other_id }),
                "no fulfillment, another claim at K_root(q) through position {last}"
            );
        }
        assert_eq!(
            reg(
                &ful_cell(b"garbage", ROUTE_LEN - 1),
                &root_cell(b"not a claim", ROUTE_LEN - 1)
            ),
            Ok(Registration::Unresolved),
            "no fulfillment and no claim: nothing is decided"
        );
        let mut unread_root = root_cell(&claim, ROUTE_LEN - 1);
        unread_root.seats[0].values = None;
        assert_eq!(reg(&final_ful, &unread_root), Err(Missing::LeaderUnread));
    }

    /// Pre-audit item 12, 12j (SoFi Amendments S14 and S20): where a
    /// fulfillment stands at its pair, with its `P` in hand. Registered when
    /// the pair is final on it and on exactly `derive(P, F)`. Lost, for good,
    /// when another fulfillment holds `K_ful(q)`'s leader link in any state —
    /// leader-held alone is enough (§23.1) — or when `K_root(q)`'s leader link
    /// is held by a claim other than `derive(P, F)`: another fulfillment's,
    /// or one naming this `F` whose body is not `F`'s. Pending otherwise.
    #[test]
    fn a_fulfillment_is_lost_to_any_other_leader_and_to_any_claim_not_its_own() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let f = fulfillment(&p, q);
        let rival = rival_of(&p, &f);
        let cells = cells_at(q);
        let own_claim = derive::resolution_claim(&p, &f);
        let at = |ful: Option<(&TraderFulfillmentBody, usize)>,
                  root: Option<(SofiResolutionClaim, usize)>| {
            let mut ful_cell = Cell::at(cells.fulfillment());
            if let Some((body, last)) = ful {
                ful_cell.write(&envelope(body), last, &[]);
            }
            let mut root_cell = Cell::at(cells.root().routed());
            if let Some((claim, last)) = root {
                root_cell.write(&signed_c_q(claim), last, &[]);
            }
            fulfillment_registered(&cells, &ful_cell.evidence(), &root_cell.evidence())
                .expect("both leaders read")
        };
        let last = ROUTE_LEN - 1;
        let standing =
            |read: &RegistrationRead, body: &TraderFulfillmentBody| read.standing_of(&p, body);

        let registered = at(Some((&f, last)), Some((own_claim, last)));
        assert_eq!(standing(&registered, &f), PairStanding::Registered);
        assert_eq!(standing(&registered, &rival), PairStanding::Lost);

        // The rival holds K_ful(q)'s leader link, only leader-held, and
        // K_root(q) holds F's own claim: F can never be final behind it.
        let behind = at(Some((&rival, 0)), Some((own_claim, last)));
        assert_eq!(standing(&behind, &f), PairStanding::Lost);
        assert_eq!(standing(&behind, &rival), PairStanding::Lost);

        let held = at(Some((&f, 0)), None);
        assert_eq!(standing(&held, &f), PairStanding::Pending);
        assert_eq!(standing(&held, &rival), PairStanding::Lost);

        let root_only = at(None, Some((own_claim, last)));
        assert_eq!(standing(&root_only, &f), PairStanding::Pending);
        assert_eq!(standing(&root_only, &rival), PairStanding::Lost);

        // A claim naming F's id, with a body that is not derive(P, F): the
        // pair matches by id, and where P is in hand F is misbodied (lost,
        // and the position Invalid for the lineage, SoFi Amendment S20; 12k).
        let forged = SofiResolutionClaim {
            realize_root: [0xBD; 32],
            ..own_claim
        };
        let mismatched = at(Some((&f, last)), Some((forged, last)));
        assert!(matches!(
            mismatched.registration(),
            Registration::Registered(signed) if signed.body == f
        ));
        assert_eq!(standing(&mismatched, &f), PairStanding::Misbodied);
        assert!(standing(&mismatched, &f).is_lost());
        // Not final yet, the same claim already loses F, and the lineage
        // waits for the pair to settle before it reads the verdict.
        let settling = at(Some((&f, last)), Some((forged, 0)));
        assert_eq!(standing(&settling, &f), PairStanding::Lost);

        let nothing = at(None, None);
        assert_eq!(standing(&nothing, &f), PairStanding::Pending);
    }

    /// The pair at position `q` of the fixture trader, routed by a fixed
    /// parent root.
    fn cells_at(q: u64) -> PositionCells {
        PositionCells::new(
            &G,
            &dev(),
            q,
            &[0x5E; 32],
            &committed_set(),
            &committed_set_id(),
        )
        .expect("the committed set")
    }

    /// Another fulfillment of the same `P` at the same position, signed by
    /// the same trader: a different policy-fulfillment set, so a different id.
    fn rival_of(p: &TraderPrecommitBody, f: &TraderFulfillmentBody) -> TraderFulfillmentBody {
        TraderFulfillmentBody::new(
            derive::precommit_id(p),
            vec![[0x03; 32], [0x04; 32]],
            f.attempts().to_vec(),
            f.position(),
            ALG,
            key(),
            crate::sofi::validation::fixtures::TRADER_ATT_A,
        )
        .unwrap()
    }
}
