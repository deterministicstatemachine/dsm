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
//! recognized view — an object naming `K_ful(q)` is a fulfillment envelope
//! whose body sits at position `q` and whose `P` names the trader whose key it
//! is; an object naming `K_root(q)` is a registered claim whose coordinates
//! derive that key. Bytes that are neither count as nothing anywhere.
//!
//! Because at most one value has a valid leader link at `K_ful(q)`, at most
//! one fulfillment is registered per position. Registered is not conforming
//! and not valid (Section 20.2): what this module answers is only whether the
//! exercise happened.

use std::collections::BTreeMap;

use crate::economic::register::{position_seed, read_root_cell, RootCell};
use crate::route_chain::{
    check_completion_proof, completion_proof, evaluate, CellError, CellEvidence, CellReading,
    ChainState, CompletionProof, Missing, ProofRefusal, RoutedCell,
};
use super::derive;
use super::publication::{recognize_fulfillment, Signed};
use super::wire::{TraderFulfillmentBody, TraderPrecommitBody};

type D32 = [u8; 32];

/// The precommits a reader fetched by `PrecommitId` (R8) for the fulfillment
/// candidates it saw. A candidate whose `P` is not in hand names nothing
/// yet: without `P`, neither the trader it belongs to nor `C_q` is known.
pub trait PrecommitLookup {
    fn precommit(&self, id: &D32) -> Option<&TraderPrecommitBody>;
}

impl PrecommitLookup for BTreeMap<D32, TraderPrecommitBody> {
    fn precommit(&self, id: &D32) -> Option<&TraderPrecommitBody> {
        self.get(id)
    }
}

/// Whether `F` proves its own authority for a cell of `device_id` (DSM
/// Amendment A10, SoFi Amendment S20): its key, with the `AttA` it carries,
/// derives that device. Decided from `F`'s bytes alone, so a reader applies
/// it before fetching anything `F` names.
pub fn fulfillment_proves_the_device(body: &TraderFulfillmentBody, device_id: &D32) -> bool {
    crate::core::identity::genesis_v2::derive_devid(
        body.claimant_public_key(),
        body.claimant_att_a(),
    ) == *device_id
}

/// An object naming `K_ful(q)` of trader `(G, DevID)`: a fulfillment
/// envelope that recognizes (R8), whose body's position is `q`, whose key and
/// `AttA` derive `DevID` ([`fulfillment_proves_the_device`]), and whose `P` —
/// fetched by the id the body names — is that trader's. A fulfillment of
/// another trader or another position, or one under a key that does not
/// derive the trader's device, written at this key is nothing: neither a
/// rival nor a winner, however early it arrived.
pub fn names_fulfillment_key(
    bytes: &[u8],
    genesis: &D32,
    device_id: &D32,
    position: u64,
    precommits: &impl PrecommitLookup,
) -> Option<Signed<TraderFulfillmentBody>> {
    let signed = recognize_fulfillment(bytes)?.1;
    if signed.body.position() != position {
        return None;
    }
    if !fulfillment_proves_the_device(&signed.body, device_id) {
        return None;
    }
    let precommit = precommits.precommit(signed.body.precommit_id())?;
    if precommit.genesis() != genesis || precommit.device_id() != device_id {
        return None;
    }
    // F is signed under the key its P commits; each was verified under its
    // own body's key when it was recognized.
    if signed.body.signature_alg() != precommit.signature_alg()
        || signed.body.claimant_public_key() != precommit.claimant_public_key()
    {
        return None;
    }
    Some(signed)
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

    /// `FulfillmentRegistered(q, F)` for exactly `fulfillment`: registered,
    /// and the registered envelope's body is this one.
    pub fn is_registered_as(&self, fulfillment: &TraderFulfillmentBody) -> bool {
        matches!(&self.registration, Registration::Registered(signed) if signed.body == *fulfillment)
    }
}

/// Which of the two cells settled the answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PositionCell {
    Fulfillment,
    Root,
}

/// `FulfillmentRegistered` at position `q`, as the reads establish it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Registration {
    /// `Final(K_ful(q), F)` and `Final(K_root(q), C_q)`: the exercise. The
    /// registered fulfillment, in the envelope the members hold.
    Registered(Signed<TraderFulfillmentBody>),
    /// `F` is final at `K_ful(q)` but `K_root(q)` is final on another claim
    /// — an ordinary transition, or another fulfillment's claim, got to the
    /// leader first. This `F` is not registered and never will be
    /// (PairMutualExclusion): the position went to the other claim.
    NeverRegistered {
        fulfillment: Signed<TraderFulfillmentBody>,
        settled_at: PositionCell,
    },
    /// No fulfillment is final at `K_ful(q)`, and `K_root(q)` is held by the
    /// claim whose entry digest is `claim`: final, or holding the leader link,
    /// so no other value will ever be final there (§9 finality 2). An `F` at
    /// `q` whose own `C_q` is another claim can never register (SoFi
    /// Amendment S14); one whose `C_q` it is waits for its fulfillment to be
    /// relayed.
    RootTaken { claim: D32 },
    /// Not registered yet: a cell is open, or the value holding it is not
    /// final yet.
    Unresolved,
}

/// A fulfillment recognized at `K_ful(q)`: its entry digest, the signed
/// fulfillment, and the precommit it names.
type RecognizedFulfillment = (D32, (Signed<TraderFulfillmentBody>, TraderPrecommitBody));

/// The recognizer of `K_ful(q)`: fulfillment envelopes naming the key
/// ([`names_fulfillment_key`]), with the precommit each names, identified by
/// the entry digest of their exact bytes.
fn fulfillment_at<'a>(
    cells: &'a PositionCells,
    precommits: &'a impl PrecommitLookup,
) -> impl Fn(&[u8]) -> Option<RecognizedFulfillment> + 'a {
    move |bytes| {
        let signed = names_fulfillment_key(
            bytes,
            cells.root.genesis(),
            cells.root.device_id(),
            cells.root.economic_position(),
            precommits,
        )?;
        let precommit = precommits.precommit(signed.body.precommit_id())?.clone();
        Some((
            crate::storage_cell::entry_digest(bytes),
            (signed, precommit),
        ))
    }
}

/// The completion proof of the fulfillment final at `K_ful(q)` (storage spec
/// §9; SoFi Amendment S10), with the fulfillment; `None` while no chain of
/// the fulfillment holding the cell has three links.
pub fn fulfillment_completion(
    cells: &PositionCells,
    evidence: &CellEvidence,
    precommits: &impl PrecommitLookup,
) -> Result<Option<(Signed<TraderFulfillmentBody>, CompletionProof)>, Missing> {
    Ok(completion_proof(
        &cells.fulfillment,
        evidence,
        fulfillment_at(cells, precommits),
    )?
    .map(|((signed, ..), proof)| (signed, proof)))
}

/// Check a kept completion proof of `K_ful(q)` against the reads in
/// `evidence`: the fulfillment it proves final.
pub fn check_fulfillment_completion(
    cells: &PositionCells,
    evidence: &CellEvidence,
    proof: &CompletionProof,
    precommits: &impl PrecommitLookup,
) -> Result<Signed<TraderFulfillmentBody>, ProofRefusal> {
    check_completion_proof(
        &cells.fulfillment,
        evidence,
        proof,
        fulfillment_at(cells, precommits),
    )
    .map(|(signed, ..)| signed)
}

/// Derive `FulfillmentRegistered(q)` from the route-chain evidence of the
/// two position cells: `K_ful(q)` over [`names_fulfillment_key`], `K_root(q)`
/// over the register reader's rule
/// ([`crate::economic::register::root_claim_naming`]; `C_q` is one such
/// claim). `Err` names what the evidence does not yet show at a cell whose
/// answer is needed: a network status, never an answer about the position.
pub fn fulfillment_registered(
    cells: &PositionCells,
    fulfillment_evidence: &CellEvidence,
    root_evidence: &CellEvidence,
    precommits: &impl PrecommitLookup,
) -> Result<RegistrationRead, Missing> {
    let registration = registration_of(cells, fulfillment_evidence, root_evidence, precommits)?;
    Ok(RegistrationRead {
        genesis: *cells.root.genesis(),
        device_id: *cells.root.device_id(),
        position: cells.root.economic_position(),
        parent_root: cells.parent_root,
        registration,
    })
}

fn registration_of(
    cells: &PositionCells,
    fulfillment_evidence: &CellEvidence,
    root_evidence: &CellEvidence,
    precommits: &impl PrecommitLookup,
) -> Result<Registration, Missing> {
    let fulfillment = evaluate(
        &cells.fulfillment,
        fulfillment_evidence,
        fulfillment_at(cells, precommits),
    )?;
    let (signed, precommit) = match fulfillment {
        CellReading::Held {
            object,
            state: ChainState::Final,
            ..
        } => object,
        CellReading::Held {
            state: ChainState::LeaderHeld | ChainState::Preserved,
            ..
        }
        | CellReading::Open => {
            // No fulfillment is final at K_ful(q) yet. The position may still
            // have gone to a claim at K_root(q), and whatever holds it is the
            // claim every F at q is measured against (SoFi Amendment S14).
            return Ok(match read_root_cell(&cells.root, root_evidence)? {
                CellReading::Held { id, .. } => Registration::RootTaken { claim: id },
                CellReading::Open => Registration::Unresolved,
            });
        }
    };
    // The root cell's reading identifies its claim by the entry digest of
    // its exact bytes, so `C_q` holds the cell exactly when the ids agree.
    let claim = crate::storage_cell::entry_digest(
        &derive::resolution_claim(&precommit, &signed.body).encode(),
    );
    Ok(match read_root_cell(&cells.root, root_evidence)? {
        CellReading::Held {
            id,
            state: ChainState::Final,
            ..
        } if id == claim => Registration::Registered(signed),
        // Another claim holds the leader link at K_root(q): final or not
        // yet, no other value will ever be final there (§9 finality 2).
        CellReading::Held { id, .. } if id != claim => Registration::NeverRegistered {
            fulfillment: signed,
            settled_at: PositionCell::Root,
        },
        CellReading::Held { .. } | CellReading::Open => Registration::Unresolved,
    })
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
    use crate::sofi::wire::AttemptEntry;

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

    fn lookup(p: &TraderPrecommitBody) -> BTreeMap<D32, TraderPrecommitBody> {
        BTreeMap::from([(derive::precommit_id(p), p.clone())])
    }

    /// The key is `(G, DevID, q)`: an envelope at another position, of a
    /// precommit not in hand, or of another trader's precommit is nothing.
    #[test]
    fn only_a_fulfillment_of_this_trader_at_this_position_names_the_key() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let f = fulfillment(&p, q);
        let bytes = envelope(&f);
        let known = lookup(&p);
        assert_eq!(
            names_fulfillment_key(&bytes, &G, &dev(), q, &known).map(|s| s.body),
            Some(f.clone())
        );
        assert!(names_fulfillment_key(&bytes, &G, &dev(), q + 1, &known).is_none());
        assert!(names_fulfillment_key(&bytes, &[0x33; 32], &dev(), q, &known).is_none());
        let unknown: BTreeMap<D32, TraderPrecommitBody> = BTreeMap::new();
        assert!(
            names_fulfillment_key(&bytes, &G, &dev(), q, &unknown).is_none(),
            "without P neither the trader nor C_q is known"
        );
        assert!(names_fulfillment_key(b"not an envelope", &G, &dev(), q, &known).is_none());
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
        let known = lookup(&squatters_p);
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
                names_fulfillment_key(&bytes, &G, &dev(), q, &known).is_none(),
                "a squatter's F names no cell of the victim's"
            );
        }
        // The trader's own F of its own P names the cell.
        let f = fulfillment(&p, q);
        assert!(fulfillment_proves_the_device(&f, &dev()));
        assert!(names_fulfillment_key(&envelope(&f), &G, &dev(), q, &lookup(&p)).is_some());
    }

    /// `K_ful(q)` is named only by a fulfillment the trader signed: its
    /// signature verifies under the key its body commits, and that key is the
    /// one its `P` commits. An unsigned or foreign-key `F` naming the right
    /// trader, position and `P` is nothing, so first at the leader it holds
    /// nothing.
    #[test]
    fn only_a_fulfillment_signed_under_its_precommits_key_names_the_key() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let f = fulfillment(&p, q);
        let known = lookup(&p);
        let unsigned = Publication::Fulfillment {
            body: &f,
            signature: &[0x77; 8],
        }
        .object_bytes()
        .unwrap();
        assert!(names_fulfillment_key(&unsigned, &G, &dev(), q, &known).is_none());

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
        assert!(names_fulfillment_key(&foreign_bytes, &G, &dev(), q, &known).is_none());

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
            fulfillment_registered(&cells, &ful.evidence(), &root.evidence(), &known)
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
        let known = lookup(&p);
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
            fulfillment_completion(&cells, &seats.evidence(), &known),
            Ok(None)
        ));
        let mut seats = Cell::at(cells.fulfillment());
        seats.write(&bytes, ROUTE_LEN - 1, &[]);
        let Ok(Some((proven, proof))) = fulfillment_completion(&cells, &seats.evidence(), &known)
        else {
            panic!("a final fulfillment has a completion proof")
        };
        assert_eq!(proven.body, f);
        let checked = check_fulfillment_completion(&cells, &seats.evidence(), &proof, &known)
            .expect("the kept proof checks");
        assert_eq!(checked.body, f);
    }

    /// The predicate over the two cells: both final, the root on this F's
    /// own claim — registered; the root held by another claim of this
    /// position, final or not — never; anything short of final at either
    /// cell — unresolved; an unread leader — not decided on this evidence.
    #[test]
    fn registration_needs_both_cells_final_and_the_root_on_this_claim() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let f = fulfillment(&p, q);
        let bytes = envelope(&f);
        let known = lookup(&p);
        let claim = signed_c_q(derive::resolution_claim(&p, &f));
        let rival = TraderFulfillmentBody::new(
            derive::precommit_id(&p),
            vec![[0x03; 32], [0x04; 32]],
            f.attempts().to_vec(),
            q,
            ALG,
            key(),
            crate::sofi::validation::fixtures::TRADER_ATT_A,
        )
        .unwrap();
        let other_claim = signed_c_q(derive::resolution_claim(&p, &rival));
        let cells = PositionCells::new(
            &G,
            &dev(),
            q,
            &[0x5E; 32],
            &committed_set(),
            &committed_set_id(),
        )
        .expect("the committed set");
        let written = |at: &RoutedCell, value: &[u8], last: usize| {
            let mut c = Cell::at(at);
            c.write(value, last, &[]);
            c.evidence()
        };
        let ful_cell = |value: &[u8], last: usize| written(cells.fulfillment(), value, last);
        let root_cell = |value: &[u8], last: usize| written(cells.root().routed(), value, last);
        let reg = |ful: &CellEvidence, root: &CellEvidence| {
            fulfillment_registered(&cells, ful, root, &known).map(|r| r.into_registration())
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
            Ok(Registration::Unresolved),
            "the claim is preserved, not final"
        );
        assert_eq!(
            reg(&final_ful, &root_cell(b"not a claim", ROUTE_LEN - 1)),
            Ok(Registration::Unresolved)
        );
        // No fulfillment final at K_ful(q): the root cell's claim is named,
        // and weighed by each F against its own C_q (SoFi Amendment S14).
        // A conditional claim is named by its derived body (SoFi Amendment S20).
        let claim_id =
            crate::storage_cell::entry_digest(&derive::resolution_claim(&p, &f).encode());
        let other_id =
            crate::storage_cell::entry_digest(&derive::resolution_claim(&p, &rival).encode());
        assert_eq!(
            reg(&ful_cell(&bytes, 1), &root_cell(&claim, ROUTE_LEN - 1)),
            Ok(Registration::RootTaken { claim: claim_id })
        );
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
                "no fulfillment final, another claim at K_root(q) through position {last}"
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
}
