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

use crate::route_chain::{evaluate, CellEvidence, CellReading, ChainState, Missing};
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

/// An object naming `K_ful(q)` of trader `(G, DevID)`: a fulfillment
/// envelope that recognizes (R8), whose body's position is `q`, and whose
/// `P` — fetched by the id the body names — is that trader's. A fulfillment
/// of another trader or another position written at this key is nothing:
/// neither a rival nor a winner, however early it arrived.
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
    let precommit = precommits.precommit(signed.body.precommit_id())?;
    if precommit.genesis() != genesis || precommit.device_id() != device_id {
        return None;
    }
    Some(signed)
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
    /// Not registered yet: a cell is open, or the value holding it is not
    /// final yet.
    Unresolved,
}

/// Derive `FulfillmentRegistered(q)` from the route-chain evidence of the
/// two position cells: `K_ful(q)` over [`names_fulfillment_key`], `K_root(q)`
/// over the register reader's rule
/// ([`crate::economic::register::root_claim_naming`]; `C_q` is one such
/// claim). `Err` names what the evidence does not yet show at a cell whose
/// answer is needed: a network status, never an answer about the position.
pub fn fulfillment_registered(
    fulfillment_cell: &CellEvidence,
    root_cell: &CellEvidence,
    genesis: &D32,
    device_id: &D32,
    position: u64,
    precommits: &impl PrecommitLookup,
) -> Result<Registration, Missing> {
    let fulfillment = evaluate(fulfillment_cell, |bytes| {
        let signed = names_fulfillment_key(bytes, genesis, device_id, position, precommits)?;
        let precommit = precommits.precommit(signed.body.precommit_id())?.clone();
        Some((
            crate::storage_cell::entry_digest(bytes),
            (signed, precommit),
        ))
    })?;
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
        | CellReading::Open => return Ok(Registration::Unresolved),
    };
    let claim = derive::resolution_claim(&precommit, &signed.body).encode();
    let k_root =
        crate::economic::register::economic_root_register_key(genesis, device_id, position);
    let root = evaluate(root_cell, |bytes| {
        crate::economic::register::root_claim_naming(bytes, &k_root)
            .is_some()
            .then(|| (crate::storage_cell::entry_digest(bytes), bytes.to_vec()))
    })?;
    Ok(match root {
        CellReading::Held {
            object,
            state: ChainState::Final,
            ..
        } if object == claim => Registration::Registered(signed),
        // Another claim holds the leader link at K_root(q): final or not
        // yet, no other value will ever be final there (§9 finality 2).
        CellReading::Held { object, .. } if object != claim => Registration::NeverRegistered {
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
    use crate::sofi::validation::fixtures::{swap_fixture_n, DEV, G};
    use crate::route_chain::{fixtures::Cell, ROUTE_LEN};
    use crate::sofi::wire::AttemptEntry;

    const KEY: [u8; 64] = [0x31; 64];
    const SIG: [u8; 8] = [0x77; 8];

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
            &KEY,
        )
        .unwrap()
    }

    fn envelope(f: &TraderFulfillmentBody) -> Vec<u8> {
        Publication::Fulfillment {
            body: f,
            signature: &SIG,
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
            names_fulfillment_key(&bytes, &G, &DEV, q, &known).map(|s| s.body),
            Some(f.clone())
        );
        assert!(names_fulfillment_key(&bytes, &G, &DEV, q + 1, &known).is_none());
        assert!(names_fulfillment_key(&bytes, &[0x33; 32], &DEV, q, &known).is_none());
        let unknown: BTreeMap<D32, TraderPrecommitBody> = BTreeMap::new();
        assert!(
            names_fulfillment_key(&bytes, &G, &DEV, q, &unknown).is_none(),
            "without P neither the trader nor C_q is known"
        );
        assert!(names_fulfillment_key(b"not an envelope", &G, &DEV, q, &known).is_none());
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
        let claim = derive::resolution_claim(&p, &f).encode();
        let rival = TraderFulfillmentBody::new(
            derive::precommit_id(&p),
            vec![[0x03; 32], [0x04; 32]],
            f.attempts().to_vec(),
            q,
            ALG,
            &KEY,
        )
        .unwrap();
        let other_claim = derive::resolution_claim(&p, &rival).encode();
        let cell = |value: &[u8], last: usize| {
            let mut c = Cell::new(b"DSM/test-position", [0x71; 32], [0x72; 32]);
            c.write(value, last, &[]);
            c.evidence()
        };
        let reg = |ful: &CellEvidence, root: &CellEvidence| {
            fulfillment_registered(ful, root, &G, &DEV, q, &known)
        };
        let registered = Signed {
            body: f.clone(),
            signature: SIG.to_vec(),
        };
        let final_ful = cell(&bytes, ROUTE_LEN - 1);
        assert_eq!(
            reg(&final_ful, &cell(&claim, ROUTE_LEN - 1)),
            Ok(Registration::Registered(registered.clone()))
        );
        for last in [0, ROUTE_LEN - 1] {
            assert_eq!(
                reg(&final_ful, &cell(&other_claim, last)),
                Ok(Registration::NeverRegistered {
                    fulfillment: registered.clone(),
                    settled_at: PositionCell::Root,
                }),
                "another claim of this position holds K_root(q) through position {last}"
            );
        }
        assert_eq!(
            reg(&final_ful, &cell(&claim, 1)),
            Ok(Registration::Unresolved),
            "the claim is preserved, not final"
        );
        assert_eq!(
            reg(&final_ful, &cell(b"not a claim", ROUTE_LEN - 1)),
            Ok(Registration::Unresolved)
        );
        assert_eq!(
            reg(&cell(&bytes, 1), &cell(&claim, ROUTE_LEN - 1)),
            Ok(Registration::Unresolved)
        );
        assert_eq!(
            reg(
                &cell(b"garbage", ROUTE_LEN - 1),
                &cell(&claim, ROUTE_LEN - 1)
            ),
            Ok(Registration::Unresolved)
        );
        let mut unread_root = cell(&claim, ROUTE_LEN - 1);
        unread_root.seats[0].values = None;
        assert_eq!(reg(&final_ful, &unread_root), Err(Missing::LeaderUnread));
    }
}
