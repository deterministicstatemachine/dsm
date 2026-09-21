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
//! `Final` at each cell is the R4 adapter over the recognized view — an
//! object naming `K_ful(q)` is a fulfillment envelope whose body sits at
//! position `q` and whose `P` names the trader whose key it is; an object
//! naming `K_root(q)` is a registered claim whose coordinates derive that
//! key. Bytes that are neither count as nothing anywhere.
//!
//! Because the leader of `s(q)` keeps one value first at `K_ful(q)`, at most
//! one fulfillment is registered per position. Registered is not conforming
//! and not valid (Section 20.2): what this module answers is only whether the
//! exercise happened.

use std::collections::BTreeMap;

use super::arith::ObjectResolution;
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
    let (_, signed) = recognize_fulfillment(bytes)?;
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
    /// Not settled: a cell is open, held at its leader but not yet copied,
    /// or its leader did not answer. A read that establishes nothing is not
    /// a statement about the position.
    Unresolved,
}

/// Derive `FulfillmentRegistered(q)` from the two cells' resolutions over
/// their recognized views: `fulfillment` resolved with
/// [`names_fulfillment_key`], `root` with the register reader's rule (any
/// registered claim whose coordinates derive `K_root(q)`; `C_q` is one).
pub fn fulfillment_registered(
    fulfillment: &ObjectResolution,
    root: &ObjectResolution,
    genesis: &D32,
    device_id: &D32,
    position: u64,
    precommits: &impl PrecommitLookup,
) -> Registration {
    let ObjectResolution::Final(bytes) = fulfillment else {
        // Open, held at the leader without two copies, or unread: nothing
        // is registered yet, and nothing is settled against this position.
        return Registration::Unresolved;
    };
    let Some(signed) = names_fulfillment_key(bytes, genesis, device_id, position, precommits)
    else {
        // The adapter only reports what the recognizer admitted; a read that
        // somehow lacks it establishes nothing.
        return Registration::Unresolved;
    };
    let Some(precommit) = precommits.precommit(signed.body.precommit_id()) else {
        return Registration::Unresolved;
    };
    let claim = derive::resolution_claim(precommit, &signed.body).encode();
    match root {
        ObjectResolution::Final(held) if *held == claim => Registration::Registered(signed),
        // Another claim is the leader's first object at K_root(q): final or
        // not yet, no other value will ever be final there (Part II §8).
        ObjectResolution::Final(_) => Registration::NeverRegistered {
            fulfillment: signed,
            settled_at: PositionCell::Root,
        },
        ObjectResolution::LeaderHeld(held) if *held != claim => Registration::NeverRegistered {
            fulfillment: signed,
            settled_at: PositionCell::Root,
        },
        ObjectResolution::LeaderHeld(_)
        | ObjectResolution::Open
        | ObjectResolution::Unavailable => Registration::Unresolved,
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::ccb::sigalg::SPHINCS_PLUS_SPX256F as ALG;
    use crate::sofi::publication::Publication;
    use crate::sofi::validation::fixtures::{swap_fixture_n, DEV, G};
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
    /// own claim — registered; the root final or leader-held on another
    /// claim — never; anything short of final at either cell — unresolved.
    #[test]
    fn registration_needs_both_cells_final_and_the_root_on_this_claim() {
        let p = swap_fixture_n(2).precommit;
        let q = p.position() + 1;
        let f = fulfillment(&p, q);
        let bytes = envelope(&f);
        let known = lookup(&p);
        let claim = derive::resolution_claim(&p, &f).encode();
        let other_claim = derive::resolution_claim(&p, &fulfillment(&p, q + 1)).encode();
        let reg = |ful: ObjectResolution, root: ObjectResolution| {
            fulfillment_registered(&ful, &root, &G, &DEV, q, &known)
        };
        use ObjectResolution::{Final, LeaderHeld, Open, Unavailable};
        assert_eq!(
            reg(Final(bytes.clone()), Final(claim.clone())),
            Registration::Registered(Signed {
                body: f.clone(),
                signature: SIG.to_vec()
            })
        );
        for root in [Final(other_claim.clone()), LeaderHeld(other_claim.clone())] {
            assert_eq!(
                reg(Final(bytes.clone()), root),
                Registration::NeverRegistered {
                    fulfillment: Signed {
                        body: f.clone(),
                        signature: SIG.to_vec()
                    },
                    settled_at: PositionCell::Root,
                }
            );
        }
        for root in [LeaderHeld(claim.clone()), Open, Unavailable] {
            assert_eq!(reg(Final(bytes.clone()), root), Registration::Unresolved);
        }
        for ful in [LeaderHeld(bytes.clone()), Open, Unavailable] {
            assert_eq!(reg(ful, Final(claim.clone())), Registration::Unresolved);
        }
        // Final bytes the recognizer would not have admitted establish nothing.
        assert_eq!(
            reg(Final(b"garbage".to_vec()), Final(claim)),
            Registration::Unresolved
        );
    }
}
