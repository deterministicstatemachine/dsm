// SPDX-License-Identifier: Apache-2.0

//! Beta admission: what this release will EXECUTE, as opposed to what the
//! format can express.
//!
//! The canonical objects accept any leg count the byte bound allows, because
//! the bytes of a legal route must be defined whether or not this release
//! runs one (R16-6). What beta refuses is executing past two hops, and the
//! refusal lives here — one place, on the way in — rather than in the codec,
//! where it would have made a three-hop route's bytes undefined and every
//! later relaxation a format change.
//!
//! The same applies to the reserved owner-authority branch: `DsmSuccessor`
//! encodes and decodes so the DSM succession track can activate it without a
//! byte change, and until then nothing may execute it or build it (R18-1).

use super::wire::{OwnerAuthority, SettlementBody, SettlementPreimage, ROUTE_MAX_LEGS};

/// Why beta will not execute an otherwise well-formed operation.
///
/// Every variant is a limit of THIS RELEASE, never a statement about the
/// protocol: the objects are canonical, they simply are not run here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotAdmissible {
    /// More hops than beta executes. The bytes are canonical; the route is not
    /// run.
    TooManyLegs { legs: usize, max: usize },
    /// The reserved DSM-succession authority. Canonically encodable, and never
    /// executed until DSM succession is activated.
    OwnerAuthorityNotActivated,
}

impl core::fmt::Display for NotAdmissible {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooManyLegs { legs, max } => write!(
                f,
                "beta executes at most {max} hops; this route has {legs}. The bytes \
                 are canonical — the route is simply not run in this release"
            ),
            Self::OwnerAuthorityNotActivated => write!(
                f,
                "the DSM-succession owner authority is reserved and not activated: \
                 it encodes, and nothing executes or builds it"
            ),
        }
    }
}

impl std::error::Error for NotAdmissible {}

/// Whether beta will execute this operation.
///
/// Called on the way in, by a producer before it builds and by admission
/// before it runs. It reads the settlement body only — a canonical object is
/// never rewritten to fit, because that would map two logical operations onto
/// one.
pub fn admissible(settlement: &SettlementBody) -> Result<(), NotAdmissible> {
    let legs = settlement.leg_count();
    if legs > ROUTE_MAX_LEGS {
        return Err(NotAdmissible::TooManyLegs {
            legs,
            max: ROUTE_MAX_LEGS,
        });
    }
    if let SettlementBody::Close {
        owner_authority, ..
    } = settlement
    {
        if !matches!(owner_authority, OwnerAuthority::Origin) {
            return Err(NotAdmissible::OwnerAuthorityNotActivated);
        }
    }
    Ok(())
}

/// The same gate over a whole preimage, for callers that hold one.
pub fn preimage_admissible(preimage: &SettlementPreimage) -> Result<(), NotAdmissible> {
    admissible(preimage.settlement())
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sofi::wire::{PreEClosureIndex, SwapHop};

    fn hop(vault: u8) -> SwapHop {
        SwapHop {
            vault_id: [vault; 32],
            parent_root: [vault ^ 0x0F; 32],
            setup_ref: [vault ^ 0xF0; 32],
            token_in: [0x51; 32],
            amount_in: 100,
            token_out: [0x52; 32],
            amount_out: 90,
        }
    }

    fn swap(legs: usize) -> SettlementBody {
        SettlementBody::Swap {
            token_in: [0x51; 32],
            amount_in: 100,
            token_out: [0x52; 32],
            exact_out: 90,
            hops: (0..legs as u8).map(|j| hop(0xC1 + j)).collect(),
            trader_core: [0xD1; 32],
            dlv_cores: (0..legs).map(|j| [0xE0 + j as u8; 32]).collect(),
            closure: PreEClosureIndex::new(Vec::new()).unwrap(),
        }
    }

    fn close(authority: OwnerAuthority) -> SettlementBody {
        SettlementBody::Close {
            vault_id: [0xC1; 32],
            parent_root: [0xC2; 32],
            setup_ref: [0xC3; 32],
            owner_authority: authority,
            reserve_a: 10,
            reserve_b: 20,
            trader_core: [0xD1; 32],
            dlv_core: [0xD2; 32],
            closure: PreEClosureIndex::new(Vec::new()).unwrap(),
        }
    }

    /// The cap is admission's, not the codec's: a three-hop route has
    /// canonical bytes and is refused here.
    #[test]
    fn beta_refuses_more_hops_than_it_executes() {
        assert_eq!(admissible(&swap(1)), Ok(()));
        assert_eq!(admissible(&swap(2)), Ok(()));
        let three = swap(3);
        // The object is canonical — that is the point of the split.
        assert!(three.encode().is_ok());
        assert_eq!(
            admissible(&three),
            Err(NotAdmissible::TooManyLegs { legs: 3, max: 2 })
        );
        assert_eq!(ROUTE_MAX_LEGS, 2);
    }

    /// The reserved authority encodes and never executes (R18-1).
    #[test]
    fn beta_refuses_the_reserved_owner_authority() {
        assert_eq!(admissible(&close(OwnerAuthority::Origin)), Ok(()));
        let reserved = close(OwnerAuthority::DsmSuccessor {
            authority_class: 0x1234,
            authority_addr: [0x5D; 32],
        });
        assert!(reserved.encode().is_ok());
        assert_eq!(
            admissible(&reserved),
            Err(NotAdmissible::OwnerAuthorityNotActivated)
        );
    }
}
