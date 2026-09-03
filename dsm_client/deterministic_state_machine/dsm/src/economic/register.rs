// SPDX-License-Identifier: Apache-2.0

//! The economic root register — where a trader publishes one root per position,
//! and what that publication does and does not establish.
//!
//! ## Registered is not validated
//!
//! Writing a claim into a write-once cell establishes exactly one thing:
//! **non-equivocation**. This identity named one root at this position and can
//! never name a second. It says nothing about whether that root resulted from a
//! valid transition — a malicious trader registers an arbitrary root perfectly
//! consistently, and the register accepts it.
//!
//! `accepted_root != valid_root`. This module produces
//! [`RegisteredEconomicRoot`] and nothing else; [`super::lineage`] owns the
//! validated side, and the two cannot be interconverted.
//!
//! ## Nodes stay dumb
//!
//! A member's checks are **storage and attribution only**:
//!
//! ```text
//! signature verifies under the body's claimant_public_key
//! claimant_public_key == authenticated_caller.public_key
//! trader_devid        == authenticated_caller.device_id
//! storage_set_id      == this node's configured set
//! then write-once
//! ```
//!
//! No P0–P6, no transition validation, no economics.
//!
//! Attribution is not optional politeness — it is the **only** thing standing
//! between a victim and a permanently burned cell. `K_root` identity-scopes
//! the coordinate but does not gate writes to it: anyone who knows a victim's
//! `G` and `DevID` can compute `K_root(G_v, D_v, k)`, and the register is
//! write-once, so one accepted value there burns that position forever. The
//! member refusing a claim whose `claimant_public_key` and `trader_devid` are
//! not the authenticated caller's is what makes that write impossible.
//!
//! ```text
//! K_root                identity-scopes the cell
//! claimant attribution  prevents third-party preemption of that cell
//! ```
//!
//! Attribution is only as strong as the authentication behind it: the caller's
//! key and device must themselves be proven, which is P0–P6's job at the
//! verifying end, not the member's.
//!
//! ## The network scope is what stops register substitution
//!
//! Genesis v3 commits `network_id` as field 2 of `GenesisParamsV3`, inside the
//! CCB that `G` commits — so an authenticated genesis already carries a
//! committed network scope, recoverable by recomputation rather than by
//! lookup. Requiring the trader's committed `network_id` to equal the
//! vault's is what stops a trader minting a genesis under some other network
//! whose profile names a different register, then presenting roots from that
//! register as though they were from this one.
//!
//! The network→root-set mapping is **immutable for the lifetime of that root
//! sequence**. Replacing the fleet requires an explicit handover or a new
//! network identity, never a config edit — a mapping that could be edited
//! would let the same position resolve to two different registers.

use crate::ccb::{storage_set_id, CcbError, StorageSetMembers};
use crate::common::domain_tags::TAG_DSM_TRADER_ECONOMIC_ROOT_REGISTER_KEY;
use crate::crypto::blake3::dsm_domain_hasher;
use crate::types::identifiers::encode_crockford;

/// `K_root = H_dom(DSM/trader-economic-root-register-key/v1,
/// G ‖ DevID ‖ u64_be(economic_position))`.
///
/// Identity-scopes the cell and nothing more. The key is **derivable by
/// anyone** who knows `(G, DevID, position)` — all public — so it confers no
/// exclusivity on its own. Exclusivity comes from write-once storage plus
/// [`AttributionError`]-checked claimant attribution.
pub fn economic_root_register_key(
    genesis: &[u8; 32],
    device_id: &[u8; 32],
    economic_position: u64,
) -> [u8; 32] {
    let mut h = dsm_domain_hasher(TAG_DSM_TRADER_ECONOMIC_ROOT_REGISTER_KEY);
    h.update(genesis);
    h.update(device_id);
    h.update(&economic_position.to_be_bytes());
    *h.finalize().as_bytes()
}

/// The register a network's economic roots live in.
///
/// Resolved from the network identity, never supplied by a claimant. A claim
/// names the set it was written to inside its **signed** body, and a verifier
/// checks that name against this resolution — so a claim cannot be lifted from
/// one network's register into another's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootRegisterProfile {
    pub storage_set_id: [u8; 32],
    pub quorum: u32,
    pub members: Vec<Vec<u8>>,
}

/// Why a register could not be resolved. Every variant is **fail-closed**:
/// there is no default register and no fallback set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterResolutionError {
    /// No profile is defined for this network. Not an error to paper over
    /// with a default — a default register is a register an attacker can
    /// steer traffic into.
    UnknownNetwork { network_id: Vec<u8> },
    /// The trader's committed network is not the one being settled against.
    NetworkMismatch { claimed: Vec<u8>, expected: Vec<u8> },
    /// The profile resolved, but its set id could not be re-derived from the
    /// members — a corrupt profile, not a recoverable condition.
    ProfileNotDerivable(CcbError),
}

impl core::fmt::Display for RegisterResolutionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::UnknownNetwork { network_id } => write!(
                f,
                "no root-register profile for network {:?} — fail closed; a default register \
                 is one an attacker can steer traffic into",
                String::from_utf8_lossy(network_id)
            ),
            Self::NetworkMismatch { claimed, expected } => write!(
                f,
                "trader genesis commits network {:?} but this is network {:?} — a genesis \
                 minted under another network resolves a different register",
                String::from_utf8_lossy(claimed),
                String::from_utf8_lossy(expected)
            ),
            Self::ProfileNotDerivable(e) => {
                write!(f, "root-register profile is not derivable: {e}")
            }
        }
    }
}

impl std::error::Error for RegisterResolutionError {}

/// The beta fleet's member ids.
///
/// Member IDENTITIES live here and not in `dlv::beta_storage_profile`, which
/// deliberately fixes cardinality and threshold only. Two modules asserting
/// membership would be two places for the fleet to be described differently.
const BETA_MEMBERS: [&[u8]; 3] = [b"dsm-node-1", b"dsm-node-2", b"dsm-node-3"];

/// The network the beta fleet serves. Matches the client database's
/// `network_id` default. The real mainnet gets its OWN id (and with it a
/// fresh, untouched faucet allocation) as a new profile at launch — nothing
/// claimed under this network can validate there.
const BETA_NETWORK_ID: &[u8] = b"dsm-testnet";

/// Resolve the register for a network. Unknown network ⇒ fail closed.
pub fn resolve_root_register_profile(
    network_id: &[u8],
) -> Result<RootRegisterProfile, RegisterResolutionError> {
    if network_id != BETA_NETWORK_ID {
        return Err(RegisterResolutionError::UnknownNetwork {
            network_id: network_id.to_vec(),
        });
    }
    let set = StorageSetMembers::new(&BETA_MEMBERS)
        .map_err(RegisterResolutionError::ProfileNotDerivable)?;
    let members: Vec<Vec<u8>> = BETA_MEMBERS.iter().map(|m| m.to_vec()).collect();
    let id = storage_set_id(&set).map_err(RegisterResolutionError::ProfileNotDerivable)?;
    Ok(RootRegisterProfile {
        storage_set_id: id,
        // Req 6.13's fixed three-member profile. Read from the DLV profile
        // module rather than restated, so the threshold has one home.
        quorum: crate::dlv::beta_storage_profile::SOFI_BETA_QUORUM,
        members,
    })
}

/// Resolve the register for a trader, requiring their committed network to be
/// the one being settled against.
///
/// `trader_network_id` must come from the `GenesisParamsV3` behind the
/// **authenticated** `G` — recovered by recomputation, not accepted from a
/// claimant.
pub fn resolve_for_trader(
    trader_network_id: &[u8],
    settling_network_id: &[u8],
) -> Result<RootRegisterProfile, RegisterResolutionError> {
    if trader_network_id != settling_network_id {
        return Err(RegisterResolutionError::NetworkMismatch {
            claimed: trader_network_id.to_vec(),
            expected: settling_network_id.to_vec(),
        });
    }
    resolve_root_register_profile(settling_network_id)
}

/// A caller a storage node has already authenticated at the transport layer.
///
/// The node knows who is talking to it; attribution is checking that the claim
/// says the same thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticatedCaller {
    pub public_key: Vec<u8>,
    /// The transport device id, already decoded to raw bytes.
    pub device_id: [u8; 32],
}

/// The largest claim envelope a register member reads: one SPHINCS+ SPX256f
/// signature (~49.9 KiB) plus a key and a small body. Shared by every member
/// implementation — the storage node's handlers and the in-process register
/// double — so "too large" is refused at the same byte on both.
pub const MAX_CLAIM_BYTES: usize = 160 * 1024;

/// Why a member refuses to store a claim. All storage-layer; none is a
/// judgement about economics. Attribution is checked on a claim whose
/// signature ALREADY verified — a signature failure is
/// [`super::claim_envelope::ClaimEnvelopeError::SignatureInvalid`], never an
/// attribution outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttributionError {
    /// The claim names a claimant that is not the authenticated caller.
    ClaimantIsNotCaller,
    /// The claim names a device that is not the authenticated caller's.
    DeviceIsNotCaller,
    /// The claim names a storage set this node is not a member of.
    WrongStorageSet {
        claimed: [u8; 32],
        configured: [u8; 32],
    },
}

impl core::fmt::Display for AttributionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::ClaimantIsNotCaller => write!(
                f,
                "economic root claim: claimant_public_key is not the authenticated caller — \
                 an authenticated caller may not claim as someone else"
            ),
            Self::DeviceIsNotCaller => write!(
                f,
                "economic root claim: trader_devid is not the authenticated caller's device — \
                 K_root is derivable by anyone, so this check is what stops a third party \
                 writing into a victim's cell and burning it"
            ),
            Self::WrongStorageSet {
                claimed,
                configured,
            } => write!(
                f,
                "economic root claim: names storage set {} but this member is configured for {}",
                encode_crockford(claimed),
                encode_crockford(configured)
            ),
        }
    }
}

impl std::error::Error for AttributionError {}

/// What a register member observed at one position.
///
/// Holding one of these means a quorum accepted these exact bytes. It means
/// **nothing** about whether `post_economic_root` is the result of a valid
/// transition — see [`super::lineage`], and note there is deliberately no
/// conversion from this type into a validated one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredEconomicRoot {
    pub trader_genesis: [u8; 32],
    pub trader_devid: [u8; 32],
    pub economic_position: u64,
    pub post_economic_root: [u8; 32],
    pub admission_manifest_addr: [u8; 32],
    pub storage_set_id: [u8; 32],
}

impl RegisteredEconomicRoot {
    /// The cell these bytes occupy.
    pub fn register_key(&self) -> [u8; 32] {
        economic_root_register_key(
            &self.trader_genesis,
            &self.trader_devid,
            self.economic_position,
        )
    }
}
