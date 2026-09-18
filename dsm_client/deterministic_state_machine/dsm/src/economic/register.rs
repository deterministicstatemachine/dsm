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
    pub quorum: u32,
    pub members: Vec<Vec<u8>>,
    /// The PINNED set id this network's root register lives under.
    ///
    /// This is the authority commitment, and it is why the field exists. With
    /// membership alone, the answer to "who chose the incarnation values the
    /// set id was derived from?" is "the resolved catalog candidate" — the
    /// catalog would be constrained to the right member ids and otherwise
    /// believed. Pinning the digest makes the catalog's job resolution and
    /// nothing else: it may say WHERE a member is reached and WHICH
    /// incarnation it claims, and this value decides whether that is the
    /// register this network actually commits to.
    ///
    /// Derived once, from the incarnations the real provisioned members
    /// minted. It is not derivable from anything in this source tree, which
    /// is the point.
    pub storage_set_id: [u8; 32],
}

impl RootRegisterProfile {
    /// Check a CANDIDATE set against this network's pinned commitment.
    ///
    /// Two conjuncts, in this order, and neither is sufficient alone:
    ///
    /// 1. the candidate's member ids are exactly this network's members —
    ///    a cheap, legible refusal that names what was wrong;
    /// 2. the id RE-DERIVED from the candidate's `(member_id,
    ///    register_incarnation_id)` pairs equals `storage_set_id`.
    ///
    /// Clause 2 is the one that makes the catalog non-authoritative. A member
    /// that rebuilt its register still has the right id, so clause 1 passes;
    /// its incarnation changed, so the re-derived digest does not match and
    /// the set is refused. That is the substitution this exists to stop, and
    /// it is refused rather than silently resolved to a different register.
    ///
    /// Endpoints are transport metadata and are not inputs to either clause.
    pub fn verify_candidate(
        &self,
        candidate: &StorageSetMembers,
    ) -> Result<(), RegisterResolutionError> {
        let mut want: Vec<&[u8]> = self.members.iter().map(|m| m.as_slice()).collect();
        want.sort_unstable();
        let got: Vec<&[u8]> = candidate.entries().iter().map(|e| e.member_id()).collect();
        if got != want {
            return Err(RegisterResolutionError::MembershipNotCanonical {
                expected: self.members.clone(),
                got: got.iter().map(|m| m.to_vec()).collect(),
            });
        }
        let derived =
            storage_set_id(candidate).map_err(RegisterResolutionError::ProfileNotDerivable)?;
        if derived != self.storage_set_id {
            return Err(RegisterResolutionError::SetIdIsNotThePinnedOne {
                pinned: self.storage_set_id,
                derived,
            });
        }
        Ok(())
    }
}

/// Why a register could not be resolved. Every variant is **fail-closed**:
/// there is no default register and no fallback set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegisterResolutionError {
    /// No profile is defined for this network. Not an error to paper over
    /// with a default — a default register is a register an attacker can
    /// steer traffic into.
    UnknownNetwork { network_id: Vec<u8> },
    /// A resolver offered a candidate set whose membership is not this
    /// network's. The catalog resolves a set; it never chooses one.
    MembershipNotCanonical {
        expected: Vec<Vec<u8>>,
        got: Vec<Vec<u8>>,
    },
    /// The candidate has this network's members, but the id re-derived from
    /// its `(member, incarnation)` pairs is not the pinned one — the members
    /// are right and at least one is not serving the register this network
    /// committed to. A rebuilt or restored member lands here.
    SetIdIsNotThePinnedOne { pinned: [u8; 32], derived: [u8; 32] },
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
            Self::MembershipNotCanonical { expected, got } => write!(
                f,
                "resolved root-register membership {:?} is not this network's canonical \
                 membership {:?} — the catalog resolves a set, it never chooses one",
                got.iter()
                    .map(|m| String::from_utf8_lossy(m))
                    .collect::<Vec<_>>(),
                expected
                    .iter()
                    .map(|m| String::from_utf8_lossy(m))
                    .collect::<Vec<_>>()
            ),
            // The digests are carried on the variant rather than rendered
            // here: this crate has no Base32-Crockford encoder (it lives in
            // the SDK), and the repository forbids hex.
            Self::SetIdIsNotThePinnedOne { .. } => write!(
                f,
                "the resolved register set has this network's members but does not derive the \
                 pinned set id — a member is not serving the register history this network \
                 committed to"
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

/// The beta fleet's PINNED authority set: each member and the register
/// incarnation it is serving.
///
/// This is the network's root-register commitment, expressed as the pairs
/// rather than as an opaque digest so it can be audited by reading it — the
/// set id is derived from exactly these bytes, and `verify_candidate` refuses
/// anything that does not re-derive to it.
///
/// The incarnations are NOT chosen here. Each is the value that member's own
/// database minted on first boot, read from its startup log; nothing in this
/// source tree can derive them, which is what makes the pin meaningful. A
/// member that loses and rebuilds its register mints a different one, stops
/// re-deriving this id, and is refused rather than silently substituted.
///
/// An all-zero incarnation is the value a node has before it has established
/// one, and `StorageSetMembers::new` refuses it — so an UNPROVISIONED network
/// fails closed here by construction rather than by anyone remembering to
/// check.
///
/// Provisioned 2026-09-12 (UTC): the beta fleet moved from the three-member
/// Alibaba set to the FIVE-member GCP set (us-central1). Each node was created
/// empty and minted its incarnation on first boot into its own fresh database;
/// these are the values each logged at that boot. Their Base32-Crockford
/// renderings are pinned in `beta_root_register_pins_render_to_the_logged_values`.
/// Nothing from the Alibaba set carries over — its members, its incarnations and
/// its set id are retired, and a claim made under it cannot validate here.
const BETA_ROOT_REGISTER_MEMBERS: [PinnedMember; 5] = [
    (
        b"dsm-node-1",
        [
            0x2E, 0xF7, 0xC8, 0x0E, 0x0B, 0x01, 0x1E, 0x8A, 0xC0, 0x83, 0xDE, 0xE6, 0xA4, 0xB9,
            0x0C, 0xC5, 0xBF, 0xD8, 0xAD, 0x90, 0x01, 0x21, 0x9E, 0x67, 0x0C, 0x2F, 0xF0, 0x3F,
            0xC4, 0x48, 0xD0, 0xE8,
        ],
    ),
    (
        b"dsm-node-2",
        [
            0xA0, 0x39, 0x3A, 0xCD, 0x83, 0x0B, 0xCA, 0x06, 0x82, 0x1F, 0xE1, 0xA5, 0xEA, 0x27,
            0xDF, 0xD3, 0x72, 0x34, 0x70, 0x6A, 0x69, 0xE1, 0xEF, 0xD6, 0xA4, 0x05, 0x6F, 0xB4,
            0x4E, 0xD7, 0x1B, 0xCA,
        ],
    ),
    (
        b"dsm-node-3",
        [
            0x9B, 0x15, 0x05, 0x78, 0xF8, 0x28, 0x51, 0x9A, 0xC8, 0x0E, 0xAA, 0x58, 0x24, 0x81,
            0xEB, 0xE3, 0xCA, 0x91, 0x6D, 0x67, 0x3D, 0x39, 0x35, 0x45, 0x19, 0xD5, 0x21, 0xB5,
            0xB1, 0xFA, 0x5F, 0x05,
        ],
    ),
    (
        b"dsm-node-4",
        [
            0x51, 0x29, 0x0F, 0xFC, 0xA1, 0x90, 0x81, 0x59, 0xFA, 0xAC, 0x2B, 0xC4, 0x60, 0x43,
            0xD6, 0xB6, 0x63, 0x12, 0x6F, 0x68, 0x77, 0x22, 0x8F, 0x0C, 0xA5, 0x7E, 0x50, 0xD7,
            0xC1, 0x1A, 0x77, 0x10,
        ],
    ),
    (
        b"dsm-node-5",
        [
            0xBD, 0x71, 0xB9, 0xEA, 0x93, 0x44, 0x6D, 0xE4, 0xB7, 0xD5, 0xC9, 0xAA, 0xFF, 0xE0,
            0xF7, 0x8B, 0x12, 0x3F, 0x21, 0xF9, 0x5C, 0x02, 0x10, 0x17, 0x08, 0xAB, 0x4B, 0x63,
            0xAC, 0x67, 0x4E, 0x22,
        ],
    ),
];

/// The network the beta fleet serves. Matches the client database's
/// `network_id` default. The real mainnet gets its OWN id (and with it a
/// fresh, untouched faucet allocation) as a new profile at launch — nothing
/// claimed under this network can validate there.
/// The network the beta root register is pinned for. One name for the
/// network, so callers resolve the profile they were built for instead of
/// each spelling the id themselves.
pub const BETA_NETWORK_ID: &[u8] = b"dsm-testnet";

/// One pinned entry: a member id and the register incarnation it serves.
pub type PinnedMember = (&'static [u8], [u8; 32]);

/// A network's PINNED root-register members, for callers that must construct
/// or display the committed set — a catalog being provisioned, a fixture that
/// has to resolve to the real register, an operator tool.
///
/// Public because it is a commitment, not a secret: it says which members and
/// which register histories this network trusts, and anyone verifying a claim
/// against this network needs to be able to check that.
pub fn pinned_root_register_members(
    network_id: &[u8],
) -> Result<&'static [PinnedMember], RegisterResolutionError> {
    if network_id != BETA_NETWORK_ID {
        return Err(RegisterResolutionError::UnknownNetwork {
            network_id: network_id.to_vec(),
        });
    }
    Ok(&BETA_ROOT_REGISTER_MEMBERS)
}

/// Resolve the register for a network. Unknown network ⇒ fail closed.
pub fn resolve_root_register_profile(
    network_id: &[u8],
) -> Result<RootRegisterProfile, RegisterResolutionError> {
    if network_id != BETA_NETWORK_ID {
        return Err(RegisterResolutionError::UnknownNetwork {
            network_id: network_id.to_vec(),
        });
    }
    // The pinned pairs are the ONE source: both the member list and the set id
    // come from them, so the two cannot drift apart.
    let pinned = StorageSetMembers::new(&BETA_ROOT_REGISTER_MEMBERS)
        .map_err(RegisterResolutionError::ProfileNotDerivable)?;
    let storage_set_id =
        storage_set_id(&pinned).map_err(RegisterResolutionError::ProfileNotDerivable)?;
    let members: Vec<Vec<u8>> = pinned
        .entries()
        .iter()
        .map(|e| e.member_id().to_vec())
        .collect();
    Ok(RootRegisterProfile {
        // Req 6.13's fixed five-member profile. Read from the DLV profile
        // module rather than restated, so the threshold has one home.
        quorum: crate::dlv::beta_storage_profile::SOFI_BETA_QUORUM,
        members,
        storage_set_id,
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
/// **Fields are private, and there is ONE constructor.** Public fields made
/// this type assemblable from arbitrary bytes: anything could name a position
/// and a root and hand the result to `advance_validated`, which is the whole
/// door the claim union was introduced to shut. The union refuses to flatten
/// a conditional claim into a root — and that is worth nothing if a caller can
/// simply build the flattened struct itself.
///
/// So the only way to one of these is
/// [`Self::from_verified_single_root`]: a claim whose envelope decoded
/// canonically, whose signature verified under its own committed key, and
/// which is a `SingleRoot` claim rather than a conditional one. Every field
/// below is then a projection of that claim, not a caller's assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisteredEconomicRoot {
    trader_genesis: [u8; 32],
    trader_devid: [u8; 32],
    economic_position: u64,
    post_economic_root: [u8; 32],
    admission_manifest_addr: [u8; 32],
    storage_set_id: [u8; 32],
}

impl RegisteredEconomicRoot {
    /// THE constructor: project a verified single-root claim.
    ///
    /// It takes the claim rather than the fields precisely so there is nothing
    /// for a caller to choose. A conditional claim cannot reach here — it has
    /// no `VerifiedEconomicRootClaim` to offer, because
    /// `RegisteredEconomicClaim::single_root` refuses it.
    pub fn from_verified_single_root(
        claim: &crate::economic::claim_envelope::VerifiedEconomicRootClaim,
    ) -> Self {
        let body = claim.body();
        Self {
            trader_genesis: body.trader_genesis,
            trader_devid: body.trader_devid,
            economic_position: body.economic_position,
            post_economic_root: body.post_economic_root,
            admission_manifest_addr: body.admission_manifest_addr,
            storage_set_id: body.root_register_storage_set_id,
        }
    }

    pub fn trader_genesis(&self) -> [u8; 32] {
        self.trader_genesis
    }

    pub fn trader_devid(&self) -> [u8; 32] {
        self.trader_devid
    }

    pub fn economic_position(&self) -> u64 {
        self.economic_position
    }

    pub fn post_economic_root(&self) -> [u8; 32] {
        self.post_economic_root
    }

    pub fn admission_manifest_addr(&self) -> [u8; 32] {
        self.admission_manifest_addr
    }

    pub fn storage_set_id(&self) -> [u8; 32] {
        self.storage_set_id
    }

    /// The cell these bytes occupy.
    pub fn register_key(&self) -> [u8; 32] {
        economic_root_register_key(
            &self.trader_genesis,
            &self.trader_devid,
            self.economic_position,
        )
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod registered_root_construction_tests {
    use super::*;
    use crate::economic::claim::EconomicRootClaimBody;
    use crate::economic::claim_envelope::{decode_registered_economic_claim, sign_economic_root_claim};

    /// THE ONLY WAY TO A REGISTERED ROOT IS A VERIFIED CLAIM.
    ///
    /// With public fields, the claim union's refusal to flatten a conditional
    /// claim into a root bought nothing: a caller could read `realize_root`
    /// off a `C_q` and assemble the struct by hand, then hand it to
    /// `advance_validated`. The type now has one constructor and it takes the
    /// verified claim, so there is no field for a caller to choose.
    #[test]
    fn a_registered_root_is_a_projection_of_a_verified_claim() {
        let (pk, sk) = crate::crypto::sphincs::generate_sphincs_keypair().unwrap();
        let body = EconomicRootClaimBody::new(
            [0x11; 32],
            [0x22; 32],
            9,
            [0xC0; 32],
            [0xD0; 32],
            [0x77; 32],
            crate::ccb::genesis::sigalg::SPHINCS_PLUS_SPX256F,
            &pk,
        )
        .unwrap();
        let envelope = sign_economic_root_claim(&body, &sk).unwrap();
        let verified = decode_registered_economic_claim(&envelope)
            .unwrap()
            .single_root()
            .unwrap()
            .clone();

        let registered = RegisteredEconomicRoot::from_verified_single_root(&verified);
        // Every field is the claim's, not an argument.
        assert_eq!(registered.trader_genesis(), [0x11; 32]);
        assert_eq!(registered.trader_devid(), [0x22; 32]);
        assert_eq!(registered.economic_position(), 9);
        assert_eq!(registered.post_economic_root(), [0xC0; 32]);
        assert_eq!(registered.admission_manifest_addr(), [0xD0; 32]);
        assert_eq!(registered.storage_set_id(), [0x77; 32]);
        assert_eq!(
            registered.register_key(),
            economic_root_register_key(&[0x11; 32], &[0x22; 32], 9)
        );
    }

    /// A CONDITIONAL CLAIM CANNOT REACH THE CONSTRUCTOR AT ALL.
    ///
    /// Not because a check rejects it — because it has no
    /// `VerifiedEconomicRootClaim` to offer. The refusal is in the type, which
    /// is what makes it impossible to forget.
    #[test]
    fn a_conditional_claim_has_nothing_to_construct_from() {
        let conditional = crate::sofi::wire::SofiResolutionClaim {
            genesis: [0x11; 32],
            device_id: [0x22; 32],
            position: 9,
            fulfillment_id: [0xF1; 32],
            realize_root: [0xA1; 32],
            void_root: [0xB1; 32],
        };
        let decoded = decode_registered_economic_claim(&conditional.encode()).unwrap();
        // The only path to the constructor's argument refuses, and there is no
        // second path: `RegisteredEconomicRoot` has no public fields and no
        // other constructor.
        assert!(decoded.single_root().is_err());
    }
}
