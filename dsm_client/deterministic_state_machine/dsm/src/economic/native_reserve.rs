// SPDX-License-Identifier: Apache-2.0

//! The native ERA reserve — one canonical lineage per network, released
//! leader first (Part IX §51; rebuild step R4).
//!
//! ## One reserve, one authority path, replicated everywhere
//!
//! ERA is fixed-supply native value. The distributable supply exists at
//! genesis in ONE reserve state per network,
//!
//! ```text
//! R_0 = NativeReserveState { reserve_id, ERA, remaining = S_genesis, generation 0, S }
//! ```
//!
//! and every unit that ever leaves it does so by a *release*: the successor
//! object at the reserve's cell `K(reserve_id, R_n)`, written leader first
//! over the committed set `S` (Part II §7, §8). Core recomputes the successor
//! state from the release's bytes,
//!
//! ```text
//! remaining_{n+1} = remaining_n − amount,     generation_{n+1} = generation_n + 1,
//! ```
//!
//! so `S_genesis = remaining + Σ released` at every state by construction:
//! there is no arm that increases `remaining`, no mint after genesis, and no
//! creator with a withdrawal — the reserve is anchored to the network, owned
//! by nobody, and `Release` is its whole transition set.
//!
//! Storage members hold replicas of the same reserve objects. More replicas
//! raise availability and nothing else: no member votes, compares or decides,
//! the leader of a cell is `FisherYates(seed(reserve_id, R_n), S)[0]` over the
//! COMMITTED set, and `Final` is the leader's first recognized object held by
//! two further links on its route chain ([`crate::route_chain::evaluate`]).
//! Which bytes at the cell are an object naming it is Core's question, answered here by
//! [`recognize_release`]: a release that does not fit its parent — wrong
//! reserve, wrong root, wrong generation, zero, or more than remains — is not
//! an occupant, however early it arrived and however many members hold it.
//!
//! ## The recipient is named directly
//!
//! A release body names its recipient and its amount. Its `source` says why
//! the release is constructible; for the beta faucet that is
//! [`ReleaseSource::FaucetClaimant`]: the recipient IS the claimant, the
//! signature under `claimant_public_key` is the whole authority, and the
//! verifier checks that key is the recipient's proven AK. `FaucetClaim(A, x)
//! ⇒ recipient = A` holds by shape — the body has no field with which to pay
//! anyone else. A later source (an emission lottery, where the event that
//! opens a release and the account that receives it may differ) adds an arm
//! to [`ReleaseSource`]; the reserve mechanics above do not change.
//!
//! ## Non-reuse
//!
//! A release binds ONE recipient position and ONE exact operation digest, and
//! the cell it wins is final exactly once. The credit provenance arm
//! (`CreditSource::NativeReserveRelease`) checks both bindings against the
//! transition it funds.

use prost::Message;

use crate::ccb::decode::DecodeError;
use crate::common::domain_tags::{
    TAG_DSM_ECON_SOURCE_NATIVE_RESERVE_RELEASE, TAG_DSM_NATIVE_RESERVE_CELL,
    TAG_DSM_NATIVE_RESERVE_ID, TAG_DSM_NATIVE_RESERVE_RELEASE, TAG_DSM_NATIVE_RESERVE_RELEASE_SIGN,
    TAG_DSM_NATIVE_RESERVE_SEED, TAG_DSM_NATIVE_RESERVE_STATE,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::route_chain::{
    check_completion_proof, completion_proof, evaluate, CellError, CellEvidence, CellReading,
    ChainState, CompletionProof, Missing, ProofRefusal, RoutedCell,
};
use crate::storage_object::immutable_addr;
use crate::types::proto as generated;

type D32 = [u8; 32];

/// The whole distributable ERA supply of one network at genesis. Nothing is
/// minted after it; every unit in circulation was released from it.
pub const ERA_RESERVE_GENESIS_SUPPLY: u64 = 80_000_000_000;

/// What one beta faucet claim releases. ERA is whole-unit (`decimals = 0`),
/// so this is literally 100 ERA. The claim names no amount: the beta claim
/// policy fixes it, and the accepting transition refuses any other delta.
pub const ERA_FAUCET_PAYOUT: u64 = 100;

/// Matches the proto's `dsm_max_len`; prost does not enforce it, so this
/// module does.
const MAX_KEY_OR_SIG_BYTES: usize = 65_535;

/// The canonical reserve identity for one network:
/// `H_dom(DSM/native-reserve-id/v1, network_id ‖ ERA_POLICY_COMMIT)`.
///
/// Recomputable by anyone from public inputs. `network_id` MUST be the one
/// committed in the claimant's authenticated Genesis v3, never a value the
/// claimant supplies beside the claim.
pub fn era_reserve_id(network_id: &[u8]) -> D32 {
    let era = crate::core::token::token_state_manager::era_policy_commit();
    let mut h = dsm_domain_hasher(TAG_DSM_NATIVE_RESERVE_ID);
    h.update(network_id);
    h.update(&era);
    *h.finalize().as_bytes()
}

/// The successor cell of the reserve state with root `parent_root`:
/// `K = H_dom(DSM/native-reserve-cell/v1, reserve_id ‖ R_n)`.
pub fn reserve_cell_key(reserve_id: &D32, parent_root: &D32) -> D32 {
    let mut h = dsm_domain_hasher(TAG_DSM_NATIVE_RESERVE_CELL);
    h.update(reserve_id);
    h.update(parent_root);
    *h.finalize().as_bytes()
}

/// The namespace the reserve's cells live under at a member.
pub fn reserve_cell_namespace() -> &'static [u8] {
    TAG_DSM_NATIVE_RESERVE_CELL.source_bytes()
}

/// The seed of that cell's leader (Part II §7.2): both the reserve and the
/// parent root enter it, so a writer cannot choose where its release is
/// decided. `FisherYates(seed, S)[0]` over the COMMITTED set is the leader.
pub fn reserve_seed(reserve_id: &D32, parent_root: &D32) -> D32 {
    let mut h = dsm_domain_hasher(TAG_DSM_NATIVE_RESERVE_SEED);
    h.update(reserve_id);
    h.update(parent_root);
    *h.finalize().as_bytes()
}

/// `SourceId` of the release at `generation`:
/// `H_dom(DSM/econ-source/native-reserve-release/v1, reserve_id ‖ u64_be(generation))`.
pub fn release_source_id(reserve_id: &D32, generation: u64) -> D32 {
    let mut h = dsm_domain_hasher(TAG_DSM_ECON_SOURCE_NATIVE_RESERVE_RELEASE);
    h.update(reserve_id);
    h.update(&generation.to_be_bytes());
    *h.finalize().as_bytes()
}

/// The content address of the EXACT signed release bytes in the immutable
/// object store — what a credit's `release_evidence_addr` must equal.
pub fn release_evidence_addr(envelope_bytes: &[u8]) -> D32 {
    immutable_addr(TAG_DSM_NATIVE_RESERVE_RELEASE, envelope_bytes)
}

/// One state of the reserve lineage. Never stored: `R_0` is computed from
/// public inputs and every later state from the releases that won.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeReserveState {
    pub reserve_id: D32,
    pub policy_commit: D32,
    pub remaining_supply: u64,
    pub generation: u64,
    /// The committed set every release must name (Part II §6).
    pub storage_set_id: D32,
}

impl NativeReserveState {
    /// `R_0` for one network: the whole genesis supply, generation 0.
    pub fn genesis(network_id: &[u8], storage_set_id: D32) -> Self {
        Self {
            reserve_id: era_reserve_id(network_id),
            policy_commit: crate::core::token::token_state_manager::era_policy_commit(),
            remaining_supply: ERA_RESERVE_GENESIS_SUPPLY,
            generation: 0,
            storage_set_id,
        }
    }

    /// `R_n`.
    pub fn root(&self) -> D32 {
        let mut h = dsm_domain_hasher(TAG_DSM_NATIVE_RESERVE_STATE);
        h.update(&self.reserve_id);
        h.update(&self.policy_commit);
        h.update(&self.remaining_supply.to_be_bytes());
        h.update(&self.generation.to_be_bytes());
        h.update(&self.storage_set_id);
        *h.finalize().as_bytes()
    }

    /// The cell where this state's successor is decided.
    pub fn successor_cell(&self) -> D32 {
        reserve_cell_key(&self.reserve_id, &self.root())
    }

    /// The seed of that cell's leader.
    pub fn successor_seed(&self) -> D32 {
        reserve_seed(&self.reserve_id, &self.root())
    }
}

/// Why a release is constructible: the source of its authority. One arm
/// today; the seam for the mainnet emission lottery is another arm here,
/// never a change to the reserve mechanics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseSource {
    /// The recipient claimed for itself. The signature over the body under
    /// this key is the whole authority; the verifier checks the key is the
    /// recipient's proven AK.
    FaucetClaimant { claimant_public_key: Vec<u8> },
}

/// The unsigned release body — what the signature covers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeReserveReleaseBody {
    pub reserve_id: D32,
    /// `R_n`, the state this release succeeds.
    pub parent_root: D32,
    /// `n + 1`.
    pub generation: u64,
    pub amount: u64,
    pub recipient_genesis: D32,
    pub recipient_devid: D32,
    /// The TARGET economic position this release funds — half of the
    /// non-reuse binding; the root register at that position is itself a
    /// cell that is final once.
    pub recipient_economic_position: u64,
    /// The digest of the exact `Operation::FaucetClaim` this release funds —
    /// the other half, pinning WHICH transition.
    pub recipient_operation_digest: D32,
    pub storage_set_id: D32,
    pub source: ReleaseSource,
}

impl NativeReserveReleaseBody {
    fn to_proto(&self) -> generated::NativeReserveReleaseBodyV1 {
        let source = match &self.source {
            ReleaseSource::FaucetClaimant {
                claimant_public_key,
            } => generated::native_reserve_release_body_v1::Source::FaucetClaimant(
                generated::FaucetClaimantRecipientV1 {
                    claimant_public_key: claimant_public_key.clone(),
                },
            ),
        };
        generated::NativeReserveReleaseBodyV1 {
            reserve_id: self.reserve_id.to_vec(),
            parent_root: self.parent_root.to_vec(),
            generation: self.generation,
            amount: self.amount,
            recipient_genesis: self.recipient_genesis.to_vec(),
            recipient_devid: self.recipient_devid.to_vec(),
            recipient_economic_position: self.recipient_economic_position,
            recipient_operation_digest: self.recipient_operation_digest.to_vec(),
            storage_set_id: self.storage_set_id.to_vec(),
            source: Some(source),
        }
    }

    /// Canonical body bytes: prost's deterministic encoding.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        self.to_proto().encode_to_vec()
    }

    fn from_proto(p: &generated::NativeReserveReleaseBodyV1) -> Result<Self, ReleaseError> {
        let fixed = |v: &[u8], what: &'static str| -> Result<D32, ReleaseError> {
            D32::try_from(v).map_err(|_| ReleaseError::Malformed(what))
        };
        let source = match &p.source {
            Some(generated::native_reserve_release_body_v1::Source::FaucetClaimant(c)) => {
                if c.claimant_public_key.is_empty()
                    || c.claimant_public_key.len() > MAX_KEY_OR_SIG_BYTES
                {
                    return Err(ReleaseError::Malformed("claimant_public_key length"));
                }
                ReleaseSource::FaucetClaimant {
                    claimant_public_key: c.claimant_public_key.clone(),
                }
            }
            None => return Err(ReleaseError::Malformed("release has no source")),
        };
        Ok(Self {
            reserve_id: fixed(&p.reserve_id, "reserve_id")?,
            parent_root: fixed(&p.parent_root, "parent_root")?,
            generation: p.generation,
            amount: p.amount,
            recipient_genesis: fixed(&p.recipient_genesis, "recipient_genesis")?,
            recipient_devid: fixed(&p.recipient_devid, "recipient_devid")?,
            recipient_economic_position: p.recipient_economic_position,
            recipient_operation_digest: fixed(
                &p.recipient_operation_digest,
                "recipient_operation_digest",
            )?,
            storage_set_id: fixed(&p.storage_set_id, "storage_set_id")?,
            source,
        })
    }

    /// `m = H_dom(DSM/native-reserve-release-sign/v1, canonical body bytes)`.
    pub fn signing_digest(&self) -> D32 {
        let mut h = dsm_domain_hasher(TAG_DSM_NATIVE_RESERVE_RELEASE_SIGN);
        h.update(&self.canonical_bytes());
        *h.finalize().as_bytes()
    }

    /// The key whose signature authorizes this release.
    pub fn signer(&self) -> &[u8] {
        match &self.source {
            ReleaseSource::FaucetClaimant {
                claimant_public_key,
            } => claimant_public_key,
        }
    }
}

/// An envelope that decoded strictly and whose signature verified under its
/// source's key.
///
/// Verifying the signature proves the body was signed by whoever holds that
/// key. It does NOT prove the key is the recipient's P0–P6-proven AK — the
/// provenance verifier checks that, because storage attribution is not the
/// DSM-identity binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedRelease {
    pub body: NativeReserveReleaseBody,
    /// The exact bytes a member stores. Retained rather than re-derived: a
    /// byte-different re-encode is a different object.
    pub envelope_bytes: Vec<u8>,
}

/// Why an envelope is not a usable release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseError {
    /// Did not decode, decoded non-canonically, or a bounded field was empty
    /// or oversized.
    Malformed(&'static str),
    /// The signature does not verify over the body under the source's key.
    SignatureInvalid,
    /// SPHINCS+ signing failed.
    SignFailed(String),
}

impl core::fmt::Display for ReleaseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "native reserve release malformed: {why}"),
            Self::SignatureInvalid => write!(f, "native reserve release signature invalid"),
            Self::SignFailed(e) => write!(f, "native reserve release sign failed: {e}"),
        }
    }
}

impl std::error::Error for ReleaseError {}

impl From<ReleaseError> for DecodeError {
    fn from(e: ReleaseError) -> Self {
        DecodeError::Invalid(e.to_string())
    }
}

/// Build and sign a release. The caller retains the returned bytes and
/// replays them verbatim on every retry — SPHINCS+ signing here is
/// deterministic, so a regenerated envelope is indistinguishable from a
/// replayed one downstream, which is exactly why regeneration is forbidden:
/// sign once per parent root, freeze, replay.
pub fn sign_release(
    body: &NativeReserveReleaseBody,
    secret_key: &[u8],
) -> Result<Vec<u8>, ReleaseError> {
    let digest = body.signing_digest();
    let signature = crate::crypto::sphincs::sphincs_sign(secret_key, &digest)
        .map_err(|e| ReleaseError::SignFailed(e.to_string()))?;
    Ok(generated::NativeReserveReleaseV1 {
        body: Some(body.to_proto()),
        signature,
    }
    .encode_to_vec())
}

/// Strictly decode an envelope and verify its signature under the source's
/// key. Refuses anything that does not re-encode to exactly the input bytes —
/// unknown fields, duplicates and non-canonical encodings all fail that
/// comparison.
pub fn decode_and_verify_release(envelope_bytes: &[u8]) -> Result<VerifiedRelease, ReleaseError> {
    if envelope_bytes.is_empty() {
        return Err(ReleaseError::Malformed("empty envelope"));
    }
    let env = generated::NativeReserveReleaseV1::decode(envelope_bytes)
        .map_err(|_| ReleaseError::Malformed("envelope does not decode"))?;
    let body_proto = env
        .body
        .as_ref()
        .ok_or(ReleaseError::Malformed("envelope has no body"))?;
    if env.signature.is_empty() || env.signature.len() > MAX_KEY_OR_SIG_BYTES {
        return Err(ReleaseError::Malformed("signature length"));
    }
    let body = NativeReserveReleaseBody::from_proto(body_proto)?;
    let reencoded = generated::NativeReserveReleaseV1 {
        body: Some(body.to_proto()),
        signature: env.signature.clone(),
    }
    .encode_to_vec();
    if reencoded != envelope_bytes {
        return Err(ReleaseError::Malformed("envelope is not canonical"));
    }
    let digest = body.signing_digest();
    let ok = crate::crypto::sphincs::sphincs_verify(body.signer(), &digest, &env.signature)
        .map_err(|_| ReleaseError::SignatureInvalid)?;
    if !ok {
        return Err(ReleaseError::SignatureInvalid);
    }
    Ok(VerifiedRelease {
        body,
        envelope_bytes: envelope_bytes.to_vec(),
    })
}

/// Why a verified release is not the successor of a given reserve state.
///
/// Each is a reason the bytes are NOT an object naming the parent's cell:
/// such bytes count as nothing anywhere (Part II §8), never as an occupant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseRefusal {
    /// Names another reserve.
    NamesAnotherReserve,
    /// `parent_root` is not `R_n`.
    ParentRootMismatch,
    /// `generation` is not `n + 1`.
    GenerationIsNotSuccessor,
    /// Names a storage set other than the one the reserve commits.
    ForeignSet,
    /// Releases nothing.
    ZeroRelease,
    /// Releases more than remains: the one arm that would mint.
    ExceedsReserve { remaining: u64, amount: u64 },
    /// Releases an amount the release rule of its source does not name. A
    /// faucet claim releases exactly [`ERA_FAUCET_PAYOUT`]: the beta claim
    /// policy fixes it, and a release the policy does not allow cannot exist
    /// (SoFi §51), so it is not an object naming the cell.
    NotTheReleaseRulesAmount { amount: u64, rule: u64 },
}

impl core::fmt::Display for ReleaseRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NamesAnotherReserve => write!(f, "release names another reserve"),
            Self::ParentRootMismatch => write!(f, "release does not succeed this reserve state"),
            Self::GenerationIsNotSuccessor => {
                write!(f, "release generation is not the parent's successor")
            }
            Self::ForeignSet => write!(f, "release names a foreign storage set"),
            Self::ZeroRelease => write!(f, "release of zero"),
            Self::ExceedsReserve { remaining, amount } => write!(
                f,
                "release of {amount} exceeds the {remaining} remaining — no valid reserve \
                 transition mints"
            ),
            Self::NotTheReleaseRulesAmount { amount, rule } => write!(
                f,
                "release of {amount}; its source's release rule releases exactly {rule}"
            ),
        }
    }
}

impl std::error::Error for ReleaseRefusal {}

/// The ONE transition of the reserve. Given the validated parent state and a
/// verified release, the successor state — or why the release is not one.
///
/// `remaining' = remaining − amount` and `generation' = generation + 1`, so
/// conservation and no-mint hold for every state this returns; there is no
/// other constructor of a reserve state past genesis.
pub fn release_constructible(
    parent: &NativeReserveState,
    release: &VerifiedRelease,
) -> Result<NativeReserveState, ReleaseRefusal> {
    let body = &release.body;
    if body.reserve_id != parent.reserve_id {
        return Err(ReleaseRefusal::NamesAnotherReserve);
    }
    if body.parent_root != parent.root() {
        return Err(ReleaseRefusal::ParentRootMismatch);
    }
    if body.generation != parent.generation.wrapping_add(1) || body.generation == 0 {
        return Err(ReleaseRefusal::GenerationIsNotSuccessor);
    }
    if body.storage_set_id != parent.storage_set_id {
        return Err(ReleaseRefusal::ForeignSet);
    }
    if body.amount == 0 {
        return Err(ReleaseRefusal::ZeroRelease);
    }
    if body.amount > parent.remaining_supply {
        return Err(ReleaseRefusal::ExceedsReserve {
            remaining: parent.remaining_supply,
            amount: body.amount,
        });
    }
    // The release rule of the source (SoFi §51 rule 3: units come out only
    // under the conditions the policy commits). Checked here, at the cell's
    // construction predicate, so a release the rule does not allow never
    // holds the cell — not merely later, when a credit would consume it.
    let rule = match &body.source {
        ReleaseSource::FaucetClaimant { .. } => ERA_FAUCET_PAYOUT,
    };
    if body.amount != rule {
        return Err(ReleaseRefusal::NotTheReleaseRulesAmount {
            amount: body.amount,
            rule,
        });
    }
    Ok(NativeReserveState {
        reserve_id: parent.reserve_id,
        policy_commit: parent.policy_commit,
        remaining_supply: parent.remaining_supply - body.amount,
        generation: body.generation,
        storage_set_id: parent.storage_set_id,
    })
}

/// Core's recognition at the parent's successor cell: the bytes rebuild into
/// a release that verifies AND is the parent's successor. Anything else
/// counts as nothing at the cell.
pub fn recognize_release(parent: &NativeReserveState, bytes: &[u8]) -> Option<VerifiedRelease> {
    let release = decode_and_verify_release(bytes).ok()?;
    release_constructible(parent, &release).ok()?;
    Some(release)
}

/// What one read of the parent's successor cell established (Part II §13).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuccessorRead {
    /// The release is final: `remaining' = remaining − amount`.
    Final {
        release: Box<VerifiedRelease>,
        child: NativeReserveState,
    },
    /// The release holds the leader link and its chain is not final yet. No
    /// other release will ever be final here; the state is settled but not
    /// yet final.
    LeaderHeld {
        release: Box<VerifiedRelease>,
        child: NativeReserveState,
    },
    /// The leader answered and holds no release of this state: the head.
    Open,
    /// The evidence in hand does not decide the cell yet: a network status
    /// the caller retries, never an answer. No member stands in.
    Unavailable(Missing),
}

/// The cell where a reserve state's successor is decided, as Core derives
/// it: the key and seed from the state, the route over the set the state
/// commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuccessorCell {
    parent: NativeReserveState,
    cell: RoutedCell,
}

impl SuccessorCell {
    /// `parent`'s successor cell. `members` must re-derive
    /// `parent.storage_set_id`; any other set is refused.
    pub fn of(
        parent: &NativeReserveState,
        members: &crate::ccb::StorageSetMembers,
    ) -> Result<Self, CellError> {
        let cell = RoutedCell::new(
            reserve_cell_namespace(),
            parent.successor_cell(),
            &parent.successor_seed(),
            members,
            &parent.storage_set_id,
        )?;
        Ok(Self {
            parent: *parent,
            cell,
        })
    }

    pub fn parent(&self) -> &NativeReserveState {
        &self.parent
    }

    pub fn routed(&self) -> &RoutedCell {
        &self.cell
    }
}

/// Resolve a successor cell from its route-chain evidence (storage spec §9):
/// the leader's arrival log, each later seat's, and the ByteCommits that make
/// their links checkable.
///
/// Recognition first: only bytes that verify as a release AND succeed this
/// parent count, so unrecognized bytes are never an occupant, never final,
/// however early they arrived. What holds the cell is the release and the
/// child state recognition built.
pub fn resolve_successor(cell: &SuccessorCell, evidence: &CellEvidence) -> SuccessorRead {
    let reading = evaluate(&cell.cell, evidence, release_of(&cell.parent));
    match reading {
        Ok(CellReading::Held {
            object: (release, child),
            state: ChainState::Final,
            ..
        }) => SuccessorRead::Final {
            release: Box::new(release),
            child,
        },
        Ok(CellReading::Held {
            object: (release, child),
            state: ChainState::LeaderHeld | ChainState::Preserved,
            ..
        }) => SuccessorRead::LeaderHeld {
            release: Box::new(release),
            child,
        },
        Ok(CellReading::Open) => SuccessorRead::Open,
        Err(missing) => SuccessorRead::Unavailable(missing),
    }
}

/// A release recognized at a successor cell: its entry digest, the verified
/// release, and the child state it builds.
type RecognizedRelease = ([u8; 32], (VerifiedRelease, NativeReserveState));

/// The recognizer of a successor cell: bytes that verify as a release AND
/// succeed `parent`, with the child state they build. Anything else counts as
/// nothing at the cell.
fn release_of(parent: &NativeReserveState) -> impl Fn(&[u8]) -> Option<RecognizedRelease> + '_ {
    move |bytes| {
        let release = decode_and_verify_release(bytes).ok()?;
        let child = release_constructible(parent, &release).ok()?;
        Some((crate::storage_cell::entry_digest(bytes), (release, child)))
    }
}

/// The completion proof of the release final at a successor cell (storage
/// spec §9), with the release and the child it builds; `None` while no chain
/// of the release holding the cell has three links.
pub fn successor_completion(
    cell: &SuccessorCell,
    evidence: &CellEvidence,
) -> Result<Option<(VerifiedRelease, NativeReserveState, CompletionProof)>, Missing> {
    Ok(
        completion_proof(&cell.cell, evidence, release_of(&cell.parent))?
            .map(|((release, child), proof)| (release, child, proof)),
    )
}

/// Check a kept completion proof of a successor cell against the reads in
/// `evidence`: the release it proves final, and the child it builds.
pub fn check_successor_completion(
    cell: &SuccessorCell,
    evidence: &CellEvidence,
    proof: &CompletionProof,
) -> Result<(VerifiedRelease, NativeReserveState), ProofRefusal> {
    check_completion_proof(&cell.cell, evidence, proof, release_of(&cell.parent))
}

/// Where a walk of the lineage stopped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalkStop {
    /// `head`'s successor cell is open: `head` is the current state.
    Head(NativeReserveState),
    /// The successor of `settled` is leader-held but not final: the next
    /// state is decided (`child`) but a release at it cannot yet be final.
    LeaderHeld {
        settled: NativeReserveState,
        release: Box<VerifiedRelease>,
        child: NativeReserveState,
    },
    /// The evidence for the successor cell of `last` does not decide it yet.
    Unavailable {
        last: NativeReserveState,
        missing: Missing,
    },
    /// The budget ran out at `last`. Never a verdict about the lineage.
    BudgetExhausted(NativeReserveState),
}

/// Walk the lineage from a validated `start` — `R_0`, or a state an earlier
/// walk established as final — reading one successor cell per step through
/// `read`, which takes the parent and returns what its cell established.
/// Every final release advances the state; `visit` sees each one, in order,
/// with the parent it succeeded, so a caller can memoise validated states.
/// An error from either stops the walk and is returned as it is: a reader
/// that could not read reports that, never a reading.
///
/// Finality is permanent (Part II §8), so a state reached through final
/// releases is a sound start for any later walk.
pub fn walk_lineage<R, V, E>(
    start: NativeReserveState,
    budget: usize,
    mut read: R,
    mut visit: V,
) -> Result<WalkStop, E>
where
    R: FnMut(&NativeReserveState) -> Result<SuccessorRead, E>,
    V: FnMut(&NativeReserveState, &VerifiedRelease, &NativeReserveState) -> Result<(), E>,
{
    let mut state = start;
    let mut remaining = budget;
    while remaining > 0 {
        remaining -= 1;
        match read(&state)? {
            SuccessorRead::Final { release, child } => {
                visit(&state, &release, &child)?;
                state = child;
            }
            SuccessorRead::LeaderHeld { release, child } => {
                return Ok(WalkStop::LeaderHeld {
                    settled: state,
                    release,
                    child,
                })
            }
            SuccessorRead::Open => return Ok(WalkStop::Head(state)),
            SuccessorRead::Unavailable(missing) => {
                return Ok(WalkStop::Unavailable {
                    last: state,
                    missing,
                })
            }
        }
    }
    Ok(WalkStop::BudgetExhausted(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route_chain::fixtures::{committed_set, committed_set_id, Cell};
    use crate::route_chain::ROUTE_LEN;

    const NETWORK: &[u8] = b"dsm-testnet";
    const G: D32 = [0x11; 32];
    const DEV: D32 = [0x22; 32];

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        crate::crypto::sphincs::generate_sphincs_keypair().expect("keypair")
    }

    fn genesis() -> NativeReserveState {
        NativeReserveState::genesis(NETWORK, committed_set_id())
    }

    fn body(parent: &NativeReserveState, amount: u64, pk: &[u8]) -> NativeReserveReleaseBody {
        NativeReserveReleaseBody {
            reserve_id: parent.reserve_id,
            parent_root: parent.root(),
            generation: parent.generation + 1,
            amount,
            recipient_genesis: G,
            recipient_devid: DEV,
            recipient_economic_position: 1,
            recipient_operation_digest: [0x33; 32],
            storage_set_id: committed_set_id(),
            source: ReleaseSource::FaucetClaimant {
                claimant_public_key: pk.to_vec(),
            },
        }
    }

    /// A release of `parent`, signed by a fresh claimant key, and that key.
    fn signed_with_key(parent: &NativeReserveState, amount: u64) -> (VerifiedRelease, Vec<u8>) {
        let (pk, sk) = keypair();
        let bytes = sign_release(&body(parent, amount, &pk), &sk).expect("signable");
        (decode_and_verify_release(&bytes).expect("verifies"), pk)
    }

    fn signed(parent: &NativeReserveState, amount: u64) -> VerifiedRelease {
        signed_with_key(parent, amount).0
    }

    /// `parent`'s successor cell over the fixture's committed set, and its
    /// seats.
    fn successor_cell(parent: &NativeReserveState) -> (SuccessorCell, Cell) {
        let cell = SuccessorCell::of(parent, &committed_set()).expect("the committed set");
        let seats = Cell::at(cell.routed());
        (cell, seats)
    }

    /// A successor cell is routed only over the set its parent commits.
    #[test]
    fn a_successor_cell_is_routed_over_the_set_its_parent_commits() {
        let r0 = genesis();
        let (cell, seats) = successor_cell(&r0);
        assert_eq!(cell.routed().key(), &r0.successor_cell());
        assert_eq!(cell.routed().namespace(), reserve_cell_namespace());
        assert_eq!(
            seats.route,
            crate::route_chain::Route::of(&r0.successor_seed(), &committed_set()).unwrap()
        );
        let other = NativeReserveState::genesis(NETWORK, [0x77; 32]);
        assert!(matches!(
            SuccessorCell::of(&other, &committed_set()),
            Err(CellError::NotTheCommittedSet { .. })
        ));
    }

    // ── Identity ─────────────────────────────────────────────────────────

    #[test]
    fn the_reserve_id_is_network_scoped_and_deterministic() {
        assert_eq!(era_reserve_id(NETWORK), era_reserve_id(NETWORK));
        assert_ne!(
            era_reserve_id(NETWORK),
            era_reserve_id(b"othernet"),
            "a different network is a DIFFERENT reserve — an asset-only id would release \
             one genesis supply once per network"
        );
    }

    #[test]
    fn the_genesis_state_holds_the_whole_supply_at_generation_zero() {
        let r0 = genesis();
        assert_eq!(r0.remaining_supply, ERA_RESERVE_GENESIS_SUPPLY);
        assert_eq!(r0.generation, 0);
        assert_eq!(
            r0.policy_commit,
            crate::core::token::token_state_manager::era_policy_commit()
        );
        assert_eq!(r0.root(), genesis().root(), "R_0 is recomputable by anyone");
    }

    // ── The envelope ─────────────────────────────────────────────────────

    #[test]
    fn the_envelope_round_trips_and_is_strict() {
        let release = signed(&genesis(), 100);
        let bytes = release.envelope_bytes.clone();
        // Decodable-but-non-canonical: unknown field, silently skipped by
        // prost, caught only by the re-encode comparison.
        let mut padded = bytes.clone();
        padded.extend_from_slice(&[0x18, 0x01]);
        assert!(matches!(
            decode_and_verify_release(&padded),
            Err(ReleaseError::Malformed("envelope is not canonical"))
        ));
        let mut tampered = bytes;
        let last = tampered.len() - 1;
        tampered[last] ^= 0xFF;
        assert!(decode_and_verify_release(&tampered).is_err());
    }

    // ── The one transition ───────────────────────────────────────────────

    /// `reserve_after = reserve_before − release`, and `release ≤ reserve_before`.
    #[test]
    fn a_release_conserves_the_reserve() {
        let r0 = genesis();
        let release = signed(&r0, ERA_FAUCET_PAYOUT);
        let r1 = release_constructible(&r0, &release).expect("constructible");
        assert_eq!(
            r1.remaining_supply + release.body.amount,
            r0.remaining_supply
        );
        assert_eq!(r1.generation, 1);
        assert_eq!(r1.reserve_id, r0.reserve_id);
        assert_ne!(r1.root(), r0.root());
    }

    /// `no valid reserve transition can mint ERA`: a release of more than
    /// remains is not a transition. The R4 mutation control for the reserve:
    /// drop the `amount > remaining` refusal and this goes red.
    #[test]
    fn no_valid_reserve_transition_can_mint_era() {
        let mut low = genesis();
        low.remaining_supply = ERA_FAUCET_PAYOUT - 1;
        let release = signed(&low, ERA_FAUCET_PAYOUT);
        assert_eq!(
            release_constructible(&low, &release),
            Err(ReleaseRefusal::ExceedsReserve {
                remaining: ERA_FAUCET_PAYOUT - 1,
                amount: ERA_FAUCET_PAYOUT
            })
        );
        assert!(
            recognize_release(&low, &release.envelope_bytes).is_none(),
            "an overdraft is not an object naming the cell: it can never occupy it"
        );
        // Exactly what remains is the last legal release; the reserve is then
        // exhausted, and nothing replenishes it.
        low.remaining_supply = ERA_FAUCET_PAYOUT;
        let last = signed(&low, ERA_FAUCET_PAYOUT);
        let exhausted = release_constructible(&low, &last).expect("the last payout");
        assert_eq!(exhausted.remaining_supply, 0);
        let more = signed(&exhausted, ERA_FAUCET_PAYOUT);
        assert!(release_constructible(&exhausted, &more).is_err());
    }

    /// SoFi §51 rule 3 and the shortcut audit of 2026-09-25: a faucet release
    /// is constructible only for the amount the claim policy fixes. A release
    /// of the whole remaining supply under any key — the one write that
    /// would otherwise leave nothing for anyone — is not an object naming the
    /// cell: first at the leader and final along its route, it holds nothing,
    /// and the payout release behind it is final. Mutation: drop the release
    /// rule's amount check and the drain holds the cell.
    #[test]
    fn a_release_of_any_amount_but_the_payout_never_holds_the_cell() {
        let r0 = genesis();
        for amount in [
            1,
            ERA_FAUCET_PAYOUT - 1,
            ERA_FAUCET_PAYOUT + 1,
            r0.remaining_supply,
        ] {
            let off_rule = signed(&r0, amount);
            assert_eq!(
                release_constructible(&r0, &off_rule),
                Err(ReleaseRefusal::NotTheReleaseRulesAmount {
                    amount,
                    rule: ERA_FAUCET_PAYOUT
                })
            );
            assert!(recognize_release(&r0, &off_rule.envelope_bytes).is_none());
        }
        let drain = signed(&r0, r0.remaining_supply);
        let payout = signed(&r0, ERA_FAUCET_PAYOUT);
        let (at, mut cell) = successor_cell(&r0);
        cell.write(&drain.envelope_bytes, ROUTE_LEN - 1, &[]);
        cell.write(&payout.envelope_bytes, ROUTE_LEN - 1, &[]);
        let child = release_constructible(&r0, &payout).unwrap();
        assert_eq!(
            child.remaining_supply,
            r0.remaining_supply - ERA_FAUCET_PAYOUT
        );
        assert_eq!(
            resolve_successor(&at, &cell.evidence()),
            SuccessorRead::Final {
                release: Box::new(payout),
                child
            }
        );
    }

    /// `total ERA conserved`: along any lineage,
    /// `S_genesis = remaining + Σ released`.
    #[test]
    fn total_era_is_conserved_along_the_lineage() {
        let mut state = genesis();
        let mut released = 0u64;
        for amount in [ERA_FAUCET_PAYOUT; 4] {
            let release = signed(&state, amount);
            state = release_constructible(&state, &release).expect("constructible");
            released += amount;
            assert_eq!(
                state.remaining_supply + released,
                ERA_RESERVE_GENESIS_SUPPLY
            );
        }
        assert_eq!(state.generation, 4);
    }

    /// `no creator backout`: the transition set is `Release` and nothing
    /// else — a state is only ever reached by subtracting what a recipient
    /// received. There is no arm that moves value to a creator, and a
    /// release that names no positive amount is refused.
    #[test]
    fn no_creator_backout_the_only_transition_is_a_release_to_its_recipient() {
        let r0 = genesis();
        let zero = signed(&r0, 0);
        assert_eq!(
            release_constructible(&r0, &zero),
            Err(ReleaseRefusal::ZeroRelease)
        );
        let (release, pk) = signed_with_key(&r0, 100);
        let r1 = release_constructible(&r0, &release).expect("constructible");
        // Every unit that left the reserve is accounted to the recipient the
        // body names, and that recipient is the signer.
        assert_eq!(
            r0.remaining_supply - r1.remaining_supply,
            release.body.amount
        );
        assert_eq!(release.body.recipient_genesis, G);
        assert_eq!(release.body.signer(), pk.as_slice());
    }

    #[test]
    fn a_release_must_succeed_exactly_its_parent() {
        let r0 = genesis();
        let (pk, sk) = keypair();
        let mut wrong_root = body(&r0, 100, &pk);
        wrong_root.parent_root = [0xEE; 32];
        let wrong_root =
            decode_and_verify_release(&sign_release(&wrong_root, &sk).unwrap()).unwrap();
        assert_eq!(
            release_constructible(&r0, &wrong_root),
            Err(ReleaseRefusal::ParentRootMismatch)
        );
        let mut wrong_gen = body(&r0, 100, &pk);
        wrong_gen.generation = 2;
        let wrong_gen = decode_and_verify_release(&sign_release(&wrong_gen, &sk).unwrap()).unwrap();
        assert_eq!(
            release_constructible(&r0, &wrong_gen),
            Err(ReleaseRefusal::GenerationIsNotSuccessor)
        );
        let mut other = body(&r0, 100, &pk);
        other.reserve_id = era_reserve_id(b"othernet");
        let other = decode_and_verify_release(&sign_release(&other, &sk).unwrap()).unwrap();
        assert_eq!(
            release_constructible(&r0, &other),
            Err(ReleaseRefusal::NamesAnotherReserve)
        );
        let mut foreign = body(&r0, 100, &pk);
        foreign.storage_set_id = [0x77; 32];
        let foreign = decode_and_verify_release(&sign_release(&foreign, &sk).unwrap()).unwrap();
        assert_eq!(
            release_constructible(&r0, &foreign),
            Err(ReleaseRefusal::ForeignSet)
        );
    }

    // ── The cell, leader first ───────────────────────────────────────────

    /// Finality without the leader is impossible: a release at every later
    /// seat with nothing at the leader leaves the cell open, and an unread
    /// leader leaves it undecided. The leader's first recognized release with
    /// two further valid links is final.
    #[test]
    fn finality_without_the_deterministic_leader_is_impossible() {
        let r0 = genesis();
        let release = signed(&r0, 100);
        let x = release.envelope_bytes.clone();
        let (at, mut skipped_leader) = successor_cell(&r0);
        skipped_leader.write(&x, ROUTE_LEN - 1, &[0]);
        assert_eq!(
            resolve_successor(&at, &skipped_leader.evidence()),
            SuccessorRead::Open,
            "four seats hold the release and the leader holds nothing"
        );
        let (at, mut cell) = successor_cell(&r0);
        cell.write(&x, ROUTE_LEN - 1, &[]);
        let child = release_constructible(&r0, &release).unwrap();
        assert_eq!(
            resolve_successor(&at, &cell.evidence()),
            SuccessorRead::Final {
                release: Box::new(release),
                child
            }
        );
        let mut unread_leader = cell.evidence();
        unread_leader.seats[0].values = None;
        assert_eq!(
            resolve_successor(&at, &unread_leader),
            SuccessorRead::Unavailable(Missing::LeaderUnread),
            "no member stands in for the leader"
        );
    }

    /// Unrecognized bytes — garbage, or a release that does not fit its
    /// parent — never occupy the cell, however early they arrived.
    #[test]
    fn unrecognized_bytes_never_occupy_the_cell() {
        let r0 = genesis();
        let release = signed(&r0, 100);
        // Signed, canonical, succeeding R_0 — and releasing more than exists.
        let too_much = signed(&r0, ERA_RESERVE_GENESIS_SUPPLY + 1);
        let (at, mut cell) = successor_cell(&r0);
        cell.write(b"not a release", 0, &[]);
        cell.write(&too_much.envelope_bytes, 0, &[]);
        cell.write(&release.envelope_bytes, ROUTE_LEN - 1, &[]);
        let child = release_constructible(&r0, &release).unwrap();
        assert_eq!(
            resolve_successor(&at, &cell.evidence()),
            SuccessorRead::Final {
                release: Box::new(release),
                child
            },
            "the first RECOGNIZED object at the leader holds the cell, not the first bytes"
        );
    }

    /// Copies never change which release holds the cell: the leader's first
    /// recognized release does, and only its own chain can make it final.
    #[test]
    fn additional_replicas_do_not_alter_the_winner() {
        let r0 = genesis();
        let a = signed(&r0, 100);
        let b = signed(&r0, 100);
        let child_a = release_constructible(&r0, &a).unwrap();
        let (at, mut cell) = successor_cell(&r0);
        cell.write(&a.envelope_bytes, 0, &[]);
        cell.write(&b.envelope_bytes, ROUTE_LEN - 1, &[]);
        assert_eq!(
            resolve_successor(&at, &cell.evidence()),
            SuccessorRead::LeaderHeld {
                release: Box::new(a.clone()),
                child: child_a
            },
            "B at every seat does not make B the winner"
        );
        cell.continue_chain(&a.envelope_bytes, 1, 2);
        assert_eq!(
            resolve_successor(&at, &cell.evidence()),
            SuccessorRead::Final {
                release: Box::new(a),
                child: child_a
            },
            "A's own chain, continued after B's copies, makes A final"
        );
    }

    /// A final release has a completion proof, and the proof checks against
    /// the same seats; a release that is only leader-held has none.
    #[test]
    fn a_final_release_has_a_completion_proof_that_checks() {
        let r0 = genesis();
        let release = signed(&r0, 100);
        let (at, mut cell) = successor_cell(&r0);
        cell.write(&release.envelope_bytes, 1, &[]);
        assert_eq!(successor_completion(&at, &cell.evidence()), Ok(None));
        let (at, mut cell) = successor_cell(&r0);
        cell.write(&release.envelope_bytes, ROUTE_LEN - 1, &[]);
        let child = release_constructible(&r0, &release).unwrap();
        let Ok(Some((proven, proven_child, proof))) = successor_completion(&at, &cell.evidence())
        else {
            panic!("a final release has a completion proof")
        };
        assert_eq!((&proven, proven_child), (&release, child));
        assert_eq!(
            check_successor_completion(&at, &cell.evidence(), &proof),
            Ok((release, child))
        );
    }

    // ── The walk ─────────────────────────────────────────────────────────

    #[test]
    fn the_walk_advances_through_final_releases_and_stops_at_the_head() {
        let r0 = genesis();
        let rel1 = signed(&r0, 100);
        let r1 = release_constructible(&r0, &rel1).unwrap();
        let rel2 = signed(&r1, ERA_FAUCET_PAYOUT);
        let r2 = release_constructible(&r1, &rel2).unwrap();
        let mut visited = Vec::new();
        let stop = walk_lineage(
            r0,
            16,
            |parent| -> Result<SuccessorRead, core::convert::Infallible> {
                Ok(if parent.root() == r0.root() {
                    SuccessorRead::Final {
                        release: Box::new(rel1.clone()),
                        child: r1,
                    }
                } else if parent.root() == r1.root() {
                    SuccessorRead::Final {
                        release: Box::new(rel2.clone()),
                        child: r2,
                    }
                } else {
                    SuccessorRead::Open
                })
            },
            |parent, release, child| {
                visited.push((parent.generation, release.body.generation, child.generation));
                Ok(())
            },
        );
        assert_eq!(stop, Ok(WalkStop::Head(r2)));
        assert_eq!(visited, vec![(0, 1, 1), (1, 2, 2)]);
        assert_eq!(
            r2.remaining_supply,
            ERA_RESERVE_GENESIS_SUPPLY - 2 * ERA_FAUCET_PAYOUT
        );
    }

    #[test]
    fn the_walk_never_turns_unavailable_or_budget_into_a_head() {
        let r0 = genesis();
        let mut visited = 0;
        assert_eq!(
            walk_lineage(
                r0,
                16,
                |parent| -> Result<SuccessorRead, core::convert::Infallible> {
                    assert_eq!(parent.generation, 0, "the walk reads R_0's cell first");
                    Ok(SuccessorRead::Unavailable(Missing::LeaderUnread))
                },
                |parent, release, child| {
                    visited += 1;
                    assert_eq!(parent.generation + 1, release.body.generation);
                    assert_eq!(release.body.generation, child.generation);
                    Ok(())
                },
            ),
            Ok(WalkStop::Unavailable {
                last: r0,
                missing: Missing::LeaderUnread
            })
        );
        assert_eq!(visited, 0, "nothing final was read");
        let rel1 = signed(&r0, 100);
        let r1 = release_constructible(&r0, &rel1).unwrap();
        let stop = walk_lineage(
            r0,
            1,
            |parent| -> Result<SuccessorRead, core::convert::Infallible> {
                Ok(if parent.root() == r0.root() {
                    SuccessorRead::Final {
                        release: Box::new(rel1.clone()),
                        child: r1,
                    }
                } else {
                    SuccessorRead::Open
                })
            },
            |parent, release, child| {
                assert_eq!(parent.generation + 1, release.body.generation);
                assert_eq!(release.body.generation, child.generation);
                Ok(())
            },
        );
        assert_eq!(stop, Ok(WalkStop::BudgetExhausted(r1)));

        // A reader that could not read stops the walk with its error.
        assert_eq!(
            walk_lineage(
                r0,
                16,
                |parent| Err(parent.generation),
                |parent, release, child| {
                    assert_eq!(parent.generation + 1, release.body.generation);
                    assert_eq!(release.body.generation, child.generation);
                    Ok(())
                },
            ),
            Err(0)
        );
    }
}
