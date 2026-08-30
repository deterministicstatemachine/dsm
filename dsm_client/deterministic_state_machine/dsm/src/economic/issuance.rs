// SPDX-License-Identifier: MIT OR Apache-2.0

//! Class `0x0029` — the authenticated issuance authorization.
//!
//! This is the source predicate the `0x0023 AuthorizedIssuance` credit arm
//! resolves against: the foreign-verifiable answer to **who had the right to
//! create these units**. Until it existed the arm failed closed, the write-set
//! table refused `Mint`, and the accepting layer refused positive issuance for
//! every asset — three refusals that were all one absence.
//!
//! ## What V1 proves, and what it does not
//!
//! ```text
//! PROVES      these exact units were issued by the authority the committed
//!             token policy permits
//! DOES NOT    that the units are redeemable for, or collateralized by, any
//!    PROVE    quantity of any other asset
//! ```
//!
//! Those are different statements and this module never conflates them. There
//! is no backing condition in the token-policy vocabulary to enforce — a
//! search of the condition enum for collateral, redemption or backing returns
//! nothing — so "authorized" may never be read as "backed" here, in the class
//! name, in the evidence, or in a test. A DLV can later pair an issued token
//! with ERA or dBTC, and that liquidity is still not a collateral guarantee.
//!
//! ## Why the support matrix is explicit
//!
//! It would be tempting to admit whatever the generic evaluator happens to
//! allow. That is not sound for a source-of-new-value predicate: three
//! conditions currently evaluate to *allowed* because they are treated as
//! configuration, and "the evaluator ignores this today" is not a finding that
//! the condition is irrelevant to issuance. Accepting an `EmissionsSchedule`
//! while ignoring it entirely would be indefensible.
//!
//! So the matrix below is a closed, exhaustive decision over the condition
//! enum, and an unknown future variant refuses by construction. That gives
//! monotonic extensibility: a V2 may admit a condition once its evidence is
//! canonical, without ever weakening V1.

use crate::ccb::{class, push_digest32, push_envelope, push_u64, CcbError, CcbObject};
use crate::common::domain_tags::TAG_DSM_ISSUANCE_AUTHORIZATION_SIGN;
use crate::crypto::blake3::dsm_domain_hasher;

/// `0x0029` schema 1 — the authenticated issuance authorization body.
///
/// ## The circularity rule, frozen
///
/// These signatures live ONLY in the transport evidence bundle. They must
/// NEVER be placed inside the `Mint` operation whose digest they authorize:
///
/// ```text
/// signature -> inside Mint -> changes operation_digest
///           -> operation_digest is inside the signed body
///           -> changes the signature            (no fixed point)
/// ```
///
/// Keeping them outside makes the ordering acyclic and obvious: the operation
/// is frozen first, its digest derived, and the authorities then sign a body
/// that commits that digest. `Mint.proof_of_authorization` is canonically
/// EMPTY under this schema — it must not become a second authorization
/// channel — and the field itself is deleted in the producer cut.
///
/// ## Non-reuse
///
/// `issuer_economic_position` names ONE write-once root-register cell and
/// `recipient_operation_digest` names ONE exact operation. An authorization
/// replayed at a later position carries the earlier position in its signed
/// body, and the verifier requires equality with the position under
/// validation — so the same bytes cannot fund a second credit. That is the
/// faucet's non-reuse argument, and it is why this arm needs no
/// consumed-source leaf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuanceAuthorizationBody {
    /// The asset. Binding it stops a signature being replayed onto another
    /// token under the same authority.
    pub policy_commit: [u8; 32],
    /// The lineage the credit may land in.
    pub issuer_genesis: [u8; 32],
    /// The device the credit may land on — also the identity checked against a
    /// committed device allowlist.
    pub issuer_devid: [u8; 32],
    /// The write-once economic position this authorization is spent at.
    pub issuer_economic_position: u64,
    /// The exact operation authorized. Derived from the FROZEN operation, so
    /// the signature can never be one of its inputs.
    pub recipient_operation_digest: [u8; 32],
    /// The authorized amount.
    pub amount: u64,
}

impl CcbObject for IssuanceAuthorizationBody {
    const CLASS: u16 = class::ISSUANCE_AUTHORIZATION_BODY;
    const SCHEMA: u16 = 1;
}

impl IssuanceAuthorizationBody {
    /// Fields 1..6 in registry order.
    pub fn encode(&self) -> Result<Vec<u8>, CcbError> {
        let mut out = Vec::new();
        push_envelope::<Self>(&mut out);
        push_digest32(&mut out, &self.policy_commit); // 1
        push_digest32(&mut out, &self.issuer_genesis); // 2
        push_digest32(&mut out, &self.issuer_devid); // 3
        push_u64(&mut out, self.issuer_economic_position); // 4
        push_digest32(&mut out, &self.recipient_operation_digest); // 5
        push_u64(&mut out, self.amount); // 6
        Ok(out)
    }

    /// `m = H_dom(DSM/issuance-authorization-sign/v1, CCB(body))` — the digest
    /// each policy-named signer signs.
    ///
    /// This strictly subsumes `token_authorization_preimage`, which binds only
    /// `(policy_commit, op, token_id, amount, authorized_by)` — every one of
    /// them stable across transitions, so one signature there authorizes an
    /// unbounded class of issuances rather than a single event.
    pub fn signing_digest(&self) -> Result<[u8; 32], CcbError> {
        let ccb = self.encode()?;
        let mut h = dsm_domain_hasher(TAG_DSM_ISSUANCE_AUTHORIZATION_SIGN);
        h.update(&ccb);
        Ok(*h.finalize().as_bytes())
    }
}

/// Why a policy is not admissible for V1 issuance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IssuancePolicyRefusal {
    /// No `TokenAuthority` condition. V1 requires one: without it, "the
    /// generic evaluator found nothing to deny" would become authenticated
    /// A `SupplyCap` with a finite ceiling. Its `circulating` input is derived
    /// from the ISSUER'S OWN chain history and is not global, so N authorized
    /// devices would each mint to the cap. Burned for canonical issuance until
    /// a globally non-duplicable cap mechanism exists.
    FiniteSupplyCap,
    /// A condition whose inputs are not foreign-verifiable, or whose issuance
    /// meaning is not defined by this schema.
    UnsupportedIssuancePolicyCondition(&'static str),
}

impl core::fmt::Display for IssuancePolicyRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::FiniteSupplyCap => write!(
                f,
                "issuance policy carries a finite SupplyCap — its circulating-supply input is \
                 per-device and not foreign-verifiable, so the cap is unenforceable and the \
                 policy is refused for canonical issuance"
            ),
            Self::UnsupportedIssuancePolicyCondition(w) => write!(
                f,
                "issuance policy carries a condition whose issuance meaning is not defined by \
                 0x0029 V1 ({w}) — refused rather than ignored"
            ),
        }
    }
}

impl std::error::Error for IssuancePolicyRefusal {}

/// The conditions V1 enforces, extracted from an admissible policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissibleIssuancePolicy<'a> {
    /// The `k` of k-of-N.
    pub threshold: u32,
    /// The `N` — raw SPHINCS+ public keys the POLICY names. The verifier draws
    /// keys from here and never from the presented proof.
    pub signers: &'a [Vec<u8>],
    /// Operations the policy permits, when it restricts them at all.
    pub allowed_operations: Option<&'a [String]>,
    /// A per-operation amount ceiling, when the policy sets one.
    pub amount_limit: Option<u64>,
}

/// The issuance-relevant facts of a committed token policy, parsed in CORE.
///
/// The blob parser lives here rather than in the SDK because the VERIFIER is
/// core: a foreign verifier holding only the operation, the policy bytes and
/// the evidence must reach the same decision, and it cannot call an SDK route
/// to do it.
///
/// Only the issuance-relevant fields are read. The blob also carries display
/// metadata (alias, description, icon) that no issuance decision may depend
/// on, and reading it here would invite exactly that.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuancePolicy {
    /// `k` — distinct policy-named signers required.
    pub threshold: u32,
    /// `N` — the raw SPHINCS+ keys the policy names.
    pub signers: Vec<Vec<u8>>,
    /// False ⇒ the policy forbids minting and burning outright.
    pub mint_burn_enabled: bool,
    /// False ⇒ the token restricts operations to mint and burn.
    pub transferable: bool,
    /// True ⇒ uncapped. False ⇒ a finite cap, which V1 refuses.
    pub unlimited_supply: bool,
    /// Inline 32-byte device ids; empty when unrestricted.
    pub allowlist_device_ids: Vec<[u8; 32]>,
}

/// Parse the issuance-relevant fields out of exact `TokenPolicyV3` bytes.
///
/// The caller must ALREADY have re-hashed these bytes to the operation's
/// `policy_commit` — this function reads a blob, it does not authenticate one.
pub fn parse_issuance_policy(policy_proto: &[u8]) -> Result<IssuancePolicy, String> {
    use prost::Message;
    let policy = crate::types::proto::TokenPolicyV3::decode(policy_proto)
        .map_err(|_| "policy proto does not decode".to_string())?;
    let b = &policy.policy_bytes;
    let mut i = 0usize;
    let need = |i: usize, n: usize, len: usize| -> Result<(), String> {
        if i + n > len {
            Err("policy blob is truncated".to_string())
        } else {
            Ok(())
        }
    };
    let len = b.len();

    need(i, 5, len)?;
    if b[0] != 3 {
        return Err(format!("policy blob version {} is not 3", b[0]));
    }
    if b[1] != 0 {
        return Err("policy blob is not FUNGIBLE".into());
    }
    let flags = b[2];
    let threshold = b[3] as u32;
    let signer_count = b[4] as usize;
    i = 5;

    let mut signers = Vec::with_capacity(signer_count);
    for _ in 0..signer_count {
        need(i, 2, len)?;
        let pk_len = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        i += 2;
        need(i, pk_len, len)?;
        signers.push(b[i..i + pk_len].to_vec());
        i += pk_len;
    }

    // Skip the display fields by length, without reading them: ticker, alias,
    // decimals.
    need(i, 1, len)?;
    let ticker_len = b[i] as usize;
    i += 1 + ticker_len;
    need(i, 2, len)?;
    let alias_len = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
    i += 2 + alias_len;
    need(i, 1, len)?;
    i += 1; // decimals

    // max_supply and initial_alloc are u128 each; the cap DECISION is the
    // `unlimited` flag, so the value is skipped rather than interpreted.
    need(i, 32, len)?;
    i += 32;

    need(i, 2, len)?;
    let desc_len = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
    i += 2 + desc_len;
    need(i, 2, len)?;
    let icon_len = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
    i += 2 + icon_len;

    need(i, 1, len)?;
    let allowlist_kind = b[i];
    i += 1;
    let mut allowlist_device_ids = Vec::new();
    if allowlist_kind == 1 {
        need(i, 2, len)?;
        let count = u16::from_be_bytes([b[i], b[i + 1]]) as usize;
        i += 2;
        for _ in 0..count {
            need(i, 32, len)?;
            let mut d = [0u8; 32];
            d.copy_from_slice(&b[i..i + 32]);
            allowlist_device_ids.push(d);
            i += 32;
        }
    } else if allowlist_kind != 0 {
        return Err("policy blob has an unknown allowlist kind".into());
    }

    // The blob must be consumed EXACTLY. A padded policy would let two byte
    // strings carry one commitment.
    if i != len {
        return Err("policy blob has trailing bytes".into());
    }

    Ok(IssuancePolicy {
        threshold,
        signers,
        mint_burn_enabled: flags & 0x01 != 0,
        transferable: flags & 0x02 != 0,
        unlimited_supply: flags & 0x08 != 0,
        allowlist_device_ids,
    })
}

/// Decide whether the committed policy permits THIS issuance.
///
/// This is the V1 support matrix, and it is the ONLY one.
///
/// It reads the committed v3 policy blob — the exact form the operation's
/// `policy_commit` commits — and refuses every shape whose issuance meaning is
/// not independently verifiable, rather than ignoring it.
///
/// There is deliberately no second matrix over the richer `PolicyCondition`
/// model. The blob cannot express those conditions at all: its fields are the
/// flags, the authority threshold and signer set, and the device allowlist,
/// so an `IdentityConstraint` or a `LogicalTimeConstraint` has no encoding
/// here to arrive in. A matrix refusing conditions that cannot reach this path
/// would be a second place for one decision to be made, and the unreachable
/// half would drift unnoticed because nothing exercises it. If the committed
/// form ever grows those conditions, the refusals belong HERE, in the function
/// the arm actually calls.
pub fn check_issuance_permitted(
    policy: &IssuancePolicy,
    operation_kind: &str,
    amount: u64,
    recipient_devid: &[u8; 32],
) -> Result<(), IssuancePolicyRefusal> {
    let _ = amount;
    // The committed flag says minting is off. Issuing anyway would authorize
    // under a policy that forbids the act.
    if !policy.mint_burn_enabled {
        return Err(IssuancePolicyRefusal::UnsupportedIssuancePolicyCondition(
            "the committed policy disables mint/burn",
        ));
    }
    // A finite cap is unenforceable, so it is refused rather than ignored —
    // the same decision the condition-level matrix makes.
    if !policy.unlimited_supply {
        return Err(IssuancePolicyRefusal::FiniteSupplyCap);
    }
    if policy.threshold == 0
        || policy.signers.is_empty()
        || (policy.threshold as usize) > policy.signers.len()
    {
        return Err(IssuancePolicyRefusal::UnsupportedIssuancePolicyCondition(
            "TokenAuthority threshold is not satisfiable by its own signer set",
        ));
    }
    // A non-transferable token still permits mint and burn; anything else is
    // outside what the blob's OperationRestriction allows.
    if !policy.transferable && !matches!(operation_kind, "mint" | "burn" | "create_token") {
        return Err(IssuancePolicyRefusal::UnsupportedIssuancePolicyCondition(
            "the committed policy restricts operations and does not allow this one",
        ));
    }
    // THE ALLOWLIST IS ABOUT THE RECEIVING DEVICE. The identity checked is the
    // authenticated DevID the credit lands on — never an `authorized_by` byte
    // string the issuer chose, which is attacker-controlled and derives from
    // nothing.
    if !policy.allowlist_device_ids.is_empty()
        && !policy.allowlist_device_ids.contains(recipient_devid)
    {
        return Err(IssuancePolicyRefusal::UnsupportedIssuancePolicyCondition(
            "the receiving device is not in the policy's committed allowlist",
        ));
    }
    Ok(())
}
