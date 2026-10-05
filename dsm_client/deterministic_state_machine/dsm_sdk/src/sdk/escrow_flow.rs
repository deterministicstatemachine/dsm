// SPDX-License-Identifier: MIT OR Apache-2.0

//! Escrow vaults (SoFi §19.9, Amendment S21): one entry per escrow route,
//! over the vault machinery of `sofi_flow` and the producers in `sofi_sdk`.
//!
//! An escrow vault holds one token's stake and releases it whole, once, to the
//! recipient of the branch whose outcome the canonical verdict on its external
//! commitment names. The verdict lives in its own cell, `K_verdict`, which
//! every vault linked to it shares: the first verdict at the cell's leader that
//! proves its own authority is the only one any of them settles against.
//!
//! Producers assemble and publish; Core decides. A route here never takes a
//! storage read, a counterpart's word or an application's word as a verdict.

use dsm::common::domain_tags::TAG_DSM_ESCROW_STATEMENT_LOCATOR;
use dsm::economic::write_set::CreditSourceFacts;
use dsm::route_chain::{CellFact, ChainState};
use dsm::sofi::escrow::{self, VerdictCell, VerdictCellRead, VerdictRefusal};
use dsm::sofi::publication::Publication;
use dsm::sofi::resolve::{AcceptedGeneses, VaultGenesis, Verifier};
use dsm::sofi::storage::Discovered;
use dsm::sofi::validation::{retire_vault_post, VaultTerms};
use dsm::sofi::wire::{
    next_position, EscrowBranch, EscrowSigner, EscrowTerms, EscrowVerdict, VaultGenesisPreimage,
    VaultStateLeaf, VerdictSignature, VAULT_STATUS_ACTIVE,
};
use dsm::types::device_state::{BalanceDelta, BalanceDirection};
use dsm::types::error::DsmError;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::economic_admission_flow::{
    admitted_self_loop_operation, validated_root_or_activate, BuiltOn,
};
use crate::sdk::realized_records::{record_realized, Moved, Realized};
use crate::sdk::route_seats::write_recorded;
use crate::sdk::sofi_flow::{
    chain_past_withheld_pairs, context, exercise_draft, head_of, identity, own_setup_ref, refuse,
    relationship_base, require_stored, set_up_with, sign, standing, storage, trader_core,
    vault_at_head, vault_core, PositionOutcome, Search, SIGNATURE_ALG,
};
use crate::sdk::sofi_publish::{publish, LOCATOR_BUDGET};
use crate::sdk::sofi_reads::{verifier_error, LiveSofiReads, VerifierContext};
use crate::sdk::sofi_sdk::{build_escrow_vault_create, draft_release, ReleaseNames};
use crate::sdk::storage_io::resolve_locator_all;
use crate::sdk::storage_set::{as_ccb_members, StorageSet};

type D32 = [u8; 32];

// ── escrow.party ────────────────────────────────────────────────────────────

/// What a device names itself by in escrow terms: its identity, which a
/// branch pays, and its signing key, which a branch is decided by.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowParty {
    pub genesis: D32,
    pub device_id: D32,
    pub signer: EscrowSigner,
}

/// `escrow.party`: this device as an escrow party.
pub fn party(core: &CoreSDK) -> Result<EscrowParty, DsmError> {
    let (genesis, device_id) = identity(core)?;
    let public_key = crate::sdk::signing_authority::current_public_key()?;
    let signer = EscrowSigner::new(SIGNATURE_ALG, &public_key).map_err(refuse)?;
    Ok(EscrowParty {
        genesis,
        device_id,
        signer,
    })
}

// ── escrow.create ───────────────────────────────────────────────────────────

/// `escrow.create`: a stake locked in a new escrow vault of this device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateEscrowIntent {
    /// `X`: the bytes the parties agreed on. DSM never reads them; the vault
    /// commits `Y = H(DSM/external/v1 ‖ X)`.
    pub external: Vec<u8>,
    /// The held token's policy commit.
    pub token: D32,
    /// The stake, in base units.
    pub amount: u64,
    /// The precommitted branches, strictly ascending by outcome.
    pub branches: Vec<EscrowBranch>,
    /// A vault this one is locked against. The vault is created only once
    /// that one is accepted, Active and bound to the same verdict cell (SoFi
    /// §19.9, "Linked vaults").
    pub counterpart: Option<D32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowCreated {
    pub vault_id: D32,
    pub verdict_cell: D32,
    pub external_commitment: D32,
    /// The owner's economic position whose transition carries the creation.
    pub position: u64,
}

/// The escrow terms `vault_id`'s accepted genesis commits.
fn escrow_terms_of(
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_id: &D32,
) -> Result<EscrowTerms, DsmError> {
    match verifier.vault_genesis(vault_id).map_err(verifier_error)? {
        VaultGenesis::Accepted(accepted) => accepted
            .escrow()
            .cloned()
            .ok_or_else(|| refuse("the vault is not an escrow vault")),
        VaultGenesis::NotPublished => Err(refuse(
            "no genesis the owner's creation carried is published",
        )),
        VaultGenesis::OwnerUnresolved(why) => Err(storage(
            "escrow vault genesis",
            format!("the owner's lineage is unresolved: {why}"),
        )),
        VaultGenesis::Refused(why) => Err(refuse(format!("vault genesis refused: {why}"))),
    }
}

/// The counterpart is linked: accepted, bound to `verdict_cell` (its `Y` and
/// outcome table are this one's), and Active at its walked head.
async fn counterpart_linked(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    counterpart: &D32,
    verdict_cell: &D32,
) -> Result<(), DsmError> {
    let terms = escrow_terms_of(verifier, counterpart)?;
    if escrow::verdict_cell_of(&terms) != *verdict_cell {
        return Err(refuse(
            "the counterpart vault is bound to another verdict cell: its commitment or its \
             outcome table differs",
        ));
    }
    let (vault, ..) = vault_at_head(set, verifier, counterpart).await?;
    if vault.state.status != VAULT_STATUS_ACTIVE {
        return Err(refuse("the counterpart vault is no longer Active"));
    }
    Ok(())
}

/// `escrow.create` (§19.9, Creation): the terms and the genesis are published
/// and read back `Stored` first, so the vault is findable by its id and by
/// its verdict cell the moment it exists; then the creation runs through the
/// Core transition, debiting the stake as one write set.
pub async fn create(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &CreateEscrowIntent,
) -> Result<EscrowCreated, DsmError> {
    if intent.amount == 0 {
        return Err(refuse("an escrow vault holds a non-zero stake"));
    }
    let (genesis, device_id) = identity(core)?;
    let validated = validated_root_or_activate(core)?;
    let create_position = next_position(validated.economic_position()).map_err(refuse)?;
    let external_commitment = escrow::external_commitment(&intent.external);
    let terms = EscrowTerms::new(intent.token, external_commitment, intent.branches.clone())
        .map_err(refuse)?;
    let verdict_cell = escrow::verdict_cell_of(&terms);
    if let Some(counterpart) = intent.counterpart {
        let ctx = VerifierContext::new(set, Some((genesis, device_id)), None)?;
        counterpart_linked(set, &ctx.verifier(), &counterpart, &verdict_cell).await?;
    }

    let published = publish(set, &Publication::EscrowTerms(&terms)).await?;
    require_stored("escrow terms", &published)?;
    let addr = published.addr;
    let preimage = VaultGenesisPreimage {
        owner_genesis: genesis,
        owner_device_id: device_id,
        create_position,
        state: VaultStateLeaf {
            owner_genesis: genesis,
            owner_device_id: device_id,
            create_position,
            market_policy: addr,
            fee_policy: addr,
            release_policy: addr,
            storage_set_id: set.id(),
            generation: 0,
            reserve_a: intent.amount,
            reserve_b: 0,
            status: VAULT_STATUS_ACTIVE,
        },
    };
    let produced = build_escrow_vault_create(&preimage, &terms).map_err(refuse)?;
    let published = publish(
        set,
        &Publication::EscrowVaultGenesis {
            preimage: &preimage,
            terms: &terms,
        },
    )
    .await?;
    require_stored("escrow vault genesis", &published)?;

    let operation = produced
        .operation
        .clone()
        .with_signature(sign(produced.signs.bytes())?);
    let deltas = [BalanceDelta {
        policy_commit: intent.token,
        direction: BalanceDirection::Debit,
        amount: intent.amount,
    }];
    let (outcome, admitted) = admitted_self_loop_operation(
        core,
        operation,
        &deltas,
        CreditSourceFacts::None,
        Vec::new(),
        None,
        Some(BuiltOn::of(&validated)),
    )
    .await?;
    let vault_id = preimage.vault_id();
    record_realized(
        &outcome.new_device_state,
        Realized::EscrowLock,
        &vault_id,
        admitted.economic_position,
        &[vault_id],
        &[Moved {
            policy_commit: intent.token,
            direction: BalanceDirection::Debit,
            amount: intent.amount,
        }],
    );
    Ok(EscrowCreated {
        vault_id,
        verdict_cell,
        external_commitment,
        position: admitted.economic_position,
    })
}

// ── escrow.sign and escrow.adjudicate ───────────────────────────────────────

/// An outcome of the escrow vault `vault_id`'s terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeIntent {
    pub vault_id: D32,
    pub outcome: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutcomeSigned {
    pub verdict_cell: D32,
    /// The address of the gathered verdict holding this device's signature.
    pub gathered: D32,
}

/// This device's signer, once it is one the terms assign to `outcome`.
fn own_signer_of(
    core: &CoreSDK,
    terms: &EscrowTerms,
    outcome: &[u8],
) -> Result<Option<EscrowSigner>, DsmError> {
    let me = party(core)?.signer;
    let decided_by = terms
        .outcome_table()
        .signers_of(outcome)
        .map(<[EscrowSigner]>::to_vec)
        .ok_or_else(|| refuse("the terms have no such outcome"))?;
    Ok(decided_by.contains(&me).then_some(me))
}

/// This device's signature over `m(outcome)` for `verdict_cell`.
fn own_signature(
    signer: &EscrowSigner,
    verdict_cell: &D32,
    outcome: &[u8],
) -> Result<VerdictSignature, DsmError> {
    let secret_key = crate::sdk::signing_authority::current_secret_key()?;
    escrow::sign_statement(signer, &secret_key, verdict_cell, outcome)
}

/// `escrow.sign`: this device's signature deciding `outcome` for the vault's
/// verdict cell, put as a gathered verdict under the cell's statement locator
/// for the other signers of the outcome to find. It decides nothing by
/// itself: only a verdict recognized at the cell does.
pub async fn sign_outcome(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &OutcomeIntent,
) -> Result<OutcomeSigned, DsmError> {
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    let terms = escrow_terms_of(&ctx.verifier(), &intent.vault_id)?;
    let signer = own_signer_of(core, &terms, &intent.outcome)?
        .ok_or_else(|| refuse("this device is not a signer of that outcome"))?;
    let verdict_cell = escrow::verdict_cell_of(&terms);
    let signature = own_signature(&signer, &verdict_cell, &intent.outcome)?;
    let gathered = EscrowVerdict::new(
        *terms.external_commitment(),
        terms.outcome_table(),
        &intent.outcome,
        vec![signature],
    )
    .map_err(refuse)?;
    let published = publish(set, &Publication::EscrowVerdict(&gathered)).await?;
    require_stored("gathered verdict", &published)?;
    Ok(OutcomeSigned {
        verdict_cell,
        gathered: published.addr,
    })
}

/// What a verdict cell holds, as Core read it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictView {
    pub verdict_cell: D32,
    /// The outcome the cell's verdict names, and how far its chain has gone;
    /// `None` while no verdict holds the cell.
    pub held: Option<(Vec<u8>, ChainState)>,
    /// Why each value the leader holds ahead of the deciding one counts as
    /// nothing there.
    pub passed_over: Vec<VerdictRefusal>,
}

impl VerdictView {
    fn of(read: &VerdictCellRead) -> Self {
        let held = match (read.verdict(), read.fact()) {
            (Some(verdict), CellFact::Held { state, .. }) => {
                Some((verdict.outcome().to_vec(), state))
            }
            (None, _) | (Some(..), CellFact::Open) => None,
        };
        Self {
            verdict_cell: *read.key(),
            held,
            passed_over: read.passed_over().to_vec(),
        }
    }
}

/// The read of `verdict_cell`, as Core evaluates it over every seat.
fn read_cell(
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    verdict_cell: &D32,
) -> Result<VerdictCellRead, DsmError> {
    verifier
        .read_verdict_cell(verdict_cell)
        .map_err(verifier_error)?
        .map_err(|missing| storage("verdict cell", format!("not decided yet: {missing:?}")))
}

/// The signatures gathered for `outcome` at `verdict_cell`: every one a
/// gathered verdict under the statement locator holds that verifies under a
/// signer of the outcome, and why each other candidate counts as nothing.
async fn gathered_signatures(
    set: &StorageSet,
    verdict_cell: &D32,
    outcome: &[u8],
) -> Result<(Vec<VerdictSignature>, Vec<VerdictRefusal>), DsmError> {
    let locator = escrow::statement_locator(verdict_cell, outcome);
    let refused = std::cell::RefCell::new(Vec::new());
    let found = resolve_locator_all(
        set,
        TAG_DSM_ESCROW_STATEMENT_LOCATOR.source_bytes(),
        &locator,
        LOCATOR_BUDGET,
        |bytes| match escrow::gathered_signatures(bytes, verdict_cell, outcome) {
            Ok(signatures) => Some((locator, signatures)),
            Err(refusal) => {
                refused.borrow_mut().push(refusal);
                None
            }
        },
    )
    .await?;
    let signatures = match found {
        Discovered::Complete(found) | Discovered::Partial(found) => {
            found.into_iter().flatten().collect()
        }
    };
    Ok((signatures, refused.into_inner()))
}

/// `escrow.adjudicate` (§19.9): assemble the verdict on `outcome` from the
/// signatures gathered under the cell's statement locator and this device's
/// own when it is a signer, write it to the verdict cell leader first, and
/// return what the cell holds — which may be another verdict that got there
/// first. A verdict the gathered signatures do not complete is refused, and
/// nothing is written.
pub async fn adjudicate(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &OutcomeIntent,
) -> Result<VerdictView, DsmError> {
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    let verifier = ctx.verifier();
    let terms = escrow_terms_of(&verifier, &intent.vault_id)?;
    let verdict_cell = escrow::verdict_cell_of(&terms);
    let (mut signatures, refused) =
        gathered_signatures(set, &verdict_cell, &intent.outcome).await?;
    if let Some(signer) = own_signer_of(core, &terms, &intent.outcome)? {
        signatures.push(own_signature(&signer, &verdict_cell, &intent.outcome)?);
    }
    let verdict = escrow::assemble_verdict(
        *terms.external_commitment(),
        terms.outcome_table(),
        &intent.outcome,
        signatures,
    )
    .map_err(|refusal| {
        refuse(format!(
            "the gathered signatures do not decide {:?}: {refusal:?}; gathered candidates passed \
             over: {refused:?}",
            String::from_utf8_lossy(&intent.outcome)
        ))
    })?;
    let cell = VerdictCell::new(&verdict_cell, &as_ccb_members(set)?, &set.id())
        .map_err(|e| refuse(format!("verdict cell: {e:?}")))?;
    let write = write_recorded(set, cell.routed(), &verdict.encode()).await?;
    if !write.reached_leader() {
        return Err(storage(
            "verdict cell",
            "the cell's leader did not take the verdict; nothing is decided",
        ));
    }
    Ok(VerdictView::of(&read_cell(&verifier, &verdict_cell)?))
}

/// `escrow.verdict`: what the verdict cell of `vault_id` holds.
pub async fn verdict(
    core: &CoreSDK,
    set: &StorageSet,
    vault_id: &D32,
) -> Result<VerdictView, DsmError> {
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    let verifier = ctx.verifier();
    let terms = escrow_terms_of(&verifier, vault_id)?;
    Ok(VerdictView::of(&read_cell(
        &verifier,
        &escrow::verdict_cell_of(&terms),
    )?))
}

// ── escrow.release ──────────────────────────────────────────────────────────

/// `escrow.release` (§19.9, Release): the whole stake of `vault_id` to this
/// device, the recipient of the branch whose outcome the verdict cell holds,
/// final. A release is built only then: a release before the verdict, or
/// of a branch that pays someone else, could never realize, so nothing is
/// admitted for it. The setup with the vault is admitted first when this
/// device has none (Amendment S16).
pub async fn release(
    core: &CoreSDK,
    set: &StorageSet,
    vault_id: &D32,
) -> Result<PositionOutcome, DsmError> {
    let accepted = &AcceptedGeneses::default();
    let (terms, outcome) = {
        let standing = standing(core)?;
        let ctx = standing.context(set, accepted)?;
        let verifier = ctx.verifier();
        let terms = escrow_terms_of(&verifier, vault_id)?;
        let read = read_cell(&verifier, &escrow::verdict_cell_of(&terms))?;
        let view = VerdictView::of(&read);
        let outcome = match view.held {
            Some((outcome, ChainState::Final)) => outcome,
            Some((.., state)) => {
                return Err(storage(
                    "verdict",
                    format!("the verdict holding the cell is {state:?}, not final yet"),
                ))
            }
            None => return Err(storage("verdict", "no verdict holds the cell yet")),
        };
        let branch = terms
            .branch(&outcome)
            .ok_or_else(|| refuse("the verdict names no branch of the vault's terms"))?;
        if *branch.recipient_genesis() != standing.genesis
            || *branch.recipient_device_id() != standing.device_id
        {
            return Err(refuse(format!(
                "the verdict {:?} pays another identity",
                String::from_utf8_lossy(&outcome)
            )));
        }
        let head = core
            .device_head()
            .ok_or_else(|| storage("device head", "none"))?;
        if !head.has_adopted(terms.token()) {
            return Err(refuse(
                "the escrow token is not adopted: adopt it before receiving it",
            ));
        }
        (terms, outcome)
    };
    set_up_with(core, set, &[*vault_id], accepted).await?;
    let standing = standing(core)?;
    let ctx = standing.context(set, accepted)?;
    let verifier = ctx.verifier();
    let chain = chain_past_withheld_pairs(
        set,
        &verifier,
        vault_id,
        verifier.chain(vault_id).map_err(verifier_error)?,
    )
    .await?;
    let (vault, ..) = head_of(set, &verifier, vault_id, chain).await?;
    if !matches!(vault.terms, VaultTerms::Escrow(..)) {
        return Err(refuse("the vault is not an escrow vault"));
    }
    if vault.state.status != VAULT_STATUS_ACTIVE {
        return Err(refuse("the escrow vault is already released"));
    }
    let setup_ref = own_setup_ref(set, &standing.genesis, &standing.device_id, vault_id).await?;
    let base = relationship_base(&standing, vault_id)?;
    let retired =
        retire_vault_post(&vault.state).map_err(|refusal| refuse(format!("{refusal:?}")))?;
    let dlv = vault_core(&standing, &vault, &retired, base)?;
    let trader = trader_core(
        &standing,
        &[(*terms.token(), vault.state.reserve_a, 0)],
        &[(*vault_id, base)],
    )?;
    let public_key = crate::sdk::signing_authority::current_public_key()?;
    let trader_ctx = context(&standing, set, &public_key, trader)?;
    let draft = draft_release(
        ReleaseNames {
            vault_id: *vault_id,
            parent_root: vault.root,
            setup_ref,
            verdict_cell: escrow::verdict_cell_of(&terms),
            outcome,
            amount: vault.state.reserve_a,
        },
        dlv,
        &trader_ctx,
        &standing.local,
    )
    .map_err(refuse)?;
    exercise_draft(core, set, &standing, draft, accepted).await
}

// ── escrow.locked and escrow.vaults ─────────────────────────────────────────

/// One escrow vault at its walked head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowVaultView {
    pub vault_id: D32,
    pub owner_genesis: D32,
    pub owner_device_id: D32,
    pub verdict_cell: D32,
    pub external_commitment: D32,
    pub token: D32,
    /// What the vault holds at its head: the stake while Active, nothing once
    /// released.
    pub amount: u64,
    pub generation: u64,
    pub status: u16,
}

async fn view_of(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_id: &D32,
) -> Result<EscrowVaultView, DsmError> {
    let (vault, ..) = vault_at_head(set, verifier, vault_id).await?;
    let VaultTerms::Escrow(terms) = &vault.terms else {
        return Err(refuse("the vault is not an escrow vault"));
    };
    Ok(EscrowVaultView {
        vault_id: *vault_id,
        owner_genesis: vault.state.owner_genesis,
        owner_device_id: vault.state.owner_device_id,
        verdict_cell: escrow::verdict_cell_of(terms),
        external_commitment: *terms.external_commitment(),
        token: *terms.token(),
        amount: vault.state.reserve_a,
        generation: vault.state.generation,
        status: vault.state.status,
    })
}

/// `escrow.locked`: the escrow vaults bound to `verdict_cell`, each accepted,
/// checked to derive the cell, and walked to its head. Discovery carries no
/// authority; a candidate not established yet makes the search partial.
pub async fn locked(
    core: &CoreSDK,
    set: &StorageSet,
    verdict_cell: &D32,
) -> Result<(Vec<EscrowVaultView>, Search), DsmError> {
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    let verifier = ctx.verifier();
    let (vaults, mut search) = match verifier
        .vaults_of_cell(verdict_cell)
        .map_err(verifier_error)?
    {
        Discovered::Complete(vaults) => (vaults, Search::Complete),
        Discovered::Partial(vaults) => (vaults, Search::Partial),
    };
    let mut out = Vec::with_capacity(vaults.len());
    for accepted in vaults {
        match view_of(set, &verifier, accepted.vault_id()).await {
            Ok(view) => out.push(view),
            // A vault whose head is not established is not shown as it
            // stands, so the search is partial, and says why.
            Err(why) => {
                search = Search::Partial;
                out_of_reach(accepted.vault_id(), &why);
            }
        }
    }
    Ok((out, search))
}

/// A vault `escrow.locked` could not show at its head: the search is partial.
fn out_of_reach(vault_id: &D32, why: &DsmError) {
    log::info!(
        "[escrow] vault {} not shown at its head: {why}",
        dsm::utils::text_id::encode_base32_crockford(vault_id)
    );
}

/// `escrow.vaults`: the escrow vaults this device created — the creation
/// records its validated root commits — each walked to its head.
pub async fn own_vaults(
    core: &CoreSDK,
    set: &StorageSet,
) -> Result<Vec<EscrowVaultView>, DsmError> {
    let accepted = &AcceptedGeneses::default();
    let standing = standing(core)?;
    let ctx = standing.context(set, accepted)?;
    let verifier = ctx.verifier();
    let mut out = Vec::new();
    for creation in standing.local.vault_creations() {
        match verifier
            .vault_genesis(&creation.vault_id)
            .map_err(verifier_error)?
        {
            VaultGenesis::Accepted(genesis) if genesis.escrow().is_some() => {
                out.push(view_of(set, &verifier, &creation.vault_id).await?);
            }
            // A market vault is `sofi.vaults`'.
            VaultGenesis::Accepted(..) => {}
            VaultGenesis::NotPublished => {
                return Err(refuse(
                    "a vault this device created has no published genesis",
                ))
            }
            VaultGenesis::OwnerUnresolved(why) => return Err(storage("escrow vault genesis", why)),
            VaultGenesis::Refused(why) => {
                return Err(refuse(format!("vault genesis refused: {why}")))
            }
        }
    }
    Ok(out)
}
