// SPDX-License-Identifier: MIT OR Apache-2.0

//! Computed escrow vaults, the wallet's side (SoFi §19.10, Amendment S22):
//! a stake in a match whose outcome a pinned program computes from the
//! players' signed transcript. Nobody signs a verdict.
//!
//! - [`create`] locks this wallet's stake: a computed escrow vault whose
//!   table pins the program, the setup and both sides' session keys. This
//!   wallet's session key is derived from its own wallet seed and the match
//!   nonce ([`session_keypair`]); its secret never leaves the wallet.
//! - [`ready`] signs this wallet's ready once it verified both vaults, and,
//!   when the other side's ready is in hand, writes the Start
//!   ([`write_start`]). [`withdraw`] voids the match while no Start holds.
//! - [`sign_entry`] applies the next entries to the verified state the
//!   wallet keeps for the match and signs the head of its own entry. It
//!   writes nothing to storage, and it never signs two entries at one index.
//! - [`settle`] writes the whole transcript, or the proof that the other
//!   side equivocated, to the match cell: the one write of a match.
//! - [`release`] releases a vault to this wallet once the cells give a final
//!   outcome whose branch pays it.
//!
//! The application relays moves and is never evidence: every entry is
//! decoded and re-encoded byte for byte, chained and checked against the
//! program before this wallet signs anything over it.

use dsm::crypto::SignatureKeyPair;
use dsm::economic::write_set::CreditSourceFacts;
use dsm::route_chain::{CellFact, ChainState};
use dsm::sofi::computed::{self, ComputedCellRead, ComputedCells, MatchOccupant, Opened, OpenedKind};
use dsm::sofi::escrow;
use dsm::sofi::publication::Publication;
use dsm::sofi::resolve::{AcceptedGeneses, VaultGenesis, Verifier};
use dsm::sofi::storage::Discovered;
use dsm::sofi::wire::{
    next_position, ComputedBranch, ComputedEscrowTerms, ComputedTable, EntryKind, EscrowSigner,
    EquivocationProof, MatchSide, SideSignature, SignedHead, StartKind, TranscriptEntry,
    TranscriptOutcome, VaultGenesisPreimage, VaultStateLeaf, COMPUTED_LABEL_A_WINS,
    COMPUTED_LABEL_B_WINS, COMPUTED_LABEL_VOID, VAULT_STATUS_ACTIVE,
};
use dsm::types::device_state::{BalanceDelta, BalanceDirection};
use dsm::types::error::DsmError;

use crate::sdk::core_sdk::CoreSDK;
use crate::sdk::economic_admission_flow::{
    admitted_self_loop_operation, validated_root_or_activate, BuiltOn,
};
use crate::sdk::outcome_programs::{read_setup, DuelProgress, MatchSetup};
use crate::sdk::realized_records::{record_realized, Moved, Realized};
use crate::sdk::route_seats::write_recorded;
use crate::sdk::sofi_flow::{
    identity, publication_addr, refuse, require_stored, sign, standing, storage, vault_at_head,
    PositionOutcome, SIGNATURE_ALG,
};
use crate::sdk::sofi_publish::publish;
use crate::sdk::sofi_reads::{verifier_error, LiveSofiReads, VerifierContext};
use crate::sdk::sofi_sdk::build_computed_vault_create;
use crate::sdk::storage_set::{as_ccb_members, StorageSet};
use crate::storage::client_db::duel_matches::{self as store, Advance, DuelEntryRow, DuelMatchRow};

type D32 = [u8; 32];

/// `DSM/escrow/session-key/v1`: the HKDF salt of a match session key.
const TAG_SESSION_KEY: dsm::crypto::domain::TaggedHashDomain<'static> =
    dsm::tagged_domain!(b"DSM/escrow/session-key/v1");

fn side_byte(side: MatchSide) -> u8 {
    side.byte()
}

fn side_of(byte: u8) -> Result<MatchSide, DsmError> {
    MatchSide::from_byte(byte).map_err(|e| storage("kept match", format!("{e:?}")))
}

fn short(id: &D32) -> String {
    let text = dsm::utils::text_id::encode_base32_crockford(id);
    text.chars().take(8).collect()
}

// ── the session key ─────────────────────────────────────────────────────────

/// This wallet's session key for the match whose setup carries
/// `match_nonce`: `HKDF(salt = DSM/escrow/session-key/v1 ‖ 0x00, ikm = wallet
/// seed, info = genesis ‖ match_nonce)`, expanded into a SPHINCS+ key pair.
/// Derived from the seed the wallet holds while unlocked, so it fails closed
/// when the wallet is locked, and it never leaves the wallet: only its public
/// half is ever returned.
pub(crate) fn session_keypair(match_nonce: &D32) -> Result<SignatureKeyPair, DsmError> {
    let genesis = crate::sdk::app_state::AppState::get_genesis_hash()
        .ok_or_else(|| DsmError::InvalidState("no genesis for a session key".into()))?;
    let wallet_seed =
        crate::sdk::recovery_sdk::RecoverySDK::get_cached_wallet_seed().ok_or_else(|| {
            DsmError::InvalidState(
                "wallet seed unavailable for a session key (wallet locked)".into(),
            )
        })?;
    let mut salt = TAG_SESSION_KEY.source_bytes().to_vec();
    salt.push(0);
    let mut info = genesis;
    info.extend(match_nonce);
    let seed = dsm::crypto::hkdf::extract_and_expand(&salt, &wallet_seed, &info, 32);
    SignatureKeyPair::generate_from_entropy(&seed)
}

/// This wallet's session public key for the match nonce: what the setup
/// names for this wallet's side.
pub fn session_public_key(match_nonce: &D32) -> Result<Vec<u8>, DsmError> {
    Ok(session_keypair(match_nonce)?.public_key().to_vec())
}

fn session_signer(public_key: &[u8]) -> Result<EscrowSigner, DsmError> {
    EscrowSigner::new(SIGNATURE_ALG, public_key).map_err(refuse)
}

// ── the terms a setup gives ─────────────────────────────────────────────────

/// The computed table `setup` gives: the program it pins, its digest and
/// both sides' session keys.
pub fn table_of(setup: &[u8], read: &MatchSetup) -> Result<ComputedTable, DsmError> {
    ComputedTable::new(
        read.program,
        computed::setup_digest(setup),
        session_signer(&read.a.session_public_key)?,
        session_signer(&read.b.session_public_key)?,
    )
    .map_err(refuse)
}

/// The terms of `owner`'s stake of `token` in the match `setup` describes:
/// `a-wins` pays side A, `b-wins` side B, `void` the vault's own owner. The
/// two players' terms differ only in that recipient, so both bind one match
/// cell. `Y` commits the setup itself.
pub fn terms_of(
    setup: &[u8],
    read: &MatchSetup,
    token: D32,
    owner: (D32, D32),
) -> Result<ComputedEscrowTerms, DsmError> {
    ComputedEscrowTerms::new(
        token,
        escrow::external_commitment(setup),
        table_of(setup, read)?,
        vec![
            ComputedBranch::new(COMPUTED_LABEL_A_WINS, read.a.genesis, read.a.device_id),
            ComputedBranch::new(COMPUTED_LABEL_B_WINS, read.b.genesis, read.b.device_id),
            ComputedBranch::new(COMPUTED_LABEL_VOID, owner.0, owner.1),
        ],
    )
    .map_err(refuse)
}

/// The computed terms `vault_id`'s accepted genesis commits.
fn computed_terms_of(
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_id: &D32,
) -> Result<(ComputedEscrowTerms, (D32, D32)), DsmError> {
    match verifier.vault_genesis(vault_id).map_err(verifier_error)? {
        VaultGenesis::Accepted(accepted) => {
            let owner = (
                accepted.preimage().owner_genesis,
                accepted.preimage().owner_device_id,
            );
            let terms = accepted
                .computed()
                .cloned()
                .ok_or_else(|| refuse("the vault is not a computed escrow vault"))?;
            Ok((terms, owner))
        }
        VaultGenesis::NotPublished => Err(refuse(
            "no genesis the owner's creation carried is published",
        )),
        VaultGenesis::OwnerUnresolved(why) => Err(storage(
            "computed vault genesis",
            format!("the owner's lineage is unresolved: {why}"),
        )),
        VaultGenesis::Refused(why) => Err(refuse(format!("vault genesis refused: {why}"))),
    }
}

/// `vault_id` is a stake of `owner` in the very match `mine` binds: accepted,
/// its `Y`, token and table `mine`'s, its `a-wins` and `b-wins` paying the
/// two players `mine` pays, its `void` refunding its own owner, Active at its
/// walked head and holding `amount`.
async fn mirrors(
    set: &StorageSet,
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    vault_id: &D32,
    mine: &ComputedEscrowTerms,
    owner: (D32, D32),
    amount: u64,
) -> Result<(), DsmError> {
    let (terms, held_by) = computed_terms_of(verifier, vault_id)?;
    let named = short(vault_id);
    if held_by != owner {
        return Err(refuse(format!(
            "vault {named} is not the expected player's"
        )));
    }
    if terms.external_commitment() != mine.external_commitment()
        || terms.table() != mine.table()
        || terms.token() != mine.token()
    {
        return Err(refuse(format!(
            "vault {named} is bound to another match: its commitment, its table or its token \
             differs"
        )));
    }
    let pays = |label: &[u8]| {
        terms
            .branch(label)
            .map(|b| (*b.recipient_genesis(), *b.recipient_device_id()))
    };
    let mine_pays = |label: &[u8]| {
        mine.branch(label)
            .map(|b| (*b.recipient_genesis(), *b.recipient_device_id()))
    };
    if pays(COMPUTED_LABEL_A_WINS) != mine_pays(COMPUTED_LABEL_A_WINS)
        || pays(COMPUTED_LABEL_B_WINS) != mine_pays(COMPUTED_LABEL_B_WINS)
        || pays(COMPUTED_LABEL_VOID) != Some(owner)
    {
        return Err(refuse(format!(
            "vault {named}'s branches are not this match's mirrored for its owner"
        )));
    }
    let (vault, ..) = vault_at_head(set, verifier, vault_id).await?;
    if vault.state.status != VAULT_STATUS_ACTIVE {
        return Err(refuse(format!("vault {named} is no longer Active")));
    }
    if vault.state.reserve_a != amount {
        return Err(refuse(format!(
            "vault {named} holds {}, not the {amount} this stake matches",
            vault.state.reserve_a
        )));
    }
    Ok(())
}

// ── create ──────────────────────────────────────────────────────────────────

/// A stake to lock in a computed match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockIntent {
    /// The canonical setup both wallets lock.
    pub setup: Vec<u8>,
    pub side: MatchSide,
    pub token: D32,
    pub amount: u64,
    /// The other player: its genesis and device id.
    pub opponent: (D32, D32),
    /// The other side's vault, when it locked first; checked to mirror this
    /// stake before this one is locked.
    pub counterpart: Option<D32>,
    /// The opponent's proof of holding the creatures the setup fields for
    /// it, as its own wallet made it (`HoldingsProofV1` bytes); verified
    /// against its validated root.
    pub opponent_holdings: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Locked {
    pub vault_id: D32,
    pub match_cell: D32,
    pub start_cell: D32,
    pub external_commitment: D32,
    pub program: D32,
    pub session_public_key: Vec<u8>,
    pub position: u64,
}

/// Lock this wallet's stake in the match `intent.setup` describes. The setup
/// is read by the program this wallet registered; it must name this wallet
/// on `intent.side` with this wallet's own session key for its nonce, and the
/// opponent on the other side. The terms are built here; the application
/// names none of them.
pub async fn create(
    core: &CoreSDK,
    set: &StorageSet,
    intent: &LockIntent,
) -> Result<Locked, DsmError> {
    if intent.amount == 0 {
        return Err(refuse("a stake must be positive"));
    }
    let read = read_setup(&intent.setup).map_err(refuse)?;
    let me = identity(core)?;
    let mine = read.side(intent.side);
    let other = read.side(intent.side.other());
    if (mine.genesis, mine.device_id) != me {
        return Err(refuse("the setup does not name this wallet on its side"));
    }
    if (other.genesis, other.device_id) != intent.opponent {
        return Err(refuse(
            "the setup does not name the opponent on the other side",
        ));
    }
    if intent.opponent == me || other.genesis == me.0 || other.device_id == me.1 {
        return Err(refuse("the two players of a match must be two identities"));
    }
    let session = session_keypair(&read.match_nonce)?;
    if session.public_key() != mine.session_public_key.as_slice() {
        return Err(refuse(
            "the setup's session key for this side is not this wallet's for the match",
        ));
    }
    let relayed = intent
        .opponent_holdings
        .as_deref()
        .ok_or_else(|| refuse("no proof that the opponent holds the creatures it fields"))?;
    let their_holdings: dsm::types::proto::HoldingsProofV1 =
        crate::sdk::connect::signed::canonical(relayed, "the opponent's holdings proof")
            .map_err(refuse)?;
    crate::sdk::outcome_programs::check_teams(
        core,
        set,
        &intent.setup,
        intent.side,
        &their_holdings,
    )
    .await
    .map_err(refuse)?;
    let terms = terms_of(&intent.setup, &read, intent.token, me)?;
    let match_cell = computed::match_cell_of(&terms);
    if store::get_match(&match_cell)
        .map_err(|e| storage("kept matches", e))?
        .is_some()
    {
        return Err(refuse("this wallet already locked a stake in this match"));
    }
    if let Some(counterpart) = &intent.counterpart {
        let ctx = VerifierContext::new(set, Some(me), None)?;
        mirrors(
            set,
            &ctx.verifier(),
            counterpart,
            &terms,
            intent.opponent,
            intent.amount,
        )
        .await?;
    }

    let validated = validated_root_or_activate(core)?;
    let create_position = next_position(validated.economic_position()).map_err(refuse)?;
    let terms_object = Publication::ComputedEscrowTerms(&terms);
    let addr = publication_addr(&terms_object)?;
    let preimage = VaultGenesisPreimage {
        owner_genesis: me.0,
        owner_device_id: me.1,
        create_position,
        state: VaultStateLeaf {
            owner_genesis: me.0,
            owner_device_id: me.1,
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
    let produced = build_computed_vault_create(&preimage, &terms).map_err(refuse)?;
    let genesis_object = Publication::ComputedEscrowVaultGenesis {
        preimage: &preimage,
        terms: &terms,
    };
    let (terms_published, genesis_published) =
        futures::future::try_join(publish(set, &terms_object), publish(set, &genesis_object))
            .await?;
    require_stored("computed escrow terms", &terms_published)?;
    if terms_published.addr != addr {
        return Err(refuse("the computed terms were stored at another address"));
    }
    require_stored("computed escrow vault genesis", &genesis_published)?;
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
    let progress = DuelProgress::start(&intent.setup).map_err(|e| refuse(e.reason))?;
    store::insert_match(&DuelMatchRow {
        match_cell,
        side: side_byte(intent.side),
        terms: terms.encode(),
        setup: intent.setup.clone(),
        vault_id,
        ready: None,
        start_final: None,
        last_index: 0,
        head: computed::genesis_head(&match_cell, terms.table().setup_digest()),
        open: [None, None],
        progress: progress.encode(),
        equivocation: None,
    })
    .map_err(|e| storage("kept matches", e))?;
    Ok(Locked {
        vault_id,
        match_cell,
        start_cell: computed::start_cell_key(&match_cell),
        external_commitment: *terms.external_commitment(),
        program: read.program,
        session_public_key: session.public_key().to_vec(),
        position: admitted.economic_position,
    })
}

// ── the kept match ──────────────────────────────────────────────────────────

/// A match this wallet locked a stake in, as it keeps it.
struct Kept {
    row: DuelMatchRow,
    side: MatchSide,
    terms: ComputedEscrowTerms,
    read: MatchSetup,
}

impl Kept {
    fn load(match_cell: &D32) -> Result<Self, DsmError> {
        let row = store::get_match(match_cell)
            .map_err(|e| storage("kept matches", e))?
            .ok_or_else(|| refuse("this wallet holds no stake in that match"))?;
        let side = side_of(row.side)?;
        let terms = ComputedEscrowTerms::decode(&row.terms)
            .map_err(|e| storage("kept match terms", format!("{e:?}")))?;
        let read = read_setup(&row.setup).map_err(|e| storage("kept match setup", e))?;
        Ok(Self {
            row,
            side,
            terms,
            read,
        })
    }

    fn table(&self) -> &ComputedTable {
        self.terms.table()
    }

    fn y(&self) -> &D32 {
        self.terms.external_commitment()
    }

    fn cells(&self, set: &StorageSet) -> Result<ComputedCells, DsmError> {
        ComputedCells::new(&self.terms, &as_ccb_members(set)?, &set.id())
            .map_err(|e| refuse(format!("computed cells: {e:?}")))
    }

    fn opponent(&self) -> (D32, D32) {
        let other = self.read.side(self.side.other());
        (other.genesis, other.device_id)
    }

    fn secret(&self) -> Result<Vec<u8>, DsmError> {
        Ok(session_keypair(&self.read.match_nonce)?
            .secret_key()
            .to_vec())
    }
}

// ── the cells as Core reads them ────────────────────────────────────────────

/// What a match's start and match cells hold, as Core read them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchView {
    pub match_cell: D32,
    pub start_cell: D32,
    /// The Start or Withdraw holding the start cell, and how far its chain
    /// has gone; `None` while the start cell is open.
    pub start: Option<(StartKind, ChainState)>,
    /// The outcome the match cell's occupant gives, whether it is an
    /// equivocation proof, and how far its chain has gone; `None` while
    /// nothing recognized holds it, or before a Start does.
    pub occupant: Option<(Vec<u8>, OccupantKind, ChainState)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OccupantKind {
    Transcript,
    Equivocation,
}

impl MatchView {
    fn of(read: &ComputedCellRead) -> Self {
        let start = match (read.start().held(), read.start().fact()) {
            (Some(kind), CellFact::Held { state, .. }) => Some((kind, state)),
            (None, _) | (Some(..), CellFact::Open) => None,
        };
        let occupant = read.matched().and_then(|m| match (m.occupant(), m.fact()) {
            (Some(o), CellFact::Held { state, .. }) => {
                let kind = match o {
                    MatchOccupant::Transcript { .. } => OccupantKind::Transcript,
                    MatchOccupant::Equivocation { .. } => OccupantKind::Equivocation,
                };
                Some((o.label().to_vec(), kind, state))
            }
            (None, _) | (Some(..), CellFact::Open) => None,
        });
        Self {
            match_cell: read.key(),
            start_cell: *read.start().key(),
            start,
            occupant,
        }
    }

    /// The outcome the cells give, once it is final: `void` for a final
    /// Withdraw, or a final occupant's label once a final Start holds.
    pub fn final_outcome(&self) -> Option<Vec<u8>> {
        match (&self.start, &self.occupant) {
            (Some((StartKind::Withdraw, ChainState::Final)), _) => {
                Some(COMPUTED_LABEL_VOID.to_vec())
            }
            (Some((StartKind::Start, ChainState::Final)), Some((label, _, ChainState::Final))) => {
                Some(label.clone())
            }
            _ => None,
        }
    }
}

fn read_cells(
    verifier: &Verifier<'_, LiveSofiReads<'_>>,
    terms: &ComputedEscrowTerms,
) -> Result<ComputedCellRead, DsmError> {
    verifier
        .read_computed_cells(terms)
        .map_err(verifier_error)?
        .map_err(|missing| {
            storage(
                "computed cells",
                format!("not established yet: {missing:?}"),
            )
        })
}

/// What the cells of a match whose terms are `terms` hold, as this wallet's
/// verifier reads them.
pub fn view_of_terms(
    core: &CoreSDK,
    set: &StorageSet,
    terms: &ComputedEscrowTerms,
) -> Result<MatchView, DsmError> {
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    Ok(MatchView::of(&read_cells(&ctx.verifier(), terms)?))
}

/// What the cells of a match this wallet holds a stake in hold.
pub fn view(core: &CoreSDK, set: &StorageSet, match_cell: &D32) -> Result<MatchView, DsmError> {
    let kept = Kept::load(match_cell)?;
    view_of_terms(core, set, &kept.terms)
}

/// What the cells of the match `vault_id` is a stake in hold, read from the
/// vault's accepted terms.
pub fn view_of_vault(
    core: &CoreSDK,
    set: &StorageSet,
    vault_id: &D32,
) -> Result<(ComputedEscrowTerms, MatchView), DsmError> {
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    let verifier = ctx.verifier();
    let (terms, _owner) = computed_terms_of(&verifier, vault_id)?;
    let read = read_cells(&verifier, &terms)?;
    Ok((terms, MatchView::of(&read)))
}

// ── ready, Start and Withdraw ───────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readied {
    pub match_cell: D32,
    /// This wallet's signature over `m_ready`: what the other side's wallet
    /// assembles the Start from.
    pub ready_signature: Vec<u8>,
    /// What the cells hold after this call: a Start this call wrote, when the
    /// other side's ready was in hand.
    pub view: MatchView,
}

/// Ready this wallet for the match (SoFi §19.10, the ready handshake): both
/// players' vaults are verified first — this wallet's own and the other
/// side's, found on the match cell — each accepted, Active, bound to this
/// match, of one token and one amount, its owner one of the two players and
/// its branches mirrored. Only then is the ready signed. When the other
/// side's ready signature is supplied, this wallet readies second and writes
/// the Start itself.
pub async fn ready(
    core: &CoreSDK,
    set: &StorageSet,
    match_cell: &D32,
    opponent_ready: Option<&[u8]>,
) -> Result<Readied, DsmError> {
    let kept = Kept::load(match_cell)?;
    let me = identity(core)?;
    let ctx = VerifierContext::new(set, Some(me), None)?;
    let verifier = ctx.verifier();
    let (own, ..) = vault_at_head(set, &verifier, &kept.row.vault_id).await?;
    let amount = own.state.reserve_a;
    mirrors(set, &verifier, &kept.row.vault_id, &kept.terms, me, amount).await?;
    let opponent = kept.opponent();
    let (found, search) = match verifier
        .vaults_of_cell(match_cell)
        .map_err(verifier_error)?
    {
        Discovered::Complete(found) => (found, "complete"),
        Discovered::Partial(found) => (found, "partial"),
    };
    let theirs: Vec<D32> = found
        .iter()
        .filter(|accepted| {
            let p = accepted.preimage();
            (p.owner_genesis, p.owner_device_id) == opponent
        })
        .map(|accepted| *accepted.vault_id())
        .collect();
    let mut mirrored = Vec::new();
    let mut passed_over = Vec::new();
    for vault_id in theirs.iter().filter(|v| **v != kept.row.vault_id) {
        match mirrors(set, &verifier, vault_id, &kept.terms, opponent, amount).await {
            Ok(()) => mirrored.push(*vault_id),
            Err(why) => passed_over.push(why.to_string()),
        }
    }
    match mirrored.as_slice() {
        [_] => {}
        [] => {
            return Err(refuse(format!(
                "no stake of the other player mirrors this one on the match cell yet (search \
                 {search}; passed over: {passed_over:?})"
            )))
        }
        _ => {
            return Err(refuse(
                "the other player holds more than one stake on the match cell",
            ))
        }
    }
    let ready_signature = match &kept.row.ready {
        Some(signature) => signature.clone(),
        None => {
            let signature =
                computed::sign_ready(kept.y(), kept.table(), kept.side, &kept.secret()?)?;
            store::set_ready(match_cell, &signature).map_err(|e| storage("kept matches", e))?;
            signature
        }
    };
    if let Some(theirs) = opponent_ready {
        write_start(set, &kept, &ready_signature, theirs).await?;
    }
    let view = MatchView::of(&read_cells(&verifier, &kept.terms)?);
    Ok(Readied {
        match_cell: *match_cell,
        ready_signature,
        view,
    })
}

/// Write the Start of the match: both ready signatures, side A's then side
/// B's, assembled by Core, which verifies each under its side's session key
/// before the Start exists. Written to the start cell's leader; whichever of
/// a Start and a Withdraw is first there holds the cell for good.
async fn write_start(
    set: &StorageSet,
    kept: &Kept,
    own_ready: &[u8],
    opponent_ready: &[u8],
) -> Result<(), DsmError> {
    let (ready_a, ready_b) = match kept.side {
        MatchSide::A => (own_ready, opponent_ready),
        MatchSide::B => (opponent_ready, own_ready),
    };
    let start = computed::assemble_start(kept.y(), kept.table(), ready_a, ready_b)
        .map_err(|why| refuse(format!("the Start does not assemble: {why:?}")))?;
    let cells = kept.cells(set)?;
    let write = write_recorded(set, cells.start_routed(), &start.encode()).await?;
    if !write.reached_leader() {
        return Err(storage(
            "start cell",
            "the cell's leader did not take the Start; nothing is started",
        ));
    }
    Ok(())
}

/// Withdraw from the match while no Start holds its start cell: this
/// wallet's side signs the Withdraw, and whichever of it and a Start is first
/// at the cell's leader holds the cell. A Withdraw holding it voids the
/// match and refunds both stakes. Answers with what the cells hold after.
pub async fn withdraw(
    core: &CoreSDK,
    set: &StorageSet,
    match_cell: &D32,
) -> Result<MatchView, DsmError> {
    let kept = Kept::load(match_cell)?;
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    let verifier = ctx.verifier();
    let before = MatchView::of(&read_cells(&verifier, &kept.terms)?);
    if let Some((StartKind::Start, _)) = before.start {
        return Err(refuse(
            "a Start holds the start cell: the match started and cannot be withdrawn",
        ));
    }
    let withdrawal = computed::sign_withdraw(kept.y(), kept.table(), kept.side, &kept.secret()?)?;
    let cells = kept.cells(set)?;
    let write = write_recorded(set, cells.start_routed(), &withdrawal.encode()).await?;
    if !write.reached_leader() {
        return Err(storage(
            "start cell",
            "the cell's leader did not take the Withdraw; nothing is withdrawn",
        ));
    }
    Ok(MatchView::of(&read_cells(&verifier, &kept.terms)?))
}

/// The Start this wallet found final at the match's start cell, read once
/// and kept: a final Start stays final. No entry is signed before one.
fn require_started(core: &CoreSDK, set: &StorageSet, kept: &mut Kept) -> Result<(), DsmError> {
    if kept.row.start_final.is_some() {
        return Ok(());
    }
    let ctx = VerifierContext::new(set, Some(identity(core)?), None)?;
    let read = read_cells(&ctx.verifier(), &kept.terms)?;
    let value = match (
        read.start().held(),
        read.start().fact(),
        read.start().value(),
    ) {
        (
            Some(StartKind::Start),
            CellFact::Held {
                state: ChainState::Final,
                ..
            },
            Some(value),
        ) => value.to_vec(),
        _ => {
            return Err(refuse(
                "no Start is final at the match's start cell: no entry is signed before one",
            ))
        }
    };
    store::set_start_final(&kept.row.match_cell, &value).map_err(|e| storage("kept matches", e))?;
    kept.row.start_final = Some(value);
    Ok(())
}

// ── applying entries ────────────────────────────────────────────────────────

/// One entry and its side's signature over the head after it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedEntry {
    pub entry: Vec<u8>,
    pub signature: Vec<u8>,
}

/// The verified state of a match, moved one entry at a time.
struct Applying {
    match_cell: D32,
    from_index: u32,
    last_index: u32,
    head: D32,
    open: [Option<(u32, D32)>; 2],
    progress: DuelProgress,
    kept: Vec<DuelEntryRow>,
}

fn slot(side: MatchSide) -> usize {
    match side {
        MatchSide::A => 0,
        MatchSide::B => 1,
    }
}

impl Applying {
    fn of(row: &DuelMatchRow) -> Result<Self, DsmError> {
        Ok(Self {
            match_cell: row.match_cell,
            from_index: row.last_index,
            last_index: row.last_index,
            head: row.head,
            open: row.open,
            progress: DuelProgress::decode(&row.progress)
                .map_err(|e| storage("kept match progress", e))?,
            kept: Vec::new(),
        })
    }

    /// Apply `bytes` as the next entry; the entry and the head after it. The
    /// bytes must decode and re-encode to themselves, name the next index,
    /// keep the commit / reveal discipline, and be a step the program takes.
    fn apply(&mut self, bytes: &[u8]) -> Result<(TranscriptEntry, D32), DsmError> {
        let entry = TranscriptEntry::decode(bytes)
            .map_err(|e| refuse(format!("an entry that does not decode: {e:?}")))?;
        if entry.encode() != bytes {
            return Err(refuse(
                "an entry that is not its canonical encoding is no entry",
            ));
        }
        let index = self.last_index + 1;
        if entry.index() != index {
            return Err(refuse(format!(
                "the entry names index {}, and the next index is {index}",
                entry.index()
            )));
        }
        let at = slot(entry.side());
        match entry.kind() {
            EntryKind::Commit { commitment } => {
                if self.open[at].is_some() {
                    return Err(refuse("a commitment while the side's last one is unopened"));
                }
                self.progress.may_commit().map_err(|why| {
                    refuse(format!("a commitment the program refuses: {}", why.reason))
                })?;
                self.open[at] = Some((index, *commitment));
            }
            EntryKind::Reveal { salt, played } => {
                let (committed_at, commitment) = self.open[at]
                    .take()
                    .ok_or_else(|| refuse("a reveal with no commitment to open"))?;
                if computed::move_commitment(salt, played) != commitment {
                    return Err(refuse("the reveal does not open its side's commitment"));
                }
                self.progress
                    .apply(&Opened {
                        index,
                        side: entry.side(),
                        kind: OpenedKind::Move {
                            committed_at,
                            played: played.clone(),
                        },
                    })
                    .map_err(|why| refuse(format!("a move the program refuses: {}", why.reason)))?;
            }
            EntryKind::Resign => {
                self.progress
                    .apply(&Opened {
                        index,
                        side: entry.side(),
                        kind: OpenedKind::Resign,
                    })
                    .map_err(|why| {
                        refuse(format!("a resignation the program refuses: {}", why.reason))
                    })?;
            }
        }
        self.head = computed::next_head(&self.head, bytes);
        self.last_index = index;
        Ok((entry, self.head))
    }

    fn keep(&mut self, side: MatchSide, entry: &[u8], signature: Vec<u8>) {
        self.kept.push(DuelEntryRow {
            idx: self.last_index,
            side: side_byte(side),
            entry: entry.to_vec(),
            head: self.head,
            signature,
        });
    }

    fn commit(self) -> Result<(), DsmError> {
        store::advance(
            &self.match_cell,
            self.from_index,
            &Advance {
                last_index: self.last_index,
                head: self.head,
                open: self.open,
                progress: self.progress.encode(),
            },
            &self.kept,
        )
        .map_err(|e| refuse(format!("the match's kept state: {e}")))
    }
}

/// `signature` verifies, under `side`'s session key, over `m_head(index,
/// head)`.
fn head_signed(
    table: &ComputedTable,
    side: MatchSide,
    match_cell: &D32,
    index: u32,
    head: &D32,
    signature: &[u8],
) -> Result<(), DsmError> {
    let session = table.session(side);
    if session.signature_alg() != SIGNATURE_ALG {
        return Err(refuse("a session key of an undeclared algorithm"));
    }
    let statement = computed::head_statement(match_cell, index, head);
    match dsm::crypto::sphincs::sphincs_verify(session.public_key(), &statement, signature)? {
        verified if verified => Ok(()),
        _ => Err(refuse(format!(
            "the signature over the head of entry {index} does not verify under its side's \
             session key"
        ))),
    }
}

/// The head before entry `index`: `h_{index-1}`.
fn head_before(kept: &Kept, index: u32) -> Result<D32, DsmError> {
    if index == 1 {
        return Ok(computed::genesis_head(
            &kept.row.match_cell,
            kept.table().setup_digest(),
        ));
    }
    store::entry_at(&kept.row.match_cell, index - 1)
        .map_err(|e| storage("kept entries", e))?
        .map(|e| e.head)
        .ok_or_else(|| storage("kept entries", format!("no entry kept at {}", index - 1)))
}

/// Apply the other side's signed entries in `given` past the kept state.
/// One the wallet already applied is skipped when its bytes are the kept
/// ones; a different entry at an index the other side already signed, under
/// a signature of its key, is an equivocation: the proof is kept and
/// returned, and nothing else is applied.
fn apply_other_side(
    kept: &Kept,
    applying: &mut Applying,
    given: &[SignedEntry],
) -> Result<Option<EquivocationProof>, DsmError> {
    let other = kept.side.other();
    for signed in given {
        let probe = TranscriptEntry::decode(&signed.entry)
            .map_err(|e| refuse(format!("an entry that does not decode: {e:?}")))?;
        if probe.side() != other {
            return Err(refuse(
                "an entry of this wallet's side is signed by this wallet only",
            ));
        }
        if probe.index() <= applying.last_index {
            let stored = store::entry_at(&kept.row.match_cell, probe.index())
                .map_err(|e| storage("kept entries", e))?
                .ok_or_else(|| storage("kept entries", "an applied index holds no entry"))?;
            if stored.entry == signed.entry {
                continue;
            }
            if stored.side != side_byte(other) {
                return Err(refuse(format!(
                    "index {} holds this wallet's own entry",
                    probe.index()
                )));
            }
            if probe.encode() != signed.entry {
                return Err(refuse(
                    "an entry that is not its canonical encoding is no entry",
                ));
            }
            let head = computed::next_head(&head_before(kept, probe.index())?, &signed.entry);
            head_signed(
                kept.table(),
                other,
                &kept.row.match_cell,
                probe.index(),
                &head,
                &signed.signature,
            )?;
            let first = SignedHead::new(stored.head, &stored.signature).map_err(refuse)?;
            let second = SignedHead::new(head, &signed.signature).map_err(refuse)?;
            let (low, high) = if first.head() < second.head() {
                (first, second)
            } else {
                (second, first)
            };
            let proof = EquivocationProof::new(
                *kept.y(),
                kept.table().clone(),
                other,
                probe.index(),
                low,
                high,
            )
            .map_err(refuse)?;
            return Ok(Some(proof));
        }
        let (_, head) = applying.apply(&signed.entry)?;
        head_signed(
            kept.table(),
            other,
            &kept.row.match_cell,
            applying.last_index,
            &head,
            &signed.signature,
        )?;
        applying.keep(other, &signed.entry, signed.signature.clone());
    }
    Ok(None)
}

/// Keep `proof` and refuse to go on: the other side equivocated, and the
/// match is settled by the proof.
fn equivocated(match_cell: &D32, proof: &EquivocationProof) -> DsmError {
    match store::set_equivocation(match_cell, &proof.encode()) {
        Ok(()) => refuse(format!(
            "the other side signed two different entries at index {}: the match is settled by \
             the proof of it",
            proof.index()
        )),
        Err(e) => storage("kept matches", e),
    }
}

/// A signature this wallet produced for its own entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntrySigned {
    pub index: u32,
    pub head: D32,
    pub signature: Vec<u8>,
}

/// Sign this wallet's next entry of the match. The other side's entries
/// since the last one this wallet applied come first in `preceding`, each
/// with that side's signature over its head; then `entry`, this wallet's.
/// Each is decoded and re-encoded byte for byte, applied to the verified
/// state the wallet keeps (O(1) an entry: the match is never replayed), and
/// checked against the program. The signature is returned only after the
/// entry and it are kept, and an index this wallet signed is never signed
/// again with other bytes. Nothing is written to storage. No entry is signed
/// before a Start is final at the start cell.
pub fn sign_entry(
    core: &CoreSDK,
    set: &StorageSet,
    match_cell: &D32,
    preceding: &[SignedEntry],
    entry: &[u8],
) -> Result<EntrySigned, DsmError> {
    let mut kept = Kept::load(match_cell)?;
    if kept.row.equivocation.is_some() {
        return Err(refuse(
            "the other side equivocated in this match: it is settled by the proof",
        ));
    }
    let probe = TranscriptEntry::decode(entry)
        .map_err(|e| refuse(format!("an entry that does not decode: {e:?}")))?;
    if probe.side() != kept.side {
        return Err(refuse("the entry to sign is not this wallet's side's"));
    }
    // An index this wallet already signed: the same bytes answer with the
    // same signature; any other bytes are refused.
    if probe.index() <= kept.row.last_index {
        let stored = store::entry_at(match_cell, probe.index())
            .map_err(|e| storage("kept entries", e))?
            .ok_or_else(|| storage("kept entries", "an applied index holds no entry"))?;
        if stored.side == side_byte(kept.side) && stored.entry == entry {
            return Ok(EntrySigned {
                index: stored.idx,
                head: stored.head,
                signature: stored.signature,
            });
        }
        return Err(refuse(format!(
            "this wallet already signed another entry at index {}: it never signs two",
            probe.index()
        )));
    }
    require_started(core, set, &mut kept)?;
    let mut applying = Applying::of(&kept.row)?;
    if let Some(proof) = apply_other_side(&kept, &mut applying, preceding)? {
        return Err(equivocated(match_cell, &proof));
    }
    let (_, head) = applying.apply(entry)?;
    let index = applying.last_index;
    let signature = computed::sign_head(
        kept.table().session(kept.side),
        &kept.secret()?,
        match_cell,
        index,
        &head,
    )?;
    applying.keep(kept.side, entry, signature.clone());
    applying.commit()?;
    Ok(EntrySigned {
        index,
        head,
        signature,
    })
}

// ── settle ──────────────────────────────────────────────────────────────────

/// Settle the match: apply the other side's last signed entries in `given`,
/// then write to the match cell the one occupant the kept state supports —
/// the proof that the other side equivocated, when the wallet holds one, or
/// else the whole transcript up to the entry that ended the match, with each
/// side's signature over the head of its last entry. Core recognizes the
/// occupant from its own bytes before it is written. This is the match's one
/// storage write. Answers with what the cells hold after.
pub async fn settle(
    core: &CoreSDK,
    set: &StorageSet,
    match_cell: &D32,
    given: &[SignedEntry],
) -> Result<MatchView, DsmError> {
    let mut kept = Kept::load(match_cell)?;
    require_started(core, set, &mut kept)?;
    let occupant = match &kept.row.equivocation {
        Some(proof) => proof.clone(),
        None => {
            let mut applying = Applying::of(&kept.row)?;
            if let Some(proof) = apply_other_side(&kept, &mut applying, given)? {
                store::set_equivocation(match_cell, &proof.encode())
                    .map_err(|e| storage("kept matches", e))?;
                proof.encode()
            } else {
                if applying.progress.winner().is_none() {
                    return Err(refuse(
                        "the match has not ended: a transcript with no end settles nothing",
                    ));
                }
                applying.commit()?;
                transcript_outcome(&kept)?.encode()
            }
        }
    };
    let recognized = computed::match_occupant(
        &occupant,
        match_cell,
        crate::sdk::outcome_programs::registry(),
    )
    .map_err(|why| {
        refuse(format!(
            "the occupant is not recognized at the match cell: {why:?}"
        ))
    })?;
    let cells = kept.cells(set)?;
    let write = write_recorded(set, cells.match_routed(), &occupant).await?;
    if !write.reached_leader() {
        return Err(storage(
            "match cell",
            format!(
                "the cell's leader did not take the {:?} occupant; nothing is settled",
                String::from_utf8_lossy(recognized.label())
            ),
        ));
    }
    view(core, set, match_cell)
}

/// The whole transcript the wallet kept, up to the entry that ended it, with
/// each side's signature over the head of the last entry it made.
fn transcript_outcome(kept: &Kept) -> Result<TranscriptOutcome, DsmError> {
    let entries = store::entries(&kept.row.match_cell).map_err(|e| storage("kept entries", e))?;
    let mut signatures = Vec::new();
    for side in [MatchSide::A, MatchSide::B] {
        if let Some(last) = entries.iter().rev().find(|e| e.side == side_byte(side)) {
            signatures.push(SideSignature::new(side, &last.signature).map_err(refuse)?);
        }
    }
    TranscriptOutcome::new(
        *kept.y(),
        kept.table().clone(),
        &kept.row.setup,
        entries.into_iter().map(|e| e.entry).collect(),
        signatures,
    )
    .map_err(refuse)
}

// ── release ─────────────────────────────────────────────────────────────────

/// Release `vault_id`, a computed escrow vault, to this wallet: only once the
/// cells give a final outcome — a final Withdraw (`void`), or a final
/// occupant on a final Start — and only when that outcome's branch pays this
/// wallet. A release that could never realize is not built.
pub async fn release(
    core: &CoreSDK,
    set: &StorageSet,
    vault_id: &D32,
) -> Result<PositionOutcome, DsmError> {
    let accepted = &AcceptedGeneses::default();
    let outcome = {
        let standing = standing(core)?;
        let ctx = standing.context(set, accepted)?;
        let verifier = ctx.verifier();
        let (terms, _owner) = computed_terms_of(&verifier, vault_id)?;
        let view = MatchView::of(&read_cells(&verifier, &terms)?);
        let outcome = view
            .final_outcome()
            .ok_or_else(|| storage("computed cells", "no outcome is final at the match yet"))?;
        let branch = terms
            .branch(&outcome)
            .ok_or_else(|| refuse("the outcome names no branch of the vault's terms"))?;
        if *branch.recipient_genesis() != standing.genesis
            || *branch.recipient_device_id() != standing.device_id
        {
            return Err(refuse(format!(
                "the outcome {:?} pays another identity",
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
        outcome
    };
    crate::sdk::escrow_flow::exercise_release(core, set, vault_id, outcome).await
}
