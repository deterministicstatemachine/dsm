// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a grant lets an application ask for without the player (DSM
//! Amendment A11). The grant is the player's consent, never a validity rule:
//! a request it covers is carried out through exactly the routes the player
//! would use by hand, and every predicate still decides what is constructed.
//!
//! Pure functions over typed scopes; the wallet's own state (what a grant has
//! spent, which tokens the application issued) is passed in.

use std::collections::BTreeSet;

use dsm::sofi::wire::EscrowSigner;
use dsm::types::proto as generated;

use super::d32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeKind {
    AcceptIssued,
    Pay,
    Swap,
    Holdings,
    /// Lock stakes in matches the application decides, and collect their
    /// results (DSM Amendment A12). Capped as a payment scope is.
    Escrow,
    /// Stake in matches a pinned program decides, sign this wallet's moves,
    /// settle and collect (SoFi Amendment S22). Capped as a payment scope
    /// is, and only for the programs it names.
    Duel,
}

/// A cap on one token, in its base units.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cap {
    pub policy_commit: [u8; 32],
    pub per_request: u64,
    pub total: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    pub kind: ScopeKind,
    /// SWAP: the pair. HOLDINGS: the tokens the application may ask about
    /// besides the objects it issued. Otherwise empty.
    pub policy_commits: Vec<[u8; 32]>,
    /// PAY, SWAP, ESCROW and DUEL: the tokens it may spend (ESCROW, DUEL:
    /// lock) and how much. Otherwise empty.
    pub caps: Vec<Cap>,
    /// DUEL: the outcome programs, by hash, whose matches it may stake in.
    /// Otherwise empty.
    pub programs: Vec<[u8; 32]>,
}

impl Scope {
    fn cap(&self, policy_commit: &[u8; 32]) -> Option<&Cap> {
        self.caps.iter().find(|c| &c.policy_commit == policy_commit)
    }

    fn pair(&self) -> BTreeSet<[u8; 32]> {
        self.policy_commits.iter().copied().collect()
    }
}

fn kind_from_wire(kind: i32) -> Result<ScopeKind, String> {
    match generated::ConnectScopeKind::try_from(kind) {
        Ok(generated::ConnectScopeKind::AcceptIssued) => Ok(ScopeKind::AcceptIssued),
        Ok(generated::ConnectScopeKind::Pay) => Ok(ScopeKind::Pay),
        Ok(generated::ConnectScopeKind::Swap) => Ok(ScopeKind::Swap),
        Ok(generated::ConnectScopeKind::Holdings) => Ok(ScopeKind::Holdings),
        Ok(generated::ConnectScopeKind::Escrow) => Ok(ScopeKind::Escrow),
        Ok(generated::ConnectScopeKind::Duel) => Ok(ScopeKind::Duel),
        _ => Err(format!("scope kind {kind} is not one this wallet knows")),
    }
}

fn kind_to_wire(kind: ScopeKind) -> generated::ConnectScopeKind {
    match kind {
        ScopeKind::AcceptIssued => generated::ConnectScopeKind::AcceptIssued,
        ScopeKind::Pay => generated::ConnectScopeKind::Pay,
        ScopeKind::Swap => generated::ConnectScopeKind::Swap,
        ScopeKind::Holdings => generated::ConnectScopeKind::Holdings,
        ScopeKind::Escrow => generated::ConnectScopeKind::Escrow,
        ScopeKind::Duel => generated::ConnectScopeKind::Duel,
    }
}

/// Scopes read from the wire, each checked for its shape:
/// - a SWAP names exactly two distinct tokens and caps only those;
/// - a PAY, SWAP, ESCROW or DUEL caps at least one token, each once, with
///   `0 < per_request ≤ total`, and only a SWAP names a pair;
/// - a DUEL names at least one program, each once, and only a DUEL names
///   programs;
/// - ACCEPT_ISSUED and HOLDINGS carry no caps, and only HOLDINGS and SWAP
///   name tokens;
/// - no two scopes cover the same thing (one of each kind, one SWAP per pair).
pub fn scopes_from_wire(wire: &[generated::ConnectScopeV1]) -> Result<Vec<Scope>, String> {
    let mut scopes: Vec<Scope> = Vec::with_capacity(wire.len());
    for w in wire {
        let kind = kind_from_wire(w.kind)?;
        let mut policy_commits = Vec::with_capacity(w.policy_commits.len());
        for c in &w.policy_commits {
            let c = d32(c, "a scope's token")?;
            if policy_commits.contains(&c) {
                return Err("a scope names one token twice".into());
            }
            policy_commits.push(c);
        }
        let mut caps: Vec<Cap> = Vec::with_capacity(w.caps.len());
        for c in &w.caps {
            let policy_commit = d32(&c.policy_commit, "a cap's token")?;
            if caps.iter().any(|k| k.policy_commit == policy_commit) {
                return Err("a scope caps one token twice".into());
            }
            if c.per_request == 0 || c.per_request > c.total {
                return Err("a cap needs 0 < per request ≤ total".into());
            }
            caps.push(Cap {
                policy_commit,
                per_request: c.per_request,
                total: c.total,
            });
        }
        let mut programs = Vec::with_capacity(w.programs.len());
        for p in &w.programs {
            let p = d32(p, "a scope's program")?;
            if programs.contains(&p) {
                return Err("a scope names one program twice".into());
            }
            programs.push(p);
        }
        if kind != ScopeKind::Duel && !programs.is_empty() {
            return Err("only a duel scope names outcome programs".into());
        }
        let scope = Scope {
            kind,
            policy_commits,
            caps,
            programs,
        };
        match kind {
            ScopeKind::AcceptIssued => {
                if !scope.policy_commits.is_empty() || !scope.caps.is_empty() {
                    return Err("an accept-issued scope names no tokens and no caps".into());
                }
            }
            ScopeKind::Holdings => {
                if !scope.caps.is_empty() {
                    return Err("a holdings scope spends nothing".into());
                }
            }
            ScopeKind::Pay => {
                if !scope.policy_commits.is_empty() || scope.caps.is_empty() {
                    return Err(
                        "a pay scope caps the tokens it may pay, and names no others".into(),
                    );
                }
            }
            ScopeKind::Escrow => {
                if !scope.policy_commits.is_empty() || scope.caps.is_empty() {
                    return Err(
                        "an escrow scope caps the tokens it may lock, and names no others".into(),
                    );
                }
            }
            ScopeKind::Duel => {
                if !scope.policy_commits.is_empty()
                    || scope.caps.is_empty()
                    || scope.programs.is_empty()
                {
                    return Err(
                        "a duel scope caps the tokens it may stake and names the programs its \
                         matches are decided by"
                            .into(),
                    );
                }
            }
            ScopeKind::Swap => {
                if scope.policy_commits.len() != 2 || scope.caps.is_empty() {
                    return Err("a swap scope names its pair and caps what it may spend".into());
                }
                if scope
                    .caps
                    .iter()
                    .any(|c| !scope.policy_commits.contains(&c.policy_commit))
                {
                    return Err("a swap scope caps only the tokens of its pair".into());
                }
            }
        }
        let overlaps = scopes.iter().any(|s| {
            s.kind == scope.kind && (scope.kind != ScopeKind::Swap || s.pair() == scope.pair())
        });
        if overlaps {
            return Err("two scopes cover the same thing".into());
        }
        scopes.push(scope);
    }
    Ok(scopes)
}

pub fn scopes_to_wire(scopes: &[Scope]) -> Vec<generated::ConnectScopeV1> {
    scopes
        .iter()
        .map(|s| generated::ConnectScopeV1 {
            kind: kind_to_wire(s.kind) as i32,
            policy_commits: s.policy_commits.iter().map(|c| c.to_vec()).collect(),
            caps: s
                .caps
                .iter()
                .map(|c| generated::ConnectCapV1 {
                    policy_commit: c.policy_commit.to_vec(),
                    per_request: c.per_request,
                    total: c.total,
                })
                .collect(),
            programs: s.programs.iter().map(|p| p.to_vec()).collect(),
        })
        .collect()
}

/// Whether `granted` is never wider than `asked`: every granted scope is an
/// asked scope of its kind (the same pair, for a swap), naming no token the
/// asked one does not, capping only tokens it caps, never above its caps.
pub fn narrows(asked: &[Scope], granted: &[Scope]) -> Result<(), String> {
    for g in granted {
        let a = asked
            .iter()
            .find(|a| a.kind == g.kind && (g.kind != ScopeKind::Swap || a.pair() == g.pair()))
            .ok_or_else(|| {
                format!(
                    "the grant covers {:?}, which the offer did not ask for",
                    g.kind
                )
            })?;
        if g.kind != ScopeKind::Swap
            && g.policy_commits
                .iter()
                .any(|c| !a.policy_commits.contains(c))
        {
            return Err(format!(
                "the {:?} grant names a token the offer did not",
                g.kind
            ));
        }
        if g.programs.iter().any(|p| !a.programs.contains(p)) {
            return Err(format!(
                "the {:?} grant names a program the offer did not",
                g.kind
            ));
        }
        for cap in &g.caps {
            let asked_cap = a
                .cap(&cap.policy_commit)
                .ok_or_else(|| format!("the {:?} grant caps a token the offer did not", g.kind))?;
            if cap.per_request > asked_cap.per_request || cap.total > asked_cap.total {
                return Err(format!(
                    "the {:?} grant is wider than the offer asked",
                    g.kind
                ));
            }
        }
    }
    Ok(())
}

/// The longest match bytes `X` a lock may name.
pub const MAX_MATCH_BYTES: usize = 256;

/// How many vaults one collect may name: a match has two stakes.
pub const MAX_COLLECTED_VAULTS: usize = 2;

/// Which side of a match a wallet plays (DSM Amendment A12).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Side {
    A,
    B,
}

impl Side {
    pub fn other(self) -> Side {
        match self {
            Side::A => Side::B,
            Side::B => Side::A,
        }
    }
}

/// The other player of a match, as the application names it: the identity
/// its branch pays and the key that, with this wallet's, decides a cancel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Opponent {
    pub genesis: [u8; 32],
    pub device_id: [u8; 32],
    pub signer: EscrowSigner,
}

/// A stake to lock for a match (DSM Amendment A12). It names no branch,
/// signer or recipient: the wallet builds the terms from its own template
/// (`super::wager`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EscrowLock {
    /// `X`, the match's agreed bytes; the vault commits only `Y`.
    pub external: Vec<u8>,
    pub policy_commit: [u8; 32],
    pub amount: u64,
    pub side: Side,
    pub opponent: Opponent,
    /// Side B: side A's vault, which this lock is made against. Side A: none.
    pub counterpart: Option<[u8; 32]>,
    pub memo: String,
}

/// A stake to lock in a computed match (SoFi Amendment S22). The wallet
/// builds the terms itself from the setup; the request names no branch or
/// recipient.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelLock {
    /// The canonical setup both wallets lock.
    pub setup: Vec<u8>,
    /// `P`, as the setup pins it: what the grant's programs are checked
    /// against. Read for its shape only; the wallet reads the whole setup
    /// with the program it registered before it locks anything.
    pub program: [u8; 32],
    pub side: Side,
    pub policy_commit: [u8; 32],
    pub amount: u64,
    pub opponent_genesis: [u8; 32],
    pub opponent_device_id: [u8; 32],
    /// The other side's vault, when it locked first.
    pub counterpart: Option<[u8; 32]>,
    pub memo: String,
    /// The opponent's proof of holding the creatures it fields, as relayed
    /// (`HoldingsProofV1` bytes). Checked by the wallet when it locks; a lock
    /// without it locks nothing.
    pub opponent_holdings: Option<Vec<u8>>,
}

/// An entry of a computed match and its side's signature over its head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuelSigned {
    pub entry: Vec<u8>,
    pub signature: Vec<u8>,
}

/// A request, read from its signed body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    AcceptIssued {
        anchor: [u8; 32],
    },
    Pay {
        policy_commit: [u8; 32],
        amount: u64,
        memo: String,
    },
    Quote {
        token_in: [u8; 32],
        token_out: [u8; 32],
        amount_in: u64,
    },
    Swap {
        token_in: [u8; 32],
        token_out: [u8; 32],
        amount_in: u64,
        min_amount_out: u64,
    },
    Holdings {
        policy_commits: Vec<[u8; 32]>,
    },
    EscrowLock(EscrowLock),
    /// Collect a match result: release each vault to this wallet.
    EscrowRelease {
        vault_ids: Vec<[u8; 32]>,
    },
    /// This wallet's session public key for a match nonce.
    DuelSessionKey {
        match_nonce: [u8; 32],
    },
    DuelLock(DuelLock),
    /// Ready for the match; with the other side's ready, write the Start.
    DuelReady {
        match_cell: [u8; 32],
        opponent_ready: Option<Vec<u8>>,
    },
    DuelWithdraw {
        match_cell: [u8; 32],
    },
    /// Sign this wallet's next entry after the other side's `preceding`.
    DuelSign {
        match_cell: [u8; 32],
        preceding: Vec<DuelSigned>,
        entry: Vec<u8>,
    },
    DuelSettle {
        match_cell: [u8; 32],
        entries: Vec<DuelSigned>,
    },
    /// Collect a computed match's result.
    DuelCollect {
        vault_ids: Vec<[u8; 32]>,
    },
}

/// The longest setup a duel lock carries.
pub const MAX_SETUP_BYTES: usize = dsm::sofi::wire::COMPUTED_MAX_SETUP_BYTES;

/// The most signed entries one duel request carries: a transcript's bound.
pub const MAX_DUEL_ENTRIES: usize = dsm::sofi::wire::TRANSCRIPT_MAX_ENTRIES;

fn duel_lock_from_wire(r: &generated::ConnectDuelLockV1) -> Result<DuelLock, String> {
    if r.setup.is_empty() || r.setup.len() > MAX_SETUP_BYTES {
        return Err(format!(
            "a match setup is 1 to {MAX_SETUP_BYTES} bytes, not {}",
            r.setup.len()
        ));
    }
    if r.amount == 0 {
        return Err("a stake must be positive".into());
    }
    let side = match r.side {
        1 => Side::A,
        2 => Side::B,
        other => return Err(format!("side {other} is neither A (1) nor B (2)")),
    };
    let program = wildstate_duel::DuelSetupV1::decode(&r.setup)
        .map_err(|e| format!("the match setup: {e}"))?
        .program;
    let counterpart = match r.counterpart_vault_id.as_slice() {
        [] => None,
        bytes => Some(d32(bytes, "the other side's vault")?),
    };
    Ok(DuelLock {
        setup: r.setup.clone(),
        program,
        side,
        policy_commit: d32(&r.policy_commit, "the stake's token")?,
        amount: r.amount,
        opponent_genesis: d32(&r.opponent_genesis, "the opponent's genesis")?,
        opponent_device_id: d32(&r.opponent_device_id, "the opponent's device id")?,
        counterpart,
        memo: r.memo.clone(),
        opponent_holdings: r
            .opponent_holdings
            .as_ref()
            .map(prost::Message::encode_to_vec),
    })
}

fn duel_entries(given: &[generated::ConnectDuelSignedEntryV1]) -> Result<Vec<DuelSigned>, String> {
    if given.len() > MAX_DUEL_ENTRIES {
        return Err(format!(
            "a duel request carries at most {MAX_DUEL_ENTRIES} entries, not {}",
            given.len()
        ));
    }
    given
        .iter()
        .map(|e| {
            if e.entry.is_empty() || e.signature.is_empty() {
                return Err("a signed entry carries its entry and its signature".to_string());
            }
            Ok(DuelSigned {
                entry: e.entry.clone(),
                signature: e.signature.clone(),
            })
        })
        .collect()
}

fn vault_list(given: &[Vec<u8>]) -> Result<Vec<[u8; 32]>, String> {
    let mut vault_ids = Vec::with_capacity(given.len());
    for v in given {
        let v = d32(v, "a vault")?;
        if vault_ids.contains(&v) {
            return Err("a collect names one vault twice".into());
        }
        vault_ids.push(v);
    }
    if vault_ids.is_empty() || vault_ids.len() > MAX_COLLECTED_VAULTS {
        return Err(format!(
            "a collect names 1 to {MAX_COLLECTED_VAULTS} vaults, not {}",
            vault_ids.len()
        ));
    }
    Ok(vault_ids)
}

/// A lock's fields read and checked for their shape: `X` of 1 to
/// [`MAX_MATCH_BYTES`] bytes, a positive amount, side 1 (A) or 2 (B), an
/// opponent whose key is a declared signing key, and a counterpart vault
/// exactly when the wallet plays side B, which locks against side A's.
fn escrow_lock_from_wire(r: &generated::ConnectEscrowLockV1) -> Result<EscrowLock, String> {
    if r.external.is_empty() || r.external.len() > MAX_MATCH_BYTES {
        return Err(format!(
            "a match's agreed bytes are 1 to {MAX_MATCH_BYTES} bytes, not {}",
            r.external.len()
        ));
    }
    if r.amount == 0 {
        return Err("a stake must be positive".into());
    }
    let side = match r.side {
        1 => Side::A,
        2 => Side::B,
        other => return Err(format!("side {other} is neither A (1) nor B (2)")),
    };
    let signer = super::wager::signer(&r.opponent_signing_key)
        .map_err(|e| format!("the opponent's key: {e}"))?;
    let opponent = Opponent {
        genesis: d32(&r.opponent_genesis, "the opponent's genesis")?,
        device_id: d32(&r.opponent_device_id, "the opponent's device id")?,
        signer,
    };
    let counterpart = match (side, r.counterpart_vault_id.as_slice()) {
        (Side::A, []) => None,
        (Side::A, ..) => return Err("side A locks first and names no vault".into()),
        (Side::B, []) => return Err("side B locks against side A's vault and must name it".into()),
        (Side::B, bytes) => Some(d32(bytes, "side A's vault")?),
    };
    Ok(EscrowLock {
        external: r.external.clone(),
        policy_commit: d32(&r.policy_commit, "the stake's token")?,
        amount: r.amount,
        side,
        opponent,
        counterpart,
        memo: r.memo.clone(),
    })
}

pub fn request_from_wire(body: &generated::AppRequestBodyV1) -> Result<Request, String> {
    use generated::app_request_body_v1::Kind;
    let pair = |a: &[u8], b: &[u8]| -> Result<([u8; 32], [u8; 32]), String> {
        let (a, b) = (d32(a, "token in")?, d32(b, "token out")?);
        if a == b {
            return Err("a swap's two tokens must differ".into());
        }
        Ok((a, b))
    };
    let positive = |amount: u64| -> Result<u64, String> {
        if amount == 0 {
            return Err("an amount must be positive".into());
        }
        Ok(amount)
    };
    match body.kind.as_ref() {
        Some(Kind::AcceptIssued(r)) => Ok(Request::AcceptIssued {
            anchor: d32(&r.anchor, "the anchor")?,
        }),
        Some(Kind::Pay(r)) => Ok(Request::Pay {
            policy_commit: d32(&r.policy_commit, "the token")?,
            amount: positive(r.amount)?,
            memo: r.memo.clone(),
        }),
        Some(Kind::Quote(r)) => {
            let (token_in, token_out) = pair(&r.token_in, &r.token_out)?;
            Ok(Request::Quote {
                token_in,
                token_out,
                amount_in: positive(r.amount_in)?,
            })
        }
        Some(Kind::Swap(r)) => {
            let (token_in, token_out) = pair(&r.token_in, &r.token_out)?;
            Ok(Request::Swap {
                token_in,
                token_out,
                amount_in: positive(r.amount_in)?,
                min_amount_out: r.min_amount_out,
            })
        }
        Some(Kind::Holdings(r)) => {
            let mut policy_commits = Vec::with_capacity(r.policy_commits.len());
            for c in &r.policy_commits {
                let c = d32(c, "a token")?;
                if policy_commits.contains(&c) {
                    return Err("a holdings request names one token twice".into());
                }
                policy_commits.push(c);
            }
            if policy_commits.is_empty() {
                return Err("a holdings request names no token".into());
            }
            Ok(Request::Holdings { policy_commits })
        }
        Some(Kind::EscrowLock(r)) => Ok(Request::EscrowLock(escrow_lock_from_wire(r)?)),
        Some(Kind::EscrowRelease(r)) => Ok(Request::EscrowRelease {
            vault_ids: vault_list(&r.vault_ids)?,
        }),
        Some(Kind::DuelSessionKey(r)) => Ok(Request::DuelSessionKey {
            match_nonce: d32(&r.match_nonce, "the match nonce")?,
        }),
        Some(Kind::DuelLock(r)) => Ok(Request::DuelLock(duel_lock_from_wire(r)?)),
        Some(Kind::DuelReady(r)) => Ok(Request::DuelReady {
            match_cell: d32(&r.match_cell, "the match cell")?,
            opponent_ready: match r.opponent_ready.as_slice() {
                [] => None,
                bytes => Some(bytes.to_vec()),
            },
        }),
        Some(Kind::DuelWithdraw(r)) => Ok(Request::DuelWithdraw {
            match_cell: d32(&r.match_cell, "the match cell")?,
        }),
        Some(Kind::DuelSign(r)) => {
            if r.entry.is_empty() {
                return Err("a sign request carries the entry to sign".into());
            }
            Ok(Request::DuelSign {
                match_cell: d32(&r.match_cell, "the match cell")?,
                preceding: duel_entries(&r.preceding)?,
                entry: r.entry.clone(),
            })
        }
        Some(Kind::DuelSettle(r)) => Ok(Request::DuelSettle {
            match_cell: d32(&r.match_cell, "the match cell")?,
            entries: duel_entries(&r.entries)?,
        }),
        Some(Kind::DuelCollect(r)) => Ok(Request::DuelCollect {
            vault_ids: vault_list(&r.vault_ids)?,
        }),
        None => Err("the request asks for nothing".into()),
    }
}

/// What the grant says about one request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Covered: carried out without asking. `spend` is what it counts
    /// against the grant's total once carried out.
    InScope { spend: Option<([u8; 32], u64)> },
    /// Not covered: it waits for the player, for this reason.
    Outside(String),
}

fn within(scope: &Scope, token: &[u8; 32], amount: u64, spent: u64) -> Decision {
    let Some(cap) = scope.cap(token) else {
        return Decision::Outside("the grant does not let it spend this token".into());
    };
    let shown = |n: u64| super::wallet::amount_text(token, n);
    if amount > cap.per_request {
        return Decision::Outside(format!(
            "{} is above the {} the grant allows per request",
            shown(amount),
            shown(cap.per_request)
        ));
    }
    match spent.checked_add(amount) {
        Some(after) if after <= cap.total => Decision::InScope {
            spend: Some((*token, amount)),
        },
        _ => Decision::Outside(format!(
            "{} more would pass the grant's total of {} ({} spent)",
            shown(amount),
            shown(cap.total),
            shown(spent)
        )),
    }
}

/// Decide `request` against `scopes`. `spent` is what the grant has already
/// spent of a token; `issued_by_app` holds the tokens whose committed policy
/// names the application's account as its creator.
pub fn decide(
    scopes: &[Scope],
    request: &Request,
    spent: &dyn Fn(&[u8; 32]) -> u64,
    issued_by_app: &BTreeSet<[u8; 32]>,
) -> Decision {
    let of_kind = |kind: ScopeKind| scopes.iter().filter(move |s| s.kind == kind);
    let swap_scope = |a: &[u8; 32], b: &[u8; 32]| {
        let pair: BTreeSet<[u8; 32]> = [*a, *b].into_iter().collect();
        of_kind(ScopeKind::Swap).find(|s| s.pair() == pair)
    };
    match request {
        Request::AcceptIssued { .. } => match of_kind(ScopeKind::AcceptIssued).next() {
            Some(..) => Decision::InScope { spend: None },
            None => Decision::Outside("the grant does not accept issued objects".into()),
        },
        Request::Pay {
            policy_commit,
            amount,
            ..
        } => match of_kind(ScopeKind::Pay).next() {
            Some(scope) => within(scope, policy_commit, *amount, spent(policy_commit)),
            None => Decision::Outside("the grant does not let it ask for payments".into()),
        },
        Request::Quote {
            token_in,
            token_out,
            ..
        } => match swap_scope(token_in, token_out) {
            Some(..) => Decision::InScope { spend: None },
            None => Decision::Outside("the grant does not cover this pair".into()),
        },
        Request::Swap {
            token_in,
            token_out,
            amount_in,
            ..
        } => match swap_scope(token_in, token_out) {
            Some(scope) => within(scope, token_in, *amount_in, spent(token_in)),
            None => Decision::Outside("the grant does not cover this pair".into()),
        },
        Request::Holdings { policy_commits } => match of_kind(ScopeKind::Holdings).next() {
            Some(scope) => {
                match policy_commits
                    .iter()
                    .find(|c| !scope.policy_commits.contains(c) && !issued_by_app.contains(*c))
                {
                    Some(..) => Decision::Outside(
                        "it asks about a token the grant does not let it see".into(),
                    ),
                    None => Decision::InScope { spend: None },
                }
            }
            None => Decision::Outside("the grant does not let it see holdings".into()),
        },
        Request::EscrowLock(lock) => match of_kind(ScopeKind::Escrow).next() {
            Some(scope) => within(
                scope,
                &lock.policy_commit,
                lock.amount,
                spent(&lock.policy_commit),
            ),
            None => Decision::Outside("the grant does not let it lock stakes".into()),
        },
        // A collect releases only to this wallet: it spends nothing.
        Request::EscrowRelease { .. } => match of_kind(ScopeKind::Escrow).next() {
            Some(..) => Decision::InScope { spend: None },
            None => Decision::Outside("the grant does not let it collect match results".into()),
        },
        // A stake is capped as a payment is, and only in a match whose
        // program the grant names.
        Request::DuelLock(lock) => match of_kind(ScopeKind::Duel).next() {
            Some(scope) if scope.programs.contains(&lock.program) => within(
                scope,
                &lock.policy_commit,
                lock.amount,
                spent(&lock.policy_commit),
            ),
            Some(..) => Decision::Outside(
                "the match is decided by a program the grant does not name".into(),
            ),
            None => Decision::Outside("the grant does not let it stake in matches".into()),
        },
        // Every other step of a match spends nothing and acts only on a match
        // this wallet locked under the grant: it runs without the player, so
        // a move never waits on a screen. The wallet's own checks still
        // decide what it signs and writes.
        Request::DuelSessionKey { .. }
        | Request::DuelReady { .. }
        | Request::DuelWithdraw { .. }
        | Request::DuelSign { .. }
        | Request::DuelSettle { .. }
        | Request::DuelCollect { .. } => match of_kind(ScopeKind::Duel).next() {
            Some(..) => Decision::InScope { spend: None },
            None => Decision::Outside("the grant does not let it play matches".into()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const WILD: [u8; 32] = [1; 32];
    const ERA: [u8; 32] = [2; 32];
    const OTHER: [u8; 32] = [3; 32];

    fn grant() -> Vec<Scope> {
        vec![
            Scope {
                kind: ScopeKind::AcceptIssued,
                policy_commits: vec![],
                caps: vec![],
                programs: vec![],
            },
            Scope {
                kind: ScopeKind::Pay,
                policy_commits: vec![],
                caps: vec![Cap {
                    policy_commit: WILD,
                    per_request: 10,
                    total: 30,
                }],
                programs: vec![],
            },
            Scope {
                kind: ScopeKind::Swap,
                policy_commits: vec![WILD, ERA],
                caps: vec![Cap {
                    policy_commit: ERA,
                    per_request: 500,
                    total: 1_000,
                }],
                programs: vec![],
            },
            Scope {
                kind: ScopeKind::Holdings,
                policy_commits: vec![WILD],
                caps: vec![],
                programs: vec![],
            },
        ]
    }

    fn nothing_spent(_: &[u8; 32]) -> u64 {
        0
    }

    #[test]
    fn a_grant_round_trips_through_the_wire() -> Result<(), String> {
        assert_eq!(scopes_from_wire(&scopes_to_wire(&grant()))?, grant());
        Ok(())
    }

    #[test]
    fn a_request_inside_the_grant_runs_and_counts_its_spend() {
        let pay = Request::Pay {
            policy_commit: WILD,
            amount: 3,
            memo: String::new(),
        };
        assert_eq!(
            decide(&grant(), &pay, &nothing_spent, &BTreeSet::new()),
            Decision::InScope {
                spend: Some((WILD, 3))
            }
        );
        let swap = Request::Swap {
            token_in: ERA,
            token_out: WILD,
            amount_in: 500,
            min_amount_out: 1,
        };
        assert_eq!(
            decide(&grant(), &swap, &nothing_spent, &BTreeSet::new()),
            Decision::InScope {
                spend: Some((ERA, 500))
            }
        );
    }

    #[test]
    fn a_request_past_a_cap_waits_for_the_player() {
        let over_one = Request::Pay {
            policy_commit: WILD,
            amount: 11,
            memo: String::new(),
        };
        assert!(matches!(
            decide(&grant(), &over_one, &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        let spent_28 = |c: &[u8; 32]| if *c == WILD { 28 } else { 0 };
        let three = Request::Pay {
            policy_commit: WILD,
            amount: 3,
            memo: String::new(),
        };
        assert!(matches!(
            decide(&grant(), &three, &spent_28, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        let spent_near_max = |_: &[u8; 32]| u64::MAX;
        assert!(matches!(
            decide(&grant(), &three, &spent_near_max, &BTreeSet::new()),
            Decision::Outside(..)
        ));
    }

    #[test]
    fn a_request_the_grant_does_not_name_waits_for_the_player() {
        let other_token = Request::Pay {
            policy_commit: ERA,
            amount: 1,
            memo: String::new(),
        };
        assert!(matches!(
            decide(&grant(), &other_token, &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        let other_pair = Request::Swap {
            token_in: ERA,
            token_out: OTHER,
            amount_in: 1,
            min_amount_out: 1,
        };
        assert!(matches!(
            decide(&grant(), &other_pair, &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        let wrong_side = Request::Swap {
            token_in: WILD,
            token_out: ERA,
            amount_in: 1,
            min_amount_out: 1,
        };
        assert!(
            matches!(
                decide(&grant(), &wrong_side, &nothing_spent, &BTreeSet::new()),
                Decision::Outside(..)
            ),
            "the grant caps only ERA in this pair"
        );
        let hidden = Request::Holdings {
            policy_commits: vec![WILD, OTHER],
        };
        assert!(matches!(
            decide(&grant(), &hidden, &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        let issued_other: BTreeSet<[u8; 32]> = [OTHER].into_iter().collect();
        assert_eq!(
            decide(&grant(), &hidden, &nothing_spent, &issued_other),
            Decision::InScope { spend: None },
            "the objects the application issued are always visible"
        );
        assert!(matches!(
            decide(
                &[],
                &Request::AcceptIssued { anchor: OTHER },
                &nothing_spent,
                &BTreeSet::new()
            ),
            Decision::Outside(..)
        ));
    }

    #[test]
    fn a_grant_is_never_wider_than_the_offer() {
        assert_eq!(narrows(&grant(), &grant()), Ok(()));
        let mut lower = grant();
        lower[1].caps[0].total = 20;
        assert_eq!(narrows(&grant(), &lower), Ok(()));
        let mut wider = grant();
        wider[1].caps[0].total = 31;
        narrows(&grant(), &wider).expect_err("must be refused");
        let mut more = grant();
        more[3].policy_commits.push(OTHER);
        narrows(&grant(), &more).expect_err("must be refused");
        narrows(&grant()[..1], &grant()).expect_err("a scope the offer never asked for");
    }

    #[test]
    fn a_malformed_scope_is_refused() {
        let mut w = scopes_to_wire(&grant());
        w[2].policy_commits.pop();
        scopes_from_wire(&w).expect_err("a swap of one token");
        let mut w = scopes_to_wire(&grant());
        w[1].caps[0].per_request = 31;
        scopes_from_wire(&w).expect_err("per request above total");
        let mut w = scopes_to_wire(&grant());
        w.push(w[1].clone());
        scopes_from_wire(&w).expect_err("two pay scopes");
        let mut w = scopes_to_wire(&grant());
        w[2].caps[0].policy_commit = OTHER.to_vec();
        scopes_from_wire(&w).expect_err("a swap capping a token outside its pair");
    }

    // ── the escrow scope (DSM Amendment A12) ──────────────────────────────

    fn escrow_grant() -> Vec<Scope> {
        vec![Scope {
            kind: ScopeKind::Escrow,
            policy_commits: vec![],
            caps: vec![Cap {
                policy_commit: WILD,
                per_request: 25,
                total: 60,
            }],
            programs: vec![],
        }]
    }

    /// A real SPHINCS+ public key, as `escrow.party` names a device's.
    fn signing_key() -> Vec<u8> {
        dsm::crypto::sphincs::generate_sphincs_keypair()
            .expect("a SPHINCS+ key pair")
            .0
    }

    fn lock_wire(amount: u64, side: u32, counterpart: &[u8]) -> generated::AppRequestBodyV1 {
        generated::AppRequestBodyV1 {
            session_id: vec![9; 32],
            seq: 1,
            kind: Some(generated::app_request_body_v1::Kind::EscrowLock(
                generated::ConnectEscrowLockV1 {
                    external: b"match 7".to_vec(),
                    policy_commit: WILD.to_vec(),
                    amount,
                    side,
                    opponent_genesis: vec![4; 32],
                    opponent_device_id: vec![5; 32],
                    opponent_signing_key: signing_key(),
                    counterpart_vault_id: counterpart.to_vec(),
                    memo: "best of three".into(),
                },
            )),
        }
    }

    fn lock(amount: u64) -> Request {
        request_from_wire(&lock_wire(amount, 1, &[])).expect("a side-A lock")
    }

    fn collect() -> Request {
        Request::EscrowRelease {
            vault_ids: vec![[6; 32], [7; 32]],
        }
    }

    #[test]
    fn an_escrow_scope_caps_what_it_may_lock_as_a_pay_scope_does() -> Result<(), String> {
        assert_eq!(
            scopes_from_wire(&scopes_to_wire(&escrow_grant()))?,
            escrow_grant()
        );
        let mut w = scopes_to_wire(&escrow_grant());
        w[0].caps.clear();
        scopes_from_wire(&w).expect_err("an escrow scope that caps nothing");
        let mut w = scopes_to_wire(&escrow_grant());
        w[0].policy_commits.push(ERA.to_vec());
        scopes_from_wire(&w).expect_err("an escrow scope naming a token it does not cap");
        let mut w = scopes_to_wire(&escrow_grant());
        w[0].caps[0].per_request = 61;
        scopes_from_wire(&w).expect_err("per request above total");
        let mut w = scopes_to_wire(&escrow_grant());
        w.push(w[0].clone());
        scopes_from_wire(&w).expect_err("two escrow scopes");
        let mut wider = escrow_grant();
        wider[0].caps[0].total = 61;
        narrows(&escrow_grant(), &wider).expect_err("a grant wider than the offer");
        narrows(&grant(), &escrow_grant()).expect_err("an escrow scope the offer never asked for");
        Ok(())
    }

    #[test]
    fn a_lock_within_the_escrow_caps_runs_and_counts_its_stake() {
        assert_eq!(
            decide(&escrow_grant(), &lock(25), &nothing_spent, &BTreeSet::new()),
            Decision::InScope {
                spend: Some((WILD, 25))
            }
        );
        let spent_35 = |c: &[u8; 32]| if *c == WILD { 35 } else { 0 };
        assert_eq!(
            decide(&escrow_grant(), &lock(25), &spent_35, &BTreeSet::new()),
            Decision::InScope {
                spend: Some((WILD, 25))
            },
            "35 spent and 25 more is the total exactly"
        );
    }

    #[test]
    fn a_lock_past_the_escrow_caps_waits_for_the_player() {
        assert!(matches!(
            decide(&escrow_grant(), &lock(26), &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        let spent_36 = |c: &[u8; 32]| if *c == WILD { 36 } else { 0 };
        assert!(matches!(
            decide(&escrow_grant(), &lock(25), &spent_36, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        let mut era_stake = lock_wire(1, 1, &[]);
        if let Some(generated::app_request_body_v1::Kind::EscrowLock(l)) = era_stake.kind.as_mut() {
            l.policy_commit = ERA.to_vec();
        }
        let era_stake = request_from_wire(&era_stake).expect("a lock of ERA");
        assert!(
            matches!(
                decide(
                    &escrow_grant(),
                    &era_stake,
                    &nothing_spent,
                    &BTreeSet::new()
                ),
                Decision::Outside(..)
            ),
            "the escrow scope caps only WILD"
        );
        assert!(
            matches!(
                decide(&grant(), &lock(1), &nothing_spent, &BTreeSet::new()),
                Decision::Outside(..)
            ),
            "a payment scope capping WILD lets nothing be locked"
        );
    }

    #[test]
    fn a_collect_is_in_scope_whenever_an_escrow_scope_stands() {
        let spent_all = |_: &[u8; 32]| 60;
        assert_eq!(
            decide(&escrow_grant(), &collect(), &spent_all, &BTreeSet::new()),
            Decision::InScope { spend: None },
            "a collect pays this wallet and spends nothing, even from a spent grant"
        );
        assert!(matches!(
            decide(&grant(), &collect(), &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
    }

    #[test]
    fn a_lock_names_its_side_and_side_as_vault_consistently() {
        let b = request_from_wire(&lock_wire(5, 2, &[8; 32])).expect("a side-B lock");
        let Request::EscrowLock(b) = b else {
            panic!("a lock read as another request");
        };
        assert_eq!((b.side, b.counterpart), (Side::B, Some([8; 32])));
        request_from_wire(&lock_wire(5, 1, &[8; 32])).expect_err("side A naming a vault");
        request_from_wire(&lock_wire(5, 2, &[])).expect_err("side B naming none");
        request_from_wire(&lock_wire(5, 0, &[])).expect_err("side 0");
        request_from_wire(&lock_wire(5, 3, &[])).expect_err("side 3");
        request_from_wire(&lock_wire(0, 1, &[])).expect_err("no stake");
        for external in [Vec::new(), vec![1; MAX_MATCH_BYTES + 1]] {
            let mut w = lock_wire(5, 1, &[]);
            if let Some(generated::app_request_body_v1::Kind::EscrowLock(l)) = w.kind.as_mut() {
                l.external = external;
            }
            request_from_wire(&w).expect_err("match bytes outside 1..=256");
        }
        let mut w = lock_wire(5, 1, &[]);
        if let Some(generated::app_request_body_v1::Kind::EscrowLock(l)) = w.kind.as_mut() {
            l.opponent_signing_key.pop();
        }
        request_from_wire(&w).expect_err("an opponent key of the wrong width");
        let release = |vault_ids: Vec<Vec<u8>>| generated::AppRequestBodyV1 {
            session_id: vec![9; 32],
            seq: 1,
            kind: Some(generated::app_request_body_v1::Kind::EscrowRelease(
                generated::ConnectEscrowReleaseV1 { vault_ids },
            )),
        };
        request_from_wire(&release(vec![])).expect_err("a collect of nothing");
        request_from_wire(&release(vec![vec![6; 32]; 2])).expect_err("one vault twice");
        request_from_wire(&release(vec![vec![6; 32], vec![7; 32], vec![8; 32]]))
            .expect_err("three vaults");
        assert_eq!(
            request_from_wire(&release(vec![vec![6; 32], vec![7; 32]])),
            Ok(collect())
        );
    }

    // ── the duel scope (SoFi Amendment S22) ───────────────────────────────

    fn program() -> [u8; 32] {
        wildstate_duel::program_hash()
    }

    fn duel_grant() -> Vec<Scope> {
        vec![Scope {
            kind: ScopeKind::Duel,
            policy_commits: vec![],
            caps: vec![Cap {
                policy_commit: WILD,
                per_request: 25,
                total: 60,
            }],
            programs: vec![program()],
        }]
    }

    /// A canonical setup of a frozen match, pinning `pinned`.
    fn setup_pinning(pinned: [u8; 32]) -> Vec<u8> {
        let set = wildstate_duel::vectors::DuelVectorSetV1::decode(wildstate_duel::VECTORS_V1)
            .expect("the vectors");
        wildstate_duel::DuelSetupV1 {
            program: pinned,
            body: set.vectors[0].body.clone(),
        }
        .encode()
    }

    fn duel_lock_wire(amount: u64, pinned: [u8; 32]) -> generated::AppRequestBodyV1 {
        generated::AppRequestBodyV1 {
            session_id: vec![9; 32],
            seq: 1,
            kind: Some(generated::app_request_body_v1::Kind::DuelLock(
                generated::ConnectDuelLockV1 {
                    setup: setup_pinning(pinned),
                    side: 1,
                    policy_commit: WILD.to_vec(),
                    amount,
                    opponent_genesis: vec![4; 32],
                    opponent_device_id: vec![5; 32],
                    counterpart_vault_id: Vec::new(),
                    memo: "best of one".into(),
                    // The grant decides whether a lock may run; the proof is
                    // the lock's own check (computed_flow::create).
                    opponent_holdings: None,
                },
            )),
        }
    }

    #[test]
    fn a_duel_scope_names_its_programs_and_caps_its_stakes() -> Result<(), String> {
        assert_eq!(
            scopes_from_wire(&scopes_to_wire(&duel_grant()))?,
            duel_grant()
        );
        let mut w = scopes_to_wire(&duel_grant());
        w[0].programs.clear();
        scopes_from_wire(&w).expect_err("a duel scope naming no program");
        let mut w = scopes_to_wire(&duel_grant());
        w[0].caps.clear();
        scopes_from_wire(&w).expect_err("a duel scope capping nothing");
        let mut w = scopes_to_wire(&duel_grant());
        w[0].programs.push(program().to_vec());
        scopes_from_wire(&w).expect_err("one program twice");
        let mut w = scopes_to_wire(&escrow_grant());
        w[0].programs.push(program().to_vec());
        scopes_from_wire(&w).expect_err("a program on an escrow scope");
        let mut other = duel_grant();
        other[0].programs = vec![[0x77; 32]];
        narrows(&duel_grant(), &other).expect_err("a program the offer did not name");
        narrows(&duel_grant(), &duel_grant())?;
        Ok(())
    }

    #[test]
    fn a_stake_runs_within_the_caps_only_for_a_named_program() {
        let lock = request_from_wire(&duel_lock_wire(25, program())).expect("a duel lock");
        assert_eq!(
            decide(&duel_grant(), &lock, &nothing_spent, &BTreeSet::new()),
            Decision::InScope {
                spend: Some((WILD, 25))
            }
        );
        let over = request_from_wire(&duel_lock_wire(26, program())).expect("a duel lock");
        assert!(matches!(
            decide(&duel_grant(), &over, &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        let elsewhere = request_from_wire(&duel_lock_wire(5, [0x66; 32])).expect("a duel lock");
        assert!(matches!(
            decide(&duel_grant(), &elsewhere, &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        assert!(matches!(
            decide(&escrow_grant(), &lock, &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        request_from_wire(&duel_lock_wire(0, program())).expect_err("no stake");
        let mut garbage = duel_lock_wire(5, program());
        if let Some(generated::app_request_body_v1::Kind::DuelLock(l)) = garbage.kind.as_mut() {
            l.setup.push(0);
        }
        request_from_wire(&garbage).expect_err("a setup that does not decode");
    }

    #[test]
    fn every_move_of_a_match_runs_without_the_player_under_a_duel_scope() {
        let sign = request_from_wire(&generated::AppRequestBodyV1 {
            session_id: vec![9; 32],
            seq: 2,
            kind: Some(generated::app_request_body_v1::Kind::DuelSign(
                generated::ConnectDuelSignV1 {
                    match_cell: vec![3; 32],
                    preceding: vec![generated::ConnectDuelSignedEntryV1 {
                        entry: vec![1, 2],
                        signature: vec![3],
                    }],
                    entry: vec![4],
                },
            )),
        })
        .expect("a sign request");
        let spent_all = |_: &[u8; 32]| 60;
        assert_eq!(
            decide(&duel_grant(), &sign, &spent_all, &BTreeSet::new()),
            Decision::InScope { spend: None },
            "a move spends nothing, even from a spent grant"
        );
        assert!(matches!(
            decide(&grant(), &sign, &nothing_spent, &BTreeSet::new()),
            Decision::Outside(..)
        ));
        let line = super::super::wallet::describe_scope(&duel_grant()[0], &Default::default());
        assert!(
            line.starts_with("Stake up to")
                && line.contains("in battles decided by program wildstate-duel v1 ("),
            "{line}"
        );
        assert!(line.ends_with("and play your moves"), "{line}");
    }
}
