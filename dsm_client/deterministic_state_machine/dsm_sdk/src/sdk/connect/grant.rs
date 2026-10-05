// SPDX-License-Identifier: MIT OR Apache-2.0

//! What a grant lets an application ask for without the player (DSM
//! Amendment A11). The grant is the player's consent, never a validity rule:
//! a request it covers is carried out through exactly the routes the player
//! would use by hand, and every predicate still decides what is constructed.
//!
//! Pure functions over typed scopes; the wallet's own state (what a grant has
//! spent, which tokens the application issued) is passed in.

use std::collections::BTreeSet;

use dsm::types::proto as generated;

use super::d32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ScopeKind {
    AcceptIssued,
    Pay,
    Swap,
    Holdings,
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
    /// PAY and SWAP: the tokens it may spend and how much. Otherwise empty.
    pub caps: Vec<Cap>,
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
        _ => Err(format!("scope kind {kind} is not one this wallet knows")),
    }
}

fn kind_to_wire(kind: ScopeKind) -> generated::ConnectScopeKind {
    match kind {
        ScopeKind::AcceptIssued => generated::ConnectScopeKind::AcceptIssued,
        ScopeKind::Pay => generated::ConnectScopeKind::Pay,
        ScopeKind::Swap => generated::ConnectScopeKind::Swap,
        ScopeKind::Holdings => generated::ConnectScopeKind::Holdings,
    }
}

/// Scopes read from the wire, each checked for its shape:
/// - a SWAP names exactly two distinct tokens and caps only those;
/// - a PAY or SWAP caps at least one token, each once, with
///   `0 < per_request ≤ total`;
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
        let scope = Scope {
            kind,
            policy_commits,
            caps,
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
            },
            Scope {
                kind: ScopeKind::Pay,
                policy_commits: vec![],
                caps: vec![Cap {
                    policy_commit: WILD,
                    per_request: 10,
                    total: 30,
                }],
            },
            Scope {
                kind: ScopeKind::Swap,
                policy_commits: vec![WILD, ERA],
                caps: vec![Cap {
                    policy_commit: ERA,
                    per_request: 500,
                    total: 1_000,
                }],
            },
            Scope {
                kind: ScopeKind::Holdings,
                policy_commits: vec![WILD],
                caps: vec![],
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
}
