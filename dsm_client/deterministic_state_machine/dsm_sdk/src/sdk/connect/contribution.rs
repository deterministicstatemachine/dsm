// SPDX-License-Identifier: MIT OR Apache-2.0

//! The contribution template (DSM Amendment A35): the escrow terms a wallet
//! builds for an amount a connected application asks it to commit.
//!
//! The application names what the amount is committed to, the object and the
//! amount. It never names a branch, a signer or a recipient: the wallet
//! builds every contribution from one fixed outcome table, and both of its
//! outcomes pay the vault's own owner.
//!
//! | outcome    | decided by      | pays                  |
//! |------------|-----------------|-----------------------|
//! | `return`   | the application | the vault's own owner |
//! | `withdraw` | the owner       | the vault's own owner |
//!
//! The application can decide when the owner gets the amount back, never who
//! gets it. This is the match template's boundary (Amendment A12) with no
//! branch that pays anyone else, and the match template is unchanged beside
//! it. Nothing here is Core's: the vault, the verdict cell and the release
//! are SoFi Amendment S21's.
//!
//! The outcome table names the owner's key, so each owner's contributions to
//! one commitment settle at that owner's own verdict cell
//! ([`verdict_cell`]). A reader that knows the owners' keys derives every
//! one of those cells and finds the vaults there.

use dsm::sofi::escrow;
use dsm::sofi::wire::{EscrowBranch, EscrowOutcome, EscrowSigner, EscrowTerms};

use super::wager::{Player, Referee};

pub const RETURN: &[u8] = b"return";
pub const WITHDRAW: &[u8] = b"withdraw";

fn decided(outcome: &[u8], by: &EscrowSigner) -> Result<EscrowOutcome, String> {
    EscrowOutcome::new(outcome, vec![by.clone()])
        .map_err(|e| format!("the {:?} outcome: {e:?}", String::from_utf8_lossy(outcome)))
}

/// The branches of the contribution `owner` holds under `application`, in
/// the table's one order. The application is never the owner: the two
/// outcomes are decided by two parties.
pub fn branches(owner: &Player, application: &Referee) -> Result<Vec<EscrowBranch>, String> {
    if owner.device_id == application.device_id || owner.signer == application.signer {
        return Err("the application cannot hold a contribution it decides".into());
    }
    Ok(vec![
        EscrowBranch::new(
            decided(RETURN, &application.signer)?,
            owner.genesis,
            owner.device_id,
        ),
        EscrowBranch::new(
            decided(WITHDRAW, &owner.signer)?,
            owner.genesis,
            owner.device_id,
        ),
    ])
}

/// The terms of `owner`'s contribution of `token` to the commitment
/// `external`.
pub fn terms(
    external: &[u8],
    token: [u8; 32],
    owner: &Player,
    application: &Referee,
) -> Result<EscrowTerms, String> {
    EscrowTerms::new(
        token,
        escrow::external_commitment(external),
        branches(owner, application)?,
    )
    .map_err(|e| format!("the contribution's terms: {e:?}"))
}

/// The verdict cell every contribution of the owner signing with `owner` to
/// the commitment `external` settles at, whatever object it holds. It needs
/// only the two keys, so anyone who knows a commitment's owners finds their
/// vaults (`escrow::cell_locator`).
pub fn verdict_cell(
    external: &[u8],
    owner: &EscrowSigner,
    application: &EscrowSigner,
) -> Result<[u8; 32], String> {
    let table = dsm::sofi::wire::OutcomeTable::new(vec![
        decided(RETURN, application)?,
        decided(WITHDRAW, owner)?,
    ])
    .map_err(|e| format!("the contribution's outcome table: {e:?}"))?;
    Ok(escrow::verdict_cell_key(
        &escrow::external_commitment(external),
        &escrow::table_digest(&table),
    ))
}

/// Whether the vault `(owner_genesis, owner_device_id)` holds under
/// `branches_held` is a contribution `application` returns: its terms are
/// exactly the template's for its owner. The owner's key is read from the
/// terms (the one key deciding `withdraw`) and the template rebuilt from it,
/// so any other branch, signer or recipient makes it another agreement.
/// The owner's key it was built for, for a reader that checks it against
/// the owner it expects.
pub fn is_contribution_of(
    owner_genesis: &[u8; 32],
    owner_device_id: &[u8; 32],
    branches_held: &[EscrowBranch],
    application: &Referee,
) -> Result<EscrowSigner, String> {
    let withdraw = branches_held
        .iter()
        .find(|b| b.outcome() == WITHDRAW)
        .ok_or("its terms have no \"withdraw\" outcome")?;
    let [owner_key] = withdraw.signers() else {
        return Err("its withdraw is not decided by one key".into());
    };
    let owner = Player {
        genesis: *owner_genesis,
        device_id: *owner_device_id,
        signer: owner_key.clone(),
    };
    if branches(&owner, application)?.as_slice() != branches_held {
        return Err("its terms are not the contribution template this application returns".into());
    }
    Ok(owner.signer)
}

#[cfg(test)]
mod tests {
    use super::super::grant::Side;
    use super::super::wager;
    use super::*;

    fn key() -> EscrowSigner {
        let (public_key, _) =
            dsm::crypto::sphincs::generate_sphincs_keypair().expect("a SPHINCS+ key pair");
        wager::signer(&public_key).expect("a device key")
    }

    fn player(n: u8) -> Player {
        Player {
            genesis: [n; 32],
            device_id: [n + 100; 32],
            signer: key(),
        }
    }

    fn application() -> Referee {
        Referee {
            device_id: [200; 32],
            signer: key(),
        }
    }

    /// `(outcome, signers, recipient genesis, recipient device)` per branch.
    type Row = (Vec<u8>, Vec<EscrowSigner>, [u8; 32], [u8; 32]);

    fn table(branches: &[EscrowBranch]) -> Vec<Row> {
        branches
            .iter()
            .map(|b| {
                (
                    b.outcome().to_vec(),
                    b.signers().to_vec(),
                    *b.recipient_genesis(),
                    *b.recipient_device_id(),
                )
            })
            .collect()
    }

    /// A12's boundary: every outcome pays the vault's owner and nobody else,
    /// the application decides one and the owner the other.
    #[test]
    fn both_outcomes_pay_the_owner_and_nobody_else() {
        let (owner, app) = (player(1), application());
        let held = branches(&owner, &app).expect("a contribution");
        assert_eq!(
            table(&held),
            vec![
                (
                    RETURN.to_vec(),
                    vec![app.signer.clone()],
                    owner.genesis,
                    owner.device_id
                ),
                (
                    WITHDRAW.to_vec(),
                    vec![owner.signer.clone()],
                    owner.genesis,
                    owner.device_id
                ),
            ]
        );
        let t = terms(b"faction 4 / tower 9", [3; 32], &owner, &app).expect("terms");
        assert_eq!(t.branches(), held.as_slice());
        assert_eq!(t.token(), &[3; 32]);
        assert_eq!(
            t.external_commitment(),
            &escrow::external_commitment(b"faction 4 / tower 9")
        );
    }

    #[test]
    fn the_application_never_holds_a_contribution_it_decides() {
        let app = application();
        let as_app = Player {
            device_id: app.device_id,
            ..player(1)
        };
        branches(&as_app, &app).expect_err("the application's own device");
        let with_app_key = Player {
            signer: app.signer.clone(),
            ..player(1)
        };
        branches(&with_app_key, &app).expect_err("the application's own key");
    }

    /// One owner's contributions to one commitment share a cell whatever
    /// they hold; another owner, another commitment or another application
    /// is another cell, and the cell is derived from the keys alone.
    #[test]
    fn a_contributions_cell_is_the_commitment_the_owner_and_the_application() {
        let (a, b, app) = (player(1), player(2), application());
        let x = b"faction 4 / tower 9";
        let steel = terms(x, [3; 32], &a, &app).expect("steel");
        let stone = terms(x, [4; 32], &a, &app).expect("stone");
        let cell = escrow::verdict_cell_of(&steel);
        assert_eq!(escrow::verdict_cell_of(&stone), cell);
        assert_eq!(verdict_cell(x, &a.signer, &app.signer), Ok(cell));

        let of_b = terms(x, [3; 32], &b, &app).expect("B's steel");
        assert_ne!(escrow::verdict_cell_of(&of_b), cell);
        assert_eq!(
            verdict_cell(x, &b.signer, &app.signer),
            Ok(escrow::verdict_cell_of(&of_b))
        );
        let elsewhere = terms(b"faction 4 / wall 2", [3; 32], &a, &app).expect("a wall");
        assert_ne!(escrow::verdict_cell_of(&elsewhere), cell);
        let other_app = terms(x, [3; 32], &a, &application()).expect("another application");
        assert_ne!(escrow::verdict_cell_of(&other_app), cell);
    }

    #[test]
    fn a_vault_is_a_contribution_only_when_its_terms_are_the_template() {
        let (a, b, app) = (player(1), player(2), application());
        let held = branches(&a, &app).expect("A's contribution");
        assert_eq!(
            is_contribution_of(&a.genesis, &a.device_id, &held, &app),
            Ok(a.signer.clone())
        );
        is_contribution_of(&a.genesis, &a.device_id, &held, &application())
            .expect_err("another application's contribution");
        is_contribution_of(&b.genesis, &b.device_id, &held, &app)
            .expect_err("A's terms held by B: they pay A");

        let pays_b = |outcome: &[u8], by: &EscrowSigner| {
            EscrowBranch::new(
                EscrowOutcome::new(outcome, vec![by.clone()]).expect("an outcome"),
                b.genesis,
                b.device_id,
            )
        };
        let mut return_pays_b = held.clone();
        return_pays_b[0] = pays_b(RETURN, &app.signer);
        is_contribution_of(&a.genesis, &a.device_id, &return_pays_b, &app)
            .expect_err("a return paying someone else");
        let mut withdraw_pays_b = held.clone();
        withdraw_pays_b[1] = pays_b(WITHDRAW, &a.signer);
        is_contribution_of(&a.genesis, &a.device_id, &withdraw_pays_b, &app)
            .expect_err("a withdraw paying someone else");

        let mut extra = held.clone();
        extra.push(pays_b(b"z-take", &app.signer));
        is_contribution_of(&a.genesis, &a.device_id, &extra, &app)
            .expect_err("a third outcome the application decides for someone else");

        let mut app_decides_both = held.clone();
        app_decides_both[1] = EscrowBranch::new(
            EscrowOutcome::new(WITHDRAW, vec![app.signer.clone()]).expect("an outcome"),
            a.genesis,
            a.device_id,
        );
        is_contribution_of(&a.genesis, &a.device_id, &app_decides_both, &app)
            .expect_err("a withdraw the application decides");

        let mut two_keys = vec![a.signer.clone(), b.signer.clone()];
        two_keys.sort_by_key(EscrowSigner::canonical);
        let mut joint = held.clone();
        joint[1] = EscrowBranch::new(
            EscrowOutcome::new(WITHDRAW, two_keys).expect("an outcome"),
            a.genesis,
            a.device_id,
        );
        is_contribution_of(&a.genesis, &a.device_id, &joint, &app)
            .expect_err("a withdraw that needs a second key");
    }

    /// The two templates are two agreements: a match is never read as a
    /// contribution, nor a contribution as a match, and the match template
    /// builds what it built before.
    #[test]
    fn a_contribution_is_never_a_match_and_a_match_never_a_contribution() {
        let (a, b, app) = (player(1), player(2), application());
        let stake = wager::branches(Side::A, &a, &b, &app).expect("A's stake");
        is_contribution_of(&a.genesis, &a.device_id, &stake, &app)
            .expect_err("a match stake read as a contribution");
        let held = branches(&a, &app).expect("A's contribution");
        wager::is_match_of(&a.genesis, &a.device_id, &held, &a, &app)
            .expect_err("a contribution read as a match");
        let outcomes: Vec<&[u8]> = stake.iter().map(|b| b.outcome()).collect();
        assert_eq!(
            outcomes,
            [wager::A_WINS, wager::B_WINS, wager::CANCEL, wager::VOID]
        );
    }
}
