// SPDX-License-Identifier: MIT OR Apache-2.0

//! The match template (DSM Amendment A12): the escrow terms a wallet builds
//! for a stake a connected application asks it to lock.
//!
//! The application picks the match, names the two players and the stake, and
//! decides the result. It never names a branch, a signer or a recipient: the
//! wallet builds every vault of a match from one fixed outcome table.
//!
//! | outcome  | decided by          | pays                  |
//! |----------|---------------------|-----------------------|
//! | `a-wins` | the application     | A                     |
//! | `b-wins` | the application     | B                     |
//! | `cancel` | A and B together    | the vault's own owner |
//! | `void`   | the application     | the vault's own owner |
//!
//! Both players' vaults commit the same `Y` and the same outcome table, so
//! they share one verdict cell and settle on one outcome (SoFi §19.9, "Linked
//! vaults"). Nothing here is Core's: the vault, the verdict cell and the
//! release are SoFi Amendment S21's, unchanged.

use dsm::sofi::escrow;
use dsm::sofi::wire::{EscrowBranch, EscrowOutcome, EscrowSigner, EscrowTerms};

use super::grant::Side;

pub const A_WINS: &[u8] = b"a-wins";
pub const B_WINS: &[u8] = b"b-wins";
pub const CANCEL: &[u8] = b"cancel";
pub const VOID: &[u8] = b"void";

/// A player of a match: the identity a branch pays and the key that, with
/// the other player's, decides a cancel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Player {
    pub genesis: [u8; 32],
    pub device_id: [u8; 32],
    pub signer: EscrowSigner,
}

/// The application deciding a match: its device and the key its connect
/// offer's card carries, the key its requests verify under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Referee {
    pub device_id: [u8; 32],
    pub signer: EscrowSigner,
}

/// `key` as an escrow signer of the device signing algorithm, the one every
/// wallet and application account signs with (`escrow.party`).
pub fn signer(key: &[u8]) -> Result<EscrowSigner, String> {
    EscrowSigner::new(crate::sdk::sofi_flow::SIGNATURE_ALG, key)
        .map_err(|e| format!("a signing key: {e:?}"))
}

fn same_identity(x: &Player, y: &Player) -> bool {
    x.device_id == y.device_id || x.genesis == y.genesis || x.signer == y.signer
}

fn is_referee(p: &Player, referee: &Referee) -> bool {
    p.device_id == referee.device_id || p.signer == referee.signer
}

/// The branches of the vault `owner` holds, playing `side` against `other`,
/// in the table's one order. Only the two players are ever paid, a refund
/// goes only to the vault's owner, and the two players are two identities,
/// neither of them the application.
pub fn branches(
    side: Side,
    owner: &Player,
    other: &Player,
    referee: &Referee,
) -> Result<Vec<EscrowBranch>, String> {
    if same_identity(owner, other) {
        return Err("the two players of a match must be two identities".into());
    }
    if is_referee(owner, referee) || is_referee(other, referee) {
        return Err("the application cannot be a player in a match it decides".into());
    }
    let (a, b) = match side {
        Side::A => (owner, other),
        Side::B => (other, owner),
    };
    let decided = |outcome: &[u8], signers: Vec<EscrowSigner>| {
        EscrowOutcome::new(outcome, signers)
            .map_err(|e| format!("the {:?} outcome: {e:?}", String::from_utf8_lossy(outcome)))
    };
    let mut players = vec![a.signer.clone(), b.signer.clone()];
    players.sort_by_key(EscrowSigner::canonical);
    let by_referee = || vec![referee.signer.clone()];
    Ok(vec![
        EscrowBranch::new(decided(A_WINS, by_referee())?, a.genesis, a.device_id),
        EscrowBranch::new(decided(B_WINS, by_referee())?, b.genesis, b.device_id),
        EscrowBranch::new(decided(CANCEL, players)?, owner.genesis, owner.device_id),
        EscrowBranch::new(decided(VOID, by_referee())?, owner.genesis, owner.device_id),
    ])
}

/// The terms of `owner`'s stake of `token` in the match `external`.
pub fn terms(
    external: &[u8],
    token: [u8; 32],
    side: Side,
    owner: &Player,
    other: &Player,
    referee: &Referee,
) -> Result<EscrowTerms, String> {
    EscrowTerms::new(
        token,
        escrow::external_commitment(external),
        branches(side, owner, other, referee)?,
    )
    .map_err(|e| format!("the match's terms: {e:?}"))
}

fn branch<'a>(branches: &'a [EscrowBranch], outcome: &[u8]) -> Result<&'a EscrowBranch, String> {
    branches
        .iter()
        .find(|b| b.outcome() == outcome)
        .ok_or_else(|| {
            format!(
                "its terms have no {:?} outcome",
                String::from_utf8_lossy(outcome)
            )
        })
}

fn pays(b: &EscrowBranch, genesis: &[u8; 32], device_id: &[u8; 32]) -> bool {
    b.recipient_genesis() == genesis && b.recipient_device_id() == device_id
}

/// Whether the vault `(owner_genesis, owner_device_id)` holds under
/// `branches` is a stake in a match `referee` decides with `me` as one of
/// its two players: its terms are exactly the template's for its owner. The
/// other player is read from the terms (the other branch the referee decides
/// and the other key of the cancel) and the template rebuilt from it, so any
/// other branch, signer or recipient makes it another agreement.
pub fn is_match_of(
    owner_genesis: &[u8; 32],
    owner_device_id: &[u8; 32],
    branches_held: &[EscrowBranch],
    me: &Player,
    referee: &Referee,
) -> Result<(), String> {
    let a_wins = branch(branches_held, A_WINS)?;
    let b_wins = branch(branches_held, B_WINS)?;
    let (my_side, other_paid) = if pays(a_wins, &me.genesis, &me.device_id) {
        (Side::A, b_wins)
    } else if pays(b_wins, &me.genesis, &me.device_id) {
        (Side::B, a_wins)
    } else {
        return Err("neither a-wins nor b-wins pays this wallet".into());
    };
    let cancel = branch(branches_held, CANCEL)?;
    let other_key = match cancel.signers() {
        [x, y] if *x == me.signer => y.clone(),
        [x, y] if *y == me.signer => x.clone(),
        _ => return Err("its cancel is not decided by this wallet and one other player".into()),
    };
    let other = Player {
        genesis: *other_paid.recipient_genesis(),
        device_id: *other_paid.recipient_device_id(),
        signer: other_key,
    };
    let rebuilt = if (owner_genesis, owner_device_id) == (&me.genesis, &me.device_id) {
        branches(my_side, me, &other, referee)?
    } else if (owner_genesis, owner_device_id) == (&other.genesis, &other.device_id) {
        branches(my_side.other(), &other, me, referee)?
    } else {
        return Err("its owner is neither player".into());
    };
    if rebuilt.as_slice() != branches_held {
        return Err("its terms are not the match template this application decides".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key() -> EscrowSigner {
        let (public_key, _) =
            dsm::crypto::sphincs::generate_sphincs_keypair().expect("a SPHINCS+ key pair");
        signer(&public_key).expect("a device key")
    }

    fn player(n: u8) -> Player {
        Player {
            genesis: [n; 32],
            device_id: [n + 100; 32],
            signer: key(),
        }
    }

    fn referee() -> Referee {
        Referee {
            device_id: [200; 32],
            signer: key(),
        }
    }

    /// `(outcome, signers, recipient device)` of each branch, in order.
    fn table(branches: &[EscrowBranch]) -> Vec<(Vec<u8>, Vec<EscrowSigner>, [u8; 32])> {
        branches
            .iter()
            .map(|b| {
                (
                    b.outcome().to_vec(),
                    b.signers().to_vec(),
                    *b.recipient_device_id(),
                )
            })
            .collect()
    }

    #[test]
    fn the_template_pays_only_the_two_players_and_refunds_only_the_owner() {
        let (a, b, r) = (player(1), player(2), referee());
        let mut players = vec![a.signer.clone(), b.signer.clone()];
        players.sort_by_key(EscrowSigner::canonical);
        let of_a = branches(Side::A, &a, &b, &r).expect("A's stake");
        assert_eq!(
            table(&of_a),
            vec![
                (A_WINS.to_vec(), vec![r.signer.clone()], a.device_id),
                (B_WINS.to_vec(), vec![r.signer.clone()], b.device_id),
                (CANCEL.to_vec(), players.clone(), a.device_id),
                (VOID.to_vec(), vec![r.signer.clone()], a.device_id),
            ]
        );
        let of_b = branches(Side::B, &b, &a, &r).expect("B's stake");
        assert_eq!(
            table(&of_b),
            vec![
                (A_WINS.to_vec(), vec![r.signer.clone()], a.device_id),
                (B_WINS.to_vec(), vec![r.signer.clone()], b.device_id),
                (CANCEL.to_vec(), players, b.device_id),
                (VOID.to_vec(), vec![r.signer.clone()], b.device_id),
            ]
        );
        let external = b"match 9";
        let terms_a = terms(external, [3; 32], Side::A, &a, &b, &r).expect("A's terms");
        let terms_b = terms(external, [3; 32], Side::B, &b, &a, &r).expect("B's terms");
        assert_eq!(
            escrow::verdict_cell_of(&terms_a),
            escrow::verdict_cell_of(&terms_b),
            "the two stakes of a match share one verdict cell"
        );
        assert_ne!(terms_a, terms_b, "each stake refunds its own owner");
    }

    #[test]
    fn the_application_and_the_wallet_itself_are_never_the_opponent() {
        let (a, r) = (player(1), referee());
        let as_app = Player {
            genesis: [9; 32],
            device_id: r.device_id,
            signer: key(),
        };
        branches(Side::A, &a, &as_app, &r).expect_err("the application's own device");
        let with_app_key = Player {
            signer: r.signer.clone(),
            ..player(2)
        };
        branches(Side::A, &a, &with_app_key, &r).expect_err("the application's own key");
        branches(Side::B, &a, &a.clone(), &r).expect_err("the wallet itself");
        let same_device = Player {
            device_id: a.device_id,
            ..player(2)
        };
        branches(Side::A, &a, &same_device, &r).expect_err("the wallet's own device");
    }

    #[test]
    fn a_vault_is_this_applications_match_only_when_its_terms_are_the_template() {
        let (a, b, r) = (player(1), player(2), referee());
        let of_a = branches(Side::A, &a, &b, &r).expect("A's stake");
        let of_b = branches(Side::B, &b, &a, &r).expect("B's stake");
        for me in [&a, &b] {
            is_match_of(&a.genesis, &a.device_id, &of_a, me, &r).expect("A's vault");
            is_match_of(&b.genesis, &b.device_id, &of_b, me, &r).expect("B's vault");
        }
        is_match_of(&a.genesis, &a.device_id, &of_a, &player(3), &r)
            .expect_err("a wallet that is not a player");
        is_match_of(&a.genesis, &a.device_id, &of_a, &a, &referee())
            .expect_err("another application's match");
        is_match_of(&b.genesis, &b.device_id, &of_a, &a, &r)
            .expect_err("A's terms held by B: its refunds pay A");
        let mut void_pays_b = of_a.clone();
        void_pays_b[3] = EscrowBranch::new(
            EscrowOutcome::new(VOID, vec![r.signer.clone()]).expect("an outcome"),
            b.genesis,
            b.device_id,
        );
        is_match_of(&a.genesis, &a.device_id, &void_pays_b, &a, &r)
            .expect_err("A's void refunding B");
        let mut a_paid_twice = of_a.clone();
        a_paid_twice[1] = EscrowBranch::new(
            EscrowOutcome::new(B_WINS, vec![r.signer.clone()]).expect("an outcome"),
            a.genesis,
            a.device_id,
        );
        is_match_of(&a.genesis, &a.device_id, &a_paid_twice, &a, &r)
            .expect_err("b-wins paying A too");
        let mut a_decides_void = of_a.clone();
        a_decides_void[3] = EscrowBranch::new(
            EscrowOutcome::new(VOID, vec![a.signer.clone()]).expect("an outcome"),
            a.genesis,
            a.device_id,
        );
        is_match_of(&a.genesis, &a.device_id, &a_decides_void, &a, &r)
            .expect_err("void decided by a player");
        let mut extra = of_a.clone();
        extra.push(EscrowBranch::new(
            EscrowOutcome::new(b"z-draw", vec![r.signer.clone()]).expect("an outcome"),
            b.genesis,
            b.device_id,
        ));
        is_match_of(&a.genesis, &a.device_id, &extra, &a, &r).expect_err("a fifth outcome");
    }
}
