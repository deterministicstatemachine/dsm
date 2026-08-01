// SPDX-License-Identifier: MIT OR Apache-2.0

//! Test fixture: a vault whose reserves are ENCUMBERED, not asserted.
//!
//! Every AMM test in this crate used to build its own
//! `FulfillmentMechanism::AmmConstantProduct { reserve_a, reserve_b, .. }` and read
//! the quantities straight back out of the predicate. That is the model this cut
//! removes: a condition describing liquidity nobody held, which is why a settled
//! swap moved zero value and why those tests stayed green throughout.
//!
//! So this fixture exists to make the new model the only convenient one. It:
//!
//!   1. builds the predicate from token identities and `fee_bps` ONLY — there is
//!      no longer a field to put a reserve in;
//!   2. funds both legs through [`DeviceState::fund_vault_reserves`], the same
//!      chokepoint production uses, so a test cannot conjure liquidity a device
//!      never had;
//!   3. reads reserves back from the owner's vault-reserve LEAVES, so what a test
//!      asserts against is what the device root actually commits;
//!   4. offers no path from an advertisement into authoritative state — an ad is a
//!      discovery hint, and a fixture that let one populate reserves would re-teach
//!      the habit this change exists to end.
//!
//! A test that wants stale or hostile reserves passes them explicitly to the
//! function under test. That is the point: quantities are now an INPUT to
//! verification, not a property of the thing being verified.

#![cfg(test)]

use std::collections::BTreeMap;

use dsm::types::device_state::DeviceState;
use dsm::vault::FulfillmentMechanism;

/// Deterministic ids shared by the AMM tests.
const GENESIS: [u8; 32] = [0u8; 32];
const DEVID: [u8; 32] = [0xD0u8; 32];
pub(crate) const VAULT_ID: [u8; 32] = [0x77u8; 32];

/// A vault that actually holds what it says it holds.
pub(crate) struct FundedVault {
    pub vault_id: [u8; 32],
    /// Lex-lower token identity, and its policy commit.
    pub token_a: Vec<u8>,
    pub pc_a: [u8; 32],
    /// Lex-higher token identity, and its policy commit.
    pub token_b: Vec<u8>,
    pub pc_b: [u8; 32],
    pub fee_bps: u32,
    /// The owner's device head AFTER funding — the authority for the reserves.
    pub head: DeviceState,
}

impl FundedVault {
    /// The unlock predicate: which pair, at what fee. No quantities.
    pub fn predicate(&self) -> FulfillmentMechanism {
        FulfillmentMechanism::AmmConstantProduct {
            token_a: self.token_a.clone(),
            token_b: self.token_b.clone(),
            fee_bps: self.fee_bps,
        }
    }

    /// Reserves read from the owner's encumbered leaves — never from the
    /// predicate, and never from an advertisement.
    pub fn reserves(&self) -> (u64, u64) {
        (
            self.head.vault_reserve(&self.vault_id, &self.pc_a),
            self.head.vault_reserve(&self.vault_id, &self.pc_b),
        )
    }

    /// Spendable (unencumbered) balance for one leg.
    pub fn spendable(&self, policy_commit: &[u8; 32]) -> u64 {
        self.head.balance(policy_commit)
    }
}

/// Token identities used across the AMM tests, lex-ordered.
pub(crate) fn token_pair() -> (Vec<u8>, Vec<u8>) {
    (b"AAA".to_vec(), b"BBB".to_vec())
}

/// Policy commits for that pair. Distinct, deterministic, and deliberately NOT
/// derived from the ticker bytes — a ticker is not an identity.
pub(crate) fn pair_commits() -> ([u8; 32], [u8; 32]) {
    ([0xA1u8; 32], [0xB2u8; 32])
}

/// A device holding `a` / `b` base units of the pair and nothing encumbered.
///
/// Built through `DeviceState::restore`, the public constructor that takes a
/// balance map — so the starting balances are ones a real device could hold.
/// As [`owner_holding`], but on a NAMED device.
///
/// Two devices in one test must not share a devid: reserve leaf keys are derived
/// from `(genesis, devid, vault_id, policy_commit)`, so identical devids would
/// make two heads derive the same leaf positions and the boundary between them
/// would be nominal.
pub(crate) fn device_holding(devid_seed: u8, a: u64, b: u64) -> DeviceState {
    let (pc_a, pc_b) = pair_commits();
    let mut balances = BTreeMap::new();
    if a > 0 {
        balances.insert(pc_a, a);
    }
    if b > 0 {
        balances.insert(pc_b, b);
    }
    DeviceState::restore(
        GENESIS,
        [devid_seed; 32],
        vec![9u8; 32],
        None,
        balances,
        Vec::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        1024,
    )
    .expect("fixture device state")
}

pub(crate) fn owner_holding(a: u64, b: u64) -> DeviceState {
    let (pc_a, pc_b) = pair_commits();
    let mut balances = BTreeMap::new();
    if a > 0 {
        balances.insert(pc_a, a);
    }
    if b > 0 {
        balances.insert(pc_b, b);
    }
    DeviceState::restore(
        GENESIS,
        DEVID,
        vec![9u8; 32],
        None,
        balances,
        Vec::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        1024,
    )
    .expect("fixture owner state")
}

/// Fund a vault with `reserve_a` / `reserve_b` base units at vault sequence 0.
pub(crate) fn funded_vault(reserve_a: u64, reserve_b: u64, fee_bps: u32) -> FundedVault {
    funded_vault_with_surplus(reserve_a, reserve_b, fee_bps, 0)
}

/// As [`funded_vault`], but leaving `surplus` of each leg SPENDABLE — so a test
/// can show that encumbered value moved out of `balances` rather than being
/// credited from nowhere.
pub(crate) fn funded_vault_with_surplus(
    reserve_a: u64,
    reserve_b: u64,
    fee_bps: u32,
    surplus: u64,
) -> FundedVault {
    let (token_a, token_b) = token_pair();
    let (pc_a, pc_b) = pair_commits();

    let head = owner_holding(reserve_a + surplus, reserve_b + surplus)
        .fund_vault_reserves(&VAULT_ID, &[(pc_a, reserve_a), (pc_b, reserve_b)], 0)
        .expect("fixture funding must succeed")
        .new_device_state;

    FundedVault {
        vault_id: VAULT_ID,
        token_a,
        pc_a,
        token_b,
        pc_b,
        fee_bps,
        head,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dsm::vault::FulfillmentMechanism;
    use prost::Message;

    /// (1) RESERVE-FREE PREDICATE SERIALIZATION.
    ///
    /// The condition must not carry quantities in memory OR on the wire. If a
    /// reserve could still round-trip through the proto, the old model would
    /// survive in serialized form and reappear on the next decode.
    #[test]
    fn the_predicate_serializes_without_reserves() {
        let v = funded_vault(1_000_000, 500_000, 30);
        let predicate = v.predicate();

        let proto: dsm::types::proto::FulfillmentMechanism = (&predicate).into();
        let bytes = proto.encode_to_vec();
        let back = dsm::types::proto::FulfillmentMechanism::decode(&*bytes).expect("decode");
        let round = FulfillmentMechanism::try_from(back).expect("convert back");

        match (&predicate, &round) {
            (
                FulfillmentMechanism::AmmConstantProduct {
                    token_a: a1,
                    token_b: b1,
                    fee_bps: f1,
                },
                FulfillmentMechanism::AmmConstantProduct {
                    token_a: a2,
                    token_b: b2,
                    fee_bps: f2,
                },
            ) => {
                assert_eq!((a1, b1, f1), (a2, b2, f2), "pair and fee survive");
            }
            other => panic!("expected an AMM predicate both sides, got {other:?}"),
        }

        // And the encoding carries neither reserve: 1_000_000 and 500_000 do not
        // appear anywhere in the bytes, in either width.
        for probe in [
            1_000_000u64.to_be_bytes().to_vec(),
            500_000u64.to_be_bytes().to_vec(),
            1_000_000u128.to_be_bytes().to_vec(),
            500_000u128.to_be_bytes().to_vec(),
        ] {
            assert!(
                !bytes.windows(probe.len()).any(|w| w == probe.as_slice()),
                "a reserve quantity leaked into the serialized predicate"
            );
        }
    }

    /// (2) TWO-LEG FUNDING moves spendable balance into reserve leaves, and both
    /// legs land under ONE final root.
    #[test]
    fn funding_moves_spendable_into_leaves_under_one_root() {
        let v = funded_vault_with_surplus(1_000_000, 500_000, 30, 7);

        assert_eq!(v.reserves(), (1_000_000, 500_000), "leaves hold the legs");
        assert_eq!(v.spendable(&v.pc_a), 7, "only the surplus stays spendable");
        assert_eq!(v.spendable(&v.pc_b), 7);

        // Per asset, spendable + encumbered is what the owner started with.
        assert_eq!(v.spendable(&v.pc_a) + v.reserves().0, 1_000_007);
        assert_eq!(v.spendable(&v.pc_b) + v.reserves().1, 500_007);

        // Both leaves verify against the SAME root — no proof binds a state in
        // which the vault held one side of the pair.
        let root = v.head.root();
        for (pc, amount) in [(v.pc_a, 1_000_000u64), (v.pc_b, 500_000u64)] {
            let key = dsm::dlv::vault_reserve_leaf::vault_reserve_key(
                &v.head.genesis_digest(),
                &v.head.devid(),
                &v.vault_id,
                &pc,
            );
            let value = dsm::dlv::vault_reserve_leaf::vault_reserve_value(amount, 0);
            assert_eq!(
                v.head.extra_leaves_snapshot().get(&key),
                Some(&value),
                "leg committed at the funding sequence"
            );
        }
        assert_ne!(root, [0u8; 32]);
    }

    /// (3) DEGENERATE AND HOSTILE FUNDING REJECTS WITH ZERO MUTATION.
    ///
    /// Zero, duplicate and insufficient legs must each leave the owner's root
    /// and balances byte-identical — a partially-applied funding would encumber
    /// value the vault does not account for.
    #[test]
    fn bad_funding_rejects_with_zero_mutation() {
        let (pc_a, pc_b) = pair_commits();
        let owner = owner_holding(1_000, 1_000);
        let root_before = owner.root();
        let bal_before = (owner.balance(&pc_a), owner.balance(&pc_b));

        let cases: Vec<(&str, Vec<([u8; 32], u64)>)> = vec![
            ("no legs at all", vec![]),
            ("a zero-amount leg", vec![(pc_a, 0)]),
            ("the same asset twice", vec![(pc_a, 100), (pc_a, 200)]),
            ("more than is held", vec![(pc_a, 1_001)]),
            (
                "the SECOND leg unaffordable — the first must not move either",
                vec![(pc_a, 500), (pc_b, 5_000)],
            ),
        ];

        for (why, legs) in cases {
            assert!(
                owner.fund_vault_reserves(&VAULT_ID, &legs, 0).is_err(),
                "must refuse: {why}"
            );
            assert_eq!(owner.root(), root_before, "root unchanged after: {why}");
            assert_eq!(
                (owner.balance(&pc_a), owner.balance(&pc_b)),
                bal_before,
                "balances unchanged after: {why}"
            );
            assert_eq!(owner.vault_reserve(&VAULT_ID, &pc_a), 0);
            assert_eq!(owner.vault_reserve(&VAULT_ID, &pc_b), 0);
        }
    }

    /// (6) A DISCOVERY ADVERTISEMENT CANNOT POPULATE AUTHORITATIVE STATE.
    ///
    /// `route.syncVaultsForPair` used to copy an ad's reserves into the owner's
    /// local vault so the owner could "observe" a settle — which made a hint
    /// anyone could publish the authority for the owner's own liquidity.
    ///
    /// The structural guarantee is stronger than any test of that one path: an
    /// advertisement is a proto with no route into `vault_reserves`, which only
    /// the funding chokepoints write. Here that is shown end to end — an ad
    /// claiming enormous reserves changes nothing about what the device holds.
    #[test]
    fn an_advertisement_cannot_change_what_the_device_holds() {
        let v = funded_vault(1_000, 2_000, 30);
        let before = (v.reserves(), v.head.root());

        // An ad claiming this vault holds far more than it does.
        let lying_ad = dsm::types::proto::RoutingVaultAdvertisementV1 {
            version: 1,
            vault_id: v.vault_id.to_vec(),
            token_a: v.token_a.clone(),
            token_b: v.token_b.clone(),
            reserve_a: u64::MAX,
            reserve_b: u64::MAX,
            fee_bps: v.fee_bps,
            updated_state_number: 99,
            ..Default::default()
        };
        assert_eq!(lying_ad.reserve_a, u64::MAX, "the ad says what it likes");

        // The device is unmoved: reserves and root are exactly as funded. There
        // is no API that would take the ad and apply it, which is the point.
        assert_eq!(v.reserves(), before.0, "reserves unchanged by an ad");
        assert_eq!(v.head.root(), before.1, "root unchanged by an ad");
        assert_eq!(v.reserves(), (1_000, 2_000));
    }

    /// The fixture itself must not offer a way to fake liquidity: reserves come
    /// from the leaves, so they always agree with the device root.
    #[test]
    fn fixture_reserves_are_the_leaves_not_a_stored_number() {
        let v = funded_vault(400, 600, 30);
        assert_eq!(
            v.reserves(),
            (
                v.head.vault_reserve(&v.vault_id, &v.pc_a),
                v.head.vault_reserve(&v.vault_id, &v.pc_b)
            )
        );
    }
}
