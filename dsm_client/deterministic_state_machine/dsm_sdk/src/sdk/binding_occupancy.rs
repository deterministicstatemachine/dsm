// SPDX-License-Identifier: Apache-2.0

//! IS THIS DLV PARENT STILL AVAILABLE TO A COMPETING CANDIDATE?
//!
//! This module answers OCCUPANCY and nothing else. Whether a bound bundle's
//! successor actually became economic state is a separate question with a
//! successor-kind-specific answer, and the frontier walk asks it separately.
//! Conflating the two is the defect the whole 5c-1 cut exists to remove: under
//! a write-once settlement slot, "this generation is consumed" and "this
//! generation composed" were one fact, and they are not.
//!
//! Two layers, deliberately separated:
//!
//! - [`observe_parent_key`] reads the register. One key, `q` counted answers,
//!   five possible verdicts. No bundle is fetched, because occupancy does not
//!   depend on the bundle's contents.
//! - [`observe_parent_binding`] resolves the bound bundle and checks it against
//!   THIS parent. That check is load-bearing rather than defensive: the binding
//!   register is application-blind (§22 #12), so a proposer may bind a bundle
//!   that does not contain this `c_n` at this key, and a member reconfigured
//!   into another set keeps serving rows written under the old one.
//!
//! `k_v = H(DSM/binding-keyset ‖ c_n)` is derived from `c_n` ALONE, and `c_n`
//! already commits the vault id, the generation, the reserves and the pair. So
//! the three coordinate checks the old slot walk performed separately —
//! "names a different cell", "a different storage set", "a different parent
//! state" — mostly collapse into *we read the right key*, and the ones that
//! remain are the ones an application-blind register cannot enforce.
//!
//! **Nothing here returns a `Result`.** A transport failure IS
//! `Unavailable`; a bundle that cannot be resolved IS `Unresolvable`. An error
//! channel beside the verdict is an invitation to collapse uncertainty into
//! "the parent is free", which is the one reading that is never safe.

use dsm::dlv::binding_observation::{observe_single_key, BindingObservation};
use dsm::dlv::settlement_bundle::{self, BundleShape};
use dsm::types::proto as pb;

use crate::sdk::quorum_bind_runner::{binding_transport, read_binding_attributed};
use crate::sdk::storage_set::StorageSet;

/// What the vault's committed set says about the binding of one parent state.
///
/// Occupancy only. `BoundBy` does NOT mean the successor was realized.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum ParentOccupancy {
    /// `q` attributed members each explicitly hold nothing at `k(c_n)`: the
    /// parent is available to a competing candidate right now.
    Free,
    /// A binding-final bundle owns this parent, resolved and checked against it.
    BoundBy(Box<BoundParent>),
    /// Conflict, Undetermined, Unavailable, or a chosen record whose bundle
    /// cannot be resolved. The string is what the caller reports; every one of
    /// them must fail closed.
    Unresolvable(String),
}

/// The bundle that owns a parent, already checked against THAT parent.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct BoundParent {
    pub bundle: pb::SettlementBundleV1,
    /// `b` — equal to the record's `value_digest`; the bytes were re-hashed.
    pub bundle_digest: [u8; 32],
    pub bundle_addr: [u8; 32],
    /// The transition naming THIS vault. Located by `vault_id`, never assumed
    /// to be index 0 — a market bundle may consume several vaults.
    pub transition_ix: usize,
    pub shape: BundleShape,
}

impl BoundParent {
    pub fn transition(&self) -> Option<&pb::VaultTransitionV1> {
        self.bundle.vault_transitions.get(self.transition_ix)
    }
}

fn as32(v: &[u8]) -> Option<[u8; 32]> {
    <[u8; 32]>::try_from(v).ok()
}

/// Read `k(c_n)` at every committed member and classify it at the vault's
/// committed `q`.
///
/// Every member is asked rather than the first `q`: a bundle that committed
/// with exactly `q` holders needs the full fan-out to find them.
pub(crate) async fn observe_parent_key(
    set: &StorageSet,
    parent_c_n: &[u8; 32],
    committed_quorum: u32,
) -> BindingObservation {
    let key = settlement_bundle::resource_key(parent_c_n);
    let members: Vec<dsm::dlv::quorum_bind::CommittedMember> = set
        .members()
        .iter()
        .map(|m| dsm::dlv::quorum_bind::CommittedMember {
            member_id: m.member_id.as_bytes().to_vec(),
            register_incarnation: m.register_incarnation_id,
        })
        .collect();
    let transport = binding_transport(set);
    let reads = read_binding_attributed(&members, &[key], transport.as_ref()).await;
    observe_single_key(&reads, committed_quorum)
}

/// Occupancy of one vault parent, with the owning bundle resolved and bound to
/// that parent.
pub(crate) async fn observe_parent_binding(
    set: &StorageSet,
    vault_id: &[u8; 32],
    generation: u64,
    parent_c_n: &[u8; 32],
    storage_set_id: &[u8; 32],
    committed_quorum: u32,
) -> ParentOccupancy {
    let chosen = match observe_parent_key(set, parent_c_n, committed_quorum).await {
        BindingObservation::Free => return ParentOccupancy::Free,
        BindingObservation::BoundFinal(c) => c,
        // A promise in flight, or an accepted record below THIS reader's
        // quorum. Retryable, and never "free": a value already chosen behind a
        // down member lands here, because two quorums intersect but one read
        // need not see the intersection.
        BindingObservation::Undetermined { attributed, .. } => {
            return ParentOccupancy::Unresolvable(format!(
                "the binding for this parent is not yet decided ({attributed} members answered)"
            ))
        }
        BindingObservation::Conflict { distinct } => {
            return ParentOccupancy::Unresolvable(format!(
                "the binding key for this parent holds {distinct} chosen values"
            ))
        }
        BindingObservation::Unavailable {
            attributed,
            required,
        } => {
            return ParentOccupancy::Unresolvable(format!(
                "only {attributed} of the vault's members answered the binding key \
                 ({required} required)"
            ))
        }
    };

    let unresolvable = |what: &str| ParentOccupancy::Unresolvable(what.to_string());

    // The record's two identity fields must agree with each other before either
    // is used to fetch anything.
    let expected_addr = dsm::storage_object::immutable_addr_from_inner(
        dsm::common::domain_tags::TAG_DSM_SETTLEMENT_BUNDLE,
        &chosen.value_digest,
    );
    if expected_addr != chosen.value_addr {
        return unresolvable("the bound record's digest and address disagree");
    }

    // Fetch by the record's own value identity. `fetch_immutable_payload`
    // re-hashes the bytes to the requested inner identity (Req 15.3).
    let bytes = match crate::sdk::storage_io::fetch_immutable_payload(
        dsm::common::domain_tags::TAG_DSM_SETTLEMENT_BUNDLE,
        &chosen.value_digest,
    )
    .await
    {
        Ok(Some(b)) => b,
        Ok(None) => return unresolvable("its bound bundle is not retrievable"),
        Err(_) => return unresolvable("its bound bundle could not be fetched"),
    };
    let Ok(bundle) = settlement_bundle::decode_canonical(&bytes) else {
        return unresolvable("its bound bundle is not a canonical settlement bundle");
    };
    let Ok(canon) = settlement_bundle::canon(&bundle) else {
        return unresolvable("its bound bundle does not re-encode canonically");
    };
    let bundle_digest = settlement_bundle::bundle_digest(&canon);
    let bundle_addr = settlement_bundle::bundle_addr(&canon);
    if bundle_digest != chosen.value_digest || bundle_addr != chosen.value_addr {
        return unresolvable("its bound bundle does not hash to the record's identity");
    }
    let Ok(shape) = settlement_bundle::shape(&bundle) else {
        return unresolvable("its bound bundle has no valid shape");
    };

    // BOUND UNDER THIS SET, AT THIS q. A member reconfigured into another set
    // still serves rows written under the old one, so a cross-set bundle is
    // reachable. `q` comes from the vault's own committed V_n, so the bundle's
    // restatement of it must AGREE — it is never consumed in place of it.
    if as32(&bundle.storage_set_id) != Some(*storage_set_id) {
        return unresolvable("its bound bundle was bound under a different storage set");
    }
    if bundle.q != committed_quorum {
        return unresolvable("its bound bundle states a different quorum than this vault commits");
    }

    // AND IT NAMES THIS PARENT. The register never inspects the value it holds,
    // so a proposer can bind a bundle at k(c_n) whose transitions name some
    // other c_n. Nothing above catches that; this does.
    let Some(transition_ix) = bundle
        .vault_transitions
        .iter()
        .position(|t| as32(&t.vault_id) == Some(*vault_id))
    else {
        return unresolvable("its bound bundle consumes no leg of this vault");
    };
    let Some(t) = bundle.vault_transitions.get(transition_ix) else {
        return unresolvable("its bound bundle lost the transition it just named");
    };
    if as32(&t.parent_state_commitment) != Some(*parent_c_n) {
        return unresolvable("its bound bundle names a different parent state for this vault");
    }
    if t.parent_generation != generation {
        return unresolvable("its bound bundle names a different generation for this vault");
    }

    ParentOccupancy::BoundBy(Box::new(BoundParent {
        bundle,
        bundle_digest,
        bundle_addr,
        transition_ix,
        shape,
    }))
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use crate::sdk::binding_fleet_double;
    use crate::sdk::settlement_bind::bind_settlement;
    use crate::sdk::storage_set::{StorageMember, StorageSet};
    use dsm::dlv::quorum_bind::Outcome;
    use dsm::storage::binding_record::Round;
    use serial_test::serial;

    const VAULT: [u8; 32] = [0x77; 32];
    const C_N: [u8; 32] = [0xC0; 32];
    const GEN: u64 = 3;

    fn test_set(n: u8) -> StorageSet {
        StorageSet::new(
            (0..n)
                .map(|i| StorageMember {
                    member_id: format!("dsm-node-{i}"),
                    register_incarnation_id: [i + 1; 32],
                    endpoint: format!("http://127.0.0.1:808{i}"),
                })
                .collect(),
        )
        .unwrap()
    }

    fn fleet_tuples(set: &StorageSet) -> Vec<(String, Vec<u8>, [u8; 32])> {
        set.members()
            .iter()
            .map(|m| {
                (
                    m.endpoint.clone(),
                    m.member_id.as_bytes().to_vec(),
                    m.register_incarnation_id,
                )
            })
            .collect()
    }

    /// A market bundle consuming `vault` at `c_n`.
    fn market_bundle(set: &StorageSet, vault: [u8; 32], c_n: [u8; 32]) -> pb::SettlementBundleV1 {
        pb::SettlementBundleV1 {
            version: settlement_bundle::SETTLEMENT_BUNDLE_VERSION_V1,
            storage_set_id: set.id().to_vec(),
            q: set.quorum(),
            intent_commitment: vec![0x1D; 32],
            route_set_commitment: vec![0x0C; 32],
            selected_route: b"route".to_vec(),
            trader_parent: c_n.to_vec(),
            trader_successor: vec![0xBB; 32],
            vault_transitions: vec![pb::VaultTransitionV1 {
                vault_id: vault.to_vec(),
                parent_generation: GEN,
                parent_state_commitment: c_n.to_vec(),
                parent_reserves_digest: vec![0x0A; 32],
                successor_ccb: vec![0x5C; 32],
                reserve_deltas: b"d".to_vec(),
                witnesses: vec![],
            }],
            proof_material: vec![],
            bundle_signatures: vec![],
            recovery_material: b"r".to_vec(),
        }
    }

    fn init() -> StorageSet {
        crate::storage::client_db::reset_database_for_tests();
        crate::storage::client_db::init_database().expect("init");
        crate::sdk::storage_io::fake_fleet::reset();
        let set = test_set(3);
        binding_fleet_double::reset_with(&fleet_tuples(&set));
        set
    }

    async fn bind(set: &StorageSet, b: &pb::SettlementBundleV1, c_n: [u8; 32]) {
        let out = bind_settlement(set, [7; 32], b, VAULT, c_n).await.unwrap();
        assert_eq!(out, Ok(Outcome::Committed));
    }

    #[tokio::test]
    #[serial]
    async fn a_parent_nothing_has_bound_is_free() {
        let set = init();
        assert_eq!(
            observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await,
            ParentOccupancy::Free
        );
    }

    #[tokio::test]
    #[serial]
    async fn a_bound_parent_resolves_to_the_bundle_that_owns_it() {
        let set = init();
        let b = market_bundle(&set, VAULT, C_N);
        bind(&set, &b, C_N).await;

        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        let ParentOccupancy::BoundBy(bp) = occ else {
            panic!("expected BoundBy, got {occ:?}");
        };
        let canon = settlement_bundle::canon(&b).unwrap();
        assert_eq!(bp.bundle_digest, settlement_bundle::bundle_digest(&canon));
        assert_eq!(bp.bundle_addr, settlement_bundle::bundle_addr(&canon));
        assert_eq!(bp.shape, BundleShape::Market);
        assert_eq!(bp.transition_ix, 0);
        // And it is occupancy ONLY: nothing here says the successor realized.
        assert_eq!(
            as32(&bp.transition().unwrap().parent_state_commitment),
            Some(C_N)
        );
    }

    /// Binding another vault's parent leaves THIS parent free. The key is
    /// derived from `c_n`, so the two never share a cell.
    #[tokio::test]
    #[serial]
    async fn binding_one_parent_does_not_occupy_another() {
        let set = init();
        let other_c_n = [0xC1; 32];
        let b = market_bundle(&set, VAULT, other_c_n);
        bind(&set, &b, other_c_n).await;
        assert_eq!(
            observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await,
            ParentOccupancy::Free
        );
    }

    /// THE APPLICATION-BLIND REGISTER. A member never inspects the value it
    /// holds, so a proposer can put a bundle's record at a key the bundle does
    /// not name. Nothing in the read catches that; the parent check does.
    #[tokio::test]
    #[serial]
    async fn a_bundle_bound_at_a_key_it_does_not_name_is_unresolvable() {
        let set = init();
        let other_c_n = [0xC1; 32];
        let b = market_bundle(&set, VAULT, other_c_n);
        bind(&set, &b, other_c_n).await;

        // Now plant that same committed record at THIS parent's key.
        let canon = settlement_bundle::canon(&b).unwrap();
        let digest = settlement_bundle::bundle_digest(&canon);
        binding_fleet_double::plant_committed(
            &["dsm-node-0", "dsm-node-1"],
            &[settlement_bundle::resource_key(&C_N)],
            digest,
            digest,
            settlement_bundle::bundle_addr(&canon),
            Round {
                counter: 21,
                proposer_id: [7; 32],
            },
        );
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w)
                     if w.contains("names a different parent state")),
            "got {occ:?}"
        );
    }

    /// A cross-set bundle is reachable: a member reconfigured into another set
    /// keeps serving rows written under the old one.
    #[tokio::test]
    #[serial]
    async fn a_bundle_bound_under_another_storage_set_is_unresolvable() {
        let set = init();
        let b = market_bundle(&set, VAULT, C_N);
        bind(&set, &b, C_N).await;
        let foreign = [0xEE; 32];
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &foreign, set.quorum()).await;
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w)
                     if w.contains("different storage set")),
            "got {occ:?}"
        );
    }

    /// Losing quorum establishes NOTHING — and in particular does not establish
    /// that the parent is free.
    #[tokio::test]
    #[serial]
    async fn a_parent_whose_members_cannot_be_reached_is_unresolvable_not_free() {
        let set = init();
        binding_fleet_double::fail_member_id("dsm-node-1");
        binding_fleet_double::fail_member_id("dsm-node-2");
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w) if w.contains("answered the binding key")),
            "got {occ:?}"
        );
    }

    /// A record held below this reader's quorum, with no absence quorum either.
    /// Retryable, and emphatically not free — the value may already be chosen
    /// behind the member that did not answer.
    #[tokio::test]
    #[serial]
    async fn an_undecided_binding_is_unresolvable_not_free() {
        let set = init();
        binding_fleet_double::plant_committed(
            &["dsm-node-0"],
            &[settlement_bundle::resource_key(&C_N)],
            [0xAB; 32],
            [0xAB; 32],
            [0xCD; 32],
            Round {
                counter: 21,
                proposer_id: [7; 32],
            },
        );
        binding_fleet_double::fail_member_id("dsm-node-2");
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w) if w.contains("not yet decided")),
            "got {occ:?}"
        );
    }

    /// A member that echoes another member's identity is uncountable, so two
    /// honest answers plus one impostor cannot reach a three-member quorum.
    #[tokio::test]
    #[serial]
    async fn an_answer_that_names_the_wrong_member_does_not_count() {
        let set = init();
        binding_fleet_double::fail_member_id("dsm-node-2");
        binding_fleet_double::set_echo("http://127.0.0.1:8081", b"dsm-node-0".to_vec(), [1; 32]);
        let occ = observe_parent_binding(&set, &VAULT, GEN, &C_N, &set.id(), set.quorum()).await;
        assert!(
            matches!(&occ, ParentOccupancy::Unresolvable(w) if w.contains("answered the binding key")),
            "got {occ:?}"
        );
    }
}
