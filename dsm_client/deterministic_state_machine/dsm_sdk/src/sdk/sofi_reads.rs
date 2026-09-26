// SPDX-License-Identifier: Apache-2.0
//! What the SoFi verifier reads, answered from the storage nodes and this
//! device's own records: the SDK's [`SofiReads`].
//!
//! Core decides what is read and what it means (`dsm::sofi::resolve`); this
//! module only answers — bytes, cells, this device's own rows — the way
//! `LiveRegisterResolver` answers the peer lineage walk. Every network read
//! runs on the SDK's multi-thread runtime from the verifier's synchronous
//! call (`block_in_place`), which is the shape the peer walk already has.

use std::collections::BTreeSet;
use std::future::Future;

use dsm::ccb::StorageSetMembers;
use dsm::common::domain_tags::TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR;
use dsm::economic::lineage::{AcceptedClaim, AdmittedEconomicPosition, ValidatedEconomicRoot};
use dsm::economic::provenance::{PeerLineageFailure, ValidatedPeerTransition};
use dsm::route_chain::{CellEvidence, CompletionProof, RoutedCell};
use dsm::sofi::derive;
use dsm::sofi::publication::Signed;
use dsm::sofi::resolve::{
    LocalLeaves, ReadFailure, RecordedGenerationRow, SofiReads, VaultLeaves, Verifier,
    VerifierFailure,
};
use dsm::sofi::storage::{Discovered, Resolved};
use dsm::sofi::validation::VaultPostState;
use dsm::sofi::wire::{TraderFulfillmentBody, TraderPrecommitBody, VaultGenesisPreimage};
use dsm::types::error::DsmError;

use crate::sdk::economic_admission_flow::committed_network_id;
use crate::sdk::economic_registers::{
    anchored_policy_bytes, resolve_peer_with_cache, LiveRegisterResolver,
};
use crate::sdk::route_seats::{keep_completion, read_cell, NodeSeats};
use crate::sdk::sofi_publish::{fetch_fulfillment, fetch_precommit, fetch_setup_bytes, LOCATOR_BUDGET};
use crate::sdk::storage_io::{read_stored_bytes, resolve_locator_all};
use crate::sdk::storage_set::{as_ccb_members, StorageSet};
use crate::storage::client_db::{economic_lineage, sofi_vault_head};

type D32 = [u8; 32];

fn storage_err(what: &str, e: impl core::fmt::Display) -> DsmError {
    DsmError::storage(format!("{what}: {e}"), None::<std::io::Error>)
}

/// A verifier failure as the SDK reports it: a read that could not be made
/// is a storage error; what the reads refuted is an invalid operation.
pub fn verifier_error(failure: VerifierFailure) -> DsmError {
    match failure {
        VerifierFailure::Read(why) => storage_err("sofi verifier", why),
        VerifierFailure::Refused(why) => {
            DsmError::invalid_operation(format!("sofi verifier: {why}"))
        }
    }
}

/// The leaves of this device's validated root, from the leaf cache; the
/// cache is a cache, so its root is recomputed and must equal the validated
/// one.
pub fn local_leaves_of_validated(
    genesis: &D32,
    device_id: &D32,
    validated: &ValidatedEconomicRoot,
) -> Result<LocalLeaves, DsmError> {
    let leaves = if validated.economic_position() == 0 {
        Vec::new()
    } else {
        economic_lineage::load_leaf_cache().map_err(|e| storage_err("load leaf cache", e))?
    };
    let decoded: Vec<(D32, dsm::economic::state::EconomicLeafState)> = leaves
        .iter()
        .map(|(key, .., ccb)| {
            dsm::economic::decode::decode_leaf_state(ccb)
                .map(|state| (*key, state))
                .map_err(|e| storage_err("decode cached leaf state", e))
        })
        .collect::<Result<_, _>>()?;
    LocalLeaves::checked(*genesis, *device_id, validated.economic_root(), decoded)
        .map_err(|e| storage_err("local leaves", e))
}

/// The verifier's reads over the storage nodes of the pinned set and this
/// device's own records.
pub struct LiveSofiReads<'a> {
    set: &'a StorageSet,
    runtime: tokio::runtime::Handle,
    network: Vec<u8>,
}

impl<'a> LiveSofiReads<'a> {
    pub fn new(set: &'a StorageSet) -> Result<Self, DsmError> {
        Ok(Self {
            set,
            runtime: tokio::runtime::Handle::current(),
            network: committed_network_id()?,
        })
    }

    fn block<T>(&self, fut: impl Future<Output = T>) -> T {
        tokio::task::block_in_place(|| self.runtime.block_on(fut))
    }

    fn read<T>(
        &self,
        what: &str,
        fut: impl Future<Output = Result<T, DsmError>>,
    ) -> Result<T, ReadFailure> {
        self.block(fut)
            .map_err(|e| ReadFailure(format!("{what}: {e}")))
    }
}

impl SofiReads for LiveSofiReads<'_> {
    fn cell(&self, cell: &RoutedCell) -> Result<CellEvidence, ReadFailure> {
        let seats = NodeSeats::new(self.set).map_err(|e| ReadFailure(format!("seats: {e}")))?;
        Ok(self.block(read_cell(&seats, cell)))
    }

    fn precommit(&self, id: &D32) -> Result<Resolved<Signed<TraderPrecommitBody>>, ReadFailure> {
        self.read("precommit", fetch_precommit(self.set, id))
    }

    fn fulfillment(
        &self,
        id: &D32,
    ) -> Result<Resolved<Signed<TraderFulfillmentBody>>, ReadFailure> {
        self.read("fulfillment", fetch_fulfillment(self.set, id))
    }

    fn setup_bytes(&self, setup_ref: &D32) -> Result<Resolved<Vec<u8>>, ReadFailure> {
        self.read("setup", fetch_setup_bytes(self.set, setup_ref))
    }

    fn stored_bytes(&self, addr: &D32) -> Result<Option<Vec<u8>>, ReadFailure> {
        self.read("stored bytes", read_stored_bytes(self.set, addr))
    }

    fn token_policy_bytes(&self, policy_commit: &D32) -> Result<Vec<u8>, ReadFailure> {
        anchored_policy_bytes(self.set, policy_commit, &self.runtime)
            .map_err(|failure| ReadFailure(format!("token policy: {failure}")))
    }

    fn vault_genesis_candidates(
        &self,
        vault_id: &D32,
    ) -> Result<Discovered<(VaultGenesisPreimage, Vec<u8>)>, ReadFailure> {
        let locator = derive::vault_genesis_locator(vault_id);
        self.read(
            "vault genesis candidates",
            resolve_locator_all(
                self.set,
                TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes(),
                &locator,
                LOCATOR_BUDGET,
                |bytes| {
                    let preimage = VaultGenesisPreimage::decode(bytes).ok()?;
                    Some((
                        derive::vault_genesis_locator(&preimage.vault_id()),
                        (preimage, bytes.to_vec()),
                    ))
                },
            ),
        )
    }

    fn vault_owner(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<ValidatedPeerTransition, PeerLineageFailure> {
        let resolver = LiveRegisterResolver {
            set: self.set,
            runtime: self.runtime.clone(),
            expected_network_id: self.network.clone(),
        };
        resolve_peer_with_cache(&resolver, &self.network, genesis, device_id, position)
    }

    fn vault_leaves_at(
        &self,
        vault_id: &D32,
        root: &D32,
        keys: &BTreeSet<D32>,
    ) -> Result<Option<VaultLeaves>, ReadFailure> {
        Ok(sofi_vault_head::leaves_at(vault_id, root, keys)
            .map_err(|e| ReadFailure(format!("vault head: {e}")))?
            .map(|(.., leaves)| leaves))
    }

    fn accepted_claim_at(
        &self,
        genesis: &D32,
        device_id: &D32,
        position: u64,
    ) -> Result<Option<AcceptedClaim>, ReadFailure> {
        let Some(admitted) = economic_lineage::get_admitted_at(position)
            .map_err(|e| ReadFailure(format!("admitted history: {e}")))?
        else {
            return Ok(None);
        };
        match AcceptedClaim::rehydrate_from_admitted_store(*genesis, *device_id, admitted) {
            Ok(claim) => Ok(Some(claim)),
            Err(unresolved) => {
                log::info!("[sofi reads] no accepted claim at {position}: {unresolved:?}");
                Ok(None)
            }
        }
    }

    fn recorded_generations(
        &self,
        vault_id: &D32,
    ) -> Result<Vec<RecordedGenerationRow>, ReadFailure> {
        sofi_vault_head::recorded_generations(vault_id)
            .map_err(|e| ReadFailure(format!("recorded generations: {e}")))
    }

    fn record_generation(&self, post: &VaultPostState) -> Result<(), ReadFailure> {
        sofi_vault_head::record_walked(post)
            .map_err(|e| ReadFailure(format!("record generation: {e}")))
    }

    fn keep_completion(
        &self,
        cell: &RoutedCell,
        proof: &CompletionProof,
    ) -> Result<(), ReadFailure> {
        keep_completion(cell, proof).map_err(|e| ReadFailure(format!("keep completion: {e}")))
    }
}

/// Everything a [`Verifier`] borrows, held together: the reads over the
/// pinned set, the set's members and id, the committed network, and — when
/// the verifier is a trader — its own leaves and the position it resolved
/// itself.
pub struct VerifierContext<'a> {
    reads: LiveSofiReads<'a>,
    members: StorageSetMembers,
    set_id: D32,
    network: Vec<u8>,
    local: Option<&'a LocalLeaves>,
    parent: Option<&'a AdmittedEconomicPosition>,
}

impl<'a> VerifierContext<'a> {
    /// A verifier over `set`. `local` and `parent` are this device's own
    /// leaves and resolved predecessor when it verifies as a trader; a relay
    /// or a reader of another trader's position brings neither.
    pub fn new(
        set: &'a StorageSet,
        local: Option<&'a LocalLeaves>,
        parent: Option<&'a AdmittedEconomicPosition>,
    ) -> Result<Self, DsmError> {
        Ok(Self {
            reads: LiveSofiReads::new(set)?,
            members: as_ccb_members(set)?,
            set_id: set.id(),
            network: committed_network_id()?,
            local,
            parent,
        })
    }

    pub fn verifier(&self) -> Verifier<'_, LiveSofiReads<'a>> {
        Verifier {
            reads: &self.reads,
            members: &self.members,
            set_id: self.set_id,
            network_id: &self.network,
            local: self.local,
            parent: self.parent,
        }
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)]
mod tests {
    use super::*;
    use crate::sdk::storage_node_sdk::SetClient;
    use dsm::crypto::domain::TaggedHashDomain;
    use dsm::sofi::resolve::VaultGenesis;

    /// MR-STOR-0021 (storage §4): a candidate under a vault's genesis locator
    /// whose bytes no member holds may be the genesis, so the scan is a
    /// network failure, never "not published"; a candidate whose bytes are
    /// held and are not a genesis is established, and nothing. On the storage
    /// node's own code, on Postgres.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    #[serial_test::serial]
    async fn an_unestablished_genesis_candidate_is_not_read_as_unpublished() {
        let _fleet = crate::test_support::one_device::Fleet::start();
        let set = crate::sdk::storage_set::canonical_set(crate::economic_fixtures::NETWORK)
            .expect("the pinned set");
        let client = SetClient::new(&set).expect("a client of the set");
        let index = TAG_DSM_SOFI_VAULT_GENESIS_LOCATOR.source_bytes();
        let ctx = VerifierContext::new(&set, None, None).expect("a verifier over the set");

        // Held bytes that are not a genesis: every candidate established.
        let held_vault = [0x71; 32];
        let domain = TaggedHashDomain::try_new(b"DSM/test/not-a-vault-genesis").expect("domain");
        let garbage = b"these bytes decode as no vault genesis preimage";
        assert_eq!(client.put_immutable(domain, garbage).await, 5);
        let held = dsm::storage_object::immutable_addr(domain, garbage);
        let locator = derive::vault_genesis_locator(&held_vault);
        assert_eq!(client.append_index(index, &locator, &held).await, 5);
        assert!(matches!(
            ctx.verifier().vault_genesis(&held_vault),
            Ok(VaultGenesis::NotPublished)
        ));

        // An address whose bytes no member holds: not established.
        let unknown_vault = [0x72; 32];
        let locator = derive::vault_genesis_locator(&unknown_vault);
        assert_eq!(client.append_index(index, &locator, &[0x99; 32]).await, 5);
        assert!(
            matches!(
                ctx.verifier().vault_genesis(&unknown_vault),
                Err(VerifierFailure::Read(..))
            ),
            "a candidate nobody holds must not read as an unpublished genesis"
        );
    }
}
