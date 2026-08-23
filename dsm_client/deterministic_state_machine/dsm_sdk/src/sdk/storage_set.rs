// SPDX-License-Identifier: MIT OR Apache-2.0

//! Canonical storage-set identity and the local catalog that resolves it.
//!
//! A quorum argument ("2 of 3") is only meaningful over ONE stable set of
//! DISTINCT members. URLs are not identity (a URL can change; two catalog
//! entries can point at one physical node), and the local node list is not
//! protocol identity (two devices can be configured differently). So:
//!
//! * a **`StorageSet`** is a validated, sorted list of distinct member
//!   identities (the storage node's own configured `node.id`) with the
//!   endpoint that currently reaches each one; its **id** is the canonical
//!   digest of the member identities alone — never of endpoints;
//! * a **`StorageSetCatalog`** is the device's local knowledge of sets. It
//!   never chooses a set: an authenticated `storage_set_id` (from a vault's
//!   signed birth anchor, or frozen on a publication artifact) is RESOLVED
//!   through it, and an entry is usable only if re-encoding + re-hashing its
//!   member ids reproduces that exact id. Otherwise the caller fails closed.
//!   *The anchor chooses the set; configuration only resolves it into
//!   endpoints.*
//!
//! Beta: the catalog holds exactly the one configured fleet, and that set is
//! immutable for the lifetime of every vault born under it. Membership change
//! is an explicit handover protocol (follow-up), not a config edit.
//!
//! "Distinct members" is executable, not administrative: member ids must be
//! unique, endpoints must be injective within a set, and (see
//! `storage_io::put_bytes_to_all_members`) an acceptance counts only when the
//! node echoes the configured id the catalog says lives at that endpoint.

use dsm::types::error::DsmError;

/// One member of a storage set: its protocol identity and its current
/// transport endpoint. `endpoint` is metadata; only `member_id` is hashed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageMember {
    pub member_id: String,
    pub endpoint: String,
}

/// A validated storage set. Members are held sorted by `member_id` (byte
/// order), unique, with injective endpoints; `id` is derived, never supplied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageSet {
    id: [u8; 32],
    members: Vec<StorageMember>,
}

/// Canonical storage-set id over member identities:
/// `storage_set_id = H_dom(DSM/storage-set, CCB(S))`.
///
/// **Delegates to the CCB encoder rather than recomputing the bytes.** This
/// function used to carry its own copy of the layout, and the storage node
/// called it directly so the two agreed by sharing code — implementation
/// monoculture, which holds only until a second implementation exists. The
/// bytes now come from `dsm::ccb`, which is written from the object registry.
///
/// Validity conditions live in the encoder too: at least one member, no empty
/// id, no duplicate. Duplicates are refused rather than collapsed, since
/// collapsing would map two logical inputs onto one encoding.
pub fn compute_storage_set_id(member_ids: &[&str]) -> Result<[u8; 32], DsmError> {
    let ids: Vec<&[u8]> = member_ids.iter().map(|s| s.as_bytes()).collect();
    let members = dsm::ccb::StorageSetMembers::new(&ids)
        .map_err(|e| DsmError::invalid_operation(format!("storage set: {e}")))?;
    dsm::ccb::storage_set_id(&members)
        .map_err(|e| DsmError::invalid_operation(format!("storage set: {e}")))
}

impl StorageSet {
    /// Build a set from members, validating distinctness on BOTH axes: unique
    /// member ids (the identity the quorum counts) and injective endpoints
    /// (so two catalog members cannot resolve to one physical node and yield
    /// two "acceptances").
    pub fn new(mut members: Vec<StorageMember>) -> Result<Self, DsmError> {
        members.sort_by(|x, y| x.member_id.as_bytes().cmp(y.member_id.as_bytes()));
        for m in &members {
            if m.endpoint.trim().is_empty() {
                return Err(DsmError::invalid_operation(format!(
                    "storage set: member {:?} has an empty endpoint",
                    m.member_id
                )));
            }
        }
        {
            let mut endpoints: Vec<&str> = members.iter().map(|m| m.endpoint.as_str()).collect();
            endpoints.sort_unstable();
            if endpoints.windows(2).any(|w| w[0] == w[1]) {
                return Err(DsmError::invalid_operation(
                    "storage set: two members share one endpoint — a set's members must be \
                     distinct physical nodes",
                ));
            }
        }
        let ids: Vec<&str> = members.iter().map(|m| m.member_id.as_str()).collect();
        let id = compute_storage_set_id(&ids)?;
        Ok(Self { id, members })
    }

    /// The canonical set id (a function of member ids only).
    pub fn id(&self) -> [u8; 32] {
        self.id
    }

    /// Members, sorted by member id.
    pub fn members(&self) -> &[StorageMember] {
        &self.members
    }

    pub fn len(&self) -> usize {
        self.members.len()
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// The ONE definition of quorum for this set: a strict majority of its
    /// members (`crate::storage::client_db::publication::quorum_for`).
    /// Publication quorum (delivery) and the settlement-slot register (the
    /// one-shot claim) both count with this — birth activation depends on
    /// publication reaching it, so it must not drift from the register's.
    pub fn quorum(&self) -> u32 {
        crate::storage::client_db::publication::quorum_for(self.members.len())
    }

    pub fn member(&self, member_id: &str) -> Option<&StorageMember> {
        self.members.iter().find(|m| m.member_id == member_id)
    }
}

/// The device's local knowledge of storage sets. Resolution is by
/// re-derivation: an entry answers for an id only if hashing its own member
/// ids reproduces that id exactly.
#[derive(Debug, Clone, Default)]
pub struct StorageSetCatalog {
    sets: Vec<StorageSet>,
}

impl StorageSetCatalog {
    pub fn new(sets: Vec<StorageSet>) -> Result<Self, DsmError> {
        let mut ids: Vec<[u8; 32]> = sets.iter().map(|s| s.id()).collect();
        ids.sort_unstable();
        if ids.windows(2).any(|w| w[0] == w[1]) {
            return Err(DsmError::invalid_operation(
                "storage set catalog: two entries have the same set id",
            ));
        }
        Ok(Self { sets })
    }

    /// The catalog this device is configured with. Beta: exactly one set — the
    /// configured fleet — built from the env config's `[[nodes]]` entries,
    /// where `name` is the node's configured protocol identity (`node.id`) and
    /// `endpoint` its transport address.
    pub fn from_env_config() -> Result<Self, DsmError> {
        let env = crate::network::NetworkConfigLoader::load_env_config()?;
        let members: Vec<StorageMember> = env
            .nodes
            .into_iter()
            .map(|n| StorageMember {
                member_id: n.name,
                endpoint: n.endpoint,
            })
            .collect();
        let set = StorageSet::new(members)?;
        Self::new(vec![set])
    }

    /// Resolve an authenticated set id to a usable set, or `None` (the caller
    /// fails closed — never falls back to "my fleet"). The match is by
    /// re-hashing the entry's member ids, not by trusting a stored id.
    pub fn resolve(&self, storage_set_id: &[u8; 32]) -> Option<&StorageSet> {
        self.sets.iter().find(|s| {
            let ids: Vec<&str> = s.members().iter().map(|m| m.member_id.as_str()).collect();
            compute_storage_set_id(&ids).ok().as_ref() == Some(storage_set_id)
        })
    }

    /// Beta convenience: the one configured set, when there is exactly one.
    /// Producers (vault birth) use this to CHOOSE a set; consumers never do —
    /// they resolve the set the vault was born under.
    pub fn sole_set(&self) -> Option<&StorageSet> {
        match self.sets.as_slice() {
            [only] => Some(only),
            _ => None,
        }
    }

    pub fn sets(&self) -> &[StorageSet] {
        &self.sets
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(id: &str, ep: &str) -> StorageMember {
        StorageMember {
            member_id: id.to_string(),
            endpoint: ep.to_string(),
        }
    }

    #[test]
    fn set_id_is_order_independent_and_length_prefixed() {
        let a = compute_storage_set_id(&["n1", "n2", "n3"]).unwrap();
        let b = compute_storage_set_id(&["n3", "n1", "n2"]).unwrap();
        assert_eq!(a, b, "order-independent");
        // Length-prefixing: ["ab","c"] and ["a","bc"] concatenate to the same
        // bytes; they must NOT hash the same.
        let x = compute_storage_set_id(&["ab", "c"]).unwrap();
        let y = compute_storage_set_id(&["a", "bc"]).unwrap();
        assert_ne!(x, y, "variable-length ids cannot be re-split");
        assert!(
            compute_storage_set_id(&["n1", "n1"]).is_err(),
            "duplicate refused"
        );
        assert!(compute_storage_set_id(&[]).is_err(), "empty refused");
        assert!(
            compute_storage_set_id(&["", "n1"]).is_err(),
            "empty id refused"
        );
    }

    #[test]
    fn set_refuses_duplicate_ids_and_shared_endpoints() {
        assert!(StorageSet::new(vec![m("a", "http://x"), m("a", "http://y")]).is_err());
        assert!(
            StorageSet::new(vec![m("a", "http://x"), m("b", "http://x")]).is_err(),
            "two members on one endpoint are not distinct nodes"
        );
        let ok = StorageSet::new(vec![m("b", "http://y"), m("a", "http://x")]).unwrap();
        assert_eq!(ok.members()[0].member_id, "a", "sorted by member id");
        assert_eq!(ok.quorum(), 2, "2 of 2 members");
        let three = StorageSet::new(vec![
            m("a", "http://x"),
            m("b", "http://y"),
            m("c", "http://z"),
        ])
        .unwrap();
        assert_eq!(three.quorum(), 2, "2 of 3");
    }

    #[test]
    fn catalog_resolves_only_by_rehash_and_never_falls_back() {
        let s = StorageSet::new(vec![
            m("a", "http://x"),
            m("b", "http://y"),
            m("c", "http://z"),
        ])
        .unwrap();
        let cat = StorageSetCatalog::new(vec![s.clone()]).unwrap();
        assert!(cat.resolve(&s.id()).is_some());
        let foreign = compute_storage_set_id(&["c", "d", "e"]).unwrap();
        assert!(
            cat.resolve(&foreign).is_none(),
            "an unknown set resolves to nothing"
        );
        assert!(cat.sole_set().is_some());
        // Two entries with the same id are refused.
        assert!(StorageSetCatalog::new(vec![s.clone(), s]).is_err());
    }
}
