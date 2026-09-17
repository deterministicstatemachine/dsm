// SPDX-License-Identifier: MIT OR Apache-2.0

//! Durable home of the persistent DLV tree ([`dsm::sofi::smt`]).
//!
//! Two tables. `sofi_smt_nodes_v2` maps an address to the canonical bytes of the
//! node that hashes to it — write-once, and verified against the address on
//! every read. `sofi_smt_pins_v2` counts the pins on each root.
//!
//! A commit takes the builder's opaque [`Shadow`] and writes its new nodes and
//! its root's pin in ONE transaction, so a crash leaves either both or neither.
//! Before it writes anything it runs [`validate_staged_frontier`], so a commit
//! whose dependencies are not present is refused whole. Collection runs in one
//! IMMEDIATE transaction too, so no commit interleaves with its mark and sweep.
//!
//! Dark: nothing calls this yet.

use dsm::sofi::smt::{collect_garbage, validate_staged_frontier, Node, NodeStore, Shadow, SmtError};
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

fn store_err(e: rusqlite::Error) -> SmtError {
    SmtError::Store(e.to_string())
}

fn fixed32(bytes: &[u8]) -> Result<[u8; 32], SmtError> {
    <[u8; 32]>::try_from(bytes)
        .map_err(|_| SmtError::Store("address column is not 32 bytes".into()))
}

/// A [`NodeStore`] over one SQLite connection.
pub struct SqliteNodeStore<'c> {
    conn: &'c Connection,
}

impl<'c> SqliteNodeStore<'c> {
    pub fn new(conn: &'c Connection) -> Self {
        Self { conn }
    }

    fn root_is_stored(&self, root: &[u8; 32]) -> Result<bool, SmtError> {
        if *root == dsm::economic::tree::empty_economic_root() {
            return Ok(true);
        }
        self.conn
            .query_row(
                "SELECT 1 FROM sofi_smt_nodes_v2 WHERE addr = ?1",
                params![root.as_slice()],
                |_| Ok(()),
            )
            .optional()
            .map(|r| r.is_some())
            .map_err(store_err)
    }
}

impl NodeStore for SqliteNodeStore<'_> {
    fn get_node(&self, address: &[u8; 32]) -> Result<Option<Node>, SmtError> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT node FROM sofi_smt_nodes_v2 WHERE addr = ?1",
                params![address.as_slice()],
                |row| row.get(0),
            )
            .optional()
            .map_err(store_err)?;
        bytes.map(|b| Node::decode_at(address, &b)).transpose()
    }

    fn commit(&mut self, shadow: &Shadow) -> Result<(), SmtError> {
        validate_staged_frontier(self, shadow)?;
        let tx = self.conn.unchecked_transaction().map_err(store_err)?;
        for node in shadow.new_nodes() {
            let address = node.address();
            let bytes = node.encode();
            tx.execute(
                "INSERT OR IGNORE INTO sofi_smt_nodes_v2 (addr, node) VALUES (?1, ?2)",
                params![address.as_slice(), bytes],
            )
            .map_err(store_err)?;
            let stored: Vec<u8> = tx
                .query_row(
                    "SELECT node FROM sofi_smt_nodes_v2 WHERE addr = ?1",
                    params![address.as_slice()],
                    |row| row.get(0),
                )
                .map_err(store_err)?;
            if stored != bytes {
                // Dropping `tx` rolls back every node written above.
                return Err(SmtError::ConflictingNode);
            }
        }
        tx.execute(
            "INSERT INTO sofi_smt_pins_v2 (root, pins) VALUES (?1, 1)
             ON CONFLICT(root) DO UPDATE SET pins = pins + 1",
            params![shadow.root().as_slice()],
        )
        .map_err(store_err)?;
        tx.commit().map_err(store_err)
    }

    fn pin(&mut self, root: &[u8; 32]) -> Result<(), SmtError> {
        if !self.root_is_stored(root)? {
            return Err(SmtError::MissingNode);
        }
        self.conn
            .execute(
                "INSERT INTO sofi_smt_pins_v2 (root, pins) VALUES (?1, 1)
                 ON CONFLICT(root) DO UPDATE SET pins = pins + 1",
                params![root.as_slice()],
            )
            .map_err(store_err)?;
        Ok(())
    }

    fn unpin(&mut self, root: &[u8; 32]) -> Result<(), SmtError> {
        // The last pin removes the row; a count never reaches zero in the table.
        let released = self
            .conn
            .execute(
                "DELETE FROM sofi_smt_pins_v2 WHERE root = ?1 AND pins = 1",
                params![root.as_slice()],
            )
            .map_err(store_err)?;
        if released == 1 {
            return Ok(());
        }
        let decremented = self
            .conn
            .execute(
                "UPDATE sofi_smt_pins_v2 SET pins = pins - 1 WHERE root = ?1 AND pins > 1",
                params![root.as_slice()],
            )
            .map_err(store_err)?;
        if decremented == 0 {
            return Err(SmtError::NotPinned);
        }
        Ok(())
    }

    fn pinned_roots(&self) -> Result<Vec<[u8; 32]>, SmtError> {
        let mut stmt = self
            .conn
            .prepare("SELECT root FROM sofi_smt_pins_v2")
            .map_err(store_err)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(store_err)?;
        rows.map(|r| r.map_err(store_err).and_then(|b| fixed32(&b)))
            .collect()
    }

    fn node_addresses(&self) -> Result<Vec<[u8; 32]>, SmtError> {
        let mut stmt = self
            .conn
            .prepare("SELECT addr FROM sofi_smt_nodes_v2")
            .map_err(store_err)?;
        let rows = stmt
            .query_map([], |row| row.get::<_, Vec<u8>>(0))
            .map_err(store_err)?;
        rows.map(|r| r.map_err(store_err).and_then(|b| fixed32(&b)))
            .collect()
    }

    fn remove_nodes(&mut self, addresses: &[[u8; 32]]) -> Result<(), SmtError> {
        let mut stmt = self
            .conn
            .prepare("DELETE FROM sofi_smt_nodes_v2 WHERE addr = ?1")
            .map_err(store_err)?;
        for address in addresses {
            stmt.execute(params![address.as_slice()])
                .map_err(store_err)?;
        }
        Ok(())
    }
}

/// Collect every node no pinned root reaches, in one IMMEDIATE transaction.
/// Refuses — removing nothing — if a pinned root is not fully stored.
pub fn collect_garbage_with_conn(conn: &mut Connection) -> Result<usize, SmtError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(store_err)?;
    let removed = {
        let mut store = SqliteNodeStore::new(&tx);
        collect_garbage(&mut store)?
    };
    tx.commit().map_err(store_err)?;
    Ok(removed)
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;
    use dsm::economic::tree::{empty_economic_root, EconomicSmt};
    use dsm::economic::tree::{default_node, ECONOMIC_SMT_HEIGHT};
    use dsm::sofi::smt::{apply, commit_shadow, get, prove, reachable, verify, Mutation};

    fn keys(n: usize) -> Vec<[u8; 32]> {
        (0..n)
            .map(|i| {
                let mut k = [0u8; 32];
                let x = (i as u64)
                    .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                    .rotate_left(17);
                k[..8].copy_from_slice(&x.to_be_bytes());
                k[8..16].copy_from_slice(&(!x).to_be_bytes());
                k[31] = i as u8;
                k
            })
            .collect()
    }

    fn value(i: usize) -> [u8; 32] {
        let mut v = [0x5Au8; 32];
        v[..8].copy_from_slice(&(i as u64).to_be_bytes());
        v
    }

    /// A key whose top bit chooses `side`, so a pair of them sits under one
    /// internal node.
    fn keyed(side: u8, byte: u8) -> [u8; 32] {
        let mut k = [byte; 32];
        k[0] = if side == 0 { 0x00 } else { 0x80 };
        k
    }

    /// Two single-leaf subtrees at `height`, and the internal node over them.
    fn pair_at(height: u16, byte: u8) -> (Node, Node, Node) {
        let left = Node::Single {
            height,
            key: keyed(0, byte),
            value: [byte; 32],
        };
        let right = Node::Single {
            height,
            key: keyed(1, byte),
            value: [byte ^ 0x0F; 32],
        };
        let root = Node::Internal {
            left: left.address(),
            right: right.address(),
        };
        (root, left, right)
    }

    /// A commit input `apply` would never produce. Only the test build can
    /// build one; `ci/sofi_shadow_nonforgeable.sh` proves production cannot.
    fn forge(root: [u8; 32], nodes: Vec<Node>) -> Shadow {
        Shadow::forge_for_tests(empty_economic_root(), root, nodes)
    }

    fn open(path: &std::path::Path) -> Connection {
        let conn = Connection::open(path).unwrap();
        super::super::create_schema(&conn).unwrap();
        conn
    }

    /// Committed trees survive closing and reopening the database, and read
    /// back as the reference tree.
    #[test]
    fn a_committed_tree_survives_reopening_the_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dsm_client.db");
        let ks = keys(300);
        let mut reference = EconomicSmt::new();
        let root = {
            let conn = open(&path);
            let mut store = SqliteNodeStore::new(&conn);
            let muts: Vec<Mutation> = ks
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    reference.insert(*k, value(i));
                    Mutation {
                        key: *k,
                        value: Some(value(i)),
                    }
                })
                .collect();
            let shadow = apply(&store, &empty_economic_root(), &muts).unwrap();
            commit_shadow(&mut store, &shadow).unwrap();
            shadow.root()
        };
        let conn = open(&path);
        let store = SqliteNodeStore::new(&conn);
        assert_eq!(root, reference.root());
        assert_eq!(store.pinned_roots().unwrap(), vec![root]);
        for (i, k) in ks.iter().enumerate().step_by(37) {
            assert_eq!(get(&store, &root, k).unwrap(), Some(value(i)));
            let proof = prove(&store, &root, k).unwrap();
            assert_eq!(*proof.siblings, reference.siblings(k));
            assert!(verify(&root, k, Some(&value(i)), &proof.siblings));
        }
    }

    /// A commit that fails part-way leaves no node and no pin behind.
    #[test]
    fn a_failed_commit_rolls_back_every_node_and_the_pin() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("dsm_client.db"));
        let mut store = SqliteNodeStore::new(&conn);
        let root = Node::Single {
            height: 256,
            key: [1; 32],
            value: [2; 32],
        };
        let victim = Node::Single {
            height: 256,
            key: [3; 32],
            value: [4; 32],
        };
        // Different bytes already sit at the victim's address.
        conn.execute(
            "INSERT INTO sofi_smt_nodes_v2 (addr, node) VALUES (?1, ?2)",
            params![victim.address().as_slice(), root.encode()],
        )
        .unwrap();
        assert_eq!(
            store.commit(&forge(root.address(), vec![root, victim])),
            Err(SmtError::ConflictingNode)
        );
        assert_eq!(store.node_addresses().unwrap(), vec![victim.address()]);
        assert!(store.pinned_roots().unwrap().is_empty());
    }

    /// The durable store runs the same staged-frontier closure as the memory
    /// one, before it writes anything: a root nothing reaches, a child or a
    /// grandchild missing, or a node at an impossible height are each refused
    /// with zero nodes and zero pins.
    #[test]
    fn a_commit_whose_frontier_is_not_closed_is_refused_whole() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("dsm_client.db"));
        let mut store = SqliteNodeStore::new(&conn);

        let refused = |store: &mut SqliteNodeStore<'_>, shadow, expected: SmtError| {
            assert_eq!(store.commit(&shadow), Err(expected));
            assert!(store.node_addresses().unwrap().is_empty());
            assert!(store.pinned_roots().unwrap().is_empty());
        };

        // An unknown root, with nothing staged.
        refused(
            &mut store,
            forge([0x5E; 32], Vec::new()),
            SmtError::MissingNode,
        );

        // A staged root missing one child, then missing a grandchild.
        let (root, left, right) = pair_at(255, 0x31);
        refused(
            &mut store,
            forge(root.address(), vec![root, left]),
            SmtError::MissingNode,
        );
        let (inner, grandchild, absent) = pair_at(254, 0x47);
        let deep = Node::Internal {
            left: inner.address(),
            right: right.address(),
        };
        refused(
            &mut store,
            forge(deep.address(), vec![deep, inner, right, grandchild]),
            SmtError::MissingNode,
        );

        // A leaf folded to the wrong height.
        let shallow = Node::Single {
            height: 254,
            key: keyed(0, 0x7A),
            value: [0x7A; 32],
        };
        let bent = Node::Internal {
            left: shallow.address(),
            right: right.address(),
        };
        assert!(matches!(
            store.commit(&forge(bent.address(), vec![bent, shallow, right])),
            Err(SmtError::CorruptNode { .. })
        ));
        assert!(store.node_addresses().unwrap().is_empty());
        assert!(store.pinned_roots().unwrap().is_empty());

        // An internal node where a leaf sits, reached by a full descent.
        let bottom = Node::Internal {
            left: [3; 32],
            right: [4; 32],
        };
        let mut chain = vec![bottom];
        let mut node = bottom;
        for height in 1..=ECONOMIC_SMT_HEIGHT {
            node = Node::Internal {
                left: node.address(),
                right: default_node(height - 1),
            };
            chain.push(node);
        }
        assert!(matches!(
            store.commit(&forge(node.address(), chain)),
            Err(SmtError::CorruptNode { .. })
        ));
        assert!(store.node_addresses().unwrap().is_empty());
        assert!(store.pinned_roots().unwrap().is_empty());

        // The closed frontier, the empty root, and an already stored root pass.
        store
            .commit(&forge(
                deep.address(),
                vec![deep, inner, right, grandchild, absent],
            ))
            .unwrap();
        assert_eq!(store.node_addresses().unwrap().len(), 5);
        store
            .commit(&forge(empty_economic_root(), Vec::new()))
            .unwrap();
        store.commit(&forge(deep.address(), Vec::new())).unwrap();
        assert_eq!(store.pinned_roots().unwrap().len(), 2);
    }

    #[test]
    fn bytes_under_the_wrong_address_read_as_corrupt() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("dsm_client.db"));
        let store = SqliteNodeStore::new(&conn);
        let node = Node::Internal {
            left: [7; 32],
            right: [8; 32],
        };
        conn.execute(
            "INSERT INTO sofi_smt_nodes_v2 (addr, node) VALUES (?1, ?2)",
            params![[0x99u8; 32].as_slice(), node.encode()],
        )
        .unwrap();
        assert!(matches!(
            store.get_node(&[0x99; 32]),
            Err(SmtError::CorruptNode { .. })
        ));
    }

    /// Collection in one transaction keeps what pinned roots reach; the
    /// unpinned shadow's own nodes go, the shared ones stay.
    #[test]
    fn collection_removes_only_unreachable_nodes() {
        let dir = tempfile::tempdir().unwrap();
        let mut conn = open(&dir.path().join("dsm_client.db"));
        let ks = keys(120);
        let (parent, shadow, shadow_only, parent_count) = {
            let mut store = SqliteNodeStore::new(&conn);
            let muts: Vec<Mutation> = ks
                .iter()
                .enumerate()
                .map(|(i, k)| Mutation {
                    key: *k,
                    value: Some(value(i)),
                })
                .collect();
            let parent = apply(&store, &empty_economic_root(), &muts).unwrap();
            commit_shadow(&mut store, &parent).unwrap();
            let shadow = apply(
                &store,
                &parent.root(),
                &[
                    Mutation {
                        key: ks[4],
                        value: None,
                    },
                    Mutation {
                        key: [0xF0; 32],
                        value: Some([1; 32]),
                    },
                ],
            )
            .unwrap();
            commit_shadow(&mut store, &shadow).unwrap();
            let parent_nodes = reachable(&store, &[parent.root()]).unwrap();
            let shadow_only = reachable(&store, &[shadow.root()])
                .unwrap()
                .difference(&parent_nodes)
                .count();
            store.unpin(&shadow.root()).unwrap();
            (
                parent.root(),
                shadow.root(),
                shadow_only,
                parent_nodes.len(),
            )
        };
        assert!(shadow_only > 0);
        assert_eq!(collect_garbage_with_conn(&mut conn).unwrap(), shadow_only);
        let store = SqliteNodeStore::new(&conn);
        assert_eq!(store.node_addresses().unwrap().len(), parent_count);
        assert_eq!(get(&store, &parent, &ks[4]).unwrap(), Some(value(4)));
        assert_eq!(
            get(&store, &shadow, &[0xF0; 32]),
            Err(SmtError::MissingNode)
        );
    }

    #[test]
    fn pins_count_and_refuse_an_unstored_root() {
        let dir = tempfile::tempdir().unwrap();
        let conn = open(&dir.path().join("dsm_client.db"));
        let mut store = SqliteNodeStore::new(&conn);
        assert_eq!(store.pin(&[0x42; 32]), Err(SmtError::MissingNode));
        let one = apply(
            &store,
            &empty_economic_root(),
            &[Mutation {
                key: [9; 32],
                value: Some([9; 32]),
            }],
        )
        .unwrap();
        commit_shadow(&mut store, &one).unwrap();
        store.pin(&one.root()).unwrap();
        store.unpin(&one.root()).unwrap();
        store.unpin(&one.root()).unwrap();
        assert_eq!(store.unpin(&one.root()), Err(SmtError::NotPinned));
        assert!(store.pinned_roots().unwrap().is_empty());
    }
}
