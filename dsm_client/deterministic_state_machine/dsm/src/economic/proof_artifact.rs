// SPDX-License-Identifier: Apache-2.0

//! THE GENERIC ECONOMIC-INCLUSION PROOF.
//!
//! A device's economic root `R_econ` is published as a write-once register
//! cell at a named position, so any stranger can establish WHAT root a device
//! committed at position n. Nothing published which LEAVES that root commits.
//! Every consumer that needs one — a trader proving the owner's vault
//! reserves (0x0026), an owner proving the trader's settlement receipt
//! (0x0027) — needed the same thing, and neither could get it.
//!
//! This is that object, once, for both directions: a publisher, ONE named
//! economic position and root, and one or more exact economic leaves each
//! with its 256-sibling inclusion path.
//!
//! Three properties are structural, not conventions:
//!
//! 1. **One snapshot.** Every leaf and every path in an artifact must derive
//!    the ONE root the artifact names. A producer that mixed two snapshots
//!    cannot pass its own construction check, and a reader that recomputes
//!    would reject it. There is no per-leaf root.
//! 2. **No self-assertion.** The artifact carries no signature and proves
//!    nothing about its own authority. `verify_against` takes the position
//!    and root the READER established independently — from the register — and
//!    refuses an artifact naming anything else. A locator that points at an
//!    artifact (a routing advertisement, an evidence descriptor) makes it
//!    findable, never valid.
//! 3. **Keys are derived, never supplied.** The leaf key comes from the
//!    decoded state's own class and the publisher's coordinates, so a
//!    publisher cannot present a leaf under a key of its choosing.

use crate::economic::state::EconomicLeafState;
use crate::economic::tree::{leaf_node, root_from_path, ECONOMIC_SMT_HEIGHT};
use crate::types::proto as generated;
use prost::Message;

/// One leaf and the path that proves it.
#[derive(Debug, Clone)]
pub struct EconomicProofLeaf {
    pub state: EconomicLeafState,
    pub siblings: Box<[[u8; 32]; ECONOMIC_SMT_HEIGHT]>,
}

/// A strictly decoded artifact. Shape only — inclusion is checked by
/// [`EconomicProofArtifact::verify_against`], against a root the reader
/// established for itself.
#[derive(Debug, Clone)]
pub struct EconomicProofArtifact {
    pub publisher_genesis: [u8; 32],
    pub publisher_devid: [u8; 32],
    pub economic_position: u64,
    pub economic_root: [u8; 32],
    pub leaves: Vec<EconomicProofLeaf>,
}

fn digest32(bytes: &[u8], what: &str) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| format!("{what} must be 32 bytes, got {}", bytes.len()))
}

impl EconomicProofArtifact {
    /// Build and SELF-CHECK. The construction runs the same recomputation a
    /// reader will, against the root the producer names, so an artifact whose
    /// leaves and paths do not all belong to one snapshot cannot be built —
    /// let alone published. This is where the one-snapshot rule is enforced
    /// for the producer; `verify_against` enforces it for the reader.
    pub fn new(
        publisher_genesis: [u8; 32],
        publisher_devid: [u8; 32],
        economic_position: u64,
        economic_root: [u8; 32],
        leaves: Vec<EconomicProofLeaf>,
    ) -> Result<Self, String> {
        let artifact = Self {
            publisher_genesis,
            publisher_devid,
            economic_position,
            economic_root,
            leaves,
        };
        artifact.check_inclusion()?;
        Ok(artifact)
    }

    /// The canonical bytes. Content-addressed by the caller under
    /// `TAG_DSM_ECONOMIC_PROOF_ARTIFACT`.
    pub fn encode(&self) -> Vec<u8> {
        generated::EconomicProofArtifactV1 {
            publisher_genesis: self.publisher_genesis.to_vec(),
            publisher_devid: self.publisher_devid.to_vec(),
            economic_position: self.economic_position,
            economic_root: self.economic_root.to_vec(),
            leaves: self
                .leaves
                .iter()
                .map(|l| generated::EconomicProofLeafV1 {
                    // A leaf whose state cannot re-encode never reached here:
                    // `new` decoded or built it, and `check_inclusion` hashed
                    // it, both of which take the same encoding.
                    state_ccb: l.state.encode().unwrap_or_default(),
                    siblings: l.siblings.iter().map(|s| s.to_vec()).collect(),
                })
                .collect(),
        }
        .encode_to_vec()
    }

    /// THE READER'S CHECK, and the only thing that makes an artifact usable.
    ///
    /// `position` and `root` are what the reader established independently —
    /// the publisher's register cell at that position, read at quorum. An
    /// artifact naming any other publisher, position or root is refused
    /// before a single hash is recomputed, so a locator can never widen what
    /// an artifact is evidence OF.
    pub fn verify_against(
        &self,
        publisher_genesis: &[u8; 32],
        publisher_devid: &[u8; 32],
        position: u64,
        root: &[u8; 32],
    ) -> Result<(), String> {
        if self.publisher_genesis != *publisher_genesis || self.publisher_devid != *publisher_devid
        {
            return Err("the artifact names a different publisher".into());
        }
        if self.economic_position != position {
            return Err(format!(
                "the artifact names economic position {}, not the {position} it is being read at",
                self.economic_position
            ));
        }
        if self.economic_root != *root {
            return Err("the artifact names a different economic root".into());
        }
        self.check_inclusion()
    }

    /// Recompute every leaf key, every leaf commitment and every path, and
    /// require each to derive the ONE named root.
    fn check_inclusion(&self) -> Result<(), String> {
        if self.leaves.is_empty() {
            return Err("an economic proof artifact carries no leaves".into());
        }
        let mut seen: Vec<[u8; 32]> = Vec::with_capacity(self.leaves.len());
        for (i, leaf) in self.leaves.iter().enumerate() {
            // The key is DERIVED from the state's own class and the
            // publisher's coordinates — never supplied alongside it.
            let key = leaf
                .state
                .leaf_key(&self.publisher_genesis, &self.publisher_devid);
            if seen.contains(&key) {
                return Err(format!("leaf {i} repeats a key already in the artifact"));
            }
            seen.push(key);
            let value = leaf
                .state
                .leaf_value()
                .map_err(|e| format!("leaf {i} does not commit: {e:?}"))?;
            let derived = root_from_path(&key, &leaf_node(&key, Some(&value)), &leaf.siblings);
            if derived != self.economic_root {
                return Err(format!(
                    "leaf {i} does not prove into the root this artifact names"
                ));
            }
        }
        Ok(())
    }

    /// The decoded states, for a consumer that knows which leaf it wants.
    pub fn states(&self) -> impl Iterator<Item = &EconomicLeafState> {
        self.leaves.iter().map(|l| &l.state)
    }
}

/// Strict decode: canonical re-encode equality, 32-byte coordinates, at least
/// one leaf, exactly 256 fixed 32-byte siblings each, every state decodable.
///
/// Decoding does NOT check inclusion. A decoded artifact is untrusted bytes
/// until [`EconomicProofArtifact::verify_against`] runs, so no path exists
/// where shape alone reads as proof.
pub fn decode_economic_proof_artifact(bytes: &[u8]) -> Result<EconomicProofArtifact, String> {
    if bytes.is_empty() {
        return Err("empty economic proof artifact".into());
    }
    let a = generated::EconomicProofArtifactV1::decode(bytes)
        .map_err(|_| "economic proof artifact does not decode".to_string())?;
    if a.encode_to_vec() != bytes {
        return Err("economic proof artifact is not canonical".into());
    }
    if a.leaves.is_empty() {
        return Err("an economic proof artifact carries no leaves".into());
    }
    let mut leaves = Vec::with_capacity(a.leaves.len());
    for (i, l) in a.leaves.iter().enumerate() {
        if l.siblings.len() != ECONOMIC_SMT_HEIGHT {
            return Err(format!(
                "leaf {i} must carry exactly {ECONOMIC_SMT_HEIGHT} siblings, got {}",
                l.siblings.len()
            ));
        }
        let mut siblings = Box::new([[0u8; 32]; ECONOMIC_SMT_HEIGHT]);
        for (j, s) in l.siblings.iter().enumerate() {
            siblings[j] = digest32(s, &format!("leaf {i} sibling {j}"))?;
        }
        let state = crate::economic::decode::decode_leaf_state(&l.state_ccb)
            .map_err(|e| format!("leaf {i} state: {e}"))?;
        leaves.push(EconomicProofLeaf { state, siblings });
    }
    Ok(EconomicProofArtifact {
        publisher_genesis: digest32(&a.publisher_genesis, "publisher_genesis")?,
        publisher_devid: digest32(&a.publisher_devid, "publisher_devid")?,
        economic_position: a.economic_position,
        economic_root: digest32(&a.economic_root, "economic_root")?,
        leaves,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economic::state::{EconomicBalanceState, EconomicVaultReserveState};
    use crate::economic::tree::EconomicSmt;

    const G: [u8; 32] = [0x61; 32];
    const D: [u8; 32] = [0x62; 32];
    const VAULT: [u8; 32] = [0x63; 32];

    fn reserve(pc: u8, amount: u64, sequence: u64) -> EconomicLeafState {
        EconomicLeafState::VaultReserve(EconomicVaultReserveState {
            vault_id: VAULT,
            policy_commit: [pc; 32],
            amount,
            vault_sequence: sequence,
        })
    }

    /// A tree holding `states`, and the artifact proving all of them.
    fn published(states: &[EconomicLeafState]) -> (EconomicSmt, EconomicProofArtifact) {
        let mut tree = EconomicSmt::new();
        for s in states {
            tree.insert(s.leaf_key(&G, &D), s.leaf_value().expect("leaf value"));
        }
        let leaves = states
            .iter()
            .map(|s| EconomicProofLeaf {
                state: s.clone(),
                siblings: Box::new(tree.siblings(&s.leaf_key(&G, &D))),
            })
            .collect();
        let artifact =
            EconomicProofArtifact::new(G, D, 7, tree.root(), leaves).expect("artifact builds");
        (tree, artifact)
    }

    /// The whole point: a stranger holding only the publisher's coordinates,
    /// position and root — everything the register cell gives it — recomputes
    /// every leaf and every path and gets that root back. Round-tripping the
    /// bytes changes nothing, because the bytes are all the stranger has.
    #[test]
    fn an_artifact_proves_its_leaves_into_the_root_a_reader_establishes_itself() {
        let (tree, artifact) = published(&[reserve(0xA1, 10_000, 0), reserve(0xB2, 5_000, 0)]);
        let bytes = artifact.encode();
        let decoded = decode_economic_proof_artifact(&bytes).expect("decodes");
        decoded
            .verify_against(&G, &D, 7, &tree.root())
            .expect("a reader recomputes the named root from the leaves and paths");
        assert_eq!(decoded.states().count(), 2);
    }

    /// ONE SNAPSHOT. A path taken before another leaf landed proves into the
    /// OLD root, so an artifact that mixes snapshots cannot be built — the
    /// producer's own construction check refuses it — and cannot be read.
    #[test]
    fn leaves_and_paths_from_two_snapshots_cannot_be_published_or_read() {
        let a = reserve(0xA1, 10_000, 0);
        let b = reserve(0xB2, 5_000, 0);
        let mut tree = EconomicSmt::new();
        tree.insert(a.leaf_key(&G, &D), a.leaf_value().expect("v"));
        // Path for `a` taken BEFORE `b` lands.
        let stale = Box::new(tree.siblings(&a.leaf_key(&G, &D)));
        tree.insert(b.leaf_key(&G, &D), b.leaf_value().expect("v"));
        let fresh = Box::new(tree.siblings(&b.leaf_key(&G, &D)));
        let root = tree.root();

        let err = EconomicProofArtifact::new(
            G,
            D,
            7,
            root,
            vec![
                EconomicProofLeaf {
                    state: a.clone(),
                    siblings: stale.clone(),
                },
                EconomicProofLeaf {
                    state: b.clone(),
                    siblings: fresh.clone(),
                },
            ],
        )
        .expect_err("a mixed-snapshot artifact must not be constructible");
        assert!(err.contains("does not prove into the root"), "got: {err}");

        // And the same bytes, assembled by hand, are refused by the reader.
        let forged = EconomicProofArtifact {
            publisher_genesis: G,
            publisher_devid: D,
            economic_position: 7,
            economic_root: root,
            leaves: vec![
                EconomicProofLeaf {
                    state: a,
                    siblings: stale,
                },
                EconomicProofLeaf {
                    state: b,
                    siblings: fresh,
                },
            ],
        };
        let bytes = forged.encode();
        let err = decode_economic_proof_artifact(&bytes)
            .expect("shape is fine")
            .verify_against(&G, &D, 7, &root)
            .expect_err("the reader must refuse it too");
        assert!(err.contains("does not prove into the root"), "got: {err}");
    }

    /// NO SELF-ASSERTION. The reader's position and root decide what the
    /// artifact may be evidence of. An artifact naming another publisher,
    /// another position or another root is refused, whatever it contains.
    #[test]
    fn an_artifact_is_refused_against_coordinates_it_does_not_name() {
        let (tree, artifact) = published(&[reserve(0xA1, 10_000, 0)]);
        let root = tree.root();
        for (name, e) in [
            (
                "another publisher",
                artifact.verify_against(&[0x99; 32], &D, 7, &root),
            ),
            (
                "another device",
                artifact.verify_against(&G, &[0x99; 32], 7, &root),
            ),
            (
                "another position",
                artifact.verify_against(&G, &D, 8, &root),
            ),
            (
                "another root",
                artifact.verify_against(&G, &D, 7, &[0x99; 32]),
            ),
        ] {
            assert!(e.is_err(), "{name} must be refused");
        }
        artifact
            .verify_against(&G, &D, 7, &root)
            .expect("the real coordinates still verify");
    }

    /// A tampered path fails the recomputation, and a leaf presented twice is
    /// refused before it can be counted twice.
    #[test]
    fn a_tampered_path_or_a_repeated_leaf_is_refused() {
        let (tree, artifact) = published(&[reserve(0xA1, 10_000, 0), reserve(0xB2, 5_000, 0)]);
        let root = tree.root();

        let mut tampered = artifact.clone();
        tampered.leaves[0].siblings[0][0] ^= 0x01;
        let err = tampered
            .verify_against(&G, &D, 7, &root)
            .expect_err("a tampered sibling must be refused");
        assert!(err.contains("does not prove into the root"), "got: {err}");

        let mut repeated = artifact.clone();
        repeated.leaves.push(artifact.leaves[0].clone());
        let err = repeated
            .verify_against(&G, &D, 7, &root)
            .expect_err("a repeated leaf must be refused");
        assert!(err.contains("repeats a key"), "got: {err}");
    }

    /// A leaf the root does not commit at all — the amount it claims is not
    /// the amount the tree holds — cannot be dressed up with a real path.
    #[test]
    fn a_leaf_whose_value_the_root_does_not_commit_is_refused() {
        let real = reserve(0xA1, 10_000, 0);
        let (tree, _) = published(std::slice::from_ref(&real));
        let inflated = reserve(0xA1, 10_001, 0);
        let artifact = EconomicProofArtifact {
            publisher_genesis: G,
            publisher_devid: D,
            economic_position: 7,
            economic_root: tree.root(),
            leaves: vec![EconomicProofLeaf {
                state: inflated,
                siblings: Box::new(tree.siblings(&real.leaf_key(&G, &D))),
            }],
        };
        let err = artifact
            .verify_against(&G, &D, 7, &tree.root())
            .expect_err("an amount the root does not commit must be refused");
        assert!(err.contains("does not prove into the root"), "got: {err}");
    }

    /// Decode is strict about shape, and shape alone is never proof: the
    /// decode of a well-formed artifact does not check inclusion.
    #[test]
    fn decode_is_strict_and_does_not_check_inclusion() {
        assert!(decode_economic_proof_artifact(&[]).is_err());
        assert!(decode_economic_proof_artifact(&[0xFF, 0xFF]).is_err());

        let (tree, artifact) = published(&[EconomicLeafState::Balance(
            EconomicBalanceState::new([0xC3; 32], 42).expect("balance"),
        )]);
        let bytes = artifact.encode();
        let mut trailing = bytes.clone();
        trailing.push(0x00);
        assert!(
            decode_economic_proof_artifact(&trailing).is_err(),
            "non-canonical bytes must be refused"
        );

        // Short sibling vector.
        let mut short = generated::EconomicProofArtifactV1::decode(bytes.as_slice()).expect("d");
        short.leaves[0].siblings.truncate(255);
        let err = decode_economic_proof_artifact(&short.encode_to_vec())
            .expect_err("a short path must be refused");
        assert!(err.contains("exactly 256 siblings"), "got: {err}");

        // No leaves at all.
        let mut empty = generated::EconomicProofArtifactV1::decode(bytes.as_slice()).expect("d");
        empty.leaves.clear();
        assert!(decode_economic_proof_artifact(&empty.encode_to_vec()).is_err());

        // A well-formed artifact carrying a WRONG root decodes fine; only
        // `verify_against` rejects it. Shape is not evidence.
        let mut wrong = generated::EconomicProofArtifactV1::decode(bytes.as_slice()).expect("d");
        wrong.economic_root = vec![0x99; 32];
        let decoded =
            decode_economic_proof_artifact(&wrong.encode_to_vec()).expect("shape is still valid");
        assert!(decoded.verify_against(&G, &D, 7, &tree.root()).is_err());
    }
}
