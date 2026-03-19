#![allow(dead_code)]
#![allow(clippy::disallowed_methods)]
//! DSM Bilateral Transaction Example — clean drop-in
//!
//! Demonstrates a full bilateral flow using the SDK surfaces you’ve been wiring:
//! 1) Contact establishment with mutual Genesis anchoring
//! 2) Bilateral relationship creation (synchronized anchors)
//! 3) Pre-commitment creation (offline-capable)
//! 4) Transaction execution over Bluetooth transport (offline)
//! 5) Relationship integrity + (optional) SMT inclusion proof checks
//!
//! Notes:
//! - No serde. No JSON/base64/hex in logic. Terminal prints use a tiny preview helper.
//! - All binary identifiers stay as bytes; display helpers are UI-only.

use std::collections::HashMap;

use dsm::core::bilateral_relationship_manager::{
    BilateralRelationshipManager, ContactEstablishmentRequest,
};
use dsm::core::bilateral_transaction_manager::BilateralTransactionManager;
use dsm::core::contact_manager::DsmContactManager;
use dsm::crypto::signatures::SignatureKeyPair;
use dsm::types::error::DsmError;
use dsm::types::identifiers::NodeId;
use dsm::types::operations::{Operation, TransactionMode, VerificationType};
use dsm::types::token_types::Balance;

// ----------------------------- display helpers (UI-only) -----------------------------

fn id_preview(id: &[u8]) -> String {
    // Compact human preview: prints first 8 bytes as three-digit decimals (no hex)
    id.iter()
        .take(8)
        .map(|b| format!("{:03}", b))
        .collect::<Vec<_>>()
        .join("")
}

fn id32_from_str(s: &str) -> [u8; 32] {
    let h = blake3::hash(s.as_bytes());
    let mut a = [0u8; 32];
    a.copy_from_slice(h.as_bytes());
    a
}

// ------------------------------ example harness ------------------------------

/// End-to-end bilateral example between Alice and Bob
pub struct BilateralTransactionExample {
    // Relationship managers (own their contact + tx managers)
    alice_manager: BilateralRelationshipManager,
    bob_manager: BilateralRelationshipManager,

    // Sig material for demo
    alice_keypair: SignatureKeyPair,
    bob_keypair: SignatureKeyPair,

    // Fixed IDs / roots (byte-only)
    alice_device_id: [u8; 32],
    bob_device_id: [u8; 32],
    alice_genesis_hash: [u8; 32],
    bob_genesis_hash: [u8; 32],
}

impl BilateralTransactionExample {
    /// Build a clean, deterministic two-party world
    pub fn new() -> Result<Self, DsmError> {
        // Deterministic keys for demo (entropy labels scoped to example)
        let alice_keypair =
            SignatureKeyPair::generate_from_entropy(b"bilateral-example-alice").expect("alice kp");
        let bob_keypair =
            SignatureKeyPair::generate_from_entropy(b"bilateral-example-bob").expect("bob kp");

        // 32B device ids & genesis roots (bytes-only)
        let alice_device_id = id32_from_str("alice_device_12345");
        let bob_device_id = id32_from_str("bob_device_67890");
        let alice_genesis_hash = id32_from_str("alice_genesis_hash_abc123");
        let bob_genesis_hash = id32_from_str("bob_genesis_hash_def456");

        // Minimal storage node set (IDs are opaque strings carried to NodeId)
        let nodes = vec![NodeId::new("storage_node_1")];

        // Contact managers (byte IDs + node set)
        let alice_contacts = DsmContactManager::new(alice_device_id, nodes.clone());
        let bob_contacts = DsmContactManager::new(bob_device_id, nodes.clone());

        // Bilateral transaction managers (own their contact managers)
        let alice_btx = BilateralTransactionManager::new(
            alice_contacts,
            alice_keypair.clone(),
            alice_device_id,
            alice_genesis_hash,
        );
        let bob_btx = BilateralTransactionManager::new(
            bob_contacts,
            bob_keypair.clone(),
            bob_device_id,
            bob_genesis_hash,
        );

        // Separate contact managers for relationship layer (clean ownership split)
        let alice_contacts_rel = DsmContactManager::new(alice_device_id, nodes.clone());
        let bob_contacts_rel = DsmContactManager::new(bob_device_id, nodes);

        // Relationship managers
        let alice_manager = BilateralRelationshipManager::new(
            alice_contacts_rel,
            alice_btx,
            alice_keypair.clone(),
            alice_device_id,
            alice_genesis_hash,
        );
        let bob_manager = BilateralRelationshipManager::new(
            bob_contacts_rel,
            bob_btx,
            bob_keypair.clone(),
            bob_device_id,
            bob_genesis_hash,
        );

        Ok(Self {
            alice_manager,
            bob_manager,
            alice_keypair,
            bob_keypair,
            alice_device_id,
            bob_device_id,
            alice_genesis_hash,
            bob_genesis_hash,
        })
    }

    // --------------------------- top-level flow ---------------------------

    pub async fn run_complete_example(&mut self) -> Result<(), DsmError> {
        println!("🚀 DSM Bilateral Transaction Example");
        println!("════════════════════════════════════");

        println!("\n📋 Step 1: Contact establishment");
        self.step_contact_establishment().await?;

        println!("\n🔗 Step 2: Bilateral relationship creation");
        self.step_relationship_creation().await?;

        println!("\n📝 Step 3: Pre-commitment creation");
        self.step_precommitment_creation().await?;

        println!("\n💸 Step 4: Execute bilateral transaction (Bluetooth)");
        self.step_bilateral_execution().await?;

        println!("\n🔍 Step 5: Integrity + SMT checks");
        self.step_integrity_and_smt().await?;

        println!("\n✅ Example completed.");
        Ok(())
    }

    // --------------------------- steps (clean) ---------------------------

    /// 1) Contact establishment with Genesis anchoring
    async fn step_contact_establishment(&mut self) -> Result<(), DsmError> {
        // Alice composes request
        let request = ContactEstablishmentRequest::new(
            self.alice_device_id,
            self.alice_genesis_hash,
            self.alice_keypair.public_key().to_vec(),
            "Alice".to_string(),
            Some("Hi Bob — requesting bilateral channel".to_string()),
            &self.alice_keypair,
        )?;

        // Bob handles and returns a request hash
        let req_hash = self
            .bob_manager
            .handle_contact_establishment_request(request.clone())
            .await?;

        println!("   Bob saw request: {}", id_preview(&req_hash));

        // Keep Alice’s local pending for matching
        let _alice_pending = self
            .alice_manager
            .register_outgoing_contact_request(&request)?;

        // Bob accepts → returns response for Alice
        let (_created, response) = self
            .bob_manager
            .accept_contact_request_with_response(&req_hash, Some("Welcome, Alice".to_string()))
            .await?;

        // Alice finalizes her side from Bob’s response
        let _alice_verified = self
            .alice_manager
            .handle_contact_establishment_response(response)
            .await?;

        println!("   ✅ Contact established and anchored on both sides");
        Ok(())
    }

    /// 2) Create bilateral relationship and validate synchronized mutual anchor
    async fn step_relationship_creation(&mut self) -> Result<(), DsmError> {
        let alice_rel = self
            .alice_manager
            .get_bilateral_tx_manager_mut()
            .establish_relationship(&self.bob_device_id)
            .await?;

        let bob_rel = self
            .bob_manager
            .get_bilateral_tx_manager_mut()
            .establish_relationship(&self.alice_device_id)
            .await?;

        println!(
            "   Alice mutual anchor: {}",
            id_preview(&alice_rel.mutual_anchor_hash)
        );
        println!(
            "   Bob   mutual anchor: {}",
            id_preview(&bob_rel.mutual_anchor_hash)
        );

        if alice_rel.mutual_anchor_hash != bob_rel.mutual_anchor_hash {
            return Err(DsmError::Relationship("mutual anchor mismatch".into()));
        }

        println!("   ✅ Mutual anchors match (relationship synchronized)");
        Ok(())
    }

    /// 3) Pre-commitment (offline-capable) for a token transfer
    async fn step_precommitment_creation(&mut self) -> Result<(), DsmError> {
        // Build a transfer op (bytes-only identifiers are stringified at the UI seam)
        let to_id = format!("dev:{}", id_preview(&self.bob_device_id));

        // Create a small positive balance amount
        let mut amount = Balance::zero();
        amount.update_add(100);

        let transfer = Operation::Transfer {
            to_device_id: to_id.clone().into_bytes(),
            amount,
            token_id: b"DSM_TOKEN".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3, 4],
            verification: VerificationType::Bilateral,
            pre_commit: None,
            recipient: b"Bob".to_vec(),
            to: to_id.into_bytes(),
            message: "Payment for services".to_string(),
            signature: Vec::new(),
        };

        let alice_pc = self
            .alice_manager
            .get_bilateral_tx_manager_mut()
            .create_bilateral_precommitment(&self.bob_device_id, transfer.clone(), 300)
            .await?;

        let bob_pc = self
            .bob_manager
            .get_bilateral_tx_manager_mut()
            .create_bilateral_precommitment(&self.alice_device_id, transfer, 300)
            .await?;

        println!(
            "   Alice precommit: {}",
            id_preview(&alice_pc.bilateral_commitment_hash)
        );
        println!(
            "   Bob   precommit: {}",
            id_preview(&bob_pc.bilateral_commitment_hash)
        );

        if !alice_pc.verify()? || !bob_pc.verify()? {
            return Err(DsmError::PreCommitment(
                "one or more pre-commitments failed verification".into(),
            ));
        }

        println!("   ✅ Both pre-commitments verified");
        Ok(())
    }

    /// 4) Execute bilateral transaction over Bluetooth (offline transport)
    async fn step_bilateral_execution(&mut self) -> Result<(), DsmError> {
        // Recreate the same logical transfer op for execution step
        let to_id = format!("dev:{}", id_preview(&self.bob_device_id));
        let mut amount = Balance::zero();
        amount.update_add(100);

        let op = Operation::Transfer {
            to_device_id: to_id.clone().into_bytes(),
            amount,
            token_id: b"DSM_TOKEN".to_vec(),
            mode: TransactionMode::Bilateral,
            nonce: vec![5, 6, 7, 8],
            verification: VerificationType::Bilateral,
            pre_commit: None,
            recipient: b"Bob".to_vec(),
            to: to_id.into_bytes(),
            message: "Bluetooth bilateral transaction".to_string(),
            signature: Vec::new(),
        };

        // Alice executes via Bluetooth
        let alice_exec = self
            .alice_manager
            .get_bilateral_tx_manager_mut()
            .execute_bilateral_transaction(&self.bob_device_id, op.clone(), true)
            .await?;

        println!(
            "   Alice tx: {}  (offline={})",
            id_preview(&alice_exec.transaction_hash),
            alice_exec.completed_offline
        );

        // Bob executes symmetric side
        let bob_exec = self
            .bob_manager
            .get_bilateral_tx_manager_mut()
            .execute_bilateral_transaction(&self.alice_device_id, op, true)
            .await?;

        println!("   Bob   tx: {}", id_preview(&bob_exec.transaction_hash));

        // Quick sync sanity: both sides report synchronized anchors
        if !(alice_exec.relationship_anchor.is_synchronized()
            && bob_exec.relationship_anchor.is_synchronized())
        {
            return Err(DsmError::Transaction(
                "post-transaction anchors not synchronized".into(),
            ));
        }

        println!("   ✅ Bilateral transaction executed and synchronized");
        Ok(())
    }

    /// 5) Integrity + SMT proof checks (if available on the relationship objects)
    async fn step_integrity_and_smt(&mut self) -> Result<(), DsmError> {
        // Locate Alice’s and Bob’s relationship records
        let a_rel = self
            .alice_manager
            .get_bilateral_tx_manager()
            .list_relationships()
            .into_iter()
            .find(|r| r.remote_device_id == self.bob_device_id)
            .ok_or_else(|| DsmError::Relationship("Alice→Bob relationship not found".into()))?;

        let b_rel = self
            .bob_manager
            .get_bilateral_tx_manager()
            .list_relationships()
            .into_iter()
            .find(|r| r.remote_device_id == self.alice_device_id)
            .ok_or_else(|| DsmError::Relationship("Bob→Alice relationship not found".into()))?;

        // Optional SMT proofs (if the manager populated them)
        if let Some(ref proof) = a_rel.smt_proof {
            println!(
                "   Alice SMT proof commit height: {}",
                proof.proof_commit_height
            );
        }
        if let Some(ref proof) = b_rel.smt_proof {
            println!(
                "   Bob   SMT proof commit height: {}",
                proof.proof_commit_height
            );
        }

        // Manager’s integrity hook
        let a_ok = self
            .alice_manager
            .get_bilateral_tx_manager()
            .verify_relationship_integrity(&self.bob_device_id)?;
        let b_ok = self
            .bob_manager
            .get_bilateral_tx_manager()
            .verify_relationship_integrity(&self.alice_device_id)?;

        if !(a_ok && b_ok) {
            return Err(DsmError::Integrity {
                context: "relationship integrity check failed".into(),
                source: None,
            });
        }

        // Demo: produce a signed attestation over current tip (local example only)
        {
            let local_tip = &a_rel.chain_tip;
            let msg = {
                let mut m = Vec::with_capacity(a_rel.mutual_anchor_hash.len() + local_tip.len());
                m.extend_from_slice(&a_rel.mutual_anchor_hash);
                m.extend_from_slice(local_tip);
                m
            };
            // Sign with Alice’s key; in a real flow Bob verifies
            let sig = self.alice_keypair.sign(&msg).map_err(|_| {
                DsmError::crypto(
                    "failed to sign attestation".to_string(),
                    None::<std::io::Error>,
                )
            })?;
            println!("   Signed attestation (Alice): {}…", id_preview(&sig));
        }

        println!("   ✅ Integrity checks passed");
        Ok(())
    }

    /// Inspect a few simple stats (UI can render these however it wants)
    pub fn stats(&self) -> HashMap<String, String> {
        let mut out = HashMap::new();

        let a_rels = self
            .alice_manager
            .get_bilateral_tx_manager()
            .list_relationships();
        let b_rels = self
            .bob_manager
            .get_bilateral_tx_manager()
            .list_relationships();

        out.insert("alice_relationships".into(), a_rels.len().to_string());
        out.insert("bob_relationships".into(), b_rels.len().to_string());

        out
    }
}

// ------------------------------ example runner ------------------------------

pub async fn run_bilateral_transaction_example() -> Result<(), DsmError> {
    let mut ex = BilateralTransactionExample::new()?;
    ex.run_complete_example().await?;

    let stats = ex.stats();
    println!("\n📊 Stats:");
    for (k, v) in stats {
        println!("   {k}: {v}");
    }
    Ok(())
}

// ------------------------------ tests ---------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn example_runs() {
        let res = run_bilateral_transaction_example().await;
        assert!(res.is_ok(), "example should complete successfully: {res:?}");
    }

    #[tokio::test]
    async fn contact_establishment_only() {
        let mut ex = BilateralTransactionExample::new().unwrap();
        let r = ex.step_contact_establishment().await;
        assert!(r.is_ok(), "contact establishment should succeed: {r:?}");
    }

    #[tokio::test]
    async fn relationship_then_precommit() {
        let mut ex = BilateralTransactionExample::new().unwrap();
        ex.step_contact_establishment().await.unwrap();
        ex.step_relationship_creation().await.unwrap();
        let r = ex.step_precommitment_creation().await;
        assert!(r.is_ok(), "precommitment should succeed: {r:?}");
    }
}

// ------------------------------- main ---------------------------------------

#[tokio::main]
async fn main() -> Result<(), DsmError> {
    env_logger::init();
    println!("=== DSM Bilateral Transaction Example ===\n");
    run_bilateral_transaction_example().await
}
