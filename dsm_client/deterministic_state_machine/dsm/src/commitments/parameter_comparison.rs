//! Parameter comparison utilities for pre-commitment verification.
//!
//! Compares operation parameters against pre-committed fixed parameters
//! to ensure that the executed operation matches the commitment. Used
//! during the commit phase of the bilateral 3-phase protocol.

use crate::types::error::DsmError;
use crate::types::operations::{Operation, PreCommitmentOp, TransactionMode, VerificationType};
use crate::types::token_types::Balance;
use std::collections::{HashMap, HashSet};

// Helper function to convert Balance to canonical bytes (deterministic; no Serde)
fn balance_to_bytes(balance: &Balance) -> Vec<u8> {
    balance.to_le_bytes()
}

// Deterministic encoder for TransactionMode
fn encode_mode(mode: &TransactionMode) -> Vec<u8> {
    match mode {
        TransactionMode::Bilateral => vec![0u8],
        TransactionMode::Unilateral => vec![1u8],
    }
}

// Deterministic encoder for VerificationType
fn encode_verification(v: &VerificationType) -> Vec<u8> {
    match v {
        VerificationType::Standard => vec![0u8],
        VerificationType::Enhanced => vec![1u8],
        VerificationType::Bilateral => vec![2u8],
        VerificationType::Directory => vec![3u8],
        VerificationType::StandardBilateral => vec![4u8],
        VerificationType::PreCommitted => vec![5u8],
        VerificationType::UnilateralIdentityAnchor => vec![6u8],
        VerificationType::Custom(bytes) => {
            let mut out = Vec::with_capacity(1 + 4 + bytes.len());
            out.push(255u8); // tag for Custom
            let len = bytes.len() as u32;
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(bytes);
            out
        }
    }
}

// Deterministic encoder for Vec<Vec<u8>> with length-prefixing
fn encode_vec_of_vecs(v: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut out = Vec::new();
    let count = v.len() as u32;
    out.extend_from_slice(&count.to_le_bytes());
    for item in v {
        let len = item.len() as u32;
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(item);
    }
    out
}

// Deterministic encoder for PreCommitmentOp (same canonical rules as Operation::to_bytes)
fn encode_precommit_op(pc: &PreCommitmentOp) -> Vec<u8> {
    let mut out = Vec::new();
    // fixed_parameters: sort by key
    let mut keys: Vec<_> = pc.fixed_parameters.keys().collect();
    keys.sort();
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        let kbytes = k.as_bytes();
        out.extend_from_slice(&(kbytes.len() as u32).to_le_bytes());
        out.extend_from_slice(kbytes);
        #[allow(clippy::expect_used)]
        let v = pc
            .fixed_parameters
            .get(k)
            .expect("key should exist as collected from keys iterator");
        out.extend_from_slice(&(v.len() as u32).to_le_bytes());
        out.extend_from_slice(v);
    }
    // variable_parameters: encode in lexicographic order for determinism
    let mut vars = pc.variable_parameters.clone();
    vars.sort();
    out.extend_from_slice(&(vars.len() as u32).to_le_bytes());
    for v in vars {
        let vb = v.as_bytes();
        out.extend_from_slice(&(vb.len() as u32).to_le_bytes());
        out.extend_from_slice(vb);
    }
    out
}

fn verify_bilateral_transfer_parameters(
    nonce: &[u8],
    verification: &VerificationType,
    pre_commit: &Option<PreCommitmentOp>,
) -> Result<HashMap<String, Vec<u8>>, DsmError> {
    let mut params = HashMap::new();
    params.insert("operation_type".to_string(), b"transfer".to_vec());
    params.insert("nonce".to_string(), nonce.to_vec());
    params.insert(
        "verification".to_string(),
        encode_verification(verification),
    );
    if let Some(pc) = pre_commit {
        // Store deterministic canonical bytes of pre-commit
        params.insert("pre_commit".to_string(), encode_precommit_op(pc));
    }
    Ok(params)
}

fn verify_unilateral_transfer_parameters(
    nonce: &[u8],
    verification: &VerificationType,
) -> Result<HashMap<String, Vec<u8>>, DsmError> {
    let mut params = HashMap::new();
    params.insert("operation_type".to_string(), b"transfer".to_vec());
    params.insert("nonce".to_string(), nonce.to_vec());
    params.insert(
        "verification".to_string(),
        encode_verification(verification),
    );
    Ok(params)
}

/// Extracts parameters from an operation in a consistent format for comparison
pub fn extract_operation_parameters(
    operation: &Operation,
) -> Result<HashMap<String, Vec<u8>>, DsmError> {
    match operation {
        Operation::Genesis => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"genesis".to_vec());
            Ok(params)
        }
        Operation::Transfer {
            amount,
            token_id,
            mode,
            nonce,
            verification,
            pre_commit,
            ..
        } => {
            let mut params = HashMap::new();
            params.insert("token_id".to_string(), token_id.clone());
            // Encode Balance deterministically as little-endian bytes
            params.insert("amount".to_string(), balance_to_bytes(amount));

            match mode {
                TransactionMode::Bilateral => {
                    // Add bilateral transfer parameters
                    let bilateral_params =
                        verify_bilateral_transfer_parameters(nonce, verification, pre_commit)?;
                    params.extend(bilateral_params);
                }
                TransactionMode::Unilateral => {
                    // Add unilateral transfer parameters
                    let unilateral_params =
                        verify_unilateral_transfer_parameters(nonce, verification)?;
                    params.extend(unilateral_params);
                }
            }
            Ok(params)
        }
        Operation::Mint {
            amount,
            token_id,
            authorized_by,
            proof_of_authorization,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"mint".to_vec());
            params.insert("amount".to_string(), balance_to_bytes(amount));
            params.insert("token_id".to_string(), token_id.clone());
            params.insert("authorized_by".to_string(), authorized_by.clone());
            params.insert(
                "proof_of_authorization".to_string(),
                proof_of_authorization.clone(),
            );
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Burn {
            amount,
            token_id,
            proof_of_ownership,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"burn".to_vec());
            params.insert("amount".to_string(), balance_to_bytes(amount));
            params.insert("token_id".to_string(), token_id.clone());
            params.insert("proof_of_ownership".to_string(), proof_of_ownership.clone());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Create {
            identity_data,
            public_key,
            metadata,
            commitment,
            message,
            proof,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"create".to_vec());
            params.insert("identity_data".to_string(), identity_data.clone());
            params.insert("public_key".to_string(), public_key.clone());
            params.insert("metadata".to_string(), metadata.clone());
            params.insert("commitment".to_string(), commitment.clone());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), encode_mode(mode));
            Ok(params)
        }
        Operation::Update {
            identity_id,
            updated_data,
            proof,
            forward_link,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"update".to_vec());
            params.insert("identity_id".to_string(), identity_id.clone());
            params.insert("updated_data".to_string(), updated_data.clone());
            params.insert("proof".to_string(), proof.clone());
            if let Some(link) = forward_link {
                params.insert("forward_link".to_string(), link.clone());
            }
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::AddRelationship {
            from_id,
            to_id,
            relationship_type,
            metadata,
            proof,
            mode,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"add_relationship".to_vec());
            params.insert("from_id".to_string(), from_id.to_vec());
            params.insert("to_id".to_string(), to_id.to_vec());
            params.insert("relationship_type".to_string(), relationship_type.clone());
            params.insert("metadata".to_string(), metadata.clone());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), encode_mode(mode));
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::CreateRelationship {
            message,
            counterparty_id,
            commitment,
            proof,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert(
                "operation_type".to_string(),
                b"create_relationship".to_vec(),
            );
            params.insert("counterparty_id".to_string(), counterparty_id.clone());
            params.insert("commitment".to_string(), commitment.clone());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), encode_mode(mode));
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::RemoveRelationship {
            from_id,
            to_id,
            relationship_type,
            proof,
            mode,
            message,
        } => {
            let mut params = HashMap::new();
            params.insert(
                "operation_type".to_string(),
                b"remove_relationship".to_vec(),
            );
            params.insert("from_id".to_string(), from_id.to_vec());
            params.insert("to_id".to_string(), to_id.to_vec());
            params.insert("relationship_type".to_string(), relationship_type.clone());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), encode_mode(mode));
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Recovery {
            state_number,
            state_hash,
            message,
            invalidation_data,
            new_state_data,
            new_state_number,
            new_state_hash,
            new_state_entropy,
            compromise_proof,
            authority_sigs,
            state_entropy,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"recovery".to_vec());
            // Encode numeric fields as canonical little-endian bytes (no string encoding)
            params.insert(
                "state_number".to_string(),
                state_number.to_le_bytes().to_vec(),
            );
            params.insert("state_hash".to_string(), state_hash.to_vec());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            params.insert("invalidation_data".to_string(), invalidation_data.clone());
            params.insert("new_state_data".to_string(), new_state_data.clone());
            params.insert(
                "new_state_number".to_string(),
                new_state_number.to_le_bytes().to_vec(),
            );
            params.insert("new_state_hash".to_string(), new_state_hash.to_vec());
            params.insert("new_state_entropy".to_string(), new_state_entropy.clone());
            params.insert("compromise_proof".to_string(), compromise_proof.clone());
            // Serialize authority_sigs to handle Vec<Vec<u8>>
            params.insert(
                "authority_sigs".to_string(),
                encode_vec_of_vecs(authority_sigs),
            );
            params.insert("state_entropy".to_string(), state_entropy.clone());
            // Removed the mode parameter since it doesn't exist in the Recovery operation
            Ok(params)
        }
        Operation::Invalidate { .. } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"invalidate".to_vec());
            Ok(params)
        }
        Operation::Delete {
            id,
            proof,
            reason,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"delete".to_vec());
            params.insert("id".to_string(), id.clone());
            params.insert("proof".to_string(), proof.clone());
            params.insert("reason".to_string(), reason.as_bytes().to_vec());
            params.insert("mode".to_string(), encode_mode(mode));
            Ok(params)
        }
        Operation::Link {
            target_id,
            link_type,
            proof,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"link".to_vec());
            params.insert("target_id".to_string(), target_id.clone());
            params.insert("link_type".to_string(), link_type.clone());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), encode_mode(mode));
            Ok(params)
        }
        Operation::Generic {
            operation_type,
            data,
            message,
            ..
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), operation_type.clone());
            params.insert("data".to_string(), data.clone());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Unlink {
            target_id,
            proof,
            mode,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"unlink".to_vec());
            params.insert("target_id".to_string(), target_id.clone());
            params.insert("proof".to_string(), proof.clone());
            params.insert("mode".to_string(), encode_mode(mode));
            Ok(params)
        }
        Operation::LockToken {
            token_id,
            amount,
            purpose,
            mode,
            ..
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"lock_token".to_vec());
            params.insert("token_id".to_string(), token_id.clone());
            params.insert("amount".to_string(), amount.to_le_bytes().to_vec());
            params.insert("purpose".to_string(), purpose.clone());
            params.insert("mode".to_string(), encode_mode(mode));
            Ok(params)
        }
        Operation::UnlockToken {
            token_id,
            amount,
            purpose,
            mode,
            ..
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"unlock_token".to_vec());
            params.insert("token_id".to_string(), token_id.clone());
            params.insert("amount".to_string(), amount.to_le_bytes().to_vec());
            params.insert("purpose".to_string(), purpose.clone());
            params.insert("mode".to_string(), encode_mode(mode));
            Ok(params)
        }
        Operation::Receive {
            token_id,
            from_device_id,
            amount,
            recipient,
            message,
            mode,
            nonce,
            verification,
            sender_state_hash,
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"receive".to_vec());
            params.insert("token_id".to_string(), token_id.clone());
            params.insert("from_device_id".to_string(), from_device_id.clone());
            params.insert("amount".to_string(), amount.to_le_bytes().to_vec());
            params.insert("recipient".to_string(), recipient.clone());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            params.insert("mode".to_string(), encode_mode(mode));
            params.insert("nonce".to_string(), nonce.clone());
            params.insert(
                "verification".to_string(),
                encode_verification(verification),
            );
            if let Some(hash) = sender_state_hash {
                params.insert("sender_state_hash".to_string(), hash.clone());
            }
            Ok(params)
        }
        Operation::Lock {
            token_id,
            amount,
            purpose,
            owner,
            message,
            ..
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"lock".to_vec());
            params.insert("token_id".to_string(), token_id.clone());
            params.insert("amount".to_string(), balance_to_bytes(amount));
            params.insert("purpose".to_string(), purpose.clone());
            params.insert("owner".to_string(), owner.clone());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::Unlock {
            token_id,
            amount,
            purpose,
            owner,
            message,
            ..
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"unlock".to_vec());
            params.insert("token_id".to_string(), token_id.clone());
            params.insert("amount".to_string(), balance_to_bytes(amount));
            params.insert("purpose".to_string(), purpose.clone());
            params.insert("owner".to_string(), owner.clone());
            params.insert("message".to_string(), message.as_bytes().to_vec());
            Ok(params)
        }
        Operation::CreateToken {
            token_id,
            initial_supply,
            name,
            symbol,
            decimals,
            metadata_uri,
            policy_anchor,
            ..
        } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"create_token".to_vec());
            params.insert("token_id".to_string(), token_id.clone());
            params.insert(
                "initial_supply".to_string(),
                balance_to_bytes(initial_supply),
            );
            params.insert("name".to_string(), name.as_bytes().to_vec());
            params.insert("symbol".to_string(), symbol.as_bytes().to_vec());
            params.insert("decimals".to_string(), vec![*decimals]);
            if let Some(uri) = metadata_uri {
                params.insert("metadata_uri".to_string(), uri.as_bytes().to_vec());
            }
            if let Some(anchor) = policy_anchor {
                params.insert("policy_anchor".to_string(), anchor.clone());
            }
            Ok(params)
        }
        Operation::Noop => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"noop".to_vec());
            Ok(params)
        }
        Operation::DlvCreate { vault_id, .. } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"dlv_create".to_vec());
            params.insert("vault_id".to_string(), vault_id.clone());
            Ok(params)
        }
        Operation::DlvUnlock { vault_id, .. } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"dlv_unlock".to_vec());
            params.insert("vault_id".to_string(), vault_id.clone());
            Ok(params)
        }
        Operation::DlvClaim { vault_id, .. } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"dlv_claim".to_vec());
            params.insert("vault_id".to_string(), vault_id.clone());
            Ok(params)
        }
        Operation::DlvInvalidate { vault_id, .. } => {
            let mut params = HashMap::new();
            params.insert("operation_type".to_string(), b"dlv_invalidate".to_vec());
            params.insert("vault_id".to_string(), vault_id.clone());
            Ok(params)
        }
    }
}

pub fn verify_operation_parameters(
    operation: &Operation,
    fixed_parameters: &HashMap<String, Vec<u8>>,
    _variable_parameters: &HashSet<String>,
    _timeout: u64,
) -> Result<bool, DsmError> {
    // Extract parameters from the operation
    let operation_params = extract_operation_parameters(operation)?;

    // Check all fixed parameters match exactly
    for (key, value) in fixed_parameters {
        // Get the operation's value for this parameter
        let op_value = match operation_params.get(key) {
            Some(val) => val,
            None => return Ok(false),
        };

        // If the values don't match, return false
        if op_value != value {
            return Ok(false);
        }
    }

    Ok(true)
}

/// Deterministic field-order encoding of forward-commitment-related parameters for comparison
pub fn encode_forward_commitment_params(
    fixed_parameters: &HashMap<String, Vec<u8>>,
    variable_parameters: &[String],
) -> Vec<u8> {
    // Sort keys and variables deterministically and length-prefix all fields
    let mut out = Vec::new();
    let mut keys: Vec<_> = fixed_parameters.keys().collect();
    keys.sort();
    out.extend_from_slice(&(keys.len() as u32).to_le_bytes());
    for k in keys {
        let kb = k.as_bytes();
        out.extend_from_slice(&(kb.len() as u32).to_le_bytes());
        out.extend_from_slice(kb);
        #[allow(clippy::expect_used)]
        let vb = fixed_parameters
            .get(k)
            .expect("key should exist as collected from keys iterator");
        out.extend_from_slice(&(vb.len() as u32).to_le_bytes());
        out.extend_from_slice(vb);
    }
    let mut vars: Vec<String> = variable_parameters.to_owned();
    vars.sort();
    out.extend_from_slice(&(vars.len() as u32).to_le_bytes());
    for v in vars {
        let vb = v.as_bytes();
        out.extend_from_slice(&(vb.len() as u32).to_le_bytes());
        out.extend_from_slice(vb);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sphincs::{generate_sphincs_keypair, sphincs_sign};
    use rand::seq::SliceRandom;
    use rand::{rngs::StdRng, SeedableRng};

    fn signed_transfer() -> Operation {
        let (_pk, sk) = generate_sphincs_keypair().expect("keypair");
        let mut balance = Balance::zero();
        balance.update_add(100);
        let mut op = Operation::Transfer {
            mode: TransactionMode::Bilateral,
            nonce: vec![1, 2, 3],
            verification: VerificationType::Standard,
            pre_commit: None,
            to_device_id: b"recipient".to_vec(),
            amount: balance,
            token_id: b"token123".to_vec(),
            message: "Test transfer".to_string(),
            recipient: b"recipient".to_vec(),
            to: b"to".to_vec(),
            signature: Vec::new(),
        };
        let sig = sphincs_sign(&sk, &op.to_bytes()).expect("sign transfer");
        if let Operation::Transfer { signature, .. } = &mut op {
            *signature = sig;
        }
        op
    }

    fn signed_update(identity_id: &str) -> Operation {
        let (_pk, sk) = generate_sphincs_keypair().expect("keypair");
        let mut op = Operation::Update {
            message: "Invalid operation".to_string(),
            identity_id: identity_id.as_bytes().to_vec(),
            updated_data: vec![4, 5, 6],
            proof: vec![],
            forward_link: None,
        };
        let sig = sphincs_sign(&sk, &op.to_bytes()).expect("sign update");
        if let Operation::Update { proof, .. } = &mut op {
            *proof = sig;
        }
        op
    }
    #[test]
    fn test_extract_operation_parameters() -> Result<(), DsmError> {
        // Test with a Transfer operation
        let transfer_op = signed_transfer();

        let params = extract_operation_parameters(&transfer_op)?;

        // Check parameters were extracted correctly
        assert_eq!(params.get("operation_type").unwrap(), b"transfer");

        // Test with a Generic operation
        let generic_op = signed_update("identity_custom");

        // Extract parameters from generic operation and check them
        let generic_params = extract_operation_parameters(&generic_op)?;
        assert_eq!(generic_params.get("operation_type").unwrap(), b"update");

        Ok(())
    }

    #[test]
    fn test_verify_operation_parameters() -> Result<(), DsmError> {
        // Create fixed parameters for a transfer operation
        let mut fixed_params = HashMap::new();
        fixed_params.insert("operation_type".to_string(), b"transfer".to_vec());

        // Create variable parameters
        let var_params = HashSet::new();

        // Create a valid operation that matches fixed parameters
        let valid_op = signed_transfer();

        // Create an invalid operation
        let invalid_op = signed_update("identity_invalid");

        // Verify operations
        assert!(verify_operation_parameters(
            &valid_op,
            &fixed_params,
            &var_params,
            0
        )?);
        assert!(!verify_operation_parameters(
            &invalid_op,
            &fixed_params,
            &var_params,
            0
        )?);
        assert!(!verify_operation_parameters(
            &invalid_op,
            &fixed_params,
            &var_params,
            0
        )?);

        Ok(())
    }

    #[test]
    fn test_encode_forward_commitment_params_order_invariance() {
        // Prepare fixed parameters and variables in a deterministic seed
        let mut fixed1: HashMap<String, Vec<u8>> = HashMap::new();
        fixed1.insert("alpha".into(), vec![1, 2]);
        fixed1.insert("beta".into(), vec![3]);
        fixed1.insert("gamma".into(), vec![4, 5, 6]);

        let mut vars2 = vec!["v2".into(), "v2".into(), "v3".into()];

        // Encode baseline
        let baseline = encode_forward_commitment_params(&fixed1, &vars2);

        // Shuffle order and re-encode; bytes MUST match
        let mut rng = StdRng::seed_from_u64(0xC0FFEE);

        // Shuffle fixed map insertion by rebuilding from shuffled keys
        let mut keys: Vec<_> = fixed1.keys().cloned().collect();
        keys.shuffle(&mut rng);
        let mut fixed2: HashMap<String, Vec<u8>> = HashMap::new();
        for k in keys {
            fixed2.insert(k.clone(), fixed1.get(&k).unwrap().clone());
        }

        // Shuffle vars
        vars2.shuffle(&mut rng);
        let vars2 = vars2.clone();

        let bytes2 = encode_forward_commitment_params(&fixed2, &vars2);
        assert_eq!(
            baseline, bytes2,
            "encode_forward_commitment_params must be order-invariant"
        );
    }

    #[test]
    fn test_encode_precommit_op_order_invariance() {
        // Build two PreCommitmentOp instances with the same logical content but different insertion orders
        let mut fixed_a: HashMap<String, Vec<u8>> = HashMap::new();
        fixed_a.insert("k1".into(), vec![0x01]);
        fixed_a.insert("k2".into(), vec![0x02, 0x03]);
        fixed_a.insert("k3".into(), vec![0x04]);

        let vars_a = vec!["z".into(), "y".into(), "x".into()];

        let pc_a = PreCommitmentOp {
            fixed_parameters: fixed_a.clone(),
            variable_parameters: vars_a.clone(),
            ..Default::default()
        };

        // Rebuild with different insertion order
        let mut keys: Vec<_> = fixed_a.keys().cloned().collect();
        let mut rng = StdRng::seed_from_u64(0xBADC0DE);
        keys.shuffle(&mut rng);
        let mut fixed_b: HashMap<String, Vec<u8>> = HashMap::new();
        for k in keys {
            fixed_b.insert(k.clone(), fixed_a.get(&k).unwrap().clone());
        }

        let mut vars_b = vars_a.clone();
        vars_b.shuffle(&mut rng);

        let pc_b = PreCommitmentOp {
            fixed_parameters: fixed_b,
            variable_parameters: vars_b,
            ..Default::default()
        };

        let enc_a = encode_precommit_op(&pc_a);
        let enc_b = encode_precommit_op(&pc_b);
        assert_eq!(enc_a, enc_b, "encode_precommit_op must be order-invariant");
    }
}
