//! Validation helpers for content carried through storage-node APIs.
//! These are deterministic, side-effect-free checks used to reject
//! malformed payloads early at the distribution/anchoring layer.

#![allow(clippy::result_unit_err)]

use prost::Message;

/// Attempt to decode SmartPolicy bytes and apply minimal structural checks.
/// Returns Ok(()) if bytes decode to SmartPolicy and pass checks; Err(()) otherwise.
pub fn validate_smart_policy_bytes(bytes: &[u8]) -> Result<(), ()> {
    // Decode SmartPolicy protobuf (prost generated in dsm crate)
    match dsm::types::proto::SmartPolicy::decode(bytes) {
        Ok(policy) => {
            // Minimal structure: at least one clause
            if policy.clauses.is_empty() {
                return Err(());
            }
            // Version 0 is allowed, but discouraged; we don't hard-fail.
            Ok(())
        }
        Err(_) => Err(()),
    }
}

/// Validate an Envelope's payload for any embedded VaultPostProto that carries
/// SmartPolicy bytes (via LimboVaultProto.FulfillmentMechanism::CryptoCondition
/// .public_params). This traverses common byte-carrying fields that may embed
/// vault posts (ExternalCommit.payload, PrecommitOption.payload, Invoke.args.body,
/// AttestedAction.payload) and also recurses into BatchEnvelope.
pub fn validate_envelope_smart_policy(env: &dsm::types::proto::Envelope) -> Result<(), ()> {
    use dsm::types::proto as P;

    // Helper: validate a raw bytes slice as potential VaultPostProto
    let check_bytes = |bytes: &[u8]| -> Result<(), ()> {
        if bytes.is_empty() {
            return Ok(());
        }
        validate_vaultpost_smart_policy_if_present(bytes)
    };

    match &env.payload {
        Some(P::envelope::Payload::UniversalTx(tx)) => {
            for op in &tx.ops {
                match &op.kind {
                    Some(P::universal_op::Kind::ExternalCommit(ec)) => {
                        check_bytes(&ec.payload)?;
                    }
                    Some(P::universal_op::Kind::PrecommitOneof(pco)) => {
                        for opt in &pco.options {
                            check_bytes(&opt.payload)?;
                        }
                    }
                    Some(P::universal_op::Kind::Invoke(inv)) => {
                        if let Some(args) = &inv.args {
                            check_bytes(&args.body)?;
                        }
                    }
                    Some(P::universal_op::Kind::AttestedAction(aa)) => {
                        check_bytes(&aa.payload)?;
                    }
                    // Other op kinds do not carry arbitrary large byte bodies
                    // that would reasonably embed VaultPostProto; skip.
                    _ => {}
                }
            }
            Ok(())
        }
        Some(P::envelope::Payload::BatchEnvelope(batch)) => {
            for e in &batch.envelopes {
                validate_envelope_smart_policy(e)?;
            }
            Ok(())
        }
        // RX or other response types do not need validation here.
        _ => Ok(()),
    }
}
/// Inspect a VaultPostProto blob and validate embedded SmartPolicy bytes if present.
/// This function is robust: if the top-level decode fails (not a VaultPostProto),
/// we return Ok(()) and let other handlers decide; if decode succeeds and a
/// CryptoCondition contains public_params, we require those bytes to be a valid
/// SmartPolicy.
pub fn validate_vaultpost_smart_policy_if_present(body: &[u8]) -> Result<(), ()> {
    // Try decoding VaultPostProto from raw bytes; if not a VaultPostProto, ignore.
    let post = match dsm::types::proto::VaultPostProto::decode(body) {
        Ok(p) => p,
        Err(_) => return Ok(()), // not a vault post; nothing to validate here
    };

    // VaultPostProto.vault_data should contain LimboVaultProto
    let limbo = match dsm::types::proto::LimboVaultProto::decode(post.vault_data.as_slice()) {
        Ok(v) => v,
        Err(_) => return Err(()), // malformed vault_data for a vault post
    };

    // Inspect fulfillment condition; if it's a CryptoCondition, its public_params may
    // carry SmartPolicy bytes per SDK conventions. Validate if present and non-empty.
    use dsm::types::proto::fulfillment_mechanism::Kind as FmKind;
    match limbo.fulfillment_condition.and_then(|fm| fm.kind) {
        Some(FmKind::CryptoCondition(cc)) => {
            if cc.public_params.is_empty() {
                // If crypto condition is declared, public_params must not be empty
                return Err(());
            }
            validate_smart_policy_bytes(&cc.public_params)
        }
        // Other condition kinds do not embed SmartPolicy bytes; accept.
        _ => Ok(()),
    }
}
