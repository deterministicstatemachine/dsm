//! Transport encoding helpers for SDK side (protobuf only)
//!
//! The SDK uses its own generated Envelope type and enforces the same strict
//! Envelope v3 contract as core on every decode path.

use crate::generated::Envelope;
use prost::Message;

pub fn to_canonical_bytes(env: &Envelope) -> Vec<u8> {
    env.encode_to_vec()
}

pub fn validate_envelope_v3(env: &Envelope) -> Result<(), String> {
    if env.version != 3 {
        return Err(format!("Envelope.version must be 3, got {}", env.version));
    }

    Ok(())
}

pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Envelope, String> {
    dsm::envelope::validate_canonical_envelope_v3_bytes(bytes).map_err(|e| e.to_string())?;
    let env = Envelope::decode(bytes).map_err(|e| format!("Failed to decode envelope: {e}"))?;
    validate_envelope_v3(&env)?;
    if env.encode_to_vec() != bytes {
        return Err("Envelope bytes are not in canonical deterministic encoding".to_string());
    }
    Ok(env)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generated::Headers;

    #[test]
    fn sdk_envelope_roundtrip_preserves_fields() {
        let env = Envelope {
            version: 3,
            headers: Some(Headers {
                device_id: vec![0x01; 32],
                chain_tip: vec![0x02; 32],
                genesis_hash: vec![0x03; 32],
                seq: 42,
            }),
            message_id: vec![0x04; 16],
            payload: None,
        };

        let decoded = from_canonical_bytes(&to_canonical_bytes(&env)).expect("decode envelope");
        assert_eq!(decoded, env);
    }

    #[test]
    fn sdk_envelope_decode_rejects_wrong_version() {
        let env = Envelope {
            version: 2,
            headers: Some(Headers {
                device_id: vec![0x01; 32],
                chain_tip: vec![0x02; 32],
                genesis_hash: vec![0x03; 32],
                seq: 1,
            }),
            message_id: vec![0x04; 16],
            payload: None,
        };

        let err = from_canonical_bytes(&to_canonical_bytes(&env)).expect_err("wrong version");
        assert!(
            err.contains("Envelope.version must be 3"),
            "unexpected error: {err}"
        );
    }
}
