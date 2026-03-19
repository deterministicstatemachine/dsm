use blake3::Hasher;
use prost::Message;
use crate::types::error::DsmError;

include!(concat!(env!("OUT_DIR"), "/dsm.qr.v3.rs")); // ContactQrV3

pub fn make_contact_qr_v3_bytes(device_id: &[u8; 32], network: &str, storage_nodes: &[&str], sdk_build_bytes: &[u8])
    -> Result<Vec<u8>, DsmError>
{
    // Optional fingerprint of the SDK build/canonicalizer (32 bytes)
    let mut h = Hasher::new();
    h.update(sdk_build_bytes);
    let fingerprint = h.finalize();

    let msg = ContactQrV3 {
        device_id: device_id.to_vec(),
        network: network.trim().to_string(),
        storage_nodes: storage_nodes
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        sdk_fingerprint: fingerprint.as_bytes().to_vec(),
    };

    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf).map_err(|e| DsmError::Codec {
        context: "encode ContactQrV3".into(),
        source: None,
    })?;

    Ok(buf) // UI encodes to QR outside SDK
}

pub fn parse_contact_qr_v3_bytes(raw: &[u8]) -> Result<ContactQrV3, DsmError> {
    ContactQrV3::decode(raw).map_err(|_| DsmError::Codec {
        context: "protobuf decode ContactQrV3".into(),
        source: None,
    })
}