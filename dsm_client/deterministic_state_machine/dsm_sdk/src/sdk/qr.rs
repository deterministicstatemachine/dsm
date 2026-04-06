use blake3::Hasher;
use prost::Message;
use crate::types::error::DsmError;
use dsm::types::proto::ContactQrV3;

pub fn make_contact_qr_v3_bytes(
    device_id: &[u8; 32],
    network: &str,
    storage_nodes: &[&str],
    sdk_build_bytes: &[u8],
) -> Result<Vec<u8>, DsmError> {
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
        ..Default::default()
    };

    let mut buf = Vec::with_capacity(msg.encoded_len());
    msg.encode(&mut buf).map_err(|_e| DsmError::Serialization {
        context: "encode ContactQrV3".into(),
        source: None,
        entity: "ContactQrV3".into(),
        details: None,
    })?;

    Ok(buf)
}

pub fn parse_contact_qr_v3_bytes(raw: &[u8]) -> Result<ContactQrV3, DsmError> {
    ContactQrV3::decode(raw).map_err(|_| DsmError::Serialization {
        context: "protobuf decode ContactQrV3".into(),
        source: None,
        entity: "ContactQrV3".into(),
        details: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_device_id() -> [u8; 32] {
        [0xAA; 32]
    }

    fn sample_sdk_build() -> &'static [u8] {
        b"sdk-build-v1.0.0"
    }

    #[test]
    fn roundtrip_encode_decode() {
        let device_id = sample_device_id();
        let network = "testnet";
        let nodes: &[&str] = &["node1.example.com", "node2.example.com"];

        let bytes =
            make_contact_qr_v3_bytes(&device_id, network, nodes, sample_sdk_build()).unwrap();
        let parsed = parse_contact_qr_v3_bytes(&bytes).unwrap();

        assert_eq!(parsed.device_id, device_id.to_vec());
        assert_eq!(parsed.network, "testnet");
        assert_eq!(
            parsed.storage_nodes,
            vec!["node1.example.com", "node2.example.com"]
        );
        assert_eq!(parsed.sdk_fingerprint.len(), 32);
    }

    #[test]
    fn empty_storage_nodes() {
        let device_id = sample_device_id();
        let bytes =
            make_contact_qr_v3_bytes(&device_id, "mainnet", &[], sample_sdk_build()).unwrap();
        let parsed = parse_contact_qr_v3_bytes(&bytes).unwrap();

        assert!(parsed.storage_nodes.is_empty());
        assert_eq!(parsed.network, "mainnet");
    }

    #[test]
    fn whitespace_trimmed_from_network_and_nodes() {
        let device_id = sample_device_id();
        let bytes = make_contact_qr_v3_bytes(
            &device_id,
            "  testnet  ",
            &["  node1.com  ", "  ", "node2.com"],
            sample_sdk_build(),
        )
        .unwrap();
        let parsed = parse_contact_qr_v3_bytes(&bytes).unwrap();

        assert_eq!(parsed.network, "testnet");
        assert_eq!(parsed.storage_nodes, vec!["node1.com", "node2.com"]);
    }

    #[test]
    fn deterministic_encoding() {
        let device_id = sample_device_id();
        let bytes1 =
            make_contact_qr_v3_bytes(&device_id, "net", &["a"], sample_sdk_build()).unwrap();
        let bytes2 =
            make_contact_qr_v3_bytes(&device_id, "net", &["a"], sample_sdk_build()).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn different_sdk_build_gives_different_fingerprint() {
        let device_id = sample_device_id();
        let bytes_a = make_contact_qr_v3_bytes(&device_id, "net", &["a"], b"build-A").unwrap();
        let bytes_b = make_contact_qr_v3_bytes(&device_id, "net", &["a"], b"build-B").unwrap();

        let parsed_a = parse_contact_qr_v3_bytes(&bytes_a).unwrap();
        let parsed_b = parse_contact_qr_v3_bytes(&bytes_b).unwrap();

        assert_ne!(parsed_a.sdk_fingerprint, parsed_b.sdk_fingerprint);
    }

    #[test]
    fn sdk_fingerprint_is_blake3_of_build_bytes() {
        let build = b"my-sdk-build";
        let mut h = blake3::Hasher::new();
        h.update(build);
        let expected = h.finalize();

        let device_id = sample_device_id();
        let bytes = make_contact_qr_v3_bytes(&device_id, "net", &[], build).unwrap();
        let parsed = parse_contact_qr_v3_bytes(&bytes).unwrap();

        assert_eq!(parsed.sdk_fingerprint, expected.as_bytes().to_vec());
    }

    #[test]
    fn decode_empty_bytes_is_valid_default_proto() {
        let parsed = parse_contact_qr_v3_bytes(&[]);
        assert!(parsed.is_ok());
        let msg = parsed.unwrap();
        assert!(msg.device_id.is_empty());
        assert!(msg.network.is_empty());
    }
}
