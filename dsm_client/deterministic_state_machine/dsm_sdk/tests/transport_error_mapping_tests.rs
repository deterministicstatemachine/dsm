use dsm_sdk::wire::pb as wirepb;
use dsm_sdk::types::error::DsmError;

#[test]
fn invalid_operation_maps_to_invalid_operation_code() {
    let e = DsmError::invalid_operation("bad");
    let we: wirepb::Error = (&e).into();
    assert_eq!(we.code, 1 /* ErrorCode::InvalidOperation */);
    assert_eq!(we.is_recoverable, e.is_recoverable());
    assert!(we.message.contains("Invalid operation: bad"));
}

#[test]
fn network_maps_to_network_code_and_recoverable() {
    let e = DsmError::network("io timeout", Option::<std::io::Error>::None);
    let we: wirepb::Error = (&e).into();
    assert_eq!(we.code, 6 /* ErrorCode::Network */);
    assert!(we.is_recoverable);
    assert!(we.message.contains("Network error: io timeout"));
}

#[test]
fn serialization_maps_to_serialization_code() {
    let e = DsmError::serialization_error(
        "encode",
        "Envelope",
        None::<String>,
        Option::<std::io::Error>::None,
    );
    let we: wirepb::Error = (&e).into();
    assert_eq!(we.code, 3 /* ErrorCode::Serialization */);
    assert!(!we.is_recoverable);
    assert!(we.message.contains("Serialization error"));
}
