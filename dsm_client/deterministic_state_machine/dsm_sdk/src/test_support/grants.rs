// SPDX-License-Identifier: MIT OR Apache-2.0

//! A write grant this device issued a writer (DSM Amendment A34), made and
//! signed the way the wallet makes one, for tests of one device's inbox reads.
//!
//! A relationship's every inbox after its first is the route bound to the
//! recipient's lock, so a read of one needs the grant that names that lock.
//! Tests that hold a single device and a contact record (no second wallet to
//! send the offer) record the grant here. The lock, the writer's key and both
//! signatures are real, the authorization is checked with Core's own
//! [`verify_write_authorization`] before it is stored, and it is stored with
//! the store's own `record_grant_issued`.

use dsm::core::relationship_write_grant::{
    derive_write_keypair, derive_write_lock_keypair, relationship_instance_id,
    verify_write_authorization, write_authorization_wire, AuthorizationExpectation, WriteGrant,
    WriteLock,
};

use crate::storage::client_db::{self, HeldGrant};

/// A master seed for a test device, derived from its device id.
fn test_smaster(device: &[u8; 32]) -> [u8; 32] {
    *blake3::hash(device).as_bytes()
}

/// Record, in this device's store, the grant `recipient` issued `writer` on
/// their relationship, and answer with its lock's public key: the key the
/// relationship's later inboxes from `writer` are bound to.
pub fn issue_grant_to(recipient: (&[u8; 32], &[u8; 32]), writer: &[u8; 32]) -> Vec<u8> {
    let (recipient_device, recipient_genesis) = recipient;
    let relationship_key =
        dsm::core::bilateral_transaction_manager::compute_smt_key(recipient_device, writer);
    let instance = relationship_instance_id(&relationship_key, recipient_genesis);
    let lock_key = derive_write_lock_keypair(
        &test_smaster(recipient_device),
        &instance,
        recipient_device,
        writer,
    )
    .expect("the lock");
    let write_key =
        derive_write_keypair(&test_smaster(writer), &instance, writer, recipient_device)
            .expect("the writer's key");
    let (ak_public, ak_secret) =
        dsm::crypto::sphincs::generate_sphincs_keypair().expect("the recipient's AK");
    let lock = WriteLock {
        relationship_instance_id: instance,
        recipient_genesis: *recipient_genesis,
        recipient_device_id: *recipient_device,
        authorized_sender_device_id: *writer,
        lock_public_key: lock_key.public_key.clone(),
    };
    let lock_wire = lock.to_wire(
        dsm::crypto::sphincs::sphincs_sign(&ak_secret, &lock.binding_target())
            .expect("the AK binds the lock"),
    );
    let grant = WriteGrant::of_key(instance, write_key.public_key.clone());
    let grant_wire = grant.to_wire(
        dsm::crypto::sphincs::sphincs_sign(&lock_key.secret_key, &grant.signing_target())
            .expect("the lock signs the grant"),
    );
    let authorization = write_authorization_wire(&lock_wire, &grant_wire);
    verify_write_authorization(
        &authorization,
        &AuthorizationExpectation {
            relationship_instance_id: &instance,
            recipient_genesis,
            recipient_device_id: recipient_device,
            sender_device_id: writer,
            write_public_key: &write_key.public_key,
            recipient_ak: &ak_public,
        },
    )
    .expect("Core verifies the authorization");
    client_db::record_grant_issued(
        writer,
        &instance,
        &write_key.public_key,
        &HeldGrant {
            grant_id: grant.grant_id(),
            grant_wire: authorization,
        },
    )
    .expect("the store records the grant");
    lock_key.public_key.clone()
}
