// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where a spool payload goes, and the ids it goes under (storage spec §8,
//! routing rule 1; DSM Amendment A3).
//!
//! The sender and the recipient compute everything here identically: the
//! recipient reads its spool at the address its sender wrote to, and a
//! redelivery lands on one spool row only when it derives the same message
//! id. So each rule exists once, here, beside the seal its payloads travel
//! under ([`crate::crypto::spool_seal`]).
//!
//! A message goes to a relationship. Its inbox address is per relationship
//! and changes every step: the hash of the recipient's genesis, the
//! recipient's device id and the relationship's current chain tip (owner,
//! 2026-09-23), each first hashed on its own axis:
//!
//! ```text
//! h_g = H(DSM/b0x-G ‖ genesis)
//! h_d = H(DSM/b0x-D ‖ device id)
//! h_t = H(DSM/b0x-T ‖ tip)
//! address = Base32Crockford(H(DSM/b0x ‖ h_g ‖ h_d ‖ h_t))
//! ```

use crate::common::domain_tags::{
    TAG_DSM_B0X, TAG_DSM_B0X_CERTRESYNC_MESSAGE_ID, TAG_DSM_B0X_D, TAG_DSM_B0X_ENVELOPE_CONTENT,
    TAG_DSM_B0X_G, TAG_DSM_B0X_REPLY_MESSAGE_ID, TAG_DSM_B0X_T,
};
use crate::crypto::blake3::dsm_domain_hasher;
use crate::crypto::domain::TaggedHashDomain;
use crate::crypto::spool_seal::MESSAGE_ID_LEN;
use crate::types::proto::Envelope;
use crate::utils::text_id::encode_base32_crockford;
use prost::Message;

fn component(tag: TaggedHashDomain<'_>, input: &[u8; 32]) -> [u8; 32] {
    let mut h = dsm_domain_hasher(tag);
    h.update(input);
    *h.finalize().as_bytes()
}

/// The inbox address of the relationship whose recipient is
/// (`recipient_genesis`, `recipient_device`), at the relationship's tip
/// `relationship_tip`: the name of the spool a sender writes to and its
/// recipient reads.
pub fn inbox_address(
    recipient_genesis: &[u8; 32],
    recipient_device: &[u8; 32],
    relationship_tip: &[u8; 32],
) -> String {
    let mut h = dsm_domain_hasher(TAG_DSM_B0X);
    h.update(&component(TAG_DSM_B0X_G, recipient_genesis));
    h.update(&component(TAG_DSM_B0X_D, recipient_device));
    h.update(&component(TAG_DSM_B0X_T, relationship_tip));
    encode_base32_crockford(h.finalize().as_bytes())
}

fn message_id(tag: TaggedHashDomain<'_>, parts: &[&[u8]]) -> [u8; MESSAGE_ID_LEN] {
    let mut h = dsm_domain_hasher(tag);
    for part in parts {
        h.update(part);
    }
    let digest = h.finalize();
    core::array::from_fn(|i| digest.as_bytes()[i])
}

/// The spool message id of an acceptance reply: derived from the
/// transition's own commitment and the sender's projection tip, never a
/// clock, so every repost of one reply is the same id and a redelivery is
/// recognized.
pub fn reply_message_id(
    commitment: &[u8; 32],
    sender_projection_tip: &[u8; 32],
) -> [u8; MESSAGE_ID_LEN] {
    message_id(
        TAG_DSM_B0X_REPLY_MESSAGE_ID,
        &[commitment, sender_projection_tip],
    )
}

/// The spool message id of a certificate resync message: its method, the
/// recipient's tip it is routed by, and its body.
pub fn certresync_message_id(
    method: &str,
    recipient_tip: &[u8; 32],
    body: &[u8],
) -> [u8; MESSAGE_ID_LEN] {
    message_id(
        TAG_DSM_B0X_CERTRESYNC_MESSAGE_ID,
        &[method.as_bytes(), recipient_tip, body],
    )
}

/// The key a reader keeps one copy of a spool message by: its message id and
/// a digest of the copy's own bytes, never the message id alone.
///
/// Identical copies of one message are one key. Two copies that differ under
/// one message id are two keys, and the reader judges each: a message id is
/// deterministic, so a key on the id alone would let the first member to
/// answer with a tampered copy hide every honest copy, on every read.
pub fn envelope_merge_key(envelope: &Envelope) -> String {
    let mut h = dsm_domain_hasher(TAG_DSM_B0X_ENVELOPE_CONTENT);
    h.update(&envelope.encode_to_vec());
    format!(
        "{}:{}",
        encode_base32_crockford(&envelope.message_id),
        encode_base32_crockford(&h.finalize().as_bytes()[..8]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::types::proto::Headers;

    /// The bytes the SDK derived before these rules moved here (owner,
    /// 2026-10-28), pinned on fixed inputs: a sender and a recipient on either
    /// side of the move compute the same address and the same ids.
    #[test]
    fn the_address_and_the_ids_keep_the_bytes_they_had_in_the_sdk() {
        assert_eq!(
            inbox_address(&[0x11; 32], &[0x22; 32], &[0x33; 32]),
            "C9RKFPBCBK8MHD713XMQ9RK22JG1Y7KTS4MMDS8AXJ98E47Y6K40"
        );
        assert_eq!(
            encode_base32_crockford(&reply_message_id(&[0xA1; 32], &[0xB2; 32])),
            "XGTW4SKJT363VQ0Z6HC5QKG0M4"
        );
        assert_eq!(
            encode_base32_crockford(&certresync_message_id(
                "cert.resync",
                &[0xC3; 32],
                &[0xD4; 48]
            )),
            "S18PJ2235HSQWAWGW2X4JM214M"
        );
        assert_eq!(
            envelope_merge_key(&envelope(&[0xA1; 16], 0xAA)),
            "M6GT38D1M6GT38D1M6GT38D1M4:608Q7GZ7YFBWJ"
        );
    }

    /// `genesis_hash` carries the bytes a member could alter in a copy.
    fn envelope(message_id: &[u8; 16], content: u8) -> Envelope {
        Envelope {
            version: 3,
            headers: Some(Headers {
                device_id: vec![0x11; 32],
                genesis_hash: vec![content; 32],
            }),
            message_id: message_id.to_vec(),
            payload: None,
        }
    }

    /// The address is the documented formula over the three axes.
    #[test]
    fn the_inbox_address_is_the_domain_hashed_formula() {
        let (genesis, device, tip) = ([0x11u8; 32], [0x22u8; 32], [0x33u8; 32]);
        let mut h = dsm_domain_hasher(TAG_DSM_B0X);
        h.update(&component(TAG_DSM_B0X_G, &genesis));
        h.update(&component(TAG_DSM_B0X_D, &device));
        h.update(&component(TAG_DSM_B0X_T, &tip));
        assert_eq!(
            inbox_address(&genesis, &device, &tip),
            encode_base32_crockford(h.finalize().as_bytes())
        );
    }

    /// Every step of a relationship moves its inbox, and an address is one
    /// Base32 Crockford digest.
    #[test]
    fn the_inbox_address_rotates_with_the_tip() {
        let (genesis, device) = ([0x41u8; 32], [0x42u8; 32]);
        let a1 = inbox_address(&genesis, &device, &[0x43; 32]);
        let a2 = inbox_address(&genesis, &device, &[0x44; 32]);
        assert_ne!(a1, a2, "an address must rotate when the tip changes");
        for a in [&a1, &a2] {
            assert_eq!(a.len(), 52, "52 Base32 characters for a 32-byte digest");
            assert_eq!(
                crate::utils::text_id::decode_base32_crockford(a).map(|b| b.len()),
                Some(32)
            );
            for ch in a.chars() {
                assert!(
                    "0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains(ch),
                    "invalid char {ch}"
                );
            }
        }
        assert_ne!(
            inbox_address(&genesis, &device, &[0x43; 32]),
            inbox_address(&device, &genesis, &[0x43; 32]),
            "the genesis and device axes are separate domains"
        );
    }

    /// IMPACT-TABLE ROWS B5 and B6, asserted in both directions.
    ///
    /// Both derive a spool message id. The double-NUL spelling carried its own
    /// NUL into `dsm_domain_hasher`, which appends another, so its preimage
    /// began `"…id" || 0x00 || 0x00`; it is reconstructed below to show the
    /// id moved.
    #[test]
    fn b5_and_b6_message_ids_moved_off_the_double_nul_digest() {
        fn old_id(tag_with_nul: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut h = blake3::Hasher::new();
            h.update(tag_with_nul); // the literal, NUL included
            h.update(&[0u8]); // the helper's appended NUL
            for p in parts {
                h.update(p);
            }
            h.finalize().as_bytes()[..16].to_vec()
        }
        fn canonical_id(tag: &[u8], parts: &[&[u8]]) -> Vec<u8> {
            let mut h = blake3::Hasher::new();
            h.update(tag);
            h.update(&[0u8]);
            for p in parts {
                h.update(p);
            }
            h.finalize().as_bytes()[..16].to_vec()
        }

        // B5
        let commitment = [0xA1u8; 32];
        let tip = [0xB2u8; 32];
        let b5 = reply_message_id(&commitment, &tip).to_vec();
        assert_ne!(
            b5,
            old_id(b"DSM/b0x-reply-message-id\0", &[&commitment, &tip]),
            "B5 still produces the doubled-NUL id"
        );
        assert_eq!(
            b5,
            canonical_id(b"DSM/b0x-reply-message-id", &[&commitment, &tip]),
            "B5 did not land on the canonical id"
        );
        assert_eq!(b5.len(), 16, "the spool id is 16 truncated bytes");

        // B6
        let method = "cert.resync";
        let rtip = [0xC3u8; 32];
        let body = [0xD4u8; 48];
        let b6 = certresync_message_id(method, &rtip, &body).to_vec();
        assert_ne!(
            b6,
            old_id(
                b"DSM/b0x-certresync-message-id\0",
                &[method.as_bytes(), &rtip, &body]
            ),
            "B6 still produces the doubled-NUL id"
        );
        assert_eq!(
            b6,
            canonical_id(
                b"DSM/b0x-certresync-message-id",
                &[method.as_bytes(), &rtip, &body]
            ),
            "B6 did not land on the canonical id"
        );

        // The two domains stay separated from each other.
        assert_ne!(b5, b6, "B5 and B6 must not share an id space");
    }

    /// A repost of the same logical message derives the SAME id, so a
    /// redelivery collapses onto one spool row rather than piling up.
    #[test]
    fn a_repost_still_derives_the_same_spool_id() {
        let c = [0x11u8; 32];
        let t = [0x22u8; 32];
        assert_eq!(reply_message_id(&c, &t), reply_message_id(&c, &t));
        assert_ne!(
            reply_message_id(&c, &t),
            reply_message_id(&c, &[0x23u8; 32]),
            "a different projection tip must give a different id"
        );
    }

    /// Cross-endpoint merge must not be first-responder-wins.
    ///
    /// Because spool ids are deterministic, a merge keyed on `message_id` alone
    /// let ONE replica serving a tampered copy shadow every honest copy, on every
    /// poll, forever. That is what made a bad acceptance artifact unrecoverable:
    /// the corrected copy existed on other replicas and could never be seen.
    #[test]
    fn divergent_copies_of_one_message_id_do_not_shadow_each_other() {
        let (id1, id2) = (&[0xA1u8; 16], &[0xB2u8; 16]);

        // Identical replicas of the same message still collapse: the honest
        // multi-replica case is unchanged.
        assert_eq!(
            envelope_merge_key(&envelope(id1, 0xAA)),
            envelope_merge_key(&envelope(id1, 0xAA)),
            "identical replicas must still merge to one entry"
        );

        // A tampered copy under the SAME id gets its own key, so both survive the
        // merge and the consumer can reject one and accept the other.
        assert_ne!(
            envelope_merge_key(&envelope(id1, 0xAA)),
            envelope_merge_key(&envelope(id1, 0xBB)),
            "two copies that disagree under one message id must BOTH survive"
        );

        // The message id is still part of the key -- identical bytes under
        // different ids remain distinct messages.
        assert_ne!(
            envelope_merge_key(&envelope(id1, 0xAA)),
            envelope_merge_key(&envelope(id2, 0xAA)),
        );
    }
}
