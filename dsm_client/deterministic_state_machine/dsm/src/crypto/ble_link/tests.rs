// SPDX-License-Identifier: MIT OR Apache-2.0

//! DSM Amendment A27 (SA-35): the BLE link handshake authenticates both
//! contacts by the keys each pinned, and its records open once, in order,
//! only for the other side.

use super::*;
use crate::crypto::kyber::generate_kyber_keypair;

/// A wallet as its contacts pinned it: its identity and its ML-KEM keys.
struct Wallet {
    identity: LinkIdentity,
    kem: crate::crypto::kyber::KyberKeyPair,
}

fn wallet(tag: u8) -> Wallet {
    Wallet {
        identity: LinkIdentity {
            device_id: [tag; 32],
            genesis: [tag ^ 0x5A; 32],
        },
        kem: generate_kyber_keypair().expect("an ML-KEM key pair"),
    }
}

/// `pinned` as a contact book: each wallet's genesis and ML-KEM public key
/// by device id.
fn book<'a>(pinned: &'a [&'a Wallet]) -> impl Fn(&D32) -> Option<(D32, Vec<u8>)> + 'a {
    move |device_id| {
        pinned
            .iter()
            .find(|w| w.identity.device_id == *device_id)
            .map(|w| (w.identity.genesis, w.kem.public_key.clone()))
    }
}

/// Run the whole handshake from `a` to `b`, each holding the other.
fn handshake(a: &Wallet, b: &Wallet) -> (LinkSession, LinkSession) {
    let (hello, initiating) =
        initiate(&a.identity, &b.identity, &b.kem.public_key).expect("a Hello");
    let hello = Hello::decode(&hello.encode()).expect("the Hello round-trips");
    let (reply, responding) = match respond(&hello, &b.identity, &b.kem.secret_key, book(&[a]))
        .expect("the Hello is answered")
    {
        Answer::Reply(reply, responding) => (reply, responding),
        Answer::NotForMe => panic!("a Hello sealed for b was not for b"),
    };
    assert_eq!(responding.peer(), &a.identity, "b learns a from the Hello");
    let reply = Reply::decode(&reply.encode()).expect("the Reply round-trips");
    let (confirm, at_a) = complete(initiating, &reply, &a.kem.secret_key).expect("a completes");
    let confirm = Confirm::decode(&confirm.encode()).expect("the Confirm round-trips");
    let at_b = finish(*responding, &confirm).expect("b finishes");
    (at_a, at_b)
}

/// Two contacts complete the handshake, each learning the other as pinned,
/// and records flow both ways, each opened once and in order. Nothing either
/// sent carries an identity, amount or salt in the clear.
#[test]
fn two_contacts_complete_the_handshake_and_exchange_records() {
    let (a, b) = (wallet(0xA1), wallet(0xB2));
    let (hello, initiating) =
        initiate(&a.identity, &b.identity, &b.kem.public_key).expect("a Hello");
    let hello_bytes = hello.encode();
    for secret in [
        &a.identity.device_id,
        &a.identity.genesis,
        &b.identity.device_id,
    ] {
        assert!(
            !hello_bytes.windows(32).any(|w| w == &secret[..]),
            "the Hello carries no identity in the clear"
        );
    }
    drop((hello, initiating));

    let (mut at_a, mut at_b) = handshake(&a, &b);
    assert_eq!(at_a.peer(), &b.identity);
    assert_eq!(at_b.peer(), &a.identity);
    let transfer = b"amount=25.00 ERA salt=0123456789abcdef recipient=b";
    let record = at_a.seal(transfer).expect("a seals");
    assert!(
        !record.windows(transfer.len()).any(|w| w == transfer),
        "a record carries nothing in the clear"
    );
    assert_eq!(record.len(), RECORD_LEN, "every record is one length");
    assert_eq!(
        at_a.seal(&[0x11; RECORD_CAPACITY])
            .expect("a full record")
            .len(),
        RECORD_LEN
    );
    assert!(matches!(
        at_a.seal(&[0x11; RECORD_CAPACITY + 1]),
        Err(LinkError::TooLong { .. })
    ));
    assert_eq!(at_b.open(&record).expect("b opens"), transfer.to_vec());
    let back = at_b.seal(b"ack").expect("b seals");
    assert_eq!(at_a.open(&back).expect("a opens"), b"ack".to_vec());
}

/// A record opens once and only past the last one taken: a replay and a
/// record older than one taken are refused, a gap is taken, and a record is
/// never taken back in the direction it was sent, nor by another session.
#[test]
fn a_record_opens_once_in_order_and_only_for_the_other_side() {
    let (a, b) = (wallet(0xA3), wallet(0xB4));
    let (mut at_a, mut at_b) = handshake(&a, &b);
    let first = at_a.seal(b"first").expect("seal");
    let second = at_a.seal(b"second").expect("seal");
    let third = at_a.seal(b"third").expect("seal");
    assert_eq!(at_b.open(&first).expect("first"), b"first".to_vec());
    assert!(matches!(at_b.open(&first), Err(LinkError::Replayed { .. })));
    assert_eq!(
        at_b.open(&third).expect("a gap is taken"),
        b"third".to_vec()
    );
    assert!(matches!(
        at_b.open(&second),
        Err(LinkError::Replayed { .. })
    ));
    // A record a sent never opens for a itself.
    let own = at_a.seal(b"own").expect("seal");
    assert!(matches!(at_a.open(&own), Err(LinkError::DoesNotOpen(..))));
    // Nor for a session of another handshake between the same two.
    let (_other_a, mut other_b) = handshake(&a, &b);
    let fresh = at_a.seal(b"fresh").expect("seal");
    assert!(matches!(
        other_b.open(&fresh),
        Err(LinkError::DoesNotOpen(..))
    ));
    // A bent record does not open.
    let mut bent = at_a.seal(b"bent").expect("seal");
    let last = bent.len() - 1;
    bent[last] ^= 0x01;
    assert!(matches!(at_b.open(&bent), Err(LinkError::DoesNotOpen(..))));
}

/// The handshake authenticates both sides by the keys each pinned:
/// - a Hello sealed for another wallet is not for this one;
/// - a Hello from a device that is not a contact, or under another genesis,
///   is refused;
/// - a Reply from a responder without the pinned key does not open for the
///   initiator;
/// - a Confirm from an initiator without the pinned key does not open for
///   the responder.
///
/// MUTATION CONTROL: dropping the genesis comparison in `respond` takes the
/// Hello under another genesis: red. Skipping the Confirm's opening in
/// `finish` takes the junk Confirm: red.
#[test]
fn the_handshake_refuses_every_side_that_does_not_hold_its_pinned_key() {
    let (a, b, c) = (wallet(0xA5), wallet(0xB6), wallet(0xC7));
    // Sealed for b, offered to c.
    let (hello, _) = initiate(&a.identity, &b.identity, &b.kem.public_key).expect("a Hello");
    assert!(matches!(
        respond(&hello, &c.identity, &c.kem.secret_key, book(&[&a])).expect("answered"),
        Answer::NotForMe
    ));
    // Sealed for b, under b's key, but b's book does not hold a.
    assert!(matches!(
        respond(&hello, &b.identity, &b.kem.secret_key, book(&[&c])),
        Err(LinkError::NotAContact)
    ));
    // a's device id with another genesis than b pinned.
    let mut impostor = wallet(0xA5);
    impostor.identity.genesis = [0x99; 32];
    let (forged, _) =
        initiate(&impostor.identity, &b.identity, &b.kem.public_key).expect("a Hello");
    assert!(matches!(
        respond(&forged, &b.identity, &b.kem.secret_key, book(&[&a])),
        Err(LinkError::NotAContact)
    ));

    // A responder that is not b: it cannot decapsulate ct1, so its Reply,
    // sealed under any other chain, does not open for a.
    let (hello, initiating) =
        initiate(&a.identity, &b.identity, &b.kem.public_key).expect("a Hello");
    let reply =
        match respond(&hello, &b.identity, &b.kem.secret_key, book(&[&a])).expect("answered") {
            Answer::Reply(reply, _) => reply,
            Answer::NotForMe => panic!("for b"),
        };
    let mut bent_reply = reply.clone();
    bent_reply.sealed[0] ^= 0x01;
    assert!(matches!(
        complete(initiating, &bent_reply, &a.kem.secret_key),
        Err(LinkError::DoesNotOpen(..))
    ));

    // An initiator that is not a: it cannot decapsulate ct2, so its Confirm
    // does not open for b.
    let (hello, initiating) =
        initiate(&a.identity, &b.identity, &b.kem.public_key).expect("a Hello");
    let (reply, responding) =
        match respond(&hello, &b.identity, &b.kem.secret_key, book(&[&a])).expect("answered") {
            Answer::Reply(reply, responding) => (reply, responding),
            Answer::NotForMe => panic!("for b"),
        };
    assert!(matches!(
        complete(initiating, &reply, &c.kem.secret_key),
        Err(LinkError::DoesNotOpen(..))
    ));
    let replayed = Confirm {
        sealed: vec![0x42; Confirm::LEN],
    };
    assert!(matches!(
        finish(*responding, &replayed),
        Err(LinkError::DoesNotOpen(..))
    ));
}
