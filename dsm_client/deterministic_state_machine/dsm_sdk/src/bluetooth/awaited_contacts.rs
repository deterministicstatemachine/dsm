// SPDX-License-Identifier: MIT OR Apache-2.0

//! The contacts a BLE identity exchange waits to see stored.
//!
//! An identity read or written over BLE can name a device that is not a
//! contact yet: the contact is being added while the radio links, and the
//! identity waits for it. Anyone in radio range can name any device id, so the
//! waits are bounded: at most a fixed number of identities wait at once, each
//! for at most [`CONTACT_AWAIT_LIMIT`], and an id already waiting is not waited
//! for twice. An identity past the bound is refused, never queued.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;

/// How long an identity waits for its contact to be stored.
pub const CONTACT_AWAIT_LIMIT: Duration = Duration::from_secs(15);

/// How often a waiting identity looks for its contact.
pub const CONTACT_AWAIT_POLL: Duration = Duration::from_millis(500);

/// The most identities that wait at once.
pub const MAX_AWAITED_CONTACTS: usize = 4;

/// Why an identity was not taken into a wait.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AwaitRefused {
    /// The device is already waited for: the wait under way answers it.
    #[error("an identity for this device is already waiting for its contact")]
    AlreadyWaiting,
    /// As many identities as the bound allows are already waiting.
    #[error("{0} identities are already waiting for their contacts")]
    Full(usize),
}

/// A bounded set of identities waiting for their contacts, each holding what
/// its wait needs once the contact is stored.
pub struct AwaitedContacts<T> {
    waiting: Arc<Mutex<HashMap<[u8; 32], T>>>,
    capacity: usize,
}

impl<T> AwaitedContacts<T> {
    /// A set that holds at most `capacity` waits.
    pub fn new(capacity: usize) -> Self {
        Self {
            waiting: Arc::new(Mutex::new(HashMap::new())),
            capacity,
        }
    }

    /// Start waiting for `device_id`'s contact, holding `entry` for when it
    /// is stored. The wait ends when the returned slot is dropped, however
    /// its holder ends: the contact found, the limit reached, or an error.
    pub fn begin(&self, device_id: [u8; 32], entry: T) -> Result<AwaitSlot<T>, AwaitRefused> {
        let mut waiting = self.waiting.lock();
        if waiting.contains_key(&device_id) {
            return Err(AwaitRefused::AlreadyWaiting);
        }
        if waiting.len() >= self.capacity {
            return Err(AwaitRefused::Full(waiting.len()));
        }
        waiting.insert(device_id, entry);
        Ok(AwaitSlot {
            waiting: Arc::clone(&self.waiting),
            device_id,
        })
    }

    /// How many identities are waiting.
    pub fn len(&self) -> usize {
        self.waiting.lock().len()
    }

    /// Whether no identity is waiting.
    pub fn is_empty(&self) -> bool {
        self.waiting.lock().is_empty()
    }
}

/// One identity's wait. Dropping it ends the wait.
pub struct AwaitSlot<T> {
    waiting: Arc<Mutex<HashMap<[u8; 32], T>>>,
    device_id: [u8; 32],
}

impl<T> AwaitSlot<T> {
    /// The device whose contact is awaited.
    pub fn device_id(&self) -> [u8; 32] {
        self.device_id
    }

    /// What the wait holds, taken once its contact is stored. The wait ends
    /// with it.
    pub fn take(self) -> Option<T> {
        self.waiting.lock().remove(&self.device_id)
    }
}

impl<T> Drop for AwaitSlot<T> {
    fn drop(&mut self) {
        self.waiting.lock().remove(&self.device_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SA-51. A peer in range can name any device id, and each id it named
    /// waited — with a polling task of its own — however many there were.
    /// Now at most the bound wait at once, an id already waiting is not
    /// waited for twice, and a wait's slot frees when it ends.
    /// MUTATION CONTROL: dropping either refusal turns this red.
    #[test]
    fn identities_wait_for_their_contacts_only_up_to_the_bound() {
        let awaited = AwaitedContacts::new(MAX_AWAITED_CONTACTS);
        let slots: Vec<AwaitSlot<u8>> = (0..MAX_AWAITED_CONTACTS)
            .map(|i| {
                let id = u8::try_from(i).expect("a small bound");
                awaited.begin([id; 32], id).expect("within the bound")
            })
            .collect();
        assert_eq!(awaited.len(), MAX_AWAITED_CONTACTS);

        assert_eq!(
            awaited.begin([0xEE; 32], 0xEE).err(),
            Some(AwaitRefused::Full(MAX_AWAITED_CONTACTS)),
            "a spoofed id past the bound waits"
        );
        assert_eq!(
            awaited.begin([0x00; 32], 0x00).err(),
            Some(AwaitRefused::AlreadyWaiting),
            "an id already waiting waits twice"
        );

        let mut slots = slots.into_iter();
        let first = slots.next().expect("a slot");
        assert_eq!(
            first.take(),
            Some(0x00),
            "the found contact takes its entry"
        );
        drop(slots.next());
        assert_eq!(
            awaited.len(),
            MAX_AWAITED_CONTACTS - 2,
            "ended waits free their slots"
        );
        let again = awaited.begin([0xEE; 32], 0xEE).expect("room again");
        assert_eq!(again.device_id(), [0xEE; 32]);
        drop(again);
        drop(slots);
        assert!(awaited.is_empty());
    }
}
