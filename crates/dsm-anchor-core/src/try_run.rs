//! The try-run: an anchor's install, gone through on the real chip and board with its permanent parts
//! substituted, before anything permanent happens.
//!
//! It is part of installing, not a test of it. It derives the identity the provisioning would bind,
//! signs a payment with both real keys and verifies what they signed, forms the record that payment
//! leaves and writes, reads back and erases one of that size, and asks the chip to go through what its
//! closing needs. Three things it does not do, because they cannot be undone, and it checks instead
//! that the chip would take them: the board's key written to its pairing slot, the factory slot
//! invalidated, and the cage. Nothing it signs leaves the anchor. An anchor is provisioned only after
//! one has passed ([`crate::durable::DurableAppliance::provision`]), and a wallet shows it, with
//! [`PERMANENT`], before it asks.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use crate::appliance::{Appliance, RecoverOutcome};
use crate::durable::{decode_anchor, encode_anchor, ActiveStore};
use crate::enrollment::{ChipBirth, Provisioning};
use crate::hash::h;
use crate::root_advance::{anchor_root_advance, transition_digest, OwnedTransition};
use crate::tropic::{PartitionSig, Tropic};

/// What installing makes permanent, for the wallet to show before it asks.
pub const PERMANENT: [&str; 4] = [
    "This anchor is bound to this wallet's device, online key and genesis. It can never serve another wallet, and a wallet wiped or created anew cannot use it.",
    "The chip's factory pairing key is invalidated, and the board's own key takes its place. The chip then opens to this board alone.",
    "The chip's counter start and resident key can never be set again.",
    "The chip's access rules are closed for good: nothing can loosen them afterward.",
];

/// One thing a try-run went through, and how it came out.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TryStep {
    pub name: String,
    pub outcome: Result<(), String>,
}

impl TryStep {
    pub fn new(name: &str, outcome: Result<(), String>) -> Self {
        Self {
            name: name.to_string(),
            outcome,
        }
    }
}

/// What a try-run went through.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TryRun {
    pub steps: Vec<TryStep>,
}

impl TryRun {
    /// The first step that did not pass, its reason with it; a run with none passed.
    pub fn first_failure(&self) -> Option<&TryStep> {
        self.steps
            .iter()
            .find(|step| matches!(step.outcome, Err(ref _kept_in_the_step)))
    }
}

/// The transition a try-run signs: shaped as the wallet's, naming no device and no counterparty.
fn try_transition(prev_root: [u8; 32], challenge: &[u8; 32]) -> OwnedTransition {
    let of = |what: &str| h("DSM/anchor/try-run/v1", &[what.as_bytes()]);
    let mut t = OwnedTransition {
        relationship_id: of("relationship"),
        object_id: of("object"),
        sender_device_id: of("sender"),
        recipient_device_id: of("recipient"),
        prev_root,
        next_root: prev_root,
        anchor_counter: 0,
        next_anchor_counter: 1,
        action_type: 0,
        action_fields: Vec::new(),
        payload_hash: of("payload"),
        old_leaf_proof: Vec::new(),
        new_leaf_proof: Vec::new(),
        authority_policy_hash: of("policy"),
    };
    let digest = transition_digest(&t.as_transition(), challenge);
    t.next_root = anchor_root_advance(&prev_root, &digest);
    t
}

/// Go through an install of `chip` for the device `provisioning` names, with the permanent parts
/// substituted. Reports every step it reached, and leaves the chip and the store as it found them.
pub fn rehearse<T: Tropic, P: PartitionSig, S: ActiveStore>(
    chip: &ChipBirth,
    tropic: &mut T,
    store: &mut S,
    provisioning: &Provisioning,
) -> TryRun {
    let mut steps = Vec::new();
    let birth = match chip.birth::<P>(provisioning) {
        Ok(birth) => {
            steps.push(TryStep::new("the anchor's identity derives", Ok(())));
            birth
        }
        Err(e) => {
            steps.push(TryStep::new(
                "the anchor's identity derives",
                Err(format!("{e:?}")),
            ));
            return TryRun { steps };
        }
    };
    let challenge = h("DSM/anchor/try-run/v1", &[b"challenge"]);
    let transition = try_transition(birth.genesis_frontier, &challenge);
    let record = {
        let mut app: Appliance<&mut T, P> = Appliance::new(
            &mut *tropic,
            chip.enrolled_counter,
            chip.anchor_id,
            chip.partition_device_id,
            birth,
        );
        let prepared = app.prepare(
            &transition.as_transition(),
            &challenge,
            &h("DSM/anchor/try-run/v1", &[b"device root before"]),
            &h("DSM/anchor/try-run/v1", &[b"device root after"]),
        );
        match prepared {
            Err(e) => {
                steps.push(TryStep::new(
                    "the chip and the board sign a payment",
                    Err(format!("{e:?}")),
                ));
                None
            }
            Ok(()) => {
                steps.push(TryStep::new(
                    "the chip and the board sign a payment",
                    Ok(()),
                ));
                let outcome = app.recover();
                steps.push(TryStep::new(
                    "both signatures verify under the keys the anchor would pin",
                    match outcome {
                        RecoverOutcome::AcceptPreparedCanComplete => Ok(()),
                        other => Err(format!("recovery answered {other:?}")),
                    },
                ));
                match app.commit_candidate() {
                    Err(e) => {
                        steps.push(TryStep::new(
                            "the payment's record forms",
                            Err(format!("{e:?}")),
                        ));
                        None
                    }
                    Ok(()) => {
                        steps.push(TryStep::new("the payment's record forms", Ok(())));
                        Some(encode_anchor(provisioning, &app.active))
                    }
                }
            }
        }
    };
    if let Some(record) = record {
        steps.push(TryStep::new(
            "a record of that size is written, read back and erased",
            store
                .try_record(&record)
                .map_err(|e| format!("{e:?}"))
                .and_then(|()| {
                    decode_anchor(&record)
                        .map(|_decoded| ())
                        .map_err(|e| format!("{e:?}"))
                }),
        ));
    }
    steps.extend(tropic.rehearse_birth());
    TryRun { steps }
}
