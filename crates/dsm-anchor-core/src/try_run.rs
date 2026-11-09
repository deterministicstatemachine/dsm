//! The try-run: an anchor's install, gone through on the real chip and board with its permanent parts
//! substituted, before anything permanent happens.
//!
//! It is part of installing, not a test of it. It runs the code a real anchor runs: the first record
//! written, a payment prepared and signed with both real keys, the counter moved with the records
//! around it, the release held, the account finalized, and the whole of it restored from its record
//! as a boot restores it. All of that goes to slots no record is ever read from, so a power cut leaves
//! nothing a boot would take, and the counter is set back. It then tries the record's own slots and
//! asks the chip to go through what its closing needs.
//!
//! Three things it does not do, because they cannot be undone, and it checks instead that the chip
//! would take them: the board's key written to its pairing slot, the factory slot invalidated, and
//! the cage. Nothing it signs leaves the anchor. An anchor is provisioned only after one has passed
//! ([`crate::durable::DurableAppliance::provision`]), and a wallet shows it, with [`PERMANENT`], before
//! it asks.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use prost::Message;

use crate::appliance::{owner_authorization_digest, ApplianceError, RecoverOutcome, Status};
use crate::durable::{ActiveStore, DurableAppliance, DurableError, TrialRecords};
use crate::enrollment::{ChipBirth, Install, Provisioning};
use crate::hash::h;
use crate::root_advance::{anchor_root_advance, transition_digest, OwnedTransition};
use crate::tropic::{PartitionSig, Tropic};
use crate::util::ct_eq_32;

/// What installing makes permanent, for the wallet to show before it asks.
pub const PERMANENT: [&str; 5] = [
    "This anchor is bound to this wallet's device, online key and genesis. It can never serve another wallet, and a wallet wiped or created anew cannot use it.",
    "The chip's factory pairing key is invalidated, and the board's own key takes its place. The chip then opens to this board alone.",
    "The chip's counter start and resident key can never be set again.",
    "The chip's access rules are closed for good: nothing can loosen them afterward.",
    "What is loaded onto this anchor can only come back through this anchor. If it dies or is lost, that balance is gone: nothing can recover it.",
];

/// What a trial install leaves for good: nothing on the chip or the board. Only a balance loaded onto
/// it and not unloaded before the board loses power is gone, since the next boot clears the trial.
pub const TRIAL_PERMANENT: [&str; 1] = [
    "Nothing on the chip or the board is permanent: this trial install serves this wallet until the board loses power, and the next boot clears it. What is loaded onto it and not unloaded before then is gone: nothing can recover it.",
];

/// What an install of this kind makes permanent, for the wallet to show before it asks.
pub fn permanent(install: Install) -> &'static [&'static str] {
    match install {
        Install::ForGood => &PERMANENT,
        Install::ForTrial => &TRIAL_PERMANENT,
    }
}

/// What a step of a try-run answers to: the trial's own working, or a production install alone.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Requirement {
    /// What the anchor needs to work at all, on a development board as on a production one.
    Works,
    /// What a production install alone needs, such as a chip whose PTRNG is tested. A development
    /// board may leave it unmet: a trial install passes over it, and an install for good refuses
    /// until it is met.
    Production,
}

/// One thing a try-run went through, and how it came out.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TryStep {
    pub name: String,
    pub outcome: Result<(), String>,
    pub requirement: Requirement,
}

impl TryStep {
    /// A step the anchor needs to work.
    pub fn new(name: &str, outcome: Result<(), String>) -> Self {
        Self {
            name: name.to_string(),
            outcome,
            requirement: Requirement::Works,
        }
    }

    /// A step only a production install needs.
    pub fn production(name: &str, outcome: Result<(), String>) -> Self {
        Self {
            name: name.to_string(),
            outcome,
            requirement: Requirement::Production,
        }
    }
}

/// What a try-run went through.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TryRun {
    pub steps: Vec<TryStep>,
    /// How long the release it signed is on the wire. The release stays on the anchor, so the answer
    /// carries [`transport_check`] of this length instead: the transport carries the largest answer
    /// an anchor ever gives, and the host can tell that it arrived whole.
    pub release_bytes: usize,
}

impl TryRun {
    /// The first step that did not pass, its reason with it; a run with none passed. What an install
    /// refuses on, production requirements among them.
    pub fn first_failure(&self) -> Option<&TryStep> {
        self.steps
            .iter()
            .find(|step| matches!(step.outcome, Err(ref _kept_in_the_step)))
    }

    /// The first step the anchor needed to work that did not pass: none on a board where the trial
    /// works, development or production.
    pub fn first_broken(&self) -> Option<&TryStep> {
        self.steps.iter().find(|step| {
            step.requirement == Requirement::Works
                && matches!(step.outcome, Err(ref _kept_in_the_step))
        })
    }

    /// The first step that keeps an install of this kind from passing. An install for good waits for
    /// every requirement. A trial install substitutes what is permanent, so what a production install
    /// alone needs does not stop it; anything the anchor needs to work still does.
    pub fn blocking(&self, install: Install) -> Option<&TryStep> {
        match install {
            Install::ForGood => self.first_failure(),
            Install::ForTrial => self.first_broken(),
        }
    }
}

/// `len` bytes a host can check for itself, in place of a release that does not leave the anchor.
pub fn transport_check(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8).collect()
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

/// Record a step and hand on what it produced: nothing after a failed step depends on it.
fn step<V, E: core::fmt::Debug>(
    steps: &mut Vec<TryStep>,
    name: &str,
    outcome: Result<V, E>,
) -> Option<V> {
    match outcome {
        Ok(value) => {
            steps.push(TryStep::new(name, Ok(())));
            Some(value)
        }
        Err(e) => {
            steps.push(TryStep::new(name, Err(format!("{e:?}"))));
            None
        }
    }
}

/// The appliance a try-run drives. A firmware holds its real one as the same two trait objects, so
/// this is the code that serves, and the image carries one copy of it.
type Lent<'a, P> = DurableAppliance<Box<dyn Tropic + 'a>, P, Box<dyn ActiveStore + 'a>>;

/// A try-run begun: what it went through so far, and the authorization its payment waits on. The
/// anchor holds no owner's key and never signs as one, so the rehearsal's payment is authorized by
/// the rehearsal owner, the wallet, over this digest, through the same check a real payment's is.
pub struct Begun {
    pub steps: Vec<TryStep>,
    /// The owner-authorization digest of the rehearsal's payment, when the run reached it.
    pub awaiting: Option<[u8; 32]>,
}

/// The challenge the rehearsal's payment is made under.
fn challenge() -> [u8; 32] {
    h("DSM/anchor/try-run/v1", &[b"challenge"])
}

/// The device roots the rehearsal's payment carries.
fn device_roots() -> ([u8; 32], [u8; 32]) {
    (
        h("DSM/anchor/try-run/v1", &[b"device root before"]),
        h("DSM/anchor/try-run/v1", &[b"device root after"]),
    )
}

/// The owner-authorization digest of the rehearsal's payment on `anchor`, standing where it does.
fn awaiting_of<P: PartitionSig>(anchor: &Lent<'_, P>) -> [u8; 32] {
    let a = anchor.appliance();
    let transition = try_transition(a.active.root, &challenge());
    let (before, after) = device_roots();
    owner_authorization_digest(
        &a.bundle,
        &a.active.root,
        transition.anchor_counter,
        &transition_digest(&transition.as_transition(), &challenge()),
        &before,
        &after,
    )
}

/// Begin a try-run of an install of `chip` for the device `rehearsal` names: the trial slots are
/// cleared and the anchor is born into them. What it needs next is its owner's authorization of its
/// payment ([`Begun::awaiting`]), which [`finish`] takes.
pub fn begin<T: Tropic, P: PartitionSig, S: ActiveStore>(
    chip: &ChipBirth,
    tropic: &mut T,
    store: &mut S,
    rehearsal: &Provisioning,
) -> Begun {
    begin_in::<P>(chip, &mut *tropic, &mut *store, rehearsal)
}

fn begin_in<P: PartitionSig>(
    chip: &ChipBirth,
    tropic: &mut dyn Tropic,
    store: &mut dyn ActiveStore,
    rehearsal: &Provisioning,
) -> Begun {
    let mut steps = Vec::new();
    let cleared = step(
        &mut steps,
        "the slots a try-run writes to are clear",
        store.trial_clear(),
    );
    let awaiting = cleared.and_then(|()| {
        step(
            &mut steps,
            "the anchor's identity derives and its first record is written",
            Lent::<P>::born(
                chip,
                Box::new(&mut *tropic),
                Box::new(TrialRecords(&mut *store)),
                rehearsal.clone(),
            )
            .map_err(|refused| refused.error),
        )
        .map(|anchor| awaiting_of(&anchor))
    });
    Begun { steps, awaiting }
}

/// Finish a try-run begun with [`begin`]. With the owner's `authorization` of its payment, the
/// payment is made as a real anchor makes it, and the anchor restored from its record as a boot
/// does; without one (none arrived), the payment is not made and the run says so. Either way the
/// chip and the store go back as they were found.
pub fn finish<T: Tropic, P: PartitionSig, S: ActiveStore>(
    chip: &ChipBirth,
    tropic: &mut T,
    store: &mut S,
    begun: Begun,
    authorization: Option<Vec<u8>>,
) -> TryRun {
    finish_in::<P>(chip, &mut *tropic, &mut *store, begun, authorization)
}

fn finish_in<P: PartitionSig>(
    chip: &ChipBirth,
    tropic: &mut dyn Tropic,
    store: &mut dyn ActiveStore,
    begun: Begun,
    authorization: Option<Vec<u8>>,
) -> TryRun {
    let mut steps = begun.steps;
    let mut release_bytes = 0;
    if let Some(awaiting) = begun.awaiting {
        // How far it reached is in its steps.
        spend::<P>(
            chip,
            &mut *tropic,
            &mut *store,
            &awaiting,
            authorization,
            &mut steps,
            &mut release_bytes,
        );
    }
    // Whatever the spend reached, the chip and the store go back as they were found.
    step(
        &mut steps,
        "everything the payment wrote is erased",
        store.trial_clear(),
    );
    step(
        &mut steps,
        "the chip's counter goes back to its start",
        tropic.set_counter_back(),
    );
    let sample = h("DSM/anchor/try-run/v1", &[b"own slots"]);
    step(
        &mut steps,
        "a record's own slots take a write, give it back and erase",
        store.try_record(&sample),
    );
    steps.extend(tropic.rehearse_birth());
    TryRun {
        steps,
        release_bytes,
    }
}

/// A try-run in one, for a host that holds the rehearsal owner's key: begun, its payment authorized
/// by `sign` over the digest it waits on, and finished.
pub fn rehearse_with<T: Tropic, P: PartitionSig, S: ActiveStore>(
    chip: &ChipBirth,
    tropic: &mut T,
    store: &mut S,
    rehearsal: &Provisioning,
    sign: impl FnOnce(&[u8; 32]) -> Result<Vec<u8>, String>,
) -> TryRun {
    let mut begun = begin::<T, P, S>(chip, tropic, store, rehearsal);
    let authorization = match begun.awaiting.map(|digest| sign(&digest)) {
        Some(Ok(signature)) => Some(signature),
        Some(Err(why)) => {
            steps_push_unauthorized(&mut begun, why);
            None
        }
        None => None,
    };
    finish::<T, P, S>(chip, tropic, store, begun, authorization)
}

/// The rehearsal owner did not authorize the payment: the run says so and waits for nothing.
fn steps_push_unauthorized(begun: &mut Begun, why: String) {
    begun
        .steps
        .push(TryStep::new("its owner authorizes the payment", Err(why)));
    begun.awaiting = None;
}

/// A whole payment, as a real anchor makes it, over the trial slots: from the record [`begin`]
/// wrote, with its owner's `authorization` of the payment that record awaits.
fn spend<P: PartitionSig>(
    chip: &ChipBirth,
    tropic: &mut dyn Tropic,
    store: &mut dyn ActiveStore,
    awaiting: &[u8; 32],
    authorization: Option<Vec<u8>>,
    steps: &mut Vec<TryStep>,
    release_bytes: &mut usize,
) -> Option<()> {
    let next_root = {
        let mut anchor = step(
            steps,
            "the anchor restores from its first record",
            Lent::<P>::restore(
                chip,
                Box::new(&mut *tropic),
                Box::new(TrialRecords(&mut *store)),
            ),
        )?;
        step(
            steps,
            "boot recovery accepts a fresh anchor",
            anchor.recover_at_boot(),
        )?;
        let digest = awaiting_of(&anchor);
        step(
            steps,
            "the payment awaiting authorization is the one begun",
            if ct_eq_32(&digest, awaiting) {
                Ok(())
            } else {
                Err("the anchor stands elsewhere")
            },
        )?;
        let transition = try_transition(anchor.appliance().active.root, &challenge());
        let (before, after) = device_roots();
        step(
            steps,
            "a payment its owner did not authorize signs nothing",
            match anchor.prepare(&transition.as_transition(), &challenge(), &before, &after) {
                Err(DurableError::Appliance(ApplianceError::OwnerUnauthorized)) => Ok(()),
                other => Err(format!("an unauthorized prepare answered {other:?}")),
            },
        )?;
        // The signature is let go once the anchor has taken the authorization: what follows signs
        // with the heap no longer holding it.
        step(
            steps,
            "its owner authorizes the payment",
            match authorization {
                Some(mut signature) => {
                    let taken = anchor.authorize(&digest, &signature);
                    crate::util::zeroize_vec(&mut signature);
                    taken
                }
                None => Err(DurableError::TryRun("no authorization arrived".to_string())),
            },
        )?;
        step(
            steps,
            "the chip and the board sign a payment, and its record is written",
            anchor.prepare(&transition.as_transition(), &challenge(), &before, &after),
        )?;
        step(
            steps,
            "both signatures verify under the keys the anchor would pin",
            match anchor.recover() {
                RecoverOutcome::AcceptPreparedCanComplete => Ok(()),
                other => Err(format!("recovery answered {other:?}")),
            },
        )?;
        step(
            steps,
            "the chip's counter moves with the records around it",
            anchor.commit(),
        )?;
        *release_bytes = step(
            steps,
            "the release is held for the receiver",
            anchor.emit().map(|release| release.to_pb().encoded_len()),
        )?;
        let finalized = step(
            steps,
            "the account advances and its record is written",
            anchor.finalize(),
        )?;
        step(
            steps,
            "the account stands where the payment left it",
            if finalized == transition.next_root {
                Ok(())
            } else {
                Err("finalize named another frontier")
            },
        )?;
        finalized
    };
    let restored = step(
        steps,
        "the anchor restores from its record, as a boot does",
        Lent::<P>::restore(
            chip,
            Box::new(&mut *tropic),
            Box::new(TrialRecords(&mut *store)),
        ),
    )?;
    let mut restored = restored;
    step(
        steps,
        "boot recovery accepts it",
        restored.recover_at_boot(),
    )?;
    let active = &restored.appliance().active;
    step(
        steps,
        "the restored account is the one the payment left",
        if active.root == next_root && active.anchor_counter == 1 && active.status == Status::Ready
        {
            Ok(())
        } else {
            Err("the record restored another account")
        },
    )?;
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::pb;
    use crate::service::err;

    /// A production requirement a development board leaves unmet: the run still works, the answer marks
    /// the step as production's, and the verdict still refuses, as an install refuses on it.
    #[test]
    fn a_production_requirement_unmet_is_marked_and_still_refused() {
        let run = TryRun {
            steps: alloc::vec![
                TryStep::new("the anchor signs a payment", Ok(())),
                TryStep::production(
                    "the chip tests its PTRNG at start-up",
                    Err("it does not".to_string())
                ),
            ],
            release_bytes: 8,
        };
        assert_eq!(run.first_broken(), None);
        assert_eq!(
            run.first_failure().map(|step| step.name.as_str()),
            Some("the chip tests its PTRNG at start-up")
        );
        let answer = crate::service::try_run_response(
            pb::Op::TryRun as i32,
            &run,
            crate::enrollment::Install::ForGood,
        );
        assert!(!answer.ok);
        assert_eq!(answer.error, err::TRY_RUN_FAILED);
        let passed: Vec<&str> = answer
            .try_run
            .iter()
            .filter(|step| step.passed)
            .map(|step| step.name.as_str())
            .collect();
        let production: Vec<&str> = answer
            .try_run
            .iter()
            .filter(|step| step.production)
            .map(|step| step.name.as_str())
            .collect();
        assert_eq!(passed, ["the anchor signs a payment"]);
        assert_eq!(production, ["the chip tests its PTRNG at start-up"]);
        assert_eq!(answer.transport_check, transport_check(8));
    }

    /// A step the anchor needs that fails breaks the run, whatever production needs too.
    #[test]
    fn a_working_step_that_fails_breaks_the_run() {
        let run = TryRun {
            steps: alloc::vec![
                TryStep::production(
                    "the chip tests its PTRNG at start-up",
                    Err("no".to_string())
                ),
                TryStep::new("the chip's counter moves", Err("no answer".to_string())),
            ],
            release_bytes: 0,
        };
        assert_eq!(
            run.first_broken().map(|step| step.name.as_str()),
            Some("the chip's counter moves")
        );
    }
}
