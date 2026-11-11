// SPDX-License-Identifier: MIT OR Apache-2.0

//! Where a relationship stands on its own chain (DSM Amendment A33).
//!
//! A relationship's leaf enters a device's tree at `h_0` when the device adds
//! the contact; nothing has happened on it yet. Its first step is ESTABLISH, a
//! moneyless step the one side makes and the other countersigns: the
//! relationship is established on a device once that device holds the step.
//! Either side may end it with TERMINATE, a moneyless step the other side
//! acknowledges by countersigning. Value moves only on an established
//! relationship, and a termination is final: nothing follows it.
//!
//! Both steps are operations on the chain, validated as any step is (A14: a
//! receiver reads the step's own parent and nothing behind it). ESTABLISH is
//! the `CreateRelationship` operation, which recovery's re-establishment
//! already uses for the first state of a successor relationship; TERMINATE is
//! `RemoveRelationship`. The lifecycle folds over the steps a device applied,
//! in the order it applied them.

use crate::types::error::DsmError;
use crate::types::operations::{Operation, TransactionMode};

/// The marker of an ordinary establishment, in the operation's `message`.
pub const ESTABLISH_MESSAGE: &str = "establish";
/// The marker of a termination, in the operation's `message`.
pub const TERMINATE_MESSAGE: &str = "terminate";
/// The relationship type a termination names.
pub const RELATIONSHIP_TYPE: &[u8] = b"bilateral";

/// Where a relationship stands on this device's chain for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelationshipLifecycle {
    /// The leaf is at `h_0`, or holds steps of neither kind: no value moves yet.
    Opened,
    /// An ESTABLISH step is on the chain and no TERMINATE after it.
    Established,
    /// A TERMINATE step is on the chain: nothing follows it.
    Ended,
}

impl RelationshipLifecycle {
    /// Canonical wire value; `0` is invalid.
    pub fn to_wire(self) -> u8 {
        match self {
            RelationshipLifecycle::Opened => 1,
            RelationshipLifecycle::Established => 2,
            RelationshipLifecycle::Ended => 3,
        }
    }

    /// Decode from the wire, fail-closed: `0` and anything unknown is `None`,
    /// never read as a state.
    pub fn from_wire(v: u8) -> Option<Self> {
        match v {
            1 => Some(RelationshipLifecycle::Opened),
            2 => Some(RelationshipLifecycle::Established),
            3 => Some(RelationshipLifecycle::Ended),
            _ => None,
        }
    }

    /// Whether a value step may follow on this chain.
    pub fn admits_value(self) -> bool {
        matches!(self, RelationshipLifecycle::Established)
    }
}

/// A lifecycle step, read off its operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleStep {
    /// ESTABLISH: the counterparty it names, and the symmetric relationship
    /// tip it was made from (the operation's `commitment`).
    Establish {
        counterparty: [u8; 32],
        made_from: [u8; 32],
    },
    /// TERMINATE: the device ending the relationship and the one it ends it
    /// with.
    Terminate { from: [u8; 32], to: [u8; 32] },
}

/// The ESTABLISH operation for the relationship with `counterparty`, made
/// from the symmetric tip `made_from` (`h_0` for a first establishment). The
/// operation carries no signature field: the step's signature is SIG A over
/// its canonical bytes, as for any operation.
pub fn establish_operation(counterparty: &[u8; 32], made_from: &[u8; 32]) -> Operation {
    Operation::CreateRelationship {
        message: ESTABLISH_MESSAGE.to_string(),
        counterparty_id: counterparty.to_vec(),
        commitment: made_from.to_vec(),
        proof: Vec::new(),
        mode: TransactionMode::Bilateral,
    }
}

/// The TERMINATE operation by `from` on its relationship with `to`.
pub fn terminate_operation(from: &[u8; 32], to: &[u8; 32]) -> Operation {
    Operation::RemoveRelationship {
        from_id: *from,
        to_id: *to,
        relationship_type: RELATIONSHIP_TYPE.to_vec(),
        proof: Vec::new(),
        mode: TransactionMode::Bilateral,
        message: TERMINATE_MESSAGE.to_string(),
    }
}

/// What lifecycle step `op` is, if it is one. A recovery re-establishment
/// (`recovery::succession_binding`) is an ESTABLISH: it is the first state of
/// the successor relationship. A `CreateRelationship` with any other marker,
/// or a `RemoveRelationship` naming another type or marker, is no step at
/// all (`Ok(None)`), and the advance refuses it as such. An establishment
/// whose counterparty or commitment is not 32 bytes is malformed: an error,
/// never a step of another kind.
pub fn lifecycle_step_of(op: &Operation) -> Result<Option<LifecycleStep>, DsmError> {
    match op {
        Operation::CreateRelationship {
            message,
            counterparty_id,
            commitment,
            ..
        } if message == ESTABLISH_MESSAGE
            || message == crate::recovery::succession_binding::RECOVERY_ESTABLISH_MESSAGE =>
        {
            let counterparty = <[u8; 32]>::try_from(counterparty_id.as_slice()).map_err(|e| {
                DsmError::invalid_operation(format!(
                    "an establishment names a 32-byte counterparty, not {} bytes: {e}",
                    counterparty_id.len()
                ))
            })?;
            // A recovery re-establishment commits its carry-forward, not a
            // tip; the receiver's own guard reads it. Either way the field is
            // 32 bytes.
            let made_from = <[u8; 32]>::try_from(commitment.as_slice()).map_err(|e| {
                DsmError::invalid_operation(format!(
                    "an establishment commits 32 bytes, not {}: {e}",
                    commitment.len()
                ))
            })?;
            Ok(Some(LifecycleStep::Establish {
                counterparty,
                made_from,
            }))
        }
        Operation::RemoveRelationship {
            from_id,
            to_id,
            relationship_type,
            message,
            ..
        } if relationship_type == RELATIONSHIP_TYPE && message == TERMINATE_MESSAGE => {
            Ok(Some(LifecycleStep::Terminate {
                from: *from_id,
                to: *to_id,
            }))
        }
        _ => Ok(None),
    }
}

/// The lifecycle after `op` is applied on the relationship between `this`
/// device and `counterparty`, which stands at `current`; or why `op` may not
/// be applied there.
///
/// - A device's own relationship (its self-loop) is established from its
///   creation and takes no lifecycle step.
/// - ESTABLISH takes an opened relationship to established; it must name one
///   of the relationship's two devices (the maker names the other; the other
///   applies a step naming itself).
/// - TERMINATE takes an opened or established relationship to ended; it must
///   name the two devices. Ended is final: a termination that reaches an
///   ended relationship (the other side's, crossing this device's own) is
///   recorded and changes nothing.
/// - Any other step needs an established relationship.
pub fn next_lifecycle(
    current: RelationshipLifecycle,
    op: &Operation,
    this: &[u8; 32],
    counterparty: &[u8; 32],
) -> Result<RelationshipLifecycle, DsmError> {
    use RelationshipLifecycle::*;
    let step = lifecycle_step_of(op)?;
    if this == counterparty {
        return match step {
            Some(_) => Err(DsmError::invalid_operation(
                "a device's own relationship takes no establishment or termination",
            )),
            None => Ok(Established),
        };
    }
    match step {
        Some(LifecycleStep::Establish {
            counterparty: named,
            ..
        }) => {
            // The maker names the device it establishes with; applied on
            // that device, the step names the device itself.
            if named != *counterparty && named != *this {
                return Err(DsmError::invalid_operation(
                    "the establishment names another device than the relationship's",
                ));
            }
            match current {
                Opened => Ok(Established),
                Established => Err(DsmError::invalid_operation(
                    "the relationship is already established (Amendment A33)",
                )),
                Ended => Err(DsmError::invalid_operation(
                    "the relationship has ended; a termination is final (Amendment A33)",
                )),
            }
        }
        Some(LifecycleStep::Terminate { from, to }) => {
            let names_pair =
                (from == *this && to == *counterparty) || (from == *counterparty && to == *this);
            if !names_pair {
                return Err(DsmError::invalid_operation(
                    "the termination names other devices than the relationship's",
                ));
            }
            match current {
                Opened | Established | Ended => Ok(Ended),
            }
        }
        None => match current {
            Established => Ok(Established),
            Opened => Err(DsmError::invalid_operation(
                "the relationship is not established: its first step is the establishment both \
                 sides sign (Amendment A33)",
            )),
            Ended => Err(DsmError::invalid_operation(
                "the relationship has ended: nothing follows a termination (Amendment A33)",
            )),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::token_types::Balance;

    const A: [u8; 32] = [0xA1; 32];
    const B: [u8; 32] = [0xB2; 32];
    const C: [u8; 32] = [0xC3; 32];
    const TIP: [u8; 32] = [0x44; 32];

    fn transfer_to(to: &[u8; 32]) -> Operation {
        Operation::Transfer {
            to_device_id: to.to_vec(),
            to_genesis: [0x11; 32],
            amount: Balance::amount(5),
            policy_commit: [0x22; 32],
            terms_commitment: [0x33; 32],
            token_policy: Vec::new(),
            signature: Vec::new(),
            authority_policy: None,
        }
    }

    fn step_of(op: &Operation) -> Option<LifecycleStep> {
        lifecycle_step_of(op).expect("a well-formed operation")
    }

    fn refused(
        current: RelationshipLifecycle,
        op: &Operation,
        this: &[u8; 32],
        cp: &[u8; 32],
    ) -> String {
        next_lifecycle(current, op, this, cp)
            .expect_err("the step is refused")
            .to_string()
    }

    #[test]
    fn the_operations_read_back_as_their_steps() {
        let e = establish_operation(&B, &TIP);
        assert_eq!(
            step_of(&e),
            Some(LifecycleStep::Establish {
                counterparty: B,
                made_from: TIP
            })
        );
        let t = terminate_operation(&A, &B);
        assert_eq!(
            step_of(&t),
            Some(LifecycleStep::Terminate { from: A, to: B })
        );
        assert_eq!(step_of(&transfer_to(&B)), None);
        // The bytes round-trip: the receiver decodes exactly these steps.
        for op in [e, t] {
            let decoded = Operation::from_bytes(&op.to_bytes()).expect("decodes");
            assert_eq!(step_of(&decoded), step_of(&op));
        }
    }

    #[test]
    fn an_establishment_naming_a_short_counterparty_is_malformed() {
        let short = Operation::CreateRelationship {
            message: ESTABLISH_MESSAGE.to_string(),
            counterparty_id: vec![0xB2; 31],
            commitment: TIP.to_vec(),
            proof: Vec::new(),
            mode: TransactionMode::Bilateral,
        };
        let err = lifecycle_step_of(&short).expect_err("31 bytes is not a counterparty");
        assert!(err.to_string().contains("32-byte counterparty"), "{err}");
    }

    #[test]
    fn a_relationship_is_opened_then_established_then_ended() {
        use RelationshipLifecycle::*;
        let establish = establish_operation(&B, &TIP);
        let terminate = terminate_operation(&B, &A);
        let pay = transfer_to(&B);
        // Nothing but the establishment moves on an opened relationship; a
        // termination ends one that never was established.
        assert!(refused(Opened, &pay, &A, &B).contains("not established"));
        assert_eq!(
            next_lifecycle(Opened, &terminate, &A, &B).expect("ends"),
            Ended
        );
        assert_eq!(
            next_lifecycle(Opened, &establish, &A, &B).expect("establishes"),
            Established
        );
        // Value moves on an established one; a second establishment is no step.
        assert_eq!(
            next_lifecycle(Established, &pay, &A, &B).expect("pays"),
            Established
        );
        assert!(refused(Established, &establish, &A, &B).contains("already established"));
        assert_eq!(
            next_lifecycle(Established, &terminate, &A, &B).expect("ends"),
            Ended
        );
        // Ended is final.
        assert!(refused(Ended, &pay, &A, &B).contains("ended"));
        assert!(refused(Ended, &establish, &A, &B).contains("final"));
        // The other side's termination, crossing this one, is recorded.
        assert_eq!(
            next_lifecycle(Ended, &terminate, &A, &B).expect("recorded"),
            Ended
        );
    }

    #[test]
    fn a_step_naming_other_devices_is_refused() {
        use RelationshipLifecycle::*;
        assert!(refused(Opened, &establish_operation(&C, &TIP), &A, &B).contains("another device"));
        // The other side applies the maker's step, which names itself.
        assert_eq!(
            next_lifecycle(Opened, &establish_operation(&A, &TIP), &A, &B).expect("applied"),
            Established
        );
        assert!(
            refused(Established, &terminate_operation(&A, &C), &A, &B).contains("other devices")
        );
        assert!(
            refused(Established, &terminate_operation(&C, &B), &A, &B).contains("other devices")
        );
    }

    #[test]
    fn the_self_loop_takes_no_lifecycle_step_and_admits_every_other() {
        use RelationshipLifecycle::*;
        assert!(refused(Established, &establish_operation(&A, &TIP), &A, &A)
            .contains("own relationship"));
        assert!(
            refused(Established, &terminate_operation(&A, &A), &A, &A).contains("own relationship")
        );
        assert_eq!(
            next_lifecycle(Established, &Operation::Noop, &A, &A).expect("its own step"),
            Established
        );
    }

    #[test]
    fn the_wire_value_is_fail_closed() {
        for l in [
            RelationshipLifecycle::Opened,
            RelationshipLifecycle::Established,
            RelationshipLifecycle::Ended,
        ] {
            assert_eq!(RelationshipLifecycle::from_wire(l.to_wire()), Some(l));
        }
        assert_eq!(RelationshipLifecycle::from_wire(0), None);
        assert_eq!(RelationshipLifecycle::from_wire(4), None);
    }
}
