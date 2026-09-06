// SPDX-License-Identifier: Apache-2.0

//! THE INITIATING-TRADER PARENT FENCE (Rev 15 Req 6.23, §22 #14, Theorem 18.2).
//!
//! Before Class K issues the first mutating binding operation for a bundle `B`,
//! it durably records a local settlement fence
//!
//! ```text
//! F_B = (trader_chain_id, trader_parent_state_commitment, b, tx_id)
//! ```
//!
//! over the initiating trader's own sovereign chain. The fence is an
//! advancement invariant, NOT a storage-node authority object: while the DLV
//! transaction is unresolved, no *different* successor may advance from the
//! fenced trader parent, even under a fresh intent or nonce. Tripwire remains
//! the underlying one-successor state rule; the fence prevents a conforming
//! client from *accidentally* advancing the parent while the quorum result is
//! in doubt.
//!
//! This module is the PURE state machine of the fence: the legal transitions
//! and the verdict a caller consults before creating a trader successor. The
//! durable row and the restart-recovery list live in the SDK
//! (`storage::client_db::trader_parent_fence`); the live advancement gate is
//! wired where the settle path is rewritten to QuorumBind. No I/O, no clock.
//!
//! The load-bearing rule is transition (4) of Req 6.23: `COMMITTED(B)` fixes
//! the permitted continuation to the EXACT `trader_successor` committed inside
//! `B`, and the quorum result alone does not consume the fence — Class K
//! releases it only when that exact successor is accepted through ordinary DSM
//! bilateral advancement. A different successor can never consume the fence.

/// Where the fenced trader parent sits relative to its DLV transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceState {
    /// The fence is placed and the DLV transaction is unresolved — pending,
    /// `RECOVERING`, or `INDETERMINATE`. No successor may advance from the
    /// parent (Req 6.23 (2)).
    Fenced,
    /// `COMMITTED(B)`: the ONLY permitted continuation is this exact committed
    /// trader successor. The quorum result has not consumed the fence
    /// (Req 6.23 (4)).
    CommittedAwaitingAcceptance { permitted_successor: [u8; 32] },
    /// The exact permitted successor was accepted through ordinary DSM
    /// bilateral advancement. The fence is consumed. Terminal.
    Released,
    /// `ABORTED(B)` or `CONFLICT_FINAL`: the fence is released WITHOUT advancing
    /// the trader chain (Req 6.23 (3)). Terminal.
    ReleasedNoAdvance,
}

impl FenceState {
    pub fn as_str(self) -> &'static str {
        match self {
            FenceState::Fenced => "fenced",
            FenceState::CommittedAwaitingAcceptance { .. } => "committed_awaiting_acceptance",
            FenceState::Released => "released",
            FenceState::ReleasedNoAdvance => "released_no_advance",
        }
    }

    /// A fence in a terminal state imposes no further advancement constraint;
    /// ordinary DSM rules (Tripwire) govern from here.
    pub fn is_terminal(self) -> bool {
        matches!(self, FenceState::Released | FenceState::ReleasedNoAdvance)
    }

    /// Unresolved fences are the restart-recovery work list (Req 16.5): they
    /// must be restored before the recovered trader chain may advance.
    pub fn is_unresolved(self) -> bool {
        matches!(
            self,
            FenceState::Fenced | FenceState::CommittedAwaitingAcceptance { .. }
        )
    }
}

/// What just happened to the DLV transaction (or its trader successor).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FenceEvent {
    /// A recovery round is in progress; the outcome is still open.
    Recovering,
    /// A mutating request's outcome was lost. Never a non-commit: the parent
    /// stays fenced (Req 16.4).
    Indeterminate,
    /// `COMMITTED(B)` for the exact bundle, carrying the trader successor `B`
    /// committed.
    Committed { successor: [u8; 32] },
    /// `ABORTED(B)`.
    Aborted,
    /// `CONFLICT_FINAL`: an overlapping key belongs to a different binding-final
    /// transaction.
    ConflictFinal,
    /// The exact committed trader successor was accepted through ordinary DSM
    /// bilateral state advancement — the only thing that consumes a committed
    /// fence.
    SuccessorAccepted { successor: [u8; 32] },
}

/// Why a transition is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceTransitionError {
    /// The fence is already terminal; nothing regresses it.
    Terminal { state: &'static str },
    /// A `SuccessorAccepted` for a value other than the one `COMMITTED` fixed.
    /// This is the rule that stops a different successor from consuming the
    /// fence (Req 6.23 (4)).
    WrongSuccessor {
        permitted: [u8; 32],
        offered: [u8; 32],
    },
    /// A `SuccessorAccepted` arrived before any `COMMITTED` fixed a successor.
    AcceptanceBeforeCommit,
}

impl core::fmt::Display for FenceTransitionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FenceTransitionError::Terminal { state } => {
                write!(f, "the fence is terminal ({state}) and does not transition")
            }
            FenceTransitionError::WrongSuccessor { .. } => write!(
                f,
                "only the exact committed successor may consume the fence"
            ),
            FenceTransitionError::AcceptanceBeforeCommit => {
                write!(f, "no successor is permitted until the bundle is COMMITTED")
            }
        }
    }
}
impl std::error::Error for FenceTransitionError {}

/// The legal transition function. A placed fence starts in [`FenceState::Fenced`].
///
/// - `Recovering` / `Indeterminate` keep it `Fenced` — an unresolved outcome
///   never releases the parent, and elapsed time never converts it (Req 15.11,
///   §22 #17).
/// - `Committed{successor}` fixes the permitted continuation.
/// - `Aborted` / `ConflictFinal` release without advancing.
/// - `SuccessorAccepted{s}` consumes the fence ONLY when `s` is exactly the
///   committed successor.
pub fn next_state(
    state: &FenceState,
    event: &FenceEvent,
) -> Result<FenceState, FenceTransitionError> {
    if state.is_terminal() {
        return Err(FenceTransitionError::Terminal {
            state: state.as_str(),
        });
    }
    Ok(match (state, event) {
        // Unresolved outcomes keep the parent fenced.
        (_, FenceEvent::Recovering) | (_, FenceEvent::Indeterminate) => FenceState::Fenced,
        // Terminal DLV outcomes.
        (_, FenceEvent::Committed { successor }) => FenceState::CommittedAwaitingAcceptance {
            permitted_successor: *successor,
        },
        (_, FenceEvent::Aborted) | (_, FenceEvent::ConflictFinal) => FenceState::ReleasedNoAdvance,
        // Only the exact committed successor consumes a committed fence.
        (
            FenceState::CommittedAwaitingAcceptance {
                permitted_successor,
            },
            FenceEvent::SuccessorAccepted { successor },
        ) => {
            if successor == permitted_successor {
                FenceState::Released
            } else {
                return Err(FenceTransitionError::WrongSuccessor {
                    permitted: *permitted_successor,
                    offered: *successor,
                });
            }
        }
        // A successor acceptance before COMMITTED fixed one is illegal.
        (FenceState::Fenced, FenceEvent::SuccessorAccepted { .. }) => {
            return Err(FenceTransitionError::AcceptanceBeforeCommit)
        }
        (FenceState::Released | FenceState::ReleasedNoAdvance, _) => {
            unreachable!("terminal handled")
        }
    })
}

/// What the fence permits when a caller wants to create a trader successor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceVerdict {
    /// No successor may advance from the parent (Req 6.23 (2)).
    BlocksAllSuccessors,
    /// Exactly this successor may advance, and no other (Req 6.23 (4)).
    PermitsOnly([u8; 32]),
    /// The fence imposes no constraint; ordinary DSM rules govern.
    Clear,
}

/// The verdict for an active fence. A caller creating a trader successor from a
/// fenced parent must obey this BEFORE advancing.
pub fn verdict(state: &FenceState) -> FenceVerdict {
    match state {
        FenceState::Fenced => FenceVerdict::BlocksAllSuccessors,
        FenceState::CommittedAwaitingAcceptance {
            permitted_successor,
        } => FenceVerdict::PermitsOnly(*permitted_successor),
        FenceState::Released | FenceState::ReleasedNoAdvance => FenceVerdict::Clear,
    }
}

/// Whether the fence permits advancing to `candidate` from the fenced parent.
/// A fresh intent or nonce cannot change this answer — the fence is keyed on the
/// parent, not the intent.
pub fn permits_successor(state: &FenceState, candidate: &[u8; 32]) -> bool {
    match verdict(state) {
        FenceVerdict::BlocksAllSuccessors => false,
        FenceVerdict::PermitsOnly(s) => &s == candidate,
        FenceVerdict::Clear => true,
    }
}

#[cfg(test)]
#[allow(clippy::disallowed_methods)] // test asserts; a failure here is the signal
mod tests {
    use super::*;

    const SUCC: [u8; 32] = [0xAA; 32];
    const OTHER: [u8; 32] = [0xBB; 32];

    #[test]
    fn an_unresolved_outcome_keeps_the_parent_fenced() {
        for ev in [FenceEvent::Recovering, FenceEvent::Indeterminate] {
            let s = next_state(&FenceState::Fenced, &ev).unwrap();
            assert_eq!(s, FenceState::Fenced);
            assert_eq!(verdict(&s), FenceVerdict::BlocksAllSuccessors);
            assert!(
                !permits_successor(&s, &SUCC),
                "unresolved blocks all successors"
            );
        }
    }

    #[test]
    fn commit_permits_exactly_the_committed_successor_and_no_other() {
        let s = next_state(
            &FenceState::Fenced,
            &FenceEvent::Committed { successor: SUCC },
        )
        .unwrap();
        assert_eq!(verdict(&s), FenceVerdict::PermitsOnly(SUCC));
        assert!(permits_successor(&s, &SUCC));
        assert!(
            !permits_successor(&s, &OTHER),
            "a different successor is not permitted by a committed fence"
        );
    }

    #[test]
    fn only_the_exact_successor_consumes_the_fence() {
        let committed = next_state(
            &FenceState::Fenced,
            &FenceEvent::Committed { successor: SUCC },
        )
        .unwrap();
        // A DIFFERENT successor cannot consume it.
        assert_eq!(
            next_state(
                &committed,
                &FenceEvent::SuccessorAccepted { successor: OTHER }
            ),
            Err(FenceTransitionError::WrongSuccessor {
                permitted: SUCC,
                offered: OTHER
            })
        );
        // The exact one does, and releases.
        let released = next_state(
            &committed,
            &FenceEvent::SuccessorAccepted { successor: SUCC },
        )
        .unwrap();
        assert_eq!(released, FenceState::Released);
        assert_eq!(verdict(&released), FenceVerdict::Clear);
    }

    #[test]
    fn abort_and_conflict_release_without_advancing() {
        for ev in [FenceEvent::Aborted, FenceEvent::ConflictFinal] {
            let s = next_state(&FenceState::Fenced, &ev).unwrap();
            assert_eq!(s, FenceState::ReleasedNoAdvance);
            assert_eq!(verdict(&s), FenceVerdict::Clear);
        }
    }

    #[test]
    fn acceptance_before_commit_is_illegal() {
        assert_eq!(
            next_state(
                &FenceState::Fenced,
                &FenceEvent::SuccessorAccepted { successor: SUCC }
            ),
            Err(FenceTransitionError::AcceptanceBeforeCommit)
        );
    }

    #[test]
    fn terminal_states_do_not_regress() {
        for terminal in [FenceState::Released, FenceState::ReleasedNoAdvance] {
            for ev in [
                FenceEvent::Recovering,
                FenceEvent::Committed { successor: OTHER },
                FenceEvent::Aborted,
                FenceEvent::SuccessorAccepted { successor: OTHER },
            ] {
                assert!(
                    matches!(
                        next_state(&terminal, &ev),
                        Err(FenceTransitionError::Terminal { .. })
                    ),
                    "terminal fence must not transition"
                );
            }
        }
    }

    #[test]
    fn unresolved_states_are_the_recovery_work_list() {
        assert!(FenceState::Fenced.is_unresolved());
        assert!(FenceState::CommittedAwaitingAcceptance {
            permitted_successor: SUCC
        }
        .is_unresolved());
        assert!(!FenceState::Released.is_unresolved());
        assert!(!FenceState::ReleasedNoAdvance.is_unresolved());
    }
}
