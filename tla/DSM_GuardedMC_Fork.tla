---- MODULE DSM_GuardedMC_Fork ----
\* ===========================================================================
\* Model-check instance for DSM_Guarded — MALFORMED (key-split) guard family.
\*
\* NEGATIVE TEST proving the Safety property has teeth. Two fulfilled candidates
\* consume the SAME key "k1" but resolve to DIFFERENT successors ("s1" vs "s2"),
\* violating guard-family well-formedness (paper Rule 1, G5/G7). TLC is EXPECTED
\* to report a Safety (NoRealizedForkAtKey) violation. Mirrors the Lean theorem
\* `malformed_family_admits_fork`.
\*
\* The violation is reported at depth 0: Safety is the paper's STATIC Thm 2/4
\* reading over Step_K enabledness, and a key-split family already has two
\* conflicting enabled steps before anything is realized. Two companion checks
\* complete the picture:
\*   DSM_GuardedMC_Fork_Ledger.cfg   same malformed family, ledger invariant
\*                                   only: a SINGLE honest verifier still never
\*                                   realizes a local fork (paper Prop 11).
\*                                   Expected: No error.
\*   DSM_GuardedBilateral.tla        TWO verifiers, same malformed family: the
\*                                   genuine multi-step realized fork appears
\*                                   across receivers (paper Thm 14 tail).
\*
\* Run:
\*   java -cp tla2tools.jar tlc2.TLC -config DSM_GuardedMC_Fork.cfg DSM_GuardedMC_Fork.tla
\* Expected: "Invariant Safety is violated."
\* ===========================================================================
EXTENDS Naturals, FiniteSets

VARIABLES current, consumed, realized, pending, ledger

MCState == {"s0", "s1", "s2"}
MCKey   == {"k1", "k2"}
MCCandidate == {
    [parent |-> "s0", succ |-> "s1", key |-> "k1", bid |-> 1, guard |-> TRUE],
    [parent |-> "s0", succ |-> "s2", key |-> "k1", bid |-> 4, guard |-> TRUE]
}

INSTANCE DSM_Guarded
    WITH State <- MCState, Key <- MCKey, Candidate <- MCCandidate

=============================================================================
