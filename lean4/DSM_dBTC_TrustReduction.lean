/-
  DSM dBTC Trust Reduction Proofs — self-contained Lean 4 proofs (no Mathlib)

  This file does not attempt to prove Bitcoin consensus security from
  first principles. It formalizes the DSM-side reduction claim:

    if a dBTC withdrawal is final-burned on mainnet, then the burn was
    authorized by Bitcoin-side settlement evidence consisting of:
      - observed Bitcoin spend,
      - SPV inclusion,
      - PoW-valid block headers,
      - checkpoint-rooted header-chain validation,
      - same-chain / entry-anchor continuity,
      - confirmation depth >= dmin.

  This mirrors the implementation trust boundary in:
    - dsm/src/bitcoin/spv.rs
    - dsm/src/bitcoin/header_chain.rs
    - dBTC settlement routing / verification paths in the SDK

  Run: `lean DSM_dBTC_TrustReduction.lean` to verify all proofs.
-/

inductive Network where
  | mainnet
  | signet
  | testnet
  deriving DecidableEq, Repr

inductive WithdrawalStatus where
  | idle
  | committed
  | finalized
  | refunded
  deriving DecidableEq, Repr

structure SettlementEvidence where
  network      : Network
  confDepth    : Nat
  bitcoinSpend : Prop
  spvValid     : Prop
  powValid     : Prop
  checkpointed : Prop
  sameChain    : Prop

structure BridgeState where
  spendable   : Nat
  inflight    : Nat
  gridBacking : Nat
  settled     : Nat
  status      : WithdrawalStatus
  deriving Repr

def ConservationInvariant (s : BridgeState) : Prop :=
  s.spendable + s.inflight = s.gridBacking

def RustVerifierAccepted (e : SettlementEvidence) (dMin : Nat) : Prop :=
  e.bitcoinSpend ∧
  e.spvValid ∧
  e.powValid ∧
  e.checkpointed ∧
  e.sameChain ∧
  e.confDepth ≥ dMin

def MainnetFinalityAssumption (e : SettlementEvidence) (dMin : Nat) : Prop :=
  e.network = .mainnet ∧ RustVerifierAccepted e dMin

def WeakenedNetworkEvidence (e : SettlementEvidence) : Prop :=
  e.bitcoinSpend ∧ e.spvValid ∧ e.confDepth ≥ 1

def CanApplyFinalBurn (s : BridgeState) (e : SettlementEvidence) (dMin : Nat) : Prop :=
  s.status = .committed ∧
  s.inflight > 0 ∧
  MainnetFinalityAssumption e dMin

def ApplyFinalBurn (s : BridgeState) : BridgeState :=
  { s with
    inflight := 0
    gridBacking := s.gridBacking - s.inflight
    settled := s.settled + 1
    status := .finalized }

theorem rustVerifierAccepted_implies_mainnet_finality
    (e : SettlementEvidence) (dMin : Nat)
    (hnet : e.network = .mainnet)
    (hverifier : RustVerifierAccepted e dMin) :
    MainnetFinalityAssumption e dMin := by
  exact ⟨hnet, hverifier⟩

theorem finalBurn_requires_mainnet_finality
    (s : BridgeState) (e : SettlementEvidence) (dMin : Nat)
    (hcan : CanApplyFinalBurn s e dMin) :
    MainnetFinalityAssumption e dMin := by
  exact hcan.2.2

theorem finalBurn_requires_mainnet_network
    (s : BridgeState) (e : SettlementEvidence) (dMin : Nat)
    (hcan : CanApplyFinalBurn s e dMin) :
    e.network = .mainnet := by
  exact (finalBurn_requires_mainnet_finality s e dMin hcan).1

theorem non_mainnet_cannot_authorize_final_burn
    (s : BridgeState) (e : SettlementEvidence) (dMin : Nat)
    (hnet : e.network ≠ .mainnet) :
    ¬ CanApplyFinalBurn s e dMin := by
  intro hcan
  exact hnet (finalBurn_requires_mainnet_network s e dMin hcan)

theorem applyFinalBurn_preserves_conservation
    (s : BridgeState) (e : SettlementEvidence) (dMin : Nat)
    (hcons : ConservationInvariant s)
    (hcan : CanApplyFinalBurn s e dMin) :
    ConservationInvariant (ApplyFinalBurn s) := by
  have hinf : s.inflight > 0 := hcan.2.1
  simp [ConservationInvariant, ApplyFinalBurn] at *
  omega

theorem applyFinalBurn_sets_finalized
    (s : BridgeState) :
    (ApplyFinalBurn s).status = .finalized := by
  simp [ApplyFinalBurn]

theorem finalized_state_carries_mainnet_assumption
    (s : BridgeState) (e : SettlementEvidence) (dMin : Nat)
    (hcan : CanApplyFinalBurn s e dMin) :
    (ApplyFinalBurn s).status = .finalized ∧ MainnetFinalityAssumption e dMin := by
  constructor
  · exact applyFinalBurn_sets_finalized s
  · exact finalBurn_requires_mainnet_finality s e dMin hcan

theorem weakened_evidence_counterexample :
    ∃ e : SettlementEvidence,
      WeakenedNetworkEvidence e ∧ ¬ MainnetFinalityAssumption e 100 := by
  refine ⟨{
    network := .signet,
    confDepth := 1,
    bitcoinSpend := True,
    spvValid := True,
    powValid := False,
    checkpointed := False,
    sameChain := False
  }, ?_⟩
  constructor
  · simp [WeakenedNetworkEvidence]
  · simp [MainnetFinalityAssumption, RustVerifierAccepted]

theorem weakened_evidence_does_not_reduce_to_mainnet
    (h : ∀ e : SettlementEvidence,
      WeakenedNetworkEvidence e → MainnetFinalityAssumption e 100) : False := by
  obtain ⟨e, hweak, hnot⟩ := weakened_evidence_counterexample
  exact hnot (h e hweak)

/-
  Summary

  The file proves four useful facts for the dBTC trust discussion:

    1. Rust-style settlement verification obligations reduce directly to the
       mainnet finality assumption.
    2. Any authorized final burn requires the mainnet assumption.
    3. Non-mainnet networks cannot justify the same final-burn theorem.
    4. Weakened evidence (e.g. signet-style confirmation + SPV only) is not
       sufficient to claim the mainnet trust boundary.

  This is a spec-level reduction theorem, not a formal proof of Bitcoin PoW.
-/
