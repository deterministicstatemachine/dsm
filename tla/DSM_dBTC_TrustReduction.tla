---- MODULE DSM_dBTC_TrustReduction ----
EXTENDS Naturals, TLC, TLAPS

(***************************************************************************
  DSM_dBTC_TrustReduction: focused trust-boundary model for dBTC
  ==============================================================

  This module does not attempt to prove Bitcoin consensus security from
  first principles. Instead it makes the dBTC trust boundary explicit and
  machine-checkable at the DSM layer:

  - final burn is allowed only after a committed withdrawal obtains
    Bitcoin-side settlement evidence;
  - on mainnet, that evidence is the conjunction of:
      * Bitcoin spend observed,
      * SPV inclusion,
      * block-header PoW validity,
      * checkpoint-rooted header-chain validation,
      * same-chain / entry-anchor continuity,
      * confirmation depth >= d_min;
  - on weakened networks (signet / testnet style development paths),
    the same strong theorem is intentionally unavailable.

  This model is deliberately tiny and single-withdrawal scoped. It exists to
  state the minimum external trust assumption honestly, not to replace the
  concrete dBTC lifecycle model in DSM_dBTC_Concrete.tla.

  Correspondence to implementation predicates:
    - spvValid      ~ dsm/src/bitcoin/spv.rs
    - powValid      ~ dsm/src/bitcoin/spv.rs (header work)
    - checkpointed  ~ dsm/src/bitcoin/header_chain.rs
    - sameChain     ~ dsm/src/bitcoin/header_chain.rs (entry anchor continuity)
    - confDepth     ~ dBTC settlement threshold dmin(P)
***************************************************************************)

CONSTANTS
  MainnetMode,
  MaxSupply,
  DMin,
  MaxStep

ASSUME TrustConstants ==
  /\ MainnetMode \in BOOLEAN
  /\ MaxSupply \in Nat
  /\ MaxSupply >= 1
  /\ DMin \in Nat
  /\ DMin >= 1
  /\ MaxStep \in Nat

VARIABLES
  spendable,
  inflight,
  gridBacking,
  withdrawalStatus,
  confDepth,
  bitcoinSpend,
  spvValid,
  powValid,
  checkpointed,
  sameChain,
  settled,
  step

vars == <<spendable, inflight, gridBacking, withdrawalStatus, confDepth,
          bitcoinSpend, spvValid, powValid, checkpointed, sameChain,
          settled, step>>

TypeInv ==
  /\ spendable \in Nat
  /\ inflight \in Nat
  /\ gridBacking \in Nat
  /\ withdrawalStatus \in {"Idle", "Committed", "Finalized", "Refunded"}
  /\ confDepth \in Nat
  /\ bitcoinSpend \in BOOLEAN
  /\ spvValid \in BOOLEAN
  /\ powValid \in BOOLEAN
  /\ checkpointed \in BOOLEAN
  /\ sameChain \in BOOLEAN
  /\ settled \in Nat
  /\ step \in Nat

ConservationInvariant == spendable + inflight = gridBacking

BoundedSupply == spendable + inflight <= MaxSupply

MainnetFinalityAssumption ==
  /\ MainnetMode
  /\ bitcoinSpend
  /\ spvValid
  /\ powValid
  /\ checkpointed
  /\ sameChain
  /\ confDepth >= DMin

WeakenedNetworkEvidence ==
  /\ bitcoinSpend
  /\ spvValid
  /\ confDepth >= 1

BurnAuthorized ==
  /\ withdrawalStatus = "Committed"
  /\ inflight > 0
  /\ MainnetFinalityAssumption

FinalizedImpliesMainnetAssumptions ==
  withdrawalStatus = "Finalized" => MainnetFinalityAssumption

WeakenedNetworkNeverFinalizes ==
  ~MainnetMode => withdrawalStatus # "Finalized"

SettledCountTracksFinalization ==
  (withdrawalStatus = "Finalized") => settled = 1

Init ==
  /\ spendable = 1
  /\ inflight = 0
  /\ gridBacking = 1
  /\ withdrawalStatus = "Idle"
  /\ confDepth = 0
  /\ bitcoinSpend = FALSE
  /\ spvValid = FALSE
  /\ powValid = FALSE
  /\ checkpointed = FALSE
  /\ sameChain = FALSE
  /\ settled = 0
  /\ step = 0

Commit ==
  /\ withdrawalStatus = "Idle"
  /\ spendable >= 1
  /\ spendable' = spendable - 1
  /\ inflight' = inflight + 1
  /\ gridBacking' = gridBacking
  /\ withdrawalStatus' = "Committed"
  /\ UNCHANGED <<confDepth, bitcoinSpend, spvValid, powValid, checkpointed,
                 sameChain, settled>>
  /\ step' = step + 1

ObserveBitcoinSpend ==
  /\ withdrawalStatus = "Committed"
  /\ ~bitcoinSpend
  /\ bitcoinSpend' = TRUE
  /\ UNCHANGED <<spendable, inflight, gridBacking, withdrawalStatus, confDepth,
                 spvValid, powValid, checkpointed, sameChain, settled>>
  /\ step' = step + 1

ObserveSpv ==
  /\ withdrawalStatus = "Committed"
  /\ ~spvValid
  /\ spvValid' = TRUE
  /\ UNCHANGED <<spendable, inflight, gridBacking, withdrawalStatus, confDepth,
                 bitcoinSpend, powValid, checkpointed, sameChain, settled>>
  /\ step' = step + 1

ObservePow ==
  /\ withdrawalStatus = "Committed"
  /\ ~powValid
  /\ powValid' = TRUE
  /\ UNCHANGED <<spendable, inflight, gridBacking, withdrawalStatus, confDepth,
                 bitcoinSpend, spvValid, checkpointed, sameChain, settled>>
  /\ step' = step + 1

ObserveCheckpoint ==
  /\ withdrawalStatus = "Committed"
  /\ ~checkpointed
  /\ checkpointed' = TRUE
  /\ UNCHANGED <<spendable, inflight, gridBacking, withdrawalStatus, confDepth,
                 bitcoinSpend, spvValid, powValid, sameChain, settled>>
  /\ step' = step + 1

ObserveSameChain ==
  /\ withdrawalStatus = "Committed"
  /\ ~sameChain
  /\ sameChain' = TRUE
  /\ UNCHANGED <<spendable, inflight, gridBacking, withdrawalStatus, confDepth,
                 bitcoinSpend, spvValid, powValid, checkpointed, settled>>
  /\ step' = step + 1

AdvanceConfirmations ==
  /\ withdrawalStatus = "Committed"
  /\ confDepth' = confDepth + 1
  /\ UNCHANGED <<spendable, inflight, gridBacking, withdrawalStatus,
                 bitcoinSpend, spvValid, powValid, checkpointed, sameChain,
                 settled>>
  /\ step' = step + 1

FinalBurn ==
  /\ BurnAuthorized
  /\ spendable' = spendable
  /\ inflight' = 0
  /\ gridBacking' = gridBacking - inflight
  /\ withdrawalStatus' = "Finalized"
  /\ UNCHANGED <<confDepth, bitcoinSpend, spvValid, powValid, checkpointed,
                 sameChain>>
  /\ settled' = settled + 1
  /\ step' = step + 1

Refund ==
  /\ withdrawalStatus = "Committed"
  /\ ~BurnAuthorized
  /\ spendable' = spendable + inflight
  /\ inflight' = 0
  /\ gridBacking' = gridBacking
  /\ withdrawalStatus' = "Refunded"
  /\ UNCHANGED <<confDepth, bitcoinSpend, spvValid, powValid, checkpointed,
                 sameChain, settled>>
  /\ step' = step + 1

NoOp ==
  /\ UNCHANGED <<spendable, inflight, gridBacking, withdrawalStatus, confDepth,
                 bitcoinSpend, spvValid, powValid, checkpointed, sameChain,
                 settled>>
  /\ step' = step + 1

Next ==
  \/ Commit
  \/ ObserveBitcoinSpend
  \/ ObserveSpv
  \/ ObservePow
  \/ ObserveCheckpoint
  \/ ObserveSameChain
  \/ AdvanceConfirmations
  \/ FinalBurn
  \/ Refund
  \/ NoOp

Fairness ==
  /\ WF_vars(FinalBurn)
  /\ WF_vars(Refund)

Spec == Init /\ [][Next]_vars /\ Fairness

StepBound == step \in 0..MaxStep

CommittedResolvesByRefundOnWeakenedNetworks ==
  ~MainnetMode =>
    [](withdrawalStatus = "Committed" => <>(withdrawalStatus = "Refunded"))

FinalBurnActionRequiresMainnet == FinalBurn => MainnetFinalityAssumption

AlwaysFinalBurnRequiresMainnet == [][FinalBurnActionRequiresMainnet]_vars

THEOREM FinalBurnRequiresMainnetTheorem ==
  ASSUME FinalBurn
  PROVE MainnetFinalityAssumption
  BY DEF FinalBurn, BurnAuthorized, MainnetFinalityAssumption

THEOREM FinalizedImpliesMainnetTheorem ==
  ASSUME TypeInv, FinalizedImpliesMainnetAssumptions, [Next]_vars
  PROVE FinalizedImpliesMainnetAssumptions'
<1>1. CASE FinalBurn
  BY <1>1, FinalBurnRequiresMainnetTheorem DEF FinalizedImpliesMainnetAssumptions
<1>2. CASE Commit
  BY <1>2 DEF Commit, FinalizedImpliesMainnetAssumptions
<1>3. CASE ObserveBitcoinSpend
  BY <1>3 DEF ObserveBitcoinSpend, FinalizedImpliesMainnetAssumptions
<1>4. CASE ObserveSpv
  BY <1>4 DEF ObserveSpv, FinalizedImpliesMainnetAssumptions
<1>5. CASE ObservePow
  BY <1>5 DEF ObservePow, FinalizedImpliesMainnetAssumptions
<1>6. CASE ObserveCheckpoint
  BY <1>6 DEF ObserveCheckpoint, FinalizedImpliesMainnetAssumptions
<1>7. CASE ObserveSameChain
  BY <1>7 DEF ObserveSameChain, FinalizedImpliesMainnetAssumptions
<1>8. CASE AdvanceConfirmations
  BY <1>8 DEF AdvanceConfirmations, FinalizedImpliesMainnetAssumptions
<1>9. CASE Refund
  BY <1>9 DEF Refund, FinalizedImpliesMainnetAssumptions
<1>10. CASE NoOp
  BY <1>10 DEF NoOp, FinalizedImpliesMainnetAssumptions
<1>11. CASE UNCHANGED vars
  BY <1>11 DEF vars, FinalizedImpliesMainnetAssumptions
<1> QED
  BY <1>1, <1>2, <1>3, <1>4, <1>5, <1>6, <1>7, <1>8, <1>9, <1>10, <1>11 DEF Next

====