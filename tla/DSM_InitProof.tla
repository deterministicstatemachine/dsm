---- MODULE DSM_InitProof ----
(**************************************************************************
  DSM_InitProof: machine-checkable proof that the concrete DSM Init state
  maps correctly to DSM_ProtocolCore!Init.

  This module exists because DSM.tla uses RECURSIVE operator definitions
  (required for TLC model checking) which TLAPS cannot parse. We import
  only the Init-relevant definitions and prove the init refinement here.

  The remaining proof surface (step refinement, invariant preservation)
  requires FiniteSetTheorems.tla which depends on Functions.tla — not yet
  available in the opam TLAPS stdlib. Those proofs are TLC-verified on all
  bounded configs and will be machine-checked when the stdlib is complete.
**************************************************************************)
EXTENDS Naturals, FiniteSets, TLAPS

CONSTANTS
  DeviceIds,
  GenesisIds,
  MaxDevices,
  MaxPayload,
  VaultIds,
  MaxVaults,
  ShardDepth,
  MaxEmissions,
  EmissionAmount,
  MaxSupply,
  MaxNet,
  MaxDupPerMsg,
  MaxStep,
  UseHarness

VARIABLES
  devices, relationships, net, nextMsgId, storageNodes, keys,
  vaults, vaultState, activatedDevices, actCount, emissionIndex,
  shardTree, djteSeed, shardLists, spentJaps, spentProofs,
  consumedProofs, sourceRemaining, phase, step, offlineSessions, ledger

\* Only the definitions needed for Init — no RECURSIVE operators.
NumShards == 2^ShardDepth

Init ==
  /\ devices = [g \in GenesisIds |-> {}]
  /\ relationships = [p \in DeviceIds \X DeviceIds |-> [tip |-> 0, state |-> "inactive"]]
  /\ net = {}
  /\ nextMsgId = 1
  /\ storageNodes = {}
  /\ keys = [d \in DeviceIds |-> [sphincs |-> 0, kyber |-> 0]]
  /\ vaults = [d \in DeviceIds |-> {}]
  /\ vaultState = [v \in VaultIds |-> [owner |-> CHOOSE d \in DeviceIds : TRUE, balance |-> 0, locked |-> FALSE, condition |-> 0]]
  /\ activatedDevices = {}
  /\ actCount = [d \in DeviceIds |-> 0]
  /\ emissionIndex = 0
  /\ shardTree = 0
  /\ djteSeed = 0
  /\ shardLists = [s \in 0..(NumShards - 1) |-> <<>>]
  /\ spentJaps = {}
  /\ spentProofs = {}
  /\ consumedProofs = {}
  /\ sourceRemaining = MaxSupply
  /\ phase = 0
  /\ step = 0
  /\ offlineSessions = {}
  /\ ledger = {}

\* Refinement mapping (mirrors DSM.tla exactly)
Core_actCount == shardTree - emissionIndex
Core_spent == spentJaps
Core_commit == shardTree
Core_supply == sourceRemaining
Core_spentProofs == { p.jap : p \in spentProofs }
Core_consumedProofs == { p.jap : p \in consumedProofs }
Core_step == step

Core == INSTANCE DSM_ProtocolCore
  WITH DeviceIds <- DeviceIds,
       MaxSupply <- MaxSupply,
       MaxStep <- MaxStep,
       actCount <- Core_actCount,
       spentJaps <- Core_spent,
       spentProofs <- Core_spentProofs,
       consumedProofs <- Core_consumedProofs,
       sourceRemaining <- Core_supply,
       commit <- Core_commit,
       step <- Core_step

THEOREM ConcreteInitRefinesCore == Init => Core!Init
  BY DEF Init, Core!Init, Core_actCount, Core_spent, Core_commit, Core_supply,
         Core_spentProofs, Core_consumedProofs, Core_step, NumShards

====
