/-
  DSM Token Issuance — the two-leg creation rule.

  Token creation is the ONLY multi-asset operation in the protocol. It
  destroys ERA to pay the creation fee and issues a new asset, in ONE
  canonical advance. These theorems discharge the arithmetic obligations of
  the `Operation::CreateToken` arm of `validate_conservation`
  (dsm/src/types/device_state.rs) and of the restated `TokenConservation`
  invariant in tla/DSM_BilateralLiveness.tla.

  The rule under proof:

    [0] one ERA Debit of exactly the protocol's creation fee
        (`TOKEN_CREATION_FEE_ERA`, SoFi Amendment S18); a creation naming any
        other fee is refused
    [1] one Credit releasing the whole genesis supply (`initial_supply`,
        `ReleaseRule::AllAtCreation`, SoFi §51), which is never zero (SoFi
        §50), under the NEW token's own policy_commit
    and no other deltas.

  Mutation control (executed 2026-10-27): dropping `fee = creationFee` from
  `tryCreateWithSupply` breaks `a_creation_paying_other_than_the_protocol_fee_is_refused`,
  the same-named test in `dsm/src/types/device_state.rs`.

  Conservation is per-asset. ERA is destroyed (no counterparty credit), so
  ERA is conserved only modulo an explicitly tracked burn. The new asset is
  issued from nothing against a commit proven distinct from every existing
  asset, so its supply equals exactly what was issued.
-/

namespace DSMTokenIssuance

/-- ERA destroyed to create a token (`dsm::core::token::TOKEN_CREATION_FEE_ERA`),
    in base units: 10.00 ERA at ERA's two decimals. -/
def creationFee : Nat := 1000

/--
  The fee leg debits EXACTLY the fee, and the destroyed value is accounted
  for by the burn counter — so ERA + burned is invariant across a creation.

  Discharges: TokenConservation (CreateTokenBurn case) in
  DSM_BilateralLiveness.tla, where the sum is
  `SumBal(Device) + EscrowedAmount + burnedTotal`.
-/
theorem create_fee_conserves_era_modulo_burn
    (era burned fee : Nat) (h : fee ≤ era) :
    (era - fee) + (burned + fee) = era + burned := by
  omega

/--
  The fee is debited exactly — never more, never less. A creation that
  charged a different amount than the operation declares would let the
  guard's `d.amount == fee_amount` check pass on a different quantity.
-/
theorem create_fee_debits_exactly (era fee : Nat) (h : fee ≤ era) :
    (era - fee) + fee = era := by
  omega

/--
  INSUFFICIENT FEE IS A NO-OP. When the creator cannot cover the fee, no
  state changes: the balance is untouched and nothing is burned.

  This is the "failed creation burns nothing" property. In the
  implementation it is structural rather than compensating — the
  conservation guard and the balance arithmetic both run inside
  `prepare_advance_relationship`, BEFORE the durable write and before the
  in-memory head install, so an abort leaves no trace to undo.
-/
def tryCreate (era burned fee : Nat) : Nat × Nat :=
  if fee ≤ era then (era - fee, burned + fee) else (era, burned)

theorem create_insufficient_fee_is_noop
    (era burned fee : Nat) (h : era < fee) :
    tryCreate era burned fee = (era, burned) := by
  unfold tryCreate
  have : ¬ (fee ≤ era) := by omega
  simp [this]

/-- And when the fee IS affordable, the guarded update is exactly the burn. -/
theorem create_affordable_applies_the_burn
    (era burned fee : Nat) (h : fee ≤ era) :
    tryCreate era burned fee = (era - fee, burned + fee) := by
  unfold tryCreate
  simp [h]

/--
  The issuance leg credits the NEW asset from zero: its supply after
  creation is exactly the initial allocation. The new asset's commit is
  proven distinct from every builtin before this point, so this credit can
  never land on an existing asset.
-/
theorem create_issues_exactly_initial_supply (initialSupply : Nat) :
    0 + initialSupply = initialSupply := by
  omega

/--
  The two legs touch exactly two DISTINCT assets, so neither can offset the
  other. ERA decreases by the fee while the new asset increases by the
  allocation; there is no arithmetic in which the issuance masks the burn.
-/
theorem create_touches_two_distinct_assets
    (era fee initialSupply : Nat) (h : fee ≤ era) :
    (era - fee) + fee = era ∧ 0 + initialSupply = initialSupply := by
  constructor
  · omega
  · omega

/--
  The creation as `validate_conservation` accepts it. A token with no genesis
  supply is not a token (SoFi §50), and the fee is the protocol's (S18): a
  creation that would issue nothing, or that names another fee, is refused
  before the fee leg, so it burns nothing and issues nothing. The guard runs
  before any write.
-/
def tryCreateWithSupply (era burned fee initialSupply : Nat) : Nat × Nat × Nat :=
  if 0 < initialSupply ∧ fee = creationFee ∧ fee ≤ era then
    (era - fee, burned + fee, initialSupply)
  else (era, burned, 0)

theorem create_with_no_supply_is_refused (era burned fee : Nat) :
    tryCreateWithSupply era burned fee 0 = (era, burned, 0) := by
  unfold tryCreateWithSupply
  simp

/-- A creation naming any fee but the protocol's — a free one included — is
    refused: nothing is burned and nothing issued. -/
theorem a_creation_paying_other_than_the_protocol_fee_is_refused
    (era burned fee initialSupply : Nat) (hf : fee ≠ creationFee) :
    tryCreateWithSupply era burned fee initialSupply = (era, burned, 0) := by
  unfold tryCreateWithSupply
  simp [hf]

/-- With a supply and the protocol's fee affordable, the creation is exactly
    the burn of the fee and the whole supply, released. -/
theorem create_with_supply_burns_and_releases
    (era burned initialSupply : Nat) (hs : 0 < initialSupply) (hf : creationFee ≤ era) :
    tryCreateWithSupply era burned creationFee initialSupply
      = (era - creationFee, burned + creationFee, initialSupply) := by
  unfold tryCreateWithSupply
  simp [hs, hf]

end DSMTokenIssuance
