-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomRoles
import Sphincs.RomItsr

/- Classical security level of DSM's BLAKE3 SPHINCS+ in the random-oracle
   model: the arithmetic of the composition. Every BLAKE3 role and the ChaCha
   seed expansion is an independent random oracle (`RomOracle`); the adversary
   makes at most `qh` oracle queries and `q_s ≤ 2^64` signing queries. The
   reduction's terms and the role bound each one stands on:

     master seed found              qh / 2^256     rom_secret_guess
     SK.seed found (PRF-key hop)    qh / 2^(8n)    rom_secret_guess
     PRF key found (PRF hop)        qh / 2^256     rom_secret_guess
     SK.prf found (msg-key hop)     qh / 2^(8n)    rom_secret_guess
     PRF_msg key found (msg hop)    qh / 2^256     rom_secret_guess
     tweak collision                (qh+V)/2^(8n)  rom_tweak_collision
     hidden WOTS chain value        (qh+V)/2^(8n)  rom_secret_guess
     hidden FORS secret             (qh+V)/2^(8n)  rom_secret_guess
     ITSR (covered digest)          (qh+1)·2^-b    itsr_spx128f / itsr_spx256f

   with `V = verifyCost` (`QueryCost.lean`). That the reduction's four events
   and five hops are instances of these role games in the ROM experiment is
   argued in SPHINCS_ROM_BOUND.md, not machine-checked. This module checks
   the sum. -/
namespace DSM.Rom
open DSM.Sphincs

/-- The challenger's oracle in a query tree: every request is an `ask`
    tagged challenger-side. -/
def challengerOracle : Oracle QT := fun r => .ask false r .done

/-- The model's key generation, signing and verification are monad-generic,
    so they run unchanged as query trees against the random oracle. -/
def keygenQT (v : Variant) (seed : Wire 32) : QT (Bytes × Bytes) :=
  generateKeypair challengerOracle v seed
def signQT (v : Variant) (sk msg : Bytes) : QT (Option Bytes) := sign challengerOracle v sk msg
def verifyQT (v : Variant) (pk msg sig : Bytes) : QT (Option Bool) :=
  verify (fun r => .ask true r .done) v pk msg sig

/-- SPX128f (n = 16, V = 11872, ITSR ≤ 2^-128). The six `2^-128` terms give
    `(6 qh + 3 V + 1) / 2^128`, the three key terms `3 qh / 2^256`. For
    `qh ≥ 2^16` the total is at most `qh · 2^-125`. -/
theorem rom_level_128f (qh : Nat) (hq : 2^16 ≤ qh) :
    ((6 * qh + 3 * 11872 + 1) * 2^128 + 3 * qh) * 2^125 ≤ qh * 2^256 := by
  have h1 : 6 * qh + 3 * 11872 + 1 ≤ 7 * qh := by omega
  have h2 : 3 * qh ≤ qh * 2^128 := by
    rw [Nat.mul_comm]; exact Nat.mul_le_mul_left qh (by decide)
  calc ((6 * qh + 3 * 11872 + 1) * 2^128 + 3 * qh) * 2^125
      ≤ (7 * qh * 2^128 + qh * 2^128) * 2^125 :=
        Nat.mul_le_mul_right _ (Nat.add_le_add (Nat.mul_le_mul_right _ h1) h2)
    _ = qh * 2^256 := by
        rw [← Nat.add_mul, show 7 * qh + qh = qh * 8 by omega, Nat.mul_assoc, Nat.mul_assoc]

/-- SPX256f (n = 32, V = 17523, ITSR ≤ 2^-255 = 2 · 2^-256): all nine terms
    over `2^256` give `(10 qh + 3 V + 2) / 2^256`; for `qh ≥ 2^14` that is at
    most `qh · 2^-252`. -/
theorem rom_level_256f (qh : Nat) (hq : 2^14 ≤ qh) :
    (10 * qh + 3 * 17523 + 2) * 2^252 ≤ qh * 2^256 := by
  have : 10 * qh + 3 * 17523 + 2 ≤ qh * 16 := by omega
  calc (10 * qh + 3 * 17523 + 2) * 2^252 ≤ qh * 16 * 2^252 := Nat.mul_le_mul_right _ this
    _ = qh * 2^256 := by rw [Nat.mul_assoc]

#print axioms rom_level_128f
#print axioms rom_level_256f
end DSM.Rom
