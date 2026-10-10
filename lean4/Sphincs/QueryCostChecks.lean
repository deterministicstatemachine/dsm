-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.QueryCost
open DSM.Sphincs DSM.Sphincs.Security

-- Executable controls for the request accounting, on both deployed variants.
-- The model functions are run against a counting oracle (constant-time per
-- request; the list-appending logging oracle is quadratic and used only for
-- verification here) and each count is compared with its proved bound, so
-- the bound's slack is visible. The oracle is a deterministic stand-in with
-- the deployed output widths, not BLAKE3.
private def toyOracle : Oracle Id := fun r =>
  (List.range r.outLen).map (fun i => UInt8.ofNat ((i * 31 + r.input.length + r.mode) % 256))

private def countOracle : Oracle (StateM Nat) := fun r => modifyGet fun c => (toyOracle r, c + 1)

private def seed : Wire 32 := ⟨List.replicate 32 5, by simp⟩

def main : IO Unit := do
  for v in [Variant.spx128f, Variant.spx256f] do
    let ((pk, sk), kg) := (generateKeypair countOracle v seed).run 0
    let msg : Bytes := [1,2,3]
    let (sigOpt, sg) := (sign countOracle v sk msg).run 0
    let sig := sigOpt.getD []
    let (ok, vf) := (verify countOracle v pk msg sig).run 0
    IO.println s!"{repr v}: keygen {kg}/{keygenCost v}, sign {sg}/{signCost v}, verify {vf}/{verifyCost v}"
    unless ok == some true do
      throw (IO.userError "the stand-in signature did not verify")
    unless kg ≤ keygenCost v && sg ≤ signCost v && vf ≤ verifyCost v do
      throw (IO.userError "a call exceeded its proved request bound")
    -- The logging oracle records the same number of requests as the counter.
    let (ok', log) := (verify (logOracle toyOracle) v pk msg sig).run []
    unless ok' == ok && log.length == vf do
      throw (IO.userError "logged verification differs from the counted run")
    -- A wrong-length signature is rejected before any request.
    let (bad, none') := (verify countOracle v pk msg [0]).run 0
    unless bad == some false && none' == 0 do
      throw (IO.userError "malformed signature issued requests")
