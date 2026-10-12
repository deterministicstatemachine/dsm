-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.MultiKey
open DSM.Sphincs DSM.Sphincs.Security

-- Deliberately insecure hash oracle, used solely to show the multi-key game is
-- winnable (so the reduction bounds something real) and that freshness is per
-- key. Its expansion depends on the seed, so the keys differ.
private def controlOracle : Oracle Id := fun r =>
  if r.mode == 3 then (List.range r.outLen).map (fun i => UInt8.ofNat ((i + (r.input.headD 0).toNat) % 251))
  else List.replicate r.outLen 0

private def seed (b : Nat) : Wire 32 := ⟨List.replicate 32 (UInt8.ofNat b), by simp⟩

def main : IO Unit := do
  let limits : Limits := ⟨2,8,by decide⟩
  for v in [Variant.spx128f,Variant.spx256f] do
    let exps := [seed 7, seed 8, seed 9].map (seedExpansion controlOracle v)
    let pks := exps.map (fun e => (keypairFromExpansion controlOracle v e).1)
    unless pks.length == 3 && pks[0]! != pks[1]! && pks[1]! != pks[2]! do
      throw (IO.userError "multi-key public keys are not distinct")
    -- Ask key 0 to sign [1], then present that signature under key k on message m.
    let attack (k : Nat) (m : Bytes) : MStrategy := fun view =>
      if view.replies.isEmpty then .query 0 [1]
      else .forge k m ((view.replies.head?.bind (·.reply.signature)).getD [])
    unless mforgeEvent v limits controlOracle exps (attack 1 [1]) do
      throw (IO.userError "insecure-oracle positive control did not forge under another key")
    unless mforgeEvent v limits controlOracle exps (attack 2 [2]) do
      throw (IO.userError "insecure-oracle positive control did not forge a fresh message")
    if mforgeEvent v limits controlOracle exps (attack 0 [1]) then
      throw (IO.userError "a message queried under the same key counted as a forgery")
    if mforgeEvent v limits controlOracle exps (attack 5 [2]) then
      throw (IO.userError "a forgery under a key that does not exist counted")
  IO.println "Multi-key controls passed: distinct keys, winnable under an insecure oracle, per-key freshness, key range."
