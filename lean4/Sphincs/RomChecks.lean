-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomRoles
open DSM.Sphincs DSM.Rom

-- Executable controls for the ROM layer: lazy answers are consistent, the
-- counted collision event is reachable (so the bound is not vacuous), and
-- secret guesses are counted.
private def adrs : Bytes := List.replicate 32 7
private def chal : Request := ⟨1, "", [9], adrs ++ [1], 16⟩
private def advReq : Request := ⟨1, "", [9], adrs ++ [2], 16⟩

-- The challenger hashes once, the adversary twice (the second a repeat).
private def prog : QT (Bytes × Bytes × Bytes) :=
  .ask false chal (fun a => .ask true advReq (fun b => .ask true advReq (fun c => .done (a, b, c))))

def main : IO Unit := do
  let ((a, b, c), d) := run [5, 5] prog []
  unless d.length == 2 && b == c do
    throw (IO.userError "a repeated request was not answered from its first draw")
  unless a == b && collides (tweakPartner 16) (256^16) d [5, 5] do
    throw (IO.userError "equal answers on a same-tweak pair were not counted")
  let (_, d') := run [5, 6] prog []
  if collides (tweakPartner 16) (256^16) d' [5, 6] then
    throw (IO.userError "different answers were counted as a collision")
  unless advCount d == 1 && pairsList (tweakPartner 16) d 1 == [0] do
    throw (IO.userError "partner accounting is wrong")
  IO.println "ROM controls passed: lazy consistency, reachable collision event, partner accounting."
