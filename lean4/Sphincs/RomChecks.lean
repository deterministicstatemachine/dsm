-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomHidden
open DSM.Sphincs DSM.Rom

-- Executable controls for the ROM layer: lazy answers are consistent, the
-- counted collision event is reachable (so the bound is not vacuous), and
-- secret guesses are counted. Symbolic-run controls: a guess of a hidden
-- value makes the real and symbolic runs disagree and is probed at the right
-- tape entry; a wrong guess leaves the runs equal and is still counted as a
-- compatible pair.
private def adrs : Bytes := List.replicate 32 7
private def chal : Request := ⟨1, "", [9], adrs ++ [1], 16⟩
private def advReq : Request := ⟨1, "", [9], adrs ++ [2], 16⟩

-- The challenger hashes once, the adversary twice (the second a repeat).
private def prog : QT (Bytes × Bytes × Bytes) :=
  .ask false chal (fun a => .ask true advReq (fun b => .ask true advReq (fun c => .done (a, b, c))))

private def adrs2 : Bytes := List.replicate 32 8
private def r1 : SReq := ⟨1, "", [.lit [9]], [.lit adrs, .lit [1]], 16⟩
private def r2 (v : SV) : SReq := ⟨1, "", [.lit [9]], [.lit adrs2, v], 16⟩
private def guessReq : Request := ⟨1, "", [9], adrs2 ++ be 16 5, 16⟩
-- The challenger hashes a secret, hashes the result, reveals only the second
-- output; the adversary then queries the second hash on a guessed secret.
private def sprog : Prog Bytes :=
  .askC r1 (fun h0 => .askC (r2 h0) (fun h1 => .reveal [h1] (fun _ => .askA guessReq .done)))
private def st0 : St := ⟨[], []⟩

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
  let hit : List Nat := [5, 77, 99]
  let miss : List Nat := [6, 77, 99]
  unless anyDis sprog st0 hit && (xrun true hit sprog st0).1 == be 16 77 &&
      (xrun false hit sprog st0).1 == be 16 99 do
    throw (IO.userError "a correct hidden-value guess did not separate the real and symbolic runs")
  unless probe 16 sprog st0 hit 3 1 == some (0, 5) && !wildColl 16 sprog st0 3 hit do
    throw (IO.userError "the guess was not pinned to the hidden tape entry")
  unless !anyDis sprog st0 miss && (xrun true miss sprog st0).1 == (xrun false miss sprog st0).1 do
    throw (IO.userError "a wrong guess changed the run")
  unless pairCount 16 sprog st0 4 miss == 1 do
    throw (IO.userError "the compatible guess was not counted")
  IO.println "ROM controls passed: lazy consistency, reachable collision event, partner accounting, hidden-value guess."
