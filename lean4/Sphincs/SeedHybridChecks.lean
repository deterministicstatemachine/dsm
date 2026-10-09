-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.SeedHybrid
open DSM.Sphincs DSM.Sphincs.Security

-- Deliberately insecure hash oracle, used solely to exercise the reduction.
-- Its expansion is nonzero and correlated; the simulation must carry those
-- exact bytes rather than substituting three independent seeds silently.
private def controlOracle : Oracle Id := fun r =>
  if r.mode == 3 then (List.range r.outLen).map (fun i => UInt8.ofNat (i%251))
  else List.replicate r.outLen 0

def main : IO Unit := do
  let limits : Limits := ⟨1,8,by decide⟩
  let master : Wire 32 := ⟨List.replicate 32 7,by decide⟩
  for v in [Variant.spx128f,Variant.spx256f] do
    let p := params v
    let expansion := seedExpansion controlOracle v master
    unless expansion.length == 3*p.n do
      throw (IO.userError "expansion width changed")
    let (pk,sk) := keypairFromExpansion controlOracle v expansion
    unless pk.take p.n == slice expansion (2*p.n) p.n && sk.take (3*p.n) == expansion do
      throw (IO.userError "challenge seed fields were altered")
    let adaptive : Strategy := fun view =>
      if view.replies.isEmpty then .query [1]
      else .forge [2] ((view.replies.head?.bind (·.signature)).getD [])
    let actual := forgeEvent v limits adaptive ⟨master,controlOracle⟩
    let simulated := seedDistinguisher v limits adaptive controlOracle expansion
    unless actual && simulated do
      throw (IO.userError "insecure-oracle positive control did not forge")
    unless actual == simulated do
      throw (IO.userError "seed challenge changed the adaptive game")
    let queriedForgery : Strategy := fun view =>
      if view.replies.isEmpty then .query [1]
      else .forge [1] ((view.replies.head?.bind (·.signature)).getD [])
    unless !seedDistinguisher v limits queriedForgery controlOracle expansion do
      throw (IO.userError "simulation bypassed message freshness")
  let a : Probability := ⟨1,4,by decide,by decide⟩
  let b : Probability := ⟨1,8,by decide,by decide⟩
  unless gapNumerator a b == 4 && gapNumerator b a == 4 do
    throw (IO.userError "different-denominator advantage accounting failed")
  IO.println "Seed hybrid controls passed: actual correlated expansion, adaptive simulation, freshness and exact advantage accounting."
