-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.SecurityGames
open DSM.Sphincs DSM.Sphincs.Security

private def require (condition : Bool) (label : String) : IO Unit :=
  unless condition do throw (IO.userError label)

-- An intentionally insecure oracle demonstrates that functional correctness
-- and primitive output widths alone do not imply unforgeability.
private def zeroOracle : Oracle Id := fun request => List.replicate request.outLen 0

private theorem zero_oracle_widths : OutputWidths zeroOracle := by
  intro request
  simp [zeroOracle]

#print axioms zero_oracle_widths

private def checks : IO Unit := do
  let limits : Limits := ⟨1,8,by decide⟩
  let view : View := ⟨[7],[]⟩
  let signing := fun m : Bytes => some (m ++ [9])
  let verifying := fun m s : Bytes => s == m ++ [9]
  let adaptive : Strategy := fun v =>
    match v.replies with
    | [] => .query [1]
    | r::_ => .forge [2] (r.signature.getD [])
  let outcome := run limits signing adaptive limits.signingAttempts view
  require (outcome.view.replies.length == 1) "adaptive query not recorded"
  require (!wins limits verifying outcome) "incorrect signature accepted"
  require (wins limits verifying (.forgery outcome.view [2] [2,9])) "fresh valid forgery rejected"
  require (!wins limits verifying (.forgery outcome.view [1] [1,9])) "queried-message freshness bypass"
  require (!wins limits verifying (.forgery view [] [9])) "empty forgery accepted"
  require (!wins limits verifying (.forgery view (List.replicate 9 1) [])) "message bound bypass"
  let exhausted := run limits signing (fun _ => .query [1]) 1 view
  require (!wins limits verifying exhausted) "exhausted adversary won"
  require (exhausted.view.replies.length == 1) "query budget bypass"
  require ((reply limits signing []).signature == none) "invalid signing query accepted"
  let space : FiniteExperiment Nat := ⟨4,by decide,fun i => i.val⟩
  let a := fun x : Nat => x < 2
  let b := fun x : Nat => x % 2 == 0
  let pa := probability space a
  let pb := probability space b
  let pu := probability space (fun x => a x || b x)
  require (pa.numerator == 2 && pb.numerator == 2 && pu.numerator == 3)
    "finite event accounting incorrect"
  let product := independentProduct space space
  require ((List.ofFn product.sample).length == 16) "independent coin product incorrect"
  let constantForgery : Strategy := fun _ =>
    .forge [2] (List.replicate (params .spx128f).sigBytes 0)
  let world : World := ⟨⟨List.replicate 32 0,by decide⟩,zeroOracle⟩
  require (forgeEvent .spx128f limits constantForgery world)
    "negative control: zero-output primitive should permit a fresh forgery"
  IO.println "Classical game controls passed; insecure-width-correct oracle permits forgery as expected."

def main : IO Unit := checks
