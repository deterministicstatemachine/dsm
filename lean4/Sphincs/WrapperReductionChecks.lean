-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.WrapperReduction
open DSM.Sphincs DSM.Sphincs.Security
private def require (ok : Bool) (message : String) : IO Unit :=
  unless ok do throw (IO.userError message)
private def constantHash (_ : Bytes) : Wire 32 := ⟨List.replicate 32 0,by simp⟩
private def lastByteHash (input : Bytes) : Wire 32 :=
  ⟨List.replicate 32 (input.getLast?.getD 0),by simp⟩
def main : IO Unit := do
  let a : Certificate := ⟨⟨List.replicate 64 0,by simp⟩,⟨List.replicate 32 1,by simp⟩⟩
  let b : Certificate := ⟨a.key,⟨List.replicate 32 2,by simp⟩⟩
  let signature := (lastByteHash b.preimage).val
  let extracted := extractWithTrace Certificate.preimage lastByteHash [a] b signature
  match extracted.1 with
  | .signatureForgery message sig =>
    require (message == signature && sig == signature) "fresh digest/signature not preserved"
    require (message != (lastByteHash a.preimage).val) "queried digest mislabeled fresh"
  | .collision _ _ => throw (IO.userError "fresh digest mislabeled collision")
  require (extracted.2 == [b.preimage,a.preimage]) "hash query trace differs from actual inputs"
  let collision := extractWithTrace Certificate.preimage constantHash [a] b []
  match collision.1 with
  | .collision left right =>
    require (left != right) "collision witness inputs not distinct"
    require ((constantHash left).val == (constantHash right).val) "collision outputs differ"
  | .signatureForgery _ _ => throw (IO.userError "queried digest mislabeled signature forgery")
  require (collision.2.length == 2) "collision extraction query count incorrect"
  let trial : WrapperTrial Certificate := ⟨[a],a,[]⟩
  require (!wrapperSuccess Certificate.preimage constantHash (fun _ _ => true) trial)
    "previously queried certificate counted as forgery"
  IO.println "Certificate extraction controls passed for fresh-digest, collision, freshness and query-trace branches."
