-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Blake3
namespace DSM.Sphincs.Blake3
 theorem compress_size (cv block : Words) (counter : Nat) (len flags : UInt32) :
    (compress cv block counter len flags).size = 16 := by
  simp [compress]
 theorem bytes_length (x : Words) : (bytes x).length = 4*x.size := by
  have h : ∀ (xs : List UInt32),
      (xs.flatMap fun w => (List.range 4).map (fun i => UInt8.ofNat (w.toNat/256^i))).length = 4*xs.length := by
    intro xs
    induction xs with
    | nil => simp
    | cons x xs ih => simp [ih,Nat.mul_add,Nat.add_comm]
  simpa [bytes] using h x.toList
 theorem rootBlock_length (o : Output) (counter : Nat) : (o.rootBlock counter).length = 64 := by
  simp [Output.rootBlock,bytes_length,compress_size]
end DSM.Sphincs.Blake3
namespace DSM.Sphincs.Blake3
 theorem rootBlocks_length (o : Output) (indices : List Nat) :
    (indices.flatMap o.rootBlock).length = 64*indices.length := by
  induction indices with
  | nil => simp
  | cons x xs ih => simp [rootBlock_length,ih,Nat.mul_add,Nat.add_comm]
 theorem root_length (o : Output) (len : Nat) : (o.root len).length = len := by
  simp only [Output.root,List.length_take,rootBlocks_length,List.length_range]
  omega
 theorem derive_length (context : String) (input : Bytes) (len : Nat) :
    (derive context input len).length = len := root_length _ _
 theorem keyed_length (key input : Bytes) (len : Nat) :
    (keyedHash key input len).length = len := root_length _ _
end DSM.Sphincs.Blake3
namespace DSM.Sphincs.Blake3
 theorem hash_length (input : Bytes) (len : Nat) : (hash input len).length = len := root_length _ _
 theorem evaluate_width (r : Request) (output : Bytes) (accepted : evaluate r = some output) :
    output.length = r.outLen := by
  unfold evaluate at accepted
  split at accepted <;> (try split at accepted) <;>
    simp only [Option.some.injEq,reduceCtorEq] at accepted
  all_goals rw [←accepted]
  all_goals first
    | (rw [derive_length] <;> simp_all)
    | rw [keyed_length]
    | (rw [hash_length] <;> simp_all)
#print axioms root_length
#print axioms evaluate_width
end DSM.Sphincs.Blake3
namespace DSM.Sphincs.Blake3
 theorem root_prefix (o : Output) (n m : Nat) (bound : n ≤ m) :
    (o.root m).take n = o.root n := by
  have counts : (n+63)/64 ≤ (m+63)/64 := by omega
  have splitRange : List.range ((m+63)/64) =
      List.range ((n+63)/64) ++
        (List.range (((m+63)/64)-((n+63)/64))).map (((n+63)/64)+·) := by
    have h := List.range_add (n := (n+63)/64) (m := ((m+63)/64)-((n+63)/64))
    simpa [Nat.add_sub_of_le counts] using h
  simp only [Output.root,List.take_take,Nat.min_eq_left bound]
  rw [splitRange,List.flatMap_append]
  apply List.take_append_of_le_length
  rw [rootBlocks_length,List.length_range]
  omega
#print axioms root_prefix
end DSM.Sphincs.Blake3
