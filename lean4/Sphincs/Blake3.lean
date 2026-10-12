-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Model

/- Executable BLAKE3 specification. Cross-reference: BLAKE3 specification
   sections 2 and 5 and upstream reference_impl/reference_impl.rs. This implements
   the algorithm, without a cryptographic-security assumption or an FFI call.
   Array accesses below have defaults; shape safety is a remaining proof. -/
namespace DSM.Sphincs.Blake3
abbrev Words := Array UInt32
def iv : Words := #[0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
  0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]
def permutation : Array Nat := #[2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8]
def rotr (x : UInt32) (n : Nat) : UInt32 :=
  (x >>> UInt32.ofNat n) ||| (x <<< UInt32.ofNat (32-n))
def mix (s : Words) (a b c d : Nat) (x y : UInt32) : Words := Id.run do
  let mut s := s
  s := s.set! a (s[a]! + s[b]! + x)
  s := s.set! d (rotr (s[d]! ^^^ s[a]!) 16)
  s := s.set! c (s[c]! + s[d]!)
  s := s.set! b (rotr (s[b]! ^^^ s[c]!) 12)
  s := s.set! a (s[a]! + s[b]! + y)
  s := s.set! d (rotr (s[d]! ^^^ s[a]!) 8)
  s := s.set! c (s[c]! + s[d]!)
  return s.set! b (rotr (s[b]! ^^^ s[c]!) 7)
def round (s m : Words) : Words :=
  let s := mix s 0 4 8 12 m[0]! m[1]!
  let s := mix s 1 5 9 13 m[2]! m[3]!
  let s := mix s 2 6 10 14 m[4]! m[5]!
  let s := mix s 3 7 11 15 m[6]! m[7]!
  let s := mix s 0 5 10 15 m[8]! m[9]!
  let s := mix s 1 6 11 12 m[10]! m[11]!
  let s := mix s 2 7 8 13 m[12]! m[13]!
  mix s 3 4 9 14 m[14]! m[15]!
def compress (cv block : Words) (counter : Nat) (len flags : UInt32) : Words := Id.run do
  let mut s := cv ++ iv.extract 0 4 ++
    #[UInt32.ofNat counter,UInt32.ofNat (counter/2^32),len,flags]
  let mut m := block
  for _ in List.range 7 do
    s := round s m
    m := permutation.map (fun i => m[i]!)
  return (Array.range 8).map (fun i => s[i]! ^^^ s[i+8]!) ++
    (Array.range 8).map (fun i => s[i+8]! ^^^ cv[i]!)
def words (x : Bytes) (count : Nat) : Words :=
  (Array.range count).map fun i => UInt32.ofNat
    ((List.range 4).foldl (fun n j => n + (x[4*i+j]?.getD 0).toNat * 256^j) 0)
def bytes (x : Words) : Bytes := x.toList.flatMap fun w =>
  (List.range 4).map (fun i => UInt8.ofNat (w.toNat/256^i))
structure Output where
  cv : Words
  block : Words
  counter : Nat
  len : UInt32
  flags : UInt32
def Output.chaining (o : Output) : Words :=
  (compress o.cv o.block o.counter o.len o.flags).extract 0 8
def Output.rootBlock (o : Output) (counter : Nat) : Bytes :=
  bytes (compress o.cv o.block counter o.len (o.flags ||| 8))
-- Output length is applied only after root-block generation; ROOT uses an
-- output-block counter, not the chunk counter saved in Output.
def Output.root (o : Output) (len : Nat) : Bytes :=
  ((List.range ((len+63)/64)).flatMap o.rootBlock).take len
def chunk (key : Words) (flags : UInt32) (counter : Nat) (input : Bytes) : Output := Id.run do
  let count := max 1 ((input.length+63)/64)
  let mut cv := key
  for i in List.range (count-1) do
    cv := (compress cv (words (slice input (64*i) 64) 16) counter 64
      (flags ||| if i == 0 then 1 else 0)).extract 0 8
  let last := slice input (64*(count-1)) 64
  return ⟨cv, words last 16, counter, UInt32.ofNat last.length,
    flags ||| 2 ||| if count == 1 then 1 else 0⟩
def parent (key : Words) (flags : UInt32) (left right : Words) : Output :=
  ⟨key,left++right,0,64,flags ||| 4⟩
def merge (key : Words) (flags : UInt32) : Nat → Nat → Words → List Words → List Words
  | 0, _, cv, stack => cv::stack
  | fuel+1, count, cv, stack =>
    match stack with
    | [] => [cv]
    | left::rest => if count%2 == 0 then
        merge key flags fuel (count/2) (parent key flags left cv).chaining rest
      else cv::stack
def tree (key : Words) (flags : UInt32) (input : Bytes) : Output := Id.run do
  let count := max 1 ((input.length+1023)/1024)
  let mut stack : List Words := []
  for i in List.range (count-1) do
    let cv := (chunk key flags i (slice input (1024*i) 1024)).chaining
    stack := merge key flags count (i+1) cv stack
  let last := chunk key flags (count-1) (slice input (1024*(count-1)) 1024)
  return stack.foldl (fun o left => parent key flags left o.chaining) last
def hash (input : Bytes) (len : Nat) : Bytes := (tree iv 0 input).root len
def keyedHash (key input : Bytes) (len : Nat) : Bytes :=
  (tree (words key 8) 16 input).root len
def contextKey (context : String) : Bytes := (tree iv 32 context.toUTF8.toList).root 32
def derive (context : String) (input : Bytes) (len : Nat) : Bytes :=
  (tree (words (contextKey context) 8) 64 input).root len

-- Reject malformed request shapes instead of silently assigning semantics to
-- a short keyed-hash key or unknown request mode. ChaCha expansion is separate.
def evaluate (r : Request) : Option Bytes :=
  match r.mode with
  | 0 => if r.key == [] && r.outLen == 32 then some (derive r.context r.input 32) else none
  | 1 => if r.key.length == 32 && r.context == "" && r.outLen ≤ 32 then
      some (keyedHash r.key r.input r.outLen) else none
  | 2 => if r.key == [] then some (derive r.context r.input r.outLen) else none
  | 4 => if r.key == [] && r.context == "" && r.outLen == 32 then
      some (hash r.input 32) else none
  | _ => none

-- These are wiring theorems. They identify the same concrete construction in
-- both derive_key and derive-key XOF requests, rather than separate oracles.
theorem derive_request (context : String) (input : Bytes) :
    evaluate ⟨0,context,[],input,32⟩ = some (derive context input 32) := by
  simp [evaluate]
theorem derive_xof_same_32 (context : String) (input : Bytes) :
    evaluate ⟨0,context,[],input,32⟩ = evaluate ⟨2,context,[],input,32⟩ := by
  simp [evaluate]
theorem keyed_request (key : Wire 32) (input : Bytes) (n : Nat) (width : n ≤ 32) :
    evaluate ⟨1,"",key.val,input,n⟩ = some (keyedHash key.val input n) := by
  simp [evaluate,key.property,width]
theorem thash_request (p : Params) (key : Wire 32) (a : Adrs) (input : Bytes)
    (width : p.n ≤ 32) :
    thash (m := Id) (fun request => (evaluate request).getD []) p key.val a input =
      keyedHash key.val (a.bytes++input) p.n := by
  simp [thash,keyed,evaluate,key.property,width]
theorem prf_request (p : Params) (key : Wire 32) (seed : Bytes) (a : Adrs)
    (width : p.n ≤ 32) :
    prf (m := Id) (fun request => (evaluate request).getD []) p key.val seed a =
      keyedHash key.val (seed++a.bytes) p.n := by
  simp [prf,keyed,evaluate,key.property,width]
theorem hmsg_request (p : Params) (r seed root msg : Bytes) :
    hmsg (m := Id) (fun request => (evaluate request).getD []) p r seed root msg =
      derive "DSM/sphincs/v2/h-msg" (r++seed++root++msg) p.m := by
  simp [hmsg,evaluate]
theorem deployed_keyed_width (v : Variant) : (params v).n ≤ 32 := by
  cases v <;> decide
-- Both deployed fast variants need more than a 32-byte message digest.
-- Security arguments restricted to ≤256 output bits do not cover these calls.
theorem deployed_hmsg_widths :
    (params .spx128f).m = 34 ∧ (params .spx256f).m = 49 := by decide
theorem contexts_distinct :
    ["DSM/sphincs/v2/prf", "DSM/sphincs/v2/thash",
     "DSM/sphincs/v2/prf-msg", "DSM/sphincs/v2/h-msg"].Pairwise (· ≠ ·) := by decide
-- Different mode bits are input separation, not an output-independence theorem.
theorem mode_bits_distinct :
    (16 : UInt32) ≠ 32 ∧ (16 : UInt32) ≠ 64 ∧ (32 : UInt32) ≠ 64 := by decide
#print axioms derive_request
#print axioms derive_xof_same_32
#print axioms hmsg_request
#print axioms thash_request
#print axioms prf_request
#print axioms deployed_hmsg_widths
#print axioms contexts_distinct
end DSM.Sphincs.Blake3
