-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Blake3Vectors
import Sphincs.Transcript
namespace DSM.Sphincs.Blake3
-- Hex is confined to decoding the official public test-vector fixture.
def unhex (s : String) : Bytes := Id.run do
  let chars := s.toList.toArray
  let digit (c : Char) := if c ≤ '9' then c.toNat-'0'.toNat else c.toNat-'a'.toNat+10
  return (List.range (chars.size/2)).map fun i =>
    UInt8.ofNat (16*digit chars[2*i]! + digit chars[2*i+1]!)
def checkVectors : IO Unit := do
  for (n,h,k,d) in vectors do
    let input := (List.range n).map (fun i => UInt8.ofNat (i%251))
    for (label,actual,expected) in
      [("hash",hash input 131,unhex h),
       ("keyed",keyedHash vectorKey.toUTF8.toList input 131,unhex k),
       ("derive",derive vectorContext input 131,unhex d)] do
      unless actual == expected do throw (IO.userError s!"official {label} vector failed at {n}")
  IO.println s!"Official BLAKE3 vectors passed: {vectors.length} lengths, all three modes, 131-byte XOF."
  unless evaluate ⟨1,"",[0],[],16⟩ == none do
    throw (IO.userError "short keyed-hash key was accepted")
  unless evaluate ⟨1,"unexpected",List.replicate 32 0,[],16⟩ == none do
    throw (IO.userError "keyed hash silently accepted a context")
  unless evaluate ⟨0,"DSM/sphincs/v2/prf",[],[],16⟩ == none do
    throw (IO.userError "derive-key request silently changed output width")
  unless evaluate ⟨99,"",[],[],32⟩ == none do
    throw (IO.userError "unknown primitive mode was accepted")
-- Every BLAKE3 output in supplied Rust transcripts is recomputed, independently
-- of the transcript replay oracle. Mode 3 is ChaCha20Rng and is not a hash call.
def checkTranscript (path : String) : IO Nat := do
  let data ← IO.FS.readBinFile path
  let c ← match readCase.run ⟨data,0⟩ with
    | .ok (c,_) => pure c
    | .error e => throw (IO.userError e)
  let mut count := 0
  for call in c.calls do
    if call.request.mode != 3 then
      match evaluate call.request with
      | none => throw (IO.userError s!"invalid BLAKE3 request in {path}")
      | some actual =>
        unless actual == call.output do
          throw (IO.userError s!"BLAKE3 bytes differ in {path}, call {count}")
        count := count+1
  return count
end DSM.Sphincs.Blake3
def main (args : List String) : IO Unit := do
  DSM.Sphincs.Blake3.checkVectors
  let mut count := 0
  for path in args do count := count + (← DSM.Sphincs.Blake3.checkTranscript path)
  IO.println s!"Independently recomputed {count} Rust BLAKE3 requests."
