-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Model
namespace DSM.Sphincs
structure Cursor where
  bytes : ByteArray
  pos : Nat := 0
abbrev Reader := StateT Cursor (Except String)
def readByte : Reader UInt8 := do
  let c ← get
  if c.pos ≥ c.bytes.size then throw "truncated vector"
  set {c with pos := c.pos+1}
  return c.bytes[c.pos]!
def readNat : Reader Nat := do
  let mut n := 0
  for _ in List.range 4 do n := n*256+(← readByte).toNat
  return n
def readBlob : Reader Bytes := do
  let n ← readNat
  let c ← get
  if c.pos+n > c.bytes.size then throw "truncated blob"
  set {c with pos := c.pos+n}
  return (c.bytes.extract c.pos (c.pos+n)).toList
structure Call where
  request : Request
  output : Bytes
structure Case where
  variant : Variant
  op : Nat
  expected : Option Bool
  pk : Bytes
  sk : Bytes
  msg : Bytes
  sig : Bytes
  calls : List Call

def readCase : Reader Case := do
  let magic ← (List.range 6).mapM fun _ => readByte
  if magic != "DSPX2".toUTF8.toList++[0] then throw "wrong construction header"
  let v ← readByte
  let variant ← match v.toNat with
    | 0 => pure Variant.spx128s | 1 => pure .spx128f
    | 2 => pure .spx192s | 3 => pure .spx192f
    | 4 => pure .spx256s | 5 => pure .spx256f
    | _ => throw "unknown variant"
  let op := (← readByte).toNat
  let e := (← readByte).toNat
  let expected ← match e with
    | 0 => pure none | 1 => pure (some false) | 2 => pure (some true)
    | _ => throw "unknown result"
  let pk ← readBlob
  let sk ← readBlob
  let msg ← readBlob
  let sig ← readBlob
  let count ← readNat
  if count > 1000000 then throw "too many calls"
  let calls ← (List.range count).mapM fun _ => do
    let mode := (← readByte).toNat
    let context ← readBlob
    let context ← match String.fromUTF8? context.toByteArray with
      | some s => pure s | none => throw "invalid context"
    let key ← readBlob
    let input ← readBlob
    let output ← readBlob
    return Call.mk ⟨mode,context,key,input,output.length⟩ output
  let c ← get
  if c.pos != c.bytes.size then throw "trailing bytes"
  return ⟨variant,op,expected,pk,sk,msg,sig,calls⟩

end DSM.Sphincs
