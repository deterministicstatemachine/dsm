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

abbrev Replay := StateT (Nat × List Call) (Except String)
def replay : Oracle Replay := fun request => do
  let (index,calls) ← get
  match calls with
  | [] => throw s!"missing primitive call {index}"
  | call::rest =>
    if call.request != request then
      throw s!"primitive request mismatch at call {index}: mode={request.mode}, n={request.outLen}"
    set (index+1,rest)
    return call.output

def check (c : Case) : Except String Nat := do
  let action : Replay (Option Bool) := do
    match c.op with
    | 0 => verify replay c.variant c.pk c.msg c.sig
    | 1 =>
      let actual ← sign replay c.variant c.sk c.msg
      return actual.map (· == c.sig)
    | 2 =>
      let seed ← match parse 32 c.msg with
        | some seed => pure seed | none => throw "invalid seed width"
      let (pk,sk) ← generateKeypair replay c.variant seed
      return some (pk == c.pk && sk == c.sk)
    | 3 | 5 =>
      let field ← match parse 32 c.msg with
        | some field => pure field | none => throw "invalid wrapper field width"
      let input := if c.op == 3 then ekCertInput c.pk field else devidInput c.pk field
      let actual ← replay ⟨4,"",[],input,32⟩
      return some (actual == c.sig)
    | 4 =>
      if c.msg.length != 128 || c.sk.length != 32 then throw "invalid EK seed fields"
      let fields ← (List.range 4).mapM fun i =>
        match parse 32 (slice c.msg (32*i) 32) with
        | some field => pure field | none => throw "invalid field"
      match fields with
      | [chain,tip,pre,step] =>
        let actual ← replay ⟨1,"",c.sk,ekSeedInput c.pk chain tip pre step,32⟩
        return some (actual == c.sig)
      | _ => throw "wrong number of fields"
    | 6 =>
      if c.msg.length != 64 then throw "invalid identity binding fields"
      let device ← match parse 32 (c.msg.take 32) with
        | some f => pure f | none => throw "invalid device width"
      let genesis ← match parse 32 (c.msg.drop 32) with
        | some f => pure f | none => throw "invalid genesis width"
      let actual ← replay ⟨4,"",[],identityBindingInput device genesis c.pk,32⟩
      return some (actual == c.sig)
    | 7 =>
      let p := params c.variant
      if c.msg.length != p.n+p.m+36 then throw "invalid utility input width"
      let message := c.msg.take p.n
      let digest := slice c.msg p.n p.m
      let tail := c.msg.drop (p.n+p.m)
      let tree := toInt (tail.take 8)
      let words := tail.drop 8
      let address : Adrs := ⟨toInt (words.take 4),toInt (slice words 4 8),
        toInt (slice words 12 4),toInt (slice words 16 4),
        toInt (slice words 20 4),toInt (slice words 24 4)⟩
      let parameterBytes := ([p.n,p.h,p.d,p.a,p.k,p.hp,p.len,p.mdBytes,p.treeBytes,
        p.leafBytes,p.m,2*p.n,4*p.n,p.sigBytes].flatMap (be 4))
      let indices := splitDigest p digest
      let (leaf,next) := nextLayer p tree
      let actual := (wotsDigits p message).flatMap (be 4) ++ be 8 indices.tree ++
        be 4 indices.leaf ++ be 4 leaf ++ be 8 next ++ (base2b digest p.a p.k).flatMap (be 4)
      return some (c.pk == parameterBytes && c.sk == address.bytes && c.sig == actual)
    | _ => throw "unknown operation"
  let (actual,(count,rest)) ← action.run (0,c.calls)
  if !rest.isEmpty then throw s!"{rest.length} unconsumed primitive calls"
  if actual != c.expected then throw "result differs from Rust"
  return count
end DSM.Sphincs

def main (args : List String) : IO UInt32 := do
  if args.isEmpty then
    IO.eprintln "supply binary Rust transcript files"
    return 1
  for path in args do
    let bytes ← IO.FS.readBinFile path
    let parsed := DSM.Sphincs.readCase.run ⟨bytes,0⟩
    match parsed with
    | .error e => IO.eprintln s!"{path}: {e}"; return 1
    | .ok (c,_) =>
      match DSM.Sphincs.check c with
      | .error e => IO.eprintln s!"{path}: {e}"; return 1
      | .ok n => IO.println s!"{path}: matched {n} primitive requests and Rust result"
  return 0
