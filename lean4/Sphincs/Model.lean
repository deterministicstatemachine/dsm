import Std

/- Construction v2, read against crates/dsm-sphincs/src/lib.rs.
   Hashes are explicit effectful requests. No security axioms are declared. -/
namespace DSM.Sphincs
abbrev Bytes := List UInt8
inductive Variant where
  | spx128s | spx128f | spx192s | spx192f | spx256s | spx256f
  deriving Repr, BEq, DecidableEq
structure Params where
  n : Nat
  h : Nat
  d : Nat
  a : Nat
  k : Nat
  deriving Repr

def params : Variant → Params
  | .spx128s => ⟨16,63,7,12,14⟩
  | .spx128f => ⟨16,66,22,6,33⟩
  | .spx192s => ⟨24,63,7,14,17⟩
  | .spx192f => ⟨24,66,22,8,33⟩
  | .spx256s => ⟨32,64,8,14,22⟩
  | .spx256f => ⟨32,68,17,9,35⟩
def Params.hp (p : Params) := p.h / p.d
def Params.len (p : Params) := 2*p.n + 3
def Params.forsBytes (p : Params) := p.k*(p.a+1)*p.n
def Params.layerBytes (p : Params) := (p.len+p.hp)*p.n
def Params.sigBytes (p : Params) := p.n+p.forsBytes+p.d*p.layerBytes
def ceil8 (n : Nat) := (n+7)/8
def Params.mdBytes (p : Params) := ceil8 (p.k*p.a)
def Params.treeBytes (p : Params) := ceil8 (p.h-p.hp)
def Params.leafBytes (p : Params) := ceil8 p.hp
def Params.m (p : Params) := p.mdBytes+p.treeBytes+p.leafBytes

-- Natural numbers denote bounded unsigned Rust words. Serialization truncates
-- to each fixed width and is always big endian; generated index bounds are
-- proved separately.
def be : Nat → Nat → Bytes
  | 0, _ => []
  | width+1, x => be width (x/256) ++ [UInt8.ofNat (x%256)]
def toInt (x : Bytes) := x.reverse.foldr (fun b acc => b.toNat+256*acc) 0
def slice (x : Bytes) (start len : Nat) := (x.drop start).take len
structure Adrs where
  layer : Nat := 0
  tree : Nat := 0
  kind : Nat := 0
  keypair : Nat := 0
  chain : Nat := 0
  hash : Nat := 0
  deriving Repr, BEq, DecidableEq

def Adrs.bytes (a : Adrs) : Bytes :=
  be 4 a.layer ++ be 4 0 ++ be 8 a.tree ++ be 4 a.kind ++
  be 4 a.keypair ++ be 4 a.chain ++ be 4 a.hash
def Adrs.setType (a : Adrs) (t : Nat) : Adrs :=
  {a with kind := t, keypair := 0, chain := 0, hash := 0}
def nextLayer (p : Params) (tree : Nat) := (tree % 2^p.hp, tree / 2^p.hp)

-- MSB-first base_2b, expressed by selecting bits rather than duplicating
-- Rust's rolling accumulator. This includes FORS's non-byte-aligned digits.
def base2b (x : Bytes) (b count : Nat) : List Nat :=
  (List.range count).map fun i =>
    (List.range b).foldl (fun acc j =>
      let bit := i*b+j
      let octet := (x[bit/8]?.getD 0).toNat
      acc*2 + (octet / 2^(7-bit%8))%2) 0

def wotsDigits (p : Params) (msg : Bytes) : List Nat := Id.run do
  let digits := base2b msg 4 (2*p.n)
  let checksum := digits.foldl (fun s d => s+15-d) 0
  return digits ++ base2b (be 2 (checksum*16)) 4 3

-- mode 0 = BLAKE3 derive_key(context,input), mode 1 = keyed BLAKE3,
-- mode 2 = derive-key-mode XOF. Keys and contexts are distinct fields.
structure Request where
  mode : Nat
  context : String
  key : Bytes
  input : Bytes
  outLen : Nat
  deriving Repr, BEq, DecidableEq
abbrev Oracle (m : Type → Type) := Request → m Bytes

def deriveKey [Monad m] (o : Oracle m) (context : String) (input : Bytes) : m Bytes :=
  o ⟨0,context,[],input,32⟩
def keyed [Monad m] (o : Oracle m) (n : Nat) (key input : Bytes) : m Bytes :=
  o ⟨1,"",key,input,n⟩
def thash [Monad m] (o : Oracle m) (p : Params) (tk : Bytes) (a : Adrs) (input : Bytes) :=
  keyed o p.n tk (a.bytes ++ input)
def prf [Monad m] (o : Oracle m) (p : Params) (key pkSeed : Bytes) (a : Adrs) :=
  keyed o p.n key (pkSeed ++ a.bytes)
def hmsg [Monad m] (o : Oracle m) (p : Params) (r seed root msg : Bytes) :=
  o ⟨2,"DSM/sphincs/v2/h-msg",[],r++seed++root++msg,p.m⟩

-- Recursive formulation gives a direct chain composition induction.
def chain [Monad m] (o : Oracle m) (p : Params) (tk : Bytes)
    (a : Adrs) (x : Bytes) (start : Nat) : Nat → m Bytes
  | 0 => pure x
  | steps+1 => do
      let y ← thash o p tk {a with hash := start} x
      chain o p tk a y (start+1) steps

def wotsCompress [Monad m] (o : Oracle m) (p : Params) (tk : Bytes)
    (a : Adrs) (tops : Bytes) :=
  thash o p tk {a.setType 1 with keypair := a.keypair} tops

def wotsPkFromSig [Monad m] (o : Oracle m) (p : Params) (tk : Bytes)
    (a : Adrs) (sig msg : Bytes) : m Bytes := do
  let mut tops := []
  for (digit,i) in (wotsDigits p msg).zipIdx do
    let top ← chain o p tk {a with chain := i} (slice sig (i*p.n) p.n) digit (15-digit)
    tops := tops ++ top
  wotsCompress o p tk a tops

-- Shared path fold: FORS retains the keypair; XMSS clears it for TREE.
def siblingIndex (i : Nat) := if i%2 == 0 then i+1 else i-1

def authWalk [Monad m] (o : Oracle m) (p : Params) (tk : Bytes)
    (a : Adrs) (localIndex globalIndex : Nat) (node auth : Bytes) (level : Nat) : Nat → m Bytes
  | 0 => pure node
  | remaining+1 => do
      let sibling := slice auth (level*p.n) p.n
      let index := globalIndex/2
      let address := {a with chain := level+1, hash := index}
      let next ← thash o p tk address
        (if localIndex%2 = 0 then node++sibling else sibling++node)
      authWalk o p tk a (localIndex/2) index next auth (level+1) remaining

def authRoot [Monad m] (o : Oracle m) (p : Params) (tk : Bytes)
    (a : Adrs) (localIndex globalIndex : Nat) (node auth : Bytes) (height : Nat) : m Bytes :=
  authWalk o p tk a localIndex globalIndex node auth 0 height

def xmssPkFromSig [Monad m] (o : Oracle m) (p : Params) (tk : Bytes)
    (a : Adrs) (idx : Nat) (sig msg : Bytes) : m Bytes := do
  let wa := {a.setType 0 with keypair := idx}
  let node ← wotsPkFromSig o p tk wa (sig.take (p.len*p.n)) msg
  authRoot o p tk (a.setType 2) idx idx node (sig.drop (p.len*p.n)) p.hp

def htRoot [Monad m] (o : Oracle m) (p : Params) (tk : Bytes)
    (sig msg : Bytes) (idxTree idxLeaf : Nat) : m Bytes := do
  let mut tree := idxTree
  let mut node ← xmssPkFromSig o p tk {tree := tree} idxLeaf
    (sig.take p.layerBytes) msg
  for layer in (List.range (p.d-1)).map (·+1) do
    let (leaf,next) := nextLayer p tree
    tree := next
    node ← xmssPkFromSig o p tk {layer := layer, tree := tree} leaf
      (slice sig (layer*p.layerBytes) p.layerBytes) node
  return node

def forsPkFromSig [Monad m] (o : Oracle m) (p : Params) (tk : Bytes)
    (a : Adrs) (sig md : Bytes) : m Bytes := do
  let mut roots := []
  for (idx,i) in (base2b md p.a p.k).zipIdx do
    let step := (p.a+1)*p.n
    let globalIndex := i*2^p.a+idx
    let part := slice sig (i*step) step
    let leaf ← thash o p tk {a with chain := 0, hash := globalIndex} (part.take p.n)
    let root ← authRoot o p tk a idx globalIndex leaf (part.drop p.n) p.a
    roots := roots++root
  thash o p tk {a.setType 4 with keypair := a.keypair} roots

structure Indices where
  md : Bytes
  tree : Nat
  leaf : Nat
  deriving Repr, BEq

def splitDigest (p : Params) (digest : Bytes) : Indices :=
  ⟨digest.take p.mdBytes,
   toInt (slice digest p.mdBytes p.treeBytes) % 2^(p.h-p.hp),
   toInt (slice digest (p.mdBytes+p.treeBytes) p.leafBytes) % 2^p.hp⟩

-- Fixed-length wire objects have no tags, alternate encodings or padding.
abbrev Wire (width : Nat) := {bytes : Bytes // bytes.length = width}
def parse (width : Nat) (bytes : Bytes) : Option (Wire width) :=
  if h : bytes.length = width then some ⟨bytes,h⟩ else none
def encode {width : Nat} (wire : Wire width) : Bytes := wire.val

-- none is the crate's empty-message error; some false is rejection.
def verify [Monad m] (o : Oracle m) (v : Variant) (pk msg sig : Bytes) : m (Option Bool) := do
  if msg.isEmpty then return none
  let p := params v
  if pk.length != 2*p.n || sig.length != p.sigBytes then return some false
  let seed := pk.take p.n
  let root := pk.drop p.n
  let tk ← deriveKey o "DSM/sphincs/v2/thash" seed
  let digest ← hmsg o p (sig.take p.n) seed root msg
  let indices := splitDigest p digest
  let fa : Adrs := {tree := indices.tree, kind := 3, keypair := indices.leaf}
  let fpk ← forsPkFromSig o p tk fa (slice sig p.n p.forsBytes) indices.md
  let actual ← htRoot o p tk (sig.drop (p.n+p.forsBytes)) fpk indices.tree indices.leaf
  return some (actual == root)

-- Signing and key generation use the same request interface. Mode 3 is
-- ChaCha20Rng::from_seed(seed).fill_bytes, an explicitly trusted expansion.
def wotsSign [Monad m] (o : Oracle m) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (msg : Bytes) : m Bytes := do
  let mut sig := []
  for (digit,i) in (wotsDigits p msg).zipIdx do
    let sa := {a.setType 5 with keypair := a.keypair, chain := i}
    let sk ← prf o p prfKey seed sa
    let part ← chain o p tk {a with chain := i} sk 0 digit
    sig := sig++part
  return sig

def wotsPkgen [Monad m] (o : Oracle m) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) : m Bytes := do
  let mut tops := []
  for i in List.range p.len do
    let sa := {a.setType 5 with keypair := a.keypair, chain := i}
    let sk ← prf o p prfKey seed sa
    let top ← chain o p tk {a with chain := i} sk 0 15
    tops := tops++top
  wotsCompress o p tk a tops

def xmssNode [Monad m] (o : Oracle m) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (idx : Nat) : Nat → m Bytes
  | 0 => wotsPkgen o p tk prfKey seed {a.setType 0 with keypair := idx}
  | height+1 => do
      let left ← xmssNode o p tk prfKey seed a (2*idx) height
      let right ← xmssNode o p tk prfKey seed a (2*idx+1) height
      thash o p tk {a.setType 2 with chain := height+1, hash := idx} (left++right)

def xmssSign [Monad m] (o : Oracle m) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (idx : Nat) (msg : Bytes) : m Bytes := do
  let mut auth := []
  for level in List.range p.hp do
    let sibling := Nat.xor (idx / 2^level) 1
    let node ← xmssNode o p tk prfKey seed a sibling level
    auth := auth++node
  let sig ← wotsSign o p tk prfKey seed {a.setType 0 with keypair := idx} msg
  return sig++auth

def htSign [Monad m] (o : Oracle m) (p : Params) (tk prfKey seed : Bytes)
    (msg : Bytes) (idxTree idxLeaf : Nat) : m Bytes := do
  let a : Adrs := {tree := idxTree}
  let first ← xmssSign o p tk prfKey seed a idxLeaf msg
  let mut root ← xmssPkFromSig o p tk a idxLeaf first msg
  let mut sig := first
  let mut tree := idxTree
  for layer in (List.range (p.d-1)).map (·+1) do
    let (leaf,next) := nextLayer p tree
    tree := next
    let a : Adrs := {layer := layer, tree := tree}
    let part ← xmssSign o p tk prfKey seed a leaf root
    if layer < p.d-1 then root ← xmssPkFromSig o p tk a leaf part root
    sig := sig++part
  return sig

def forsSecret [Monad m] (o : Oracle m) (p : Params) (prfKey seed : Bytes)
    (a : Adrs) (idx : Nat) : m Bytes :=
  prf o p prfKey seed {a.setType 6 with keypair := a.keypair, hash := idx}

def forsNode [Monad m] (o : Oracle m) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (idx : Nat) : Nat → m Bytes
  | 0 => do
      let sk ← forsSecret o p prfKey seed a idx
      thash o p tk {a with chain := 0, hash := idx} sk
  | height+1 => do
      let left ← forsNode o p tk prfKey seed a (2*idx) height
      let right ← forsNode o p tk prfKey seed a (2*idx+1) height
      thash o p tk {a with chain := height+1, hash := idx} (left++right)

def forsSign [Monad m] (o : Oracle m) (p : Params) (tk prfKey seed : Bytes)
    (a : Adrs) (md : Bytes) : m Bytes := do
  let mut sig := []
  for (idx,i) in (base2b md p.a p.k).zipIdx do
    let sk ← forsSecret o p prfKey seed a (i*2^p.a+idx)
    sig := sig++sk
    for level in List.range p.a do
      let sibling := Nat.xor (idx / 2^level) 1
      let node ← forsNode o p tk prfKey seed a (i*2^(p.a-level)+sibling) level
      sig := sig++node
  return sig

def generateKeypair [Monad m] (o : Oracle m) (v : Variant) (seed32 : Wire 32) : m (Bytes × Bytes) := do
  let p := params v
  let expanded ← o ⟨3,"ChaCha20Rng",[],seed32.val,3*p.n⟩
  let seed := slice expanded (2*p.n) p.n
  let tk ← deriveKey o "DSM/sphincs/v2/thash" seed
  let prfKey ← deriveKey o "DSM/sphincs/v2/prf" (expanded.take p.n)
  let root ← xmssNode o p tk prfKey seed {layer := p.d-1} 0 p.hp
  return (seed++root,expanded++root)

-- none denotes an error (empty message, wrong key length, or failed
-- self-check). The error strings themselves are mapped by the host wrapper.
def sign [Monad m] (o : Oracle m) (v : Variant) (sk msg : Bytes) : m (Option Bytes) := do
  let p := params v
  if msg.isEmpty || sk.length != 4*p.n then return none
  let seed := slice sk (2*p.n) p.n
  let root := sk.drop (3*p.n)
  let tk ← deriveKey o "DSM/sphincs/v2/thash" seed
  let prfKey ← deriveKey o "DSM/sphincs/v2/prf" (sk.take p.n)
  let msgKey ← deriveKey o "DSM/sphincs/v2/prf-msg" (slice sk p.n p.n)
  let r ← keyed o p.n msgKey (seed++msg)
  let digest ← hmsg o p r seed root msg
  let indices := splitDigest p digest
  let a : Adrs := {tree := indices.tree,kind := 3,keypair := indices.leaf}
  let fs ← forsSign o p tk prfKey seed a indices.md
  let fpk ← forsPkFromSig o p tk a fs indices.md
  let hs ← htSign o p tk prfKey seed fpk indices.tree indices.leaf
  let actual ← htRoot o p tk hs fpk indices.tree indices.leaf
  if actual != root then return none
  return some (r++fs++hs)

-- DSM wrapper byte builders. The signing primitive itself does not prepend
-- a domain: the caller owns these bytes and the hash result it signs.
def domainInput (tag : String) (payload : Bytes) : Bytes := tag.toUTF8.toList ++ [0] ++ payload
def ekSeedInput (alg : Bytes) (chain tip pre step : Wire 32) : Bytes :=
  domainInput "DSM/ek/v1" (alg++chain.val++tip.val++pre.val++step.val)
def ekCertInput (pk : Bytes) (tip : Wire 32) := domainInput "DSM/ek-cert" (pk++tip.val)
def devidInput (pk : Bytes) (att : Wire 32) := domainInput "DSM/devid" (pk++att.val)
def identityBindingInput (device genesis : Wire 32) (kem : Bytes) :=
  domainInput "DSM/kyber-identity-binding" (device.val++genesis.val++kem)
def resolutionClaimInput (claim : Bytes) (alg : Nat) (pk : Bytes) (att : Wire 32) :=
  domainInput "DSM/sofi/resolution-claim-sign/v1" (claim++be 2 alg++be 4 pk.length++pk++att.val)
end DSM.Sphincs
