module

public import Statement.LeanVmVerifier

/-!
# Research build: the SoFi vault step a node proves

What the node's statement carries of a vault (`VaultChain`, `crates/claims/src/lib.rs`), the cells
it is absorbed as (`vault_cells`, `crates/aggregation/src/statement.rs`), what a node holds a step
by (`StepWitness`, `crates/vault_step/src/reference.rs`), and the step's hint pushes
(`hints`, `crates/vault_step/src/program.rs`), which need the vault's keys and so BLAKE3
(`reference.rs`'s `h`, the `blake3` crate) on inputs of one chunk.

Transcribed from the research build's Rust, cited by its items' names. What the step proves, and the
statement's relation for it, are not stated here: these are the data and the pushes alone.
-/

@[expose] public section

namespace LeanVM.Vault

open LeanVM.Parameters LeanVM.Protocol LeanVM.Protocol.Verifier LeanVM.Protocol.KeccakHash

/-! ## BLAKE3 on one chunk -/

/-- BLAKE3's IV, SHA-256's (`IV`, the `blake3` crate). -/
def iv : Array UInt32 :=
  #[0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

/-- The message word permutation between rounds (`MSG_PERMUTATION`). -/
def msgPermutation : Array ℕ := #[2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

/-- Rotate right by `n < 32`. -/
def rotr (x : UInt32) (n : UInt32) : UInt32 := (x >>> n) ||| (x <<< (32 - n))

/-- The quarter-round on the state's words `a b c d` with message words `x y` (`g`). -/
def quarter (v : Array UInt32) (a b c d : ℕ) (x y : UInt32) : Array UInt32 :=
  let v := v.set! a (v[a]! + v[b]! + x)
  let v := v.set! d (rotr (v[d]! ^^^ v[a]!) 16)
  let v := v.set! c (v[c]! + v[d]!)
  let v := v.set! b (rotr (v[b]! ^^^ v[c]!) 12)
  let v := v.set! a (v[a]! + v[b]! + y)
  let v := v.set! d (rotr (v[d]! ^^^ v[a]!) 8)
  let v := v.set! c (v[c]! + v[d]!)
  v.set! b (rotr (v[b]! ^^^ v[c]!) 7)

/-- One round: the columns, then the diagonals (`round`). -/
def round (v m : Array UInt32) : Array UInt32 :=
  let v := quarter v 0 4 8 12 m[0]! m[1]!
  let v := quarter v 1 5 9 13 m[2]! m[3]!
  let v := quarter v 2 6 10 14 m[4]! m[5]!
  let v := quarter v 3 7 11 15 m[6]! m[7]!
  let v := quarter v 0 5 10 15 m[8]! m[9]!
  let v := quarter v 1 6 11 12 m[10]! m[11]!
  let v := quarter v 2 7 8 13 m[12]! m[13]!
  quarter v 3 4 9 14 m[14]! m[15]!

/-- The compression function's new chaining value: seven rounds, the message permuted between them,
then the two halves of the state xored (`compress_in_place`). -/
def compress (cv block : Array UInt32) (counter : UInt64) (blockLen flags : UInt32) : Array UInt32 :=
  let v := cv ++ iv.extract 0 4 ++ #[counter.toUInt32, (counter >>> 32).toUInt32, blockLen, flags]
  let rounds := (List.range 7).foldl (fun (vm : Array UInt32 × Array UInt32) i ↦
      let v := round vm.1 vm.2
      (v, if i < 6 then msgPermutation.map (vm.2[·]!) else vm.2)) (v, block)
  (List.range 8).toArray.map fun i ↦ rounds.1[i]! ^^^ rounds.1[i + 8]!

/-- The flags (`CHUNK_START`, `CHUNK_END`, `ROOT`). -/
def chunkStart : UInt32 := 1
def chunkEnd : UInt32 := 2
def rootFlag : UInt32 := 8

/-- A block's sixteen little-endian words, its bytes zero-padded to `64`. -/
def blockWords (bytes : List UInt8) : Array UInt32 :=
  let b := bytes ++ List.replicate (64 - bytes.length) 0
  (List.range 16).toArray.map fun i ↦
    (List.range 4).foldl (fun w j ↦ w ||| ((b.getD (4 * i + j) 0).toUInt32 <<< (8 * j).toUInt32)) 0

/-- **BLAKE3 of an input of at most one chunk** (`1024` bytes): its blocks chained from the IV, the
first flagged as the chunk's start, the last as its end and the root, the counter zero; the
32-byte output, little-endian. Every hash the step's hints need is of one chunk. -/
def blake3 (input : List UInt8) : List UInt8 :=
  let nBlocks := max 1 ((input.length + 63) / 64)
  let cv := (List.range nBlocks).foldl (fun cv i ↦
      let block := (input.drop (64 * i)).take 64
      let flags := (if i = 0 then chunkStart else 0) |||
        (if i + 1 = nBlocks then chunkEnd ||| rootFlag else 0)
      compress cv (blockWords block) 0 block.length.toUInt32 flags) iv
  cv.toList.flatMap fun w ↦ (List.range 4).map fun j ↦ (w >>> (8 * j).toUInt32).toUInt8

/-- A domain-separated hash: the tag, a NUL, the parts (`h`, `reference.rs`). -/
def taggedHash (tag : List UInt8) (parts : List (List UInt8)) : List UInt8 :=
  blake3 (tag ++ [0] ++ parts.flatten)

/-- `TAG_VAULT_STATE_KEY`. -/
def tagVaultStateKey : List UInt8 := "DSM/sofi/vault-state-key/v1".toUTF8.toList
/-- `TAG_REL_KEY`. -/
def tagRelKey : List UInt8 := "DSM/sofi/rel-key/v1".toUTF8.toList

/-- A vault's state leaf's key in the economic tree (`vault_state_key`). -/
def vaultStateKey (vaultId : List UInt8) : List UInt8 := taggedHash tagVaultStateKey [vaultId]

/-- A trader's relationship leaf's key (`relationship_key`). -/
def relationshipKey (genesis deviceId vaultId : List UInt8) : List UInt8 :=
  taggedHash tagRelKey [genesis, deviceId, vaultId]

/-- A key's bit at a depth, the first byte's top bit first (`get_bit`). -/
def keyBit (key : List UInt8) (b : ℕ) : ℕ := ((key.getD (b / 8) 0).toNat >>> (7 - b % 8)) % 2

/-- The tree's height (`HEIGHT`). -/
def height : ℕ := 256

/-- The first depth at which two keys part, `height` for equal keys. -/
def divergence (k₁ k₂ : List UInt8) : ℕ :=
  ((List.range height).find? fun b ↦ keyBit k₁ b ≠ keyBit k₂ b).getD height

/-! ## Cells -/

/-- 16 bytes as a cell, limb `0` the first 8, little-endian (`cell`, `program.rs`). -/
def cell16 (b : List UInt8) : E := E.ofLimbs (K.ofLane (littleEndianLane b 0)) (K.ofLane (littleEndianLane b 1))

/-- A 32-byte value's two cells (`cells`, `program.rs`). -/
def cells32 (b : List UInt8) : List E := [cell16 b, cell16 (b.drop 16)]

/-- An integer below `2^64` as a field element, its bits the polynomial basis's (`F128::from(u128)`). -/
def intCell (n : ℕ) : E := E.ofLimbs (K.ofLane (UInt64.ofNat n)) (K.ofLane 0)

/-- `0` or `1` (`bit`). -/
def bitCell (b : Bool) : E := intCell (if b then 1 else 0)

/-- The `n` base-16 digits of `v`, least significant first, each in the exponent (`digits_u128`). -/
def digits (v n : ℕ) : List E := (List.range n).map fun k ↦ gpow (v / 16 ^ k % 16)

/-- A 32-byte big-endian integer (`gap_be`'s operands). -/
def bigEndian (b : List UInt8) : ℕ := b.foldl (fun acc x ↦ 256 * acc + x.toNat) 0

/-! ## The vault chain a statement carries -/

/-- **A run of consecutive steps of one vault**, as a node's statement carries it (`VaultChain`,
`crates/claims/src/lib.rs`): the vault, the tree root the run starts from and the one it ends at,
the last step's new generation, its external commitment and its attempt key. -/
structure VaultChain where
  vaultId : List UInt8
  rFirst : List UInt8
  rLast : List UInt8
  generation : ℕ
  externalCommitment : List UInt8
  attemptKey : List UInt8

/-- The cells a statement absorbs for its vault chain, `12` (`VAULT_CELLS`): each 32-byte field's two
cells, the generation's 16 digits `d_k` as `Σ d_k g^(4k)`, and the marker `1`; zeros without a
chain (`vault_cells`, `crates/aggregation/src/statement.rs`). -/
def vaultCells : Option VaultChain → List E
  | none => List.replicate 12 0
  | some v =>
    cells32 v.vaultId ++ cells32 v.rFirst ++ cells32 v.rLast ++ cells32 v.externalCommitment ++
      cells32 v.attemptKey ++
      [((List.range 16).map fun k ↦ intCell (v.generation / 16 ^ k % 16) * gpow (4 * k)).sum, intCell 1]

/-! ## The step's witness and its hints -/

/-- The vault's state leaf as a step reads it (`VaultStateLeaf`, `reference.rs`). -/
structure StateLeaf where
  ownerGenesis : List UInt8
  ownerDeviceId : List UInt8
  createPosition : ℕ
  releasePolicy : List UInt8
  storageSetId : List UInt8
  generation : ℕ
  reserveA : ℕ
  reserveB : ℕ

/-- **What a node holds a vault step by** (`VaultStep`, `crates/aggregation/src/node.rs`, of a
`StepWitness`, `reference.rs`): the vault, its state leaf, its tokens and fee, the hop, the trader,
the relationship leaf's base and whether it is present, the external commitment, the successor
attempt, the two leaves' paths (`height` siblings each, 32 bytes) and the root the step starts from. -/
structure StepWitness where
  vaultId : List UInt8
  state : StateLeaf
  tokenA : List UInt8
  tokenB : List UInt8
  feeBps : ℕ
  inIsA : Bool
  amountIn : ℕ
  amountOut : ℕ
  traderGenesis : List UInt8
  traderDeviceId : List UInt8
  relationshipBase : List UInt8
  relationshipPresent : Bool
  externalCommitment : List UInt8
  attempt : ℕ
  statePath : List (List UInt8)
  relationshipPath : List (List UInt8)
  rPrev : List UInt8

/-- `BPS_DENOMINATOR`. -/
def bpsDenominator : ℕ := 10000

/-- The `vs_digits` entries, in the order the step puts them: the state's and the hop's integers
(16 digits each), the fee (8), the token gap `b - a - 1` (64), the fee's complement (4), the
price's remainder and its slack to the divisor (21 each), and the reserve left after the payout (16)
(`hints`, `program.rs`). -/
def digitEntries (w : StepWitness) : List (List E) :=
  let s := w.state
  let feeC := bpsDenominator - w.feeBps
  let (rIn, rOut) := if w.inIsA then (s.reserveA, s.reserveB) else (s.reserveB, s.reserveA)
  let afterFee := w.amountIn * feeC
  let den := rIn * bpsDenominator + afterFee
  let rem := rOut * afterFee % den
  [s.createPosition, s.generation, s.reserveA, s.reserveB, w.amountIn, w.amountOut, w.attempt].map
      (digits · 16) ++
    [digits w.feeBps 8, digits (bigEndian w.tokenB - bigEndian w.tokenA - 1) 64, digits feeC 4,
      digits rem 21, digits (den - rem - 1) 21, digits (rOut - w.amountOut) 16]

/-- The `vs_value` entries: twelve 32-byte values' cells (`hints`, `program.rs`). -/
def valueEntries (w : StepWitness) : List (List E) :=
  [w.vaultId, w.rPrev, w.externalCommitment, w.traderGenesis, w.traderDeviceId, w.relationshipBase,
    w.state.ownerGenesis, w.state.ownerDeviceId, w.state.releasePolicy, w.state.storageSetId,
    w.tokenA, w.tokenB].map cells32

/-- **The step's hint pushes**, each stream's entries in order, the streams by name, as the node
pushes them (`hints`, whose `BTreeMap` orders the streams; `aggregate_with_vault`). -/
def stepPushes (w : StepWitness) : List (String × List E) :=
  let stateKey := vaultStateKey w.vaultId
  let relKey := relationshipKey w.traderGenesis w.traderDeviceId w.vaultId
  [("vs_attempt_is_zero", [bitCell (w.attempt == 0)])] ++
    (digitEntries w).map ("vs_digits", ·) ++
    [("vs_divergence", [gpow (divergence stateKey relKey)]),
      ("vs_flags", [bitCell w.inIsA, bitCell w.relationshipPresent]),
      ("vs_relationship_path", w.relationshipPath.flatMap cells32),
      ("vs_state_path", w.statePath.flatMap cells32)] ++
    (valueEntries w).map ("vs_value", ·)

end LeanVM.Vault

end
