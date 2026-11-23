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

/-! The compression (`Semantics.Blake3.compress`) and a block's words (`blockWords`) are the
`BLAKE3` instruction's, in `Statement/LeanIsa.lean`. -/

/-- The flags (`CHUNK_START`, `CHUNK_END`, `ROOT`). -/
def chunkStart : UInt32 := 1
def chunkEnd : UInt32 := 2
def rootFlag : UInt32 := 8

open LeanVM.Semantics.Blake3 in
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
  wordBytes cv.toList

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
the last step's new generation, its external commitment, its attempt key, and the digest of what a release names
(`op_digest`; zeros for a swap or a close). -/
structure VaultChain where
  vaultId : List UInt8
  rFirst : List UInt8
  rLast : List UInt8
  generation : ℕ
  externalCommitment : List UInt8
  attemptKey : List UInt8
  opDigest : List UInt8

/-- The cells a statement absorbs for its vault chain, `14` (`VAULT_CELLS`): each 32-byte field's two
cells, the generation's 16 digits `d_k` as `Σ d_k g^(4k)`, the marker `1`, then the op digest's two
cells; zeros without a chain (`vault_cells`, `crates/aggregation/src/statement.rs`). -/
def vaultCells : Option VaultChain → List E
  | none => List.replicate 14 0
  | some v =>
    cells32 v.vaultId ++ cells32 v.rFirst ++ cells32 v.rLast ++ cells32 v.externalCommitment ++
      cells32 v.attemptKey ++
      [((List.range 16).map fun k ↦ intCell (v.generation / 16 ^ k % 16) * gpow (4 * k)).sum, intCell 1] ++
      cells32 v.opDigest

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

/-- Which operation a step is (`Kind`, `reference.rs`; `SettlementBody`'s three branches): a swap hop,
the owner's full close, or an escrow vault's release naming its terms' bytes, its verdict cell and its
outcome. -/
inductive Kind where
  | swap
  | close
  | release (terms verdictCell outcome : List UInt8)

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
  kind : Kind
  traderGenesis : List UInt8
  traderDeviceId : List UInt8
  relationshipBase : List UInt8
  relationshipPresent : Bool
  externalCommitment : List UInt8
  attempt : ℕ
  statePath : List (List UInt8)
  relationshipPath : List (List UInt8)
  rPrev : List UInt8

/-- A big-endian integer of `n` bytes at byte `i`. -/
def beAt (b : List UInt8) (i n : ℕ) : ℕ :=
  (List.range n).foldl (fun acc k ↦ 256 * acc + (b.getD (i + k) 0).toNat) 0

/-- Signed terms' branches from byte `i`, `k` of them: each label, and the outcome table's bytes so far
(`decode_escrow`: `u32 |o| ‖ o ‖ u8 n ‖ signers` per branch). -/
def signedWalk (b : List UInt8) : ℕ → ℕ → List (List UInt8) × ℕ → List (List UInt8) × ℕ
  | 0, _, acc => acc
  | k + 1, i, (labels, table) =>
    let l := beAt b i 4
    let ns := beAt b (i + 4 + l) 4
    signedWalk b k (i + 8 + l + 70 * ns + 64)
      (labels ++ [(b.drop (i + 4)).take l], table + 5 + l + 70 * ns)

/-- Escrow terms' branch labels and their outcome table's length (`decode_escrow`): signed terms
(`0x0063`) walked, computed terms (`0x0067`) their three fixed labels and no table. -/
def escrowLabels (b : List UInt8) : List (List UInt8) × ℕ :=
  if b.getD 1 0 = 0x63 then signedWalk b (beAt b 68 4) 72 ([], 1)
  else (["a-wins", "b-wins", "void"].map (·.toUTF8.toList), 0)

/-- `length_split`'s hint for an `n`-byte message: `n - 1 = 64 (a + 16 b) + l - 1`, `l ∈ 1..64`. -/
def lengthSplit (n : ℕ) : List E :=
  let q := (n - 1) / 64
  let l := n - 64 * q
  [gpow (q % 16), gpow (q / 16), gpow (l % 16), gpow (l / 16)]

/-- A byte string's nibble digits, low nibble first, zero-padded to `len` (`nibble_digits`). -/
def nibbleDigits (bytes : List UInt8) (len : ℕ) : List E :=
  let d := bytes.flatMap fun x ↦ [gpow (x.toNat % 16), gpow (x.toNat / 16)]
  d ++ List.replicate (len - d.length) (gpow 0)

/-- A release's pushes, stream by stream (`release_hints`, `program.rs`): the terms' length, their
blocks, the outcome's length and bytes, its branch, the outcome table's length (signed terms), and
each dynamic hash's length split: the terms', the table's, the op digest's. -/
def releasePushes (terms outcome : List UInt8) : List (String × List E) :=
  let total := 27 + terms.length
  let blocks := (total + 63) / 64
  let padded := nibbleDigits terms (128 * blocks)
  let (labels, table) := escrowLabels terms
  let j := (labels.findIdx? (· == outcome)).getD 0
  let signed := terms.getD 1 0 = 0x63
  [("vs_branch", [gpow j])] ++
    [("vs_hlen", lengthSplit total)] ++
    (if signed then [("vs_hlen", lengthSplit (28 + table))] else []) ++
    [("vs_hlen", lengthSplit (69 + outcome.length)),
      ("vs_olen", [gpow (outcome.length % 16), gpow (outcome.length / 16)]),
      ("vs_outcome", nibbleDigits outcome 128)] ++
    (if signed then [("vs_qlen", digits (28 + table) 4)] else []) ++
    (List.range blocks).map (fun i ↦ ("vs_terms", (padded.drop (128 * i)).take 128)) ++
    [("vs_tlen", digits terms.length 4)]

/-- `BPS_DENOMINATOR`. -/
def bpsDenominator : ℕ := 10000

/-- The `vs_digits` entries, in the order the step puts them: the state's and the hop's integers
(16 digits each), the fee (8), the token gap `b - a - 1` (64), and, for a swap only, the fee's
complement (4), the price's remainder and its slack to the divisor (21 each), and the reserve left after
the payout (16) (`hints`, `program.rs`). -/
def digitEntries (w : StepWitness) : List (List E) :=
  let s := w.state
  let feeC := bpsDenominator - w.feeBps
  let (rIn, rOut) := if w.inIsA then (s.reserveA, s.reserveB) else (s.reserveB, s.reserveA)
  let afterFee := w.amountIn * feeC
  let den := rIn * bpsDenominator + afterFee
  let rem := rOut * afterFee % den
  [s.createPosition, s.generation, s.reserveA, s.reserveB, w.amountIn, w.amountOut, w.attempt].map
      (digits · 16) ++
    [digits w.feeBps 8, digits (bigEndian w.tokenB - bigEndian w.tokenA - 1) 64] ++
    match w.kind with
    | .swap => [digits feeC 4, digits rem 21, digits (den - rem - 1) 21, digits (rOut - w.amountOut) 16]
    | _ => []

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
  let rel := match w.kind with
    | .release terms _ outcome => releasePushes terms outcome
    | _ => []
  let byName := fun (n : String) ↦ rel.filter (·.1 == n)
  let kindBits := match w.kind with
    | .swap => [false, false, false]
    | .close => [true, false, false]
    | .release terms _ _ => [true, true, terms.getD 1 0 = 0x67]
  [("vs_attempt_is_zero", [bitCell (w.attempt == 0)])] ++ byName "vs_branch" ++
    (digitEntries w).map ("vs_digits", ·) ++
    [("vs_divergence", [gpow (divergence stateKey relKey)]),
      ("vs_flags", [bitCell w.inIsA, bitCell w.relationshipPresent])] ++ byName "vs_hlen" ++
    [("vs_kind", kindBits.map bitCell)] ++ byName "vs_olen" ++ byName "vs_outcome" ++ byName "vs_qlen" ++
    [("vs_relationship_path", w.relationshipPath.flatMap cells32),
      ("vs_state_path", w.statePath.flatMap cells32)] ++ byName "vs_terms" ++ byName "vs_tlen" ++
    (valueEntries w).map ("vs_value", ·)

end LeanVM.Vault

end
