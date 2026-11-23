module

public import Statement.Prover.Script
public import Statement.Prover.Mle

/-!
# Flock's honest prover (research build)

The prover of `flockPhase` (`verify_flock`, `crates/verifier/src/flock.rs`): every `BLAKE3`
instance's witness of `2^14` bits, then the zerocheck and the lincheck. The Rust prover is
`flock`'s (`generate_witness_with_ab_packed_and_lincheck`, `Blake2sSetup::prove_reduction_precomputed`,
`crates/stable_prover/flock`, through `crates/lean_vm_core/src/blake3flock.rs`); this one is a
plain reference prover over arrays, computing the same messages, which are fixed by the
protocol.

The circuit is walked by one generic forward walk (`walk`), the shape of the verifier's
`blake3RowValues`, over a monad and a type of wire values: over bits it computes an instance's
witness (each row's slot is set to its product as the row is reached, before any later row reads
it) with its `A₀ z` and `B₀ z`; over a tape of sums it records the matrices once, whose adjoint
gives the lincheck's column weights `A₀ᵀ e + α B₀ᵀ e`.

The witness `z` of instance `j` is indexed `b + 64·s + 2^14·j`, `b` a bit of its 64-bit word `s`
(`q_flock`'s word `s` of instance `j`, slot-major at `s·2^h + j`). The zerocheck binds the low six
coordinates by its univariate skip on the nodes `PHI[0..64]`, the rest by equality-mode rounds;
the lincheck binds the eight word coordinates, highest first, and leaves the `64` slices.
-/

@[expose] public section

namespace LeanVM.Prover.Flock

open LeanVM.Parameters LeanVM.Protocol.Verifier LeanVM.Protocol.Compile

/-! ## The circuit walk, generic -/

/-- What a walk of the circuit computes with: the zero wire, the sum of two wires, the wire of a
column, and setting a row's two sides (`A₀ w` and `B₀ w`). -/
structure Walk (m : Type → Type) (α : Type) where
  zero : α
  add : α → α → m α
  col : ℕ → m α
  setRow : ℕ → α → α → m Unit

section Walk

variable {m : Type → Type} [Monad m] {α : Type} (W : Walk m α)

/-- The word of the columns `base … base + 31`. -/
def slots (base : ℕ) : m (Array α) :=
  (List.range 32).foldlM (fun acc bit ↦ do return acc.push (← W.col (base + bit))) #[]

/-- A constant word: the constant wire `one` at its one bits. -/
def literal (one : α) (value : ℕ) : Array α :=
  Array.ofFn (n := 32) fun bit ↦ if (value >>> bit.val) % 2 = 1 then one else W.zero

/-- The sum of two words, bit by bit. -/
def xorW (x y : Array α) : m (Array α) :=
  (List.range 32).foldlM (fun acc bit ↦ do
    return acc.push (← W.add (x.getD bit W.zero) (y.getD bit W.zero))) #[]

/-- A word rotated right. -/
def rotrW (word : Array α) (amount : ℕ) : Array α :=
  Array.ofFn (n := 32) fun bit ↦ word.getD ((bit.val + amount) % 32) W.zero

/-- A ripple-carry add (`RowValues::add`): row `carryBase + i` (`i < 31`) is
`(x_i + c_i)·(y_i + c_i)`, the carry `c_i` the sum of the rows below it. -/
def addW (x y : Array α) (carryBase : ℕ) : m (Array α) := do
  let mut carry := W.zero
  let mut out : Array α := #[]
  for bit in List.range 32 do
    let xb := x.getD bit W.zero
    let yb := y.getD bit W.zero
    if bit < 31 then
      W.setRow (carryBase + bit) (← W.add xb carry) (← W.add yb carry)
    out := out.push (← W.add (← W.add xb yb) carry)
    if bit < 31 then
      carry ← W.add carry (← W.col (carryBase + bit))
  return out

/-- A fused three-operand add (`RowValues::add3`): `31` majority rows `(x + z)·(y + z)`, then `30`
ripple rows of `x + y + z` against the majorities shifted up a bit. -/
def add3W (x y z : Array α) (base : ℕ) : m (Array α) := do
  let mut majority : Array α := #[]
  for bit in List.range 31 do
    let zb := z.getD bit W.zero
    W.setRow (base + bit) (← W.add (x.getD bit W.zero) zb) (← W.add (y.getD bit W.zero) zb)
    majority := majority.push (← W.add (← W.col (base + bit)) zb)
  let rippleBase := base + 31
  let mut carry := W.zero
  let mut out : Array α := #[]
  for bit in List.range 32 do
    let q := if bit = 0 then W.zero else majority.getD (bit - 1) W.zero
    let left ← W.add (← W.add (← W.add (x.getD bit W.zero) (y.getD bit W.zero))
      (z.getD bit W.zero)) carry
    out := out.push (← W.add left q)
    if 1 ≤ bit ∧ bit ≤ 30 then
      W.setRow (rippleBase + bit - 1) left (← W.add q carry)
      carry ← W.add carry (← W.col (rippleBase + bit - 1))
  return out

/-- The first column of `X` (`x_base`, `flock.rs`). -/
def xBase : ℕ := 1280 + 184 * 56

/-- **The walk of the circuit** (`blake3_row_values`'s, `flock.rs`): the identity rows of the
chaining value, the message, the metadata and `X`, `Y`, `W`; the state from the chaining value,
the IV and the metadata; the effective message; the seven rounds of eight `G`s; the output rows;
the constant row. -/
def walk : m Unit := do
  let one ← W.col blake3ConstantColumn
  for (base, length) in [(0, 256), (640, 512), (1152, 128), (xBase, 768)] do
    for i in List.range length do
      W.setRow (base + i) (← W.col (base + i)) one
  let iv := Semantics.Blake3.iv
  let mut state : Array (Array α) := #[]
  for word in List.range 8 do
    state := state.push (← slots W (32 * word))
  for word in List.range 4 do
    state := state.push (literal W one (iv.getD word 0).toNat)
  for base in [1152, 1184, 1216, 1248] do
    state := state.push (← slots W base)
  let mut message : Array (Array α) := #[]
  for i in List.range 16 do
    let mut word : Array α := #[]
    for j in List.range 32 do
      let slot ← W.col (640 + 32 * i + j)
      match relocationSource (32 * i + j) with
      | some source => word := word.push (← W.add slot (← W.col (xBase + source)))
      | none => word := word.push slot
    message := message.push word
  for (sigma, round) in blake3Sigma.zipIdx do
    for (lanes, gateIndex) in blake3GLanes.zipIdx do
      let la := lanes.getD 0 0
      let lb := lanes.getD 1 0
      let lc := lanes.getD 2 0
      let ld := lanes.getD 3 0
      let gateBase := 1280 + 184 * (round * 8 + gateIndex)
      let mx := message.getD (sigma.getD (2 * gateIndex) 0) #[]
      let my := message.getD (sigma.getD (2 * gateIndex + 1) 0) #[]
      let a1 ← add3W W (state.getD la #[]) (state.getD lb #[]) mx gateBase
      let d1 := rotrW W (← xorW W (state.getD ld #[]) a1) 16
      let c1 ← addW W (state.getD lc #[]) d1 (gateBase + 61)
      let b1 := rotrW W (← xorW W (state.getD lb #[]) c1) 12
      let a2 ← add3W W a1 b1 my (gateBase + 92)
      let d2 := rotrW W (← xorW W d1 a2) 8
      let c2 ← addW W c1 d2 (gateBase + 153)
      let b2 := rotrW W (← xorW W b1 c2) 7
      state := ((state.set! la a2).set! lb b2 |>.set! lc c2).set! ld d2
  for word in List.range 8 do
    let out ← xorW W (state.getD word #[]) (state.getD (word + 8) #[])
    for bit in List.range 32 do
      W.setRow (256 + 32 * word + bit) (out.getD bit W.zero) one
  W.setRow blake3ConstantColumn one one

end Walk

/-! ## An instance's witness -/

/-- The bits a witness walk keeps: `z`, and each row's `A₀ z` and `B₀ z`. -/
structure Bits where
  z : Array Bool
  a : Array Bool
  b : Array Bool

/-- The walk over bits: a row's slot is set to its product when the row is reached. -/
def bitWalk : Walk (StateM Bits) Bool where
  zero := false
  add x y := pure (x != y)
  col c := do return (← get).z.getD c false
  setRow r l rt := modify fun ⟨z, a, b⟩ ↦ ⟨z.set! r (l && rt), a.set! r l, b.set! r rt⟩

/-- An instance's words, `256` 64-bit words a side: `z`, `A₀ z`, `B₀ z`. -/
structure Instance where
  z : Array UInt64
  a : Array UInt64
  b : Array UInt64
  deriving Inhabited

/-- `2^14` bits as `256` little-endian 64-bit words. -/
def packBits (bits : Array Bool) : Array UInt64 :=
  Array.ofFn (n := 256) fun s ↦ (List.range 64).foldl (fun w k ↦
    if bits.getD (64 * s.val + k) false then w ||| ((1 : UInt64) <<< k.toUInt64) else w) 0

/-- Set the `n` bits of `value` from `base` on. -/
def setBits (bits : Array Bool) (base n value : ℕ) : Array Bool :=
  (List.range n).foldl (fun bits k ↦ bits.set! (base + k) ((value >>> k) % 2 = 1)) bits

/-- **An instance's witness** of the compression of `cv` (8 words), the message `msg` (16 words),
the counter, the block length and the flags, and `X ‖ Y ‖ W` (24 words): the inputs placed (the
chaining value at bit `0`, the constant at `512`, the message at `640`, the metadata at `1152`,
`X ‖ Y ‖ W` at `xBase`), then the walk. -/
def instanceOf (cv msg : List ℕ) (counter blockLen flags : ℕ) (xyw : List ℕ) : Instance :=
  let bits := Array.replicate (2 ^ blake3R1csLogSize) false
  let bits := cv.zipIdx.foldl (fun bits (w, k) ↦ setBits bits (32 * k) 32 w) bits
  let bits := bits.set! blake3ConstantColumn true
  let bits := msg.zipIdx.foldl (fun bits (w, k) ↦ setBits bits (640 + 32 * k) 32 w) bits
  let bits := setBits bits 1152 64 counter
  let bits := setBits bits 1216 32 blockLen
  let bits := setBits bits 1248 32 flags
  let bits := xyw.zipIdx.foldl (fun bits (w, k) ↦ setBits bits (xBase + 32 * k) 32 w) bits
  let zero := Array.replicate (2 ^ blake3R1csLogSize) false
  let st := ((walk bitWalk).run ⟨bits, zero, zero⟩).2
  ⟨packBits st.z, packBits st.a, packBits st.b⟩

/-- The four 32-bit words of a cell's two limbs, limb `0`'s low half first. -/
def limbWords (lo hi : K) : List ℕ :=
  let w := fun (k : K) ↦ kToNat k
  [w lo % 2 ^ 32, w lo / 2 ^ 32, w hi % 2 ^ 32, w hi / 2 ^ 32]

/-- The instance of a `BLAKE3` row's value limbs, its row read by local column (`compression`,
`blake3flock.rs`): the message `m0 … m3`, the chaining value `cv0`, `cv1`, the metadata `md`
(the counter in its low limb, the block length and the flags its high limb's halves), and the
`X`, `Y`, `W` pairs. -/
def instanceOfRow (row : ℕ → K) : Instance :=
  let c := columnIndexByName blake3Columns
  let cells := fun (names : List String) ↦
    names.flatMap fun n ↦ limbWords (row (c (n ++ "_lo"))) (row (c (n ++ "_hi")))
  let mdHi := kToNat (row (c "md_hi"))
  instanceOf (cells ["cv0", "cv1"]) (cells ["m0", "m1", "m2", "m3"]) (kToNat (row (c "md_lo")))
    (mdHi % 2 ^ 32) (mdHi / 2 ^ 32) (cells ["x0", "x1", "y0", "y1", "w0", "w1"])

/-- **The padding instance** (`blake3_padding_word`): `blake3(0^64)` as one block, the IV, a zero
message, chunk `0`, `64` bytes, `CHUNK_START | CHUNK_END | ROOT`, zero `X`, `Y`, `W`. -/
def paddingInstance : Instance :=
  instanceOf (Semantics.Blake3.iv.toList.map (·.toNat)) (List.replicate 16 0) 0 64 (1 ||| 2 ||| 8)
    (List.replicate 24 0)

/-- Every instance of a `BLAKE3` table of `rows` rows at the height `2^h`: the rows', then the
padding instance. -/
def instancesOf (rows : Array (Array K)) (h : ℕ) : Array Instance :=
  Array.ofFn (n := 2 ^ h) fun j ↦
    if j.val < rows.size then instanceOfRow fun i ↦ (rows.getD j.val #[]).getD i 0
    else paddingInstance

/-- **`q_flock`**: word `s` of instance `j` at `s·2^h + j`, slot-major (`place`,
`blake3flock.rs`). -/
def qflockColumn (instances : Array Instance) (h : ℕ) : Array K :=
  Array.ofFn (n := 2 ^ (h + qflockSlotBits)) fun i ↦
    K.ofLane ((instances.getD (i.val % 2 ^ h) default).z.getD (i.val / 2 ^ h) 0)

/-! ## The matrices' tape -/

/-- A wire of the tape: the zero wire, a column, or the sum of two earlier wires. -/
inductive Node
  | zero
  | col (c : ℕ)
  | sum (a b : ℕ)
  deriving Inhabited

/-- The tape: its wires, each column's wire once, and each row's two sides' wires. -/
structure Tape where
  nodes : Array Node
  colNode : Array ℕ
  rows : Array (Option (ℕ × ℕ))

/-- The walk over the tape. -/
def tapeWalk : Walk (StateM Tape) ℕ where
  zero := 0
  add a b := do
    if a = 0 then return b
    if b = 0 then return a
    modifyGet fun ⟨nodes, colNode, rows⟩ ↦ (nodes.size, ⟨nodes.push (.sum a b), colNode, rows⟩)
  col c := do
    let t ← get
    let known := t.colNode.getD c 0
    if known ≠ 0 then return known
    modifyGet fun ⟨nodes, colNode, rows⟩ ↦
      (nodes.size, ⟨nodes.push (.col c), colNode.set! c nodes.size, rows⟩)
  setRow r l rt := modify fun ⟨nodes, colNode, rows⟩ ↦ ⟨nodes, colNode, rows.set! r (some (l, rt))⟩

/-- **The matrices `A₀`, `B₀`**, as the tape of one walk: computed once. -/
def tape : Tape :=
  let size := 2 ^ blake3R1csLogSize
  ((walk tapeWalk).run ⟨#[.zero], Array.replicate size 0, Array.replicate size none⟩).2

/-- **The column weights `A₀ᵀ eA + B₀ᵀ eB`**, by the tape's adjoint: each row puts its weights on
its sides' wires, then every wire, last first, passes its weight to its summands, a column's to
the column. -/
def adjoint (eA eB : Array E) : Array E :=
  let t := tape
  let grad := (List.range t.rows.size).foldl (fun grad r ↦
    match t.rows.getD r none with
    | some (l, rt) => (grad.modify l (· + eA.getD r 0)).modify rt (· + eB.getD r 0)
    | none => grad) (Array.replicate t.nodes.size 0)
  let (_, out) := (List.range t.nodes.size).reverse.foldl (fun (st : Array E × Array E) i ↦
    let (grad, out) := st
    let gi := grad.getD i 0
    match t.nodes.getD i .zero with
    | .zero => (grad, out)
    | .col c => (grad, out.modify c (· + gi))
    | .sum a b => ((grad.modify a (· + gi)).modify b (· + gi), out))
    (grad, Array.replicate (2 ^ blake3R1csLogSize) 0)
  out

/-! ## The zerocheck -/

/-- Byte tables of a linear map on 64-bit words: entry `256·k + v` is `Σ_{i < 8, bit i of v}
w_{8k + i}`, so the image of a word is eight lookups. -/
def byteTables (w : Array E) : Array E :=
  Array.ofFn (n := 8 * 256) fun i ↦
    (List.range 8).foldl (fun acc bit ↦
      if ((i.val % 256) >>> bit) % 2 = 1 then acc + w.getD (8 * (i.val / 256) + bit) 0 else acc) 0

/-- The image of a word under a byte-tabled map: `Σ_{b : bit b of x} w_b`. -/
def applyBytes (tables : Array E) (x : UInt64) : E :=
  (List.range 8).foldl (fun acc k ↦
    acc + tables.getD (256 * k + ((x >>> (8 * k).toUInt64) &&& 255).toNat) 0) 0

/-- The equality weights of the zerocheck: an instance's `256` words, then the instances, the
point's coordinates in order. -/
def wordsOf (instances : Array Instance) (side : Instance → Array UInt64) : Array UInt64 :=
  instances.flatMap fun inst ↦ Array.ofFn (n := 256) fun s ↦ (side inst).getD s.val 0

/-- **`P` on the coset** `PHI[64..128]`: `P(Z) = Σ_x' eq(r, x')·(Â·B̂ + Ĉ)(Z, x')`, each hat the
skip coordinate's Lagrange interpolation over `PHI[0..64]`. -/
def pCoset (r : List E) (a b z : Array UInt64) : List E :=
  let eq := eqTable r
  (List.range kBits).map fun t ↦
    let tables := byteTables (lagrangeWeights kBits (phi (kBits + t))).toArray
    (List.range eq.size).foldl (fun acc x ↦
      let (ax, bx, zx) := (a.getD x 0, b.getD x 0, z.getD x 0)
      if ax = 0 ∧ zx = 0 then acc
      else acc + eq.getD x 0 * (applyBytes tables ax * applyBytes tables bx + applyBytes tables zx)) 0

/-- The equality-mode rounds' state: the three tables, and the equality tables of the remaining
coordinates for each round to come. -/
structure ZcState where
  a : Array E
  b : Array E
  c : Array E
  eqs : List (Array E)

/-- A round's coefficients, constant first, of `Σ_m eq_m·(A·B + C)(X, m)`, the bound coordinate
the lowest. -/
def zcRound (st : ZcState) : List E :=
  let w := st.eqs.headD #[]
  let half := st.a.size / 2
  let at' := fun (t : Array E) (m : ℕ) ↦ (t.getD (2 * m) 0, t.getD (2 * m) 0 + t.getD (2 * m + 1) 0)
  let (c0, c1, c2) := (List.range half).foldl (fun (acc : E × E × E) m ↦
    let (la, da) := at' st.a m
    let (lb, db) := at' st.b m
    let (lc, dc) := at' st.c m
    let wm := w.getD m 0
    (acc.1 + wm * (la * lb + lc), acc.2.1 + wm * (la * db + da * lb + dc),
      acc.2.2 + wm * (da * db))) (0, 0, 0)
  [c0, c1, c2]

/-- Bind the lowest coordinate at `c`. -/
def zcFold (st : ZcState) (c : E) : ZcState :=
  ⟨foldPairsA c st.a, foldPairsA c st.b, foldPairsA c st.c, st.eqs.drop 1⟩

/-- **The zerocheck's prover** (`verify_flock_zerocheck`): a grind, the sampled coordinates, `P`
on the coset, a grind, the skip challenge, the equality-mode rounds, `v_a` and `v_b`; the skip
challenge and the round challenges. -/
def zerocheck (instances : Array Instance) (logN : ℕ) : Script (E × List E) := do
  let nSampled := logN - flockKSkip - nFixedChallenges
  if 0 < nSampled then Script.grindBits flockPointGrindBits
  let sampled ← Script.sampleN nSampled
  let r := fixedChallenges ++ sampled
  let a := wordsOf instances (·.a)
  let b := wordsOf instances (·.b)
  let z := wordsOf instances (·.z)
  Script.sendList (pCoset r a b z)
  Script.grindBits flockSkipGrindBits
  let zSkip ← Script.sampleE
  let skip := byteTables (lagrangeWeights kBits zSkip).toArray
  let st : ZcState := ⟨a.map (applyBytes skip), b.map (applyBytes skip), z.map (applyBytes skip),
    (List.range r.length).map fun i ↦ eqTable (r.drop (i + 1))⟩
  let (chi, st) ← sumcheckBy zcRound zcFold (r.map some) st
  Script.sendList [st.a.getD 0 0, st.b.getD 0 0]
  return (zSkip, chi)

/-! ## The lincheck -/

/-- A round's coefficients, constant first, of `Σ W·Z` with the highest coordinate bound. -/
def lcRound (st : Array E × Array E) : List E :=
  let (w, z) := st
  let half := w.size / 2
  let (c0, c1, c2) := (List.range half).foldl (fun (acc : E × E × E) m ↦
    let (lw, lz) := (w.getD m 0, z.getD m 0)
    let (dw, dz) := (w.getD (m + half) 0 + lw, z.getD (m + half) 0 + lz)
    (acc.1 + lw * lz, acc.2.1 + (lw * dz + dw * lz), acc.2.2 + dw * dz)) (0, 0, 0)
  [c0, c1, c2]

/-- Bind the highest coordinate at `c`. -/
def foldTop (c : E) (t : Array E) : Array E :=
  let half := t.size / 2
  Array.ofFn (n := half) fun m ↦
    let lo := t.getD m.val 0
    lo + c * (t.getD (m.val + half) 0 + lo)

/-- **The lincheck's prover** (`verify_flock_lincheck`): a grind, `α`, eight rounds binding the
word coordinates, highest first, of `Σ_c W(c)·Z(c)`, `W = A₀ᵀe + α B₀ᵀe + α² e + α³ [c = 512]`
for `e(row) = L_{row mod 64}(z_skip)·eq(χ_in, ⌊row/64⌋)`, `Z` the witness at the instances' point
`χ_rest`; then the `64` slices. -/
def lincheck (instances : Array Instance) (zSkip : E) (chi : List E) : Script Unit := do
  Script.grindBits (grindingBits 3)
  let alpha ← Script.sampleE
  let skip := (lagrangeWeights kBits zSkip).toArray
  let high := eqTable (chi.take flockNumLincheckRounds)
  let size := 2 ^ blake3R1csLogSize
  let e : Array E := Array.ofFn (n := size) fun row ↦
    skip.getD (row.val % kBits) 0 * high.getD (row.val / kBits) 0
  let wAB := adjoint e (e.map (alpha * ·))
  let w : Array E := Array.ofFn (n := size) fun c ↦
    wAB.getD c.val 0 + alpha ^ 2 * e.getD c.val 0 +
      if c.val = blake3ConstantColumn then alpha ^ 3 else 0
  let inst := eqTable (chi.drop flockNumLincheckRounds)
  let zAt : Array E := Array.ofFn (n := size) fun c ↦
    (List.range instances.size).foldl (fun acc j ↦
      if ((instances.getD j default).z.getD (c.val / 64) 0 >>> (c.val % 64).toUInt64) &&& 1 = 1
      then acc + inst.getD j 0 else acc) 0
  let (_, st) ← sumcheckBy lcRound (fun st c ↦ (foldTop c st.1, foldTop c st.2))
    (List.replicate flockNumLincheckRounds none) (w, zAt)
  Script.sendList st.2.toList

/-- **Flock's prover**, the zerocheck then the lincheck, over the instances of a `BLAKE3` table of
height `2^h`. -/
def prove (instances : Array Instance) (h : ℕ) : Script Unit := do
  let (zSkip, chi) ← zerocheck instances (blake3R1csLogSize + h)
  lincheck instances zSkip chi

end LeanVM.Prover.Flock

end
