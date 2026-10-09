-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Model

/- Modular proof, strategy revision (map §13, item T5): EasyCrypt's signature
   values and DSM's signature bytes.

   EasyCrypt's signature (`SPHINCS_PLUS.ec` 668) is a triple
   `(mk, sigFORSTW, sigFLSLXMSSMTTW)`: a message key; `k` pairs of a FORS
   leaf secret and an authentication path of `a` nodes (`FORS_ES.ec`
   170–191); and `d` pairs of a WOTS signature of `len` blocks and an
   authentication path of `h'` nodes (`FL_SL_XMSS_MT_ES.ec` 612–634,
   `WOTS_TW_ES.ec` 222). `EcSig` is that triple with every block a byte
   string; `EcSig.Ok` is the subtype conditions plus `n`-byte blocks.

   EasyCrypt builds every authentication path with `cons_ap`
   (`MerkleTrees.ec` 12), which lists the sibling nearest the root first.
   DSM (`forsSign`, `xmssSign`) stores the sibling of the leaf first. So
   `ecEncode` writes `mk ‖ fors ‖ ht` with every path reversed, and
   `ecDecode` cuts the bytes at DSM's fixed offsets and reverses every path
   back.

   Proved: `ecEncode` maps well-formed values to `Params.sigBytes` bytes,
   `ecDecode` inverts it on well-formed values, and `ecEncode ∘ ecDecode` is
   the identity on byte strings of length `Params.sigBytes` (whose decodings
   are well formed). So the two are mutually inverse bijections between
   well-formed EasyCrypt signatures and DSM signature byte strings. -/
namespace DSM.Sphincs.Comp
open DSM.Sphincs

/-- `c` consecutive `w`-byte blocks. -/
def chunks (w : Nat) : Nat → Bytes → List Bytes
  | 0, _ => []
  | c+1, x => x.take w :: chunks w c (x.drop w)

theorem flatten_length (w : Nat) (l : List Bytes) (h : ∀ y ∈ l, y.length = w) :
    l.flatten.length = l.length * w := by
  induction l with
  | nil => simp
  | cons y l ih =>
    simp only [List.flatten_cons, List.length_append, List.length_cons, Nat.succ_mul]
    rw [h y (by simp), ih (fun z hz => h z (by simp [hz]))]
    omega

theorem chunks_flatten (w : Nat) (l : List Bytes) (h : ∀ y ∈ l, y.length = w) :
    chunks w l.length l.flatten = l := by
  induction l with
  | nil => rfl
  | cons y l ih =>
    have hy := h y (by simp)
    have e1 : (y ++ l.flatten).take w = y := by rw [← hy]; exact List.take_left
    have e2 : (y ++ l.flatten).drop w = l.flatten := by rw [← hy]; exact List.drop_left
    simp only [List.length_cons, List.flatten_cons, chunks, e1, e2,
      ih (fun z hz => h z (by simp [hz]))]

theorem chunks_spec (w c : Nat) (x : Bytes) (h : x.length = c*w) :
    (chunks w c x).flatten = x ∧ (chunks w c x).length = c ∧
      ∀ y ∈ chunks w c x, y.length = w := by
  induction c generalizing x with
  | zero =>
    have : x = [] := List.eq_nil_of_length_eq_zero (by simpa using h)
    subst this
    exact ⟨rfl, rfl, by simp [chunks]⟩
  | succ c ih =>
    have hl : (x.drop w).length = c*w := by
      rw [List.length_drop, h, Nat.succ_mul]; omega
    obtain ⟨e1, e2, e3⟩ := ih _ hl
    refine ⟨?_, ?_, ?_⟩
    · simp only [chunks, List.flatten_cons, e1]
      exact List.take_append_drop w x
    · simp only [chunks, List.length_cons, e2]
    · intro y hy
      simp only [chunks, List.mem_cons] at hy
      rcases hy with rfl | hy
      · rw [List.length_take, h, Nat.succ_mul]; omega
      · exact e3 y hy

/-- `c` blocks of `n` bytes. -/
def NodesOk (n c : Nat) (l : List Bytes) : Prop := l.length = c ∧ ∀ y ∈ l, y.length = n

theorem nodesOk_reverse {n c : Nat} {l : List Bytes} (h : NodesOk n c l) :
    NodesOk n c l.reverse :=
  ⟨by rw [List.length_reverse]; exact h.1, fun y hy => h.2 y (List.mem_reverse.mp hy)⟩

theorem nodes_flatten_length {n c : Nat} {l : List Bytes} (h : NodesOk n c l) :
    l.flatten.length = c*n := by
  rw [flatten_length n l h.2, h.1]

theorem chunks_nodes (n c : Nat) (l : List Bytes) (h : NodesOk n c l) :
    chunks n c l.flatten = l := by
  have := chunks_flatten n l h.2
  rwa [h.1] at this

theorem nodes_chunks (n c : Nat) (x : Bytes) (h : x.length = c*n) :
    NodesOk n c (chunks n c x) :=
  ⟨(chunks_spec n c x h).2.1, (chunks_spec n c x h).2.2⟩

/-- An EasyCrypt signature value, blocks as byte strings. -/
structure EcSig where
  key : Bytes
  fors : List (Bytes × List Bytes)
  ht : List (List Bytes × List Bytes)

section
variable (p : Params)

def ForsOk (e : Bytes × List Bytes) : Prop := e.1.length = p.n ∧ NodesOk p.n p.a e.2
def HtOk (e : List Bytes × List Bytes) : Prop := NodesOk p.n p.len e.1 ∧ NodesOk p.n p.hp e.2

/-- EasyCrypt's subtype conditions (sizes `k`, `a`, `d`, `len`, `h'`) with
    `n`-byte blocks. -/
def EcSig.Ok (s : EcSig) : Prop :=
  s.key.length = p.n ∧ s.fors.length = p.k ∧ (∀ e ∈ s.fors, ForsOk p e) ∧
    s.ht.length = p.d ∧ ∀ e ∈ s.ht, HtOk p e

/-- One FORS tree in DSM's order: secret, then the path leaf-first. -/
def serF (e : Bytes × List Bytes) : Bytes := e.1 ++ e.2.reverse.flatten
def parF (y : Bytes) : Bytes × List Bytes := (y.take p.n, (chunks p.n p.a (y.drop p.n)).reverse)
/-- One hypertree layer in DSM's order: WOTS signature, then the path
    leaf-first. -/
def serH (e : List Bytes × List Bytes) : Bytes := e.1.flatten ++ e.2.reverse.flatten
def parH (y : Bytes) : List Bytes × List Bytes :=
  (chunks p.n p.len (y.take (p.len*p.n)), (chunks p.n p.hp (y.drop (p.len*p.n))).reverse)

/-- DSM's signature bytes of an EasyCrypt signature value. -/
def ecEncode (s : EcSig) : Bytes := s.key ++ (s.fors.map serF).flatten ++ (s.ht.map serH).flatten

/-- The EasyCrypt signature value of DSM signature bytes. -/
def ecDecode (x : Bytes) : EcSig :=
  ⟨x.take p.n, (chunks ((p.a+1)*p.n) p.k (slice x p.n p.forsBytes)).map (parF p),
    (chunks p.layerBytes p.d (x.drop (p.n+p.forsBytes))).map (parH p)⟩
end

/-- A toy layout (n = 1, a = 2, k = 1, d = 1, h' = 1, len = 5; 10 bytes): the
    FORS path `[2, 3]` (leaf sibling first) decodes as `[3, 2]` (root first),
    and the one-node hypertree path is unchanged. -/
example : (ecDecode ⟨1,1,1,2,1⟩ ((List.range 10).map UInt8.ofNat)).key = [0] ∧
    (ecDecode ⟨1,1,1,2,1⟩ ((List.range 10).map UInt8.ofNat)).fors = [([1], [[3], [2]])] ∧
    (ecDecode ⟨1,1,1,2,1⟩ ((List.range 10).map UInt8.ofNat)).ht =
      [([[4], [5], [6], [7], [8]], [[9]])] := by decide

section
variable {p : Params}

theorem serF_length {e : Bytes × List Bytes} (h : ForsOk p e) : (serF e).length = (p.a+1)*p.n := by
  simp only [serF, List.length_append, h.1, nodes_flatten_length (nodesOk_reverse h.2),
    Nat.succ_mul]
  omega

theorem parF_serF {e : Bytes × List Bytes} (h : ForsOk p e) : parF p (serF e) = e := by
  obtain ⟨s, ap⟩ := e
  have e1 : (s ++ ap.reverse.flatten).take p.n = s := by rw [← h.1]; exact List.take_left
  have e2 : (s ++ ap.reverse.flatten).drop p.n = ap.reverse.flatten := by
    rw [← h.1]; exact List.drop_left
  simp only [parF, serF, e1, e2, chunks_nodes _ _ _ (nodesOk_reverse h.2), List.reverse_reverse]

theorem serF_parF {y : Bytes} (h : y.length = (p.a+1)*p.n) :
    serF (parF p y) = y ∧ ForsOk p (parF p y) := by
  have hd : (y.drop p.n).length = p.a*p.n := by rw [List.length_drop, h, Nat.succ_mul]; omega
  obtain ⟨f, _, _⟩ := chunks_spec p.n p.a _ hd
  refine ⟨?_, ?_, nodesOk_reverse (nodes_chunks _ _ _ hd)⟩
  · simp only [serF, parF, List.reverse_reverse, f]
    exact List.take_append_drop _ _
  · show (y.take p.n).length = p.n
    rw [List.length_take, h, Nat.succ_mul]; omega

theorem serH_length {e : List Bytes × List Bytes} (h : HtOk p e) : (serH e).length = p.layerBytes := by
  simp only [serH, List.length_append, nodes_flatten_length h.1,
    nodes_flatten_length (nodesOk_reverse h.2), Params.layerBytes, Nat.add_mul]

theorem parH_serH {e : List Bytes × List Bytes} (h : HtOk p e) : parH p (serH e) = e := by
  obtain ⟨w, ap⟩ := e
  have hw : w.flatten.length = p.len*p.n := nodes_flatten_length h.1
  have e1 : (w.flatten ++ ap.reverse.flatten).take (p.len*p.n) = w.flatten := by
    rw [← hw]; exact List.take_left
  have e2 : (w.flatten ++ ap.reverse.flatten).drop (p.len*p.n) = ap.reverse.flatten := by
    rw [← hw]; exact List.drop_left
  simp only [parH, serH, e1, e2, chunks_nodes _ _ _ h.1, chunks_nodes _ _ _ (nodesOk_reverse h.2),
    List.reverse_reverse]

theorem serH_parH {y : Bytes} (h : y.length = p.layerBytes) :
    serH (parH p y) = y ∧ HtOk p (parH p y) := by
  have ht : (y.take (p.len*p.n)).length = p.len*p.n := by
    rw [List.length_take, h, Params.layerBytes, Nat.add_mul]; omega
  have hd : (y.drop (p.len*p.n)).length = p.hp*p.n := by
    rw [List.length_drop, h, Params.layerBytes, Nat.add_mul]; omega
  obtain ⟨f1, _, _⟩ := chunks_spec p.n p.len _ ht
  obtain ⟨f2, _, _⟩ := chunks_spec p.n p.hp _ hd
  refine ⟨?_, nodes_chunks _ _ _ ht, nodesOk_reverse (nodes_chunks _ _ _ hd)⟩
  simp only [serH, parH, List.reverse_reverse, f1, f2]
  exact List.take_append_drop _ _

/-- Encoding then cutting a list of fixed-width parts gives the list back. -/
theorem decode_list {α : Type} (W : Nat) (ser : α → Bytes) (par : Bytes → α) (Ok : α → Prop)
    (l : List α) (hw : ∀ e, Ok e → (ser e).length = W) (hp : ∀ e, Ok e → par (ser e) = e)
    (hl : ∀ e ∈ l, Ok e) : (chunks W l.length (l.map ser).flatten).map par = l := by
  have := chunks_flatten W (l.map ser) (fun y hy => by
    obtain ⟨e, he, rfl⟩ := List.mem_map.mp hy
    exact hw e (hl e he))
  rw [List.length_map] at this
  rw [this, List.map_map]
  conv => rhs; rw [← List.map_id l]
  exact List.map_congr_left (fun e he => hp e (hl e he))

theorem encode_list {α : Type} (W c : Nat) (ser : α → Bytes) (par : Bytes → α) (Ok : α → Prop)
    (hs : ∀ y : Bytes, y.length = W → ser (par y) = y ∧ Ok (par y)) (x : Bytes)
    (hx : x.length = c*W) :
    (((chunks W c x).map par).map ser).flatten = x ∧ ((chunks W c x).map par).length = c ∧
      ∀ e ∈ (chunks W c x).map par, Ok e := by
  obtain ⟨f, len, ws⟩ := chunks_spec W c x hx
  refine ⟨?_, by rw [List.length_map, len], ?_⟩
  · rw [List.map_map]
    conv => rhs; rw [← f]
    congr 1
    conv => rhs; rw [← List.map_id (chunks W c x)]
    exact List.map_congr_left (fun y hy => (hs y (ws y hy)).1)
  · intro e he
    obtain ⟨y, hy, rfl⟩ := List.mem_map.mp he
    exact (hs y (ws y hy)).2

theorem forsBytes_eq (p : Params) : p.forsBytes = p.k*((p.a+1)*p.n) := by
  simp only [Params.forsBytes, Nat.mul_assoc]

/-- A well-formed EasyCrypt signature encodes to `sigBytes` bytes. -/
theorem ecEncode_length (s : EcSig) (h : s.Ok p) : (ecEncode s).length = p.sigBytes := by
  obtain ⟨hm, hk, hf, hd, hh⟩ := h
  have f1 := flatten_length _ (s.fors.map serF) (fun y hy => by
    obtain ⟨e, he, rfl⟩ := List.mem_map.mp hy; exact serF_length (hf e he))
  have f2 := flatten_length _ (s.ht.map serH) (fun y hy => by
    obtain ⟨e, he, rfl⟩ := List.mem_map.mp hy; exact serH_length (hh e he))
  simp only [List.length_map] at f1 f2
  simp only [ecEncode, List.length_append, hm, f1, f2, hk, hd, Params.sigBytes, forsBytes_eq,
    Nat.mul_comm p.d]

/-- `ecDecode` inverts `ecEncode` on well-formed EasyCrypt signatures. -/
theorem ecDecode_ecEncode (s : EcSig) (h : s.Ok p) : ecDecode p (ecEncode s) = s := by
  obtain ⟨hm, hk, hf, hd, hh⟩ := h
  have lf : (s.fors.map serF).flatten.length = p.forsBytes := by
    rw [flatten_length _ _ (fun y hy => by
      obtain ⟨e, he, rfl⟩ := List.mem_map.mp hy; exact serF_length (hf e he)),
      List.length_map, hk, forsBytes_eq]
  have e0 : (s.key ++ (s.fors.map serF).flatten ++ (s.ht.map serH).flatten).take p.n = s.key := by
    rw [List.append_assoc, ← hm]; exact List.take_left
  have e1 : slice (s.key ++ (s.fors.map serF).flatten ++ (s.ht.map serH).flatten) p.n p.forsBytes =
      (s.fors.map serF).flatten := by
    unfold slice
    rw [List.append_assoc, ← hm, List.drop_left, ← lf]
    exact List.take_left
  have e2 : (s.key ++ (s.fors.map serF).flatten ++ (s.ht.map serH).flatten).drop (p.n+p.forsBytes) =
      (s.ht.map serH).flatten := by
    rw [← hm, ← lf, ← List.length_append]
    exact List.drop_left
  obtain ⟨key, fors, ht⟩ := s
  simp only at hm hk hf hd hh e0 e1 e2
  simp only [ecDecode, ecEncode, e0, e1, e2, EcSig.mk.injEq, true_and]
  constructor
  · rw [forsBytes_eq] at lf
    have := decode_list ((p.a+1)*p.n) serF (parF p) (ForsOk p) fors (fun _ h => serF_length h)
      (fun _ h => parF_serF h) hf
    rwa [hk] at this
  · have := decode_list p.layerBytes serH (parH p) (HtOk p) ht (fun _ h => serH_length h)
      (fun _ h => parH_serH h) hh
    rwa [hd] at this

/-- `ecEncode` inverts `ecDecode` on byte strings of DSM's signature length,
    and their decodings are well formed. -/
theorem ecEncode_ecDecode (x : Bytes) (hx : x.length = p.sigBytes) :
    ecEncode (ecDecode p x) = x ∧ (ecDecode p x).Ok p := by
  have hlf : (slice x p.n p.forsBytes).length = p.k*((p.a+1)*p.n) := by
    unfold slice
    rw [List.length_take, List.length_drop, hx, Params.sigBytes, ← forsBytes_eq]; omega
  have hlh : (x.drop (p.n+p.forsBytes)).length = p.d*p.layerBytes := by
    rw [List.length_drop, hx, Params.sigBytes]; omega
  have hlm : (x.take p.n).length = p.n := by
    rw [List.length_take, hx, Params.sigBytes]; omega
  obtain ⟨ff, fl, fo⟩ := encode_list _ p.k serF (parF p) (ForsOk p) (fun y h => serF_parF h) _ hlf
  obtain ⟨hf, hl, ho⟩ := encode_list _ p.d serH (parH p) (HtOk p) (fun y h => serH_parH h) _ hlh
  refine ⟨?_, hlm, fl, fo, hl, ho⟩
  simp only [ecEncode, ecDecode, ff, hf]
  unfold slice
  rw [List.append_assoc]
  conv => rhs; rw [← List.take_append_drop p.n x]
  congr 1
  have hrest : (x.drop p.n).length = p.forsBytes + p.d*p.layerBytes := by
    rw [List.length_drop, hx, Params.sigBytes]; omega
  conv => rhs; rw [← List.take_append_drop p.forsBytes (x.drop p.n)]
  rw [List.drop_drop]

#print axioms ecDecode_ecEncode
#print axioms ecEncode_ecDecode
#print axioms ecEncode_length
end
end DSM.Sphincs.Comp
