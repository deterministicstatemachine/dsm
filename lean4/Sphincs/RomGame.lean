-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.RomSigner
import Sphincs.SecurityGames

/- The EUF-CMA game in the random-oracle model, as a query tree and as a
   symbolic program. The adversary is an interactive program (`RAdv`) that
   makes oracle queries, signing queries and finally outputs a forgery; the
   challenger answers signing queries with the model's `sign`, and the
   forgery is checked with the model's `verify`, whose requests are tagged
   adversary-side (as in `RomBound`). Game H1: the secret key's 3n-byte seed
   expansion is three independent uniform n-byte values, tape entries 0-2,
   registered as oracle entries under a request shape (mode 999) that no DSM
   function issues; the seed hop (ChaCha20 expansion of a secret 32-byte
   seed into those values) is not part of this game. `sim_game`: on every
   tape the real run of the symbolic game returns the query-tree game's
   result, so the hidden-value bound applies to the model's own game. -/
namespace DSM.Rom
open DSM.Sphincs DSM.Sphincs.Security

inductive RAdv where
  | hq (r : Request) (k : Bytes → RAdv)
  | sq (m : Bytes) (k : Option Bytes → RAdv)
  | out (m s : Bytes)

/-- The game's result: the win bit and the transcript the analysis reads. -/
structure Out where
  win : Bool
  msg : Bytes
  sig : Bytes
  signed : List Bytes

def advQ : Oracle QT := fun r => .ask true r .done
def advP : Oracle Prog := fun r => .askA r .done

/-- The game after key generation, as a query tree. -/
def playQT (v : Variant) (limits : Limits) (pk sk : Bytes) : RAdv → List Bytes → QT Out
  | .hq r k, signed => .ask true r (fun b => playQT v limits pk sk (k b) signed)
  | .sq m k, signed =>
    if legal limits m then
      QT.bind (sign challengerOracle v sk m) (fun s => playQT v limits pk sk (k s) (signed ++ [m]))
    else playQT v limits pk sk (k none) signed
  | .out m s, signed =>
    QT.bind (verify advQ v pk m s)
      (fun ok => .done ⟨legal limits m && !signed.contains m && ok.getD false, m, s, signed⟩)

/-- The H1 game as a query tree, from the seed expansion `ex`. -/
def gameQT (v : Variant) (limits : Limits) (A : Bytes → RAdv) (ex : Bytes) : QT Out :=
  QT.bind (kgTail challengerOracle v ex) (fun ks => playQT v limits ks.1 ks.2 (A ks.1) [])

/-- The game after key generation, symbolically: signatures are revealed. -/
def playS (v : Variant) (limits : Limits) (pk : Bytes) (sk : SB) : RAdv → List Bytes → Prog Out
  | .hq r k, signed => .askA r (fun b => playS v limits pk sk (k b) signed)
  | .sq m k, signed =>
    if legal limits m then
      Prog.bind (sSign v sk m) (fun s => match s with
        | none => playS v limits pk sk (k none) (signed ++ [m])
        | some sg => .reveal sg (fun sb => playS v limits pk sk (k (some sb)) (signed ++ [m])))
    else playS v limits pk sk (k none) signed
  | .out m s, signed =>
    Prog.bind (verify advP v pk m s)
      (fun ok => .done ⟨legal limits m && !signed.contains m && ok.getD false, m, s, signed⟩)

def gameS (v : Variant) (limits : Limits) (A : Bytes → RAdv) (ex : SB) : Prog Out :=
  Prog.bind (sKgTail v ex) (fun ks => .reveal ks.1 (fun pk => playS v limits pk ks.2 (A pk) []))

/-- Coin entries: tape entries 0-2 under a request shape no DSM function issues. -/
def coin (n k : Nat) : SReq := ⟨999, "DSM/rom/coin", [], [.hid k n], n⟩
def coinSt (n : Nat) : St := ⟨[(false, coin n 0), (false, coin n 1), (false, coin n 2)], []⟩
def coinEx (n : Nat) : SB := [.hid 0 n, .hid 1 n, .hid 2 n]

/-! The adversary's verification runs unchanged on both sides. -/

section
variable {t : List Nat}

theorem simA (r : Request) : Sim t (advP r) (advQ r) Eq :=
  Sim.askA r _ _ (fun _ => Sim.pure' rfl)

theorem simA_chain (p : Params) (tk : Bytes) (a : Adrs) : ∀ (steps : Nat) (x : Bytes) (start : Nat),
    Sim t (chain advP p tk a x start steps) (chain advQ p tk a x start steps) Eq
  | 0, x, _ => Sim.pure' rfl
  | steps+1, x, start => by
    simp only [chain]
    exact Sim.bind (simA _) (fun y y' h => h ▸ simA_chain p tk a steps y (start+1))

theorem simA_authWalk (p : Params) (tk : Bytes) (a : Adrs) (auth : Bytes) :
    ∀ (remaining li gi level : Nat) (node : Bytes),
    Sim t (authWalk advP p tk a li gi node auth level remaining)
      (authWalk advQ p tk a li gi node auth level remaining) Eq
  | 0, _, _, _, _ => Sim.pure' rfl
  | remaining+1, li, gi, level, node => by
    simp only [authWalk]
    exact Sim.bind (simA _) (fun y y' h => h ▸ simA_authWalk p tk a auth remaining _ _ _ y)

theorem simA_wotsPkFromSig (p : Params) (tk : Bytes) (a : Adrs) (sig msg : Bytes) :
    Sim t (wotsPkFromSig advP p tk a sig msg) (wotsPkFromSig advQ p tk a sig msg) Eq := by
  simp only [wotsPkFromSig, wotsCompress, thash, keyed]
  refine Sim.bind (Sim.forIn _ _ _ Eq ?_ [] [] rfl) (fun x y h => h ▸ simA _)
  intro x _ s s' hs
  obtain ⟨digit, i⟩ := x
  subst hs
  exact Sim.bind (simA_chain p tk _ _ _ _) (fun y y' h => h ▸ Sim.pure' rfl)

theorem simA_xmssPkFromSig (p : Params) (tk : Bytes) (a : Adrs) (idx : Nat) (sig msg : Bytes) :
    Sim t (xmssPkFromSig advP p tk a idx sig msg) (xmssPkFromSig advQ p tk a idx sig msg) Eq := by
  simp only [xmssPkFromSig, authRoot]
  exact Sim.bind (simA_wotsPkFromSig p tk _ _ _) (fun y y' h => h ▸ simA_authWalk p tk _ _ _ _ _ _ _)

theorem simA_htRootTail (p : Params) (tk : Bytes) : ∀ (remaining layer tree : Nat) (node sig : Bytes),
    Sim t (htRootTail advP p tk layer tree node sig remaining)
      (htRootTail advQ p tk layer tree node sig remaining) Eq
  | 0, _, _, _, _ => Sim.pure' rfl
  | remaining+1, layer, tree, node, sig => by
    simp only [htRootTail]
    exact Sim.bind (simA_xmssPkFromSig p tk _ _ _ _) (fun y y' h => h ▸ simA_htRootTail p tk remaining _ _ y _)

theorem simA_htRoot (p : Params) (tk sig msg : Bytes) (tree leaf : Nat) :
    Sim t (htRoot advP p tk sig msg tree leaf) (htRoot advQ p tk sig msg tree leaf) Eq := by
  simp only [htRoot]
  exact Sim.bind (simA_xmssPkFromSig p tk _ _ _ _) (fun y y' h => h ▸ simA_htRootTail p tk _ _ _ y _)

theorem simA_forsPkFromSig (p : Params) (tk : Bytes) (a : Adrs) (sig md : Bytes) :
    Sim t (forsPkFromSig advP p tk a sig md) (forsPkFromSig advQ p tk a sig md) Eq := by
  simp only [forsPkFromSig, authRoot, thash, keyed]
  refine Sim.bind (Sim.forIn _ _ _ Eq ?_ [] [] rfl) (fun x y h => h ▸ simA _)
  intro x _ s s' hs
  obtain ⟨idx, i⟩ := x
  subst hs
  exact Sim.bind (simA _) (fun l l' hl => hl ▸ Sim.bind (simA_authWalk p tk _ _ _ _ _ _ _)
    (fun r r' hr => hr ▸ Sim.pure' rfl))

theorem simA_verify (v : Variant) (pk msg sig : Bytes) :
    Sim t (verify advP v pk msg sig) (verify advQ v pk msg sig) Eq := by
  simp only [verify]
  apply Sim.ite
  · intro _; exact Sim.pure' rfl
  · intro _
    refine Sim.bind Sim.unit (fun _ _ _ => ?_)
    apply Sim.ite
    · intro _; exact Sim.pure' rfl
    · intro _
      refine Sim.bind Sim.unit (fun _ _ _ => ?_)
      refine Sim.bind (simA _) (fun tk tk' h1 => ?_)
      subst h1
      refine Sim.bind (simA _) (fun dg dg' h2 => ?_)
      subst h2
      refine Sim.bind (simA_forsPkFromSig _ _ _ _ _) (fun f f' h3 => ?_)
      subst h3
      refine Sim.bind (simA_htRoot _ _ _ _ _ _) (fun ac ac' h4 => ?_)
      subst h4
      exact Sim.pure' rfl

/-- The symbolic game simulates the query-tree game, for every adversary. -/
theorem sim_play (v : Variant) (limits : Limits) (pk : Bytes) (sk : SB) (sk' : Bytes)
    (hsk : RBn t (params v).n sk sk') :
    ∀ (A : RAdv) (signed : List Bytes),
      Sim t (playS v limits pk sk A signed) (playQT v limits pk sk' A signed) Eq
  | .hq r k, signed => Sim.askA r _ _ (fun _ => sim_play v limits pk sk sk' hsk (k _) signed)
  | .sq m k, signed => by
    simp only [playS, playQT]
    apply Sim.ite
    · intro _
      apply Sim.bind' (sim_sign v sk sk' hsk m)
      intro s s' hs
      cases s with
      | none =>
        simp only [ROpt, Option.map_none] at hs
        subst hs
        exact sim_play v limits pk sk sk' hsk (k none) _
      | some sg =>
        simp only [ROpt, Option.map_some] at hs
        subst hs
        exact Sim.reveal _ _ _ (sim_play v limits pk sk sk' hsk (k (some _)) _)
    · intro _; exact sim_play v limits pk sk sk' hsk (k none) signed
  | .out m s, signed => by
    simp only [playS, playQT]
    exact Sim.bind' (simA_verify v pk m s) (fun ok ok' h => h ▸ Sim.pure' rfl)

theorem coinEx_WN (n : Nat) : WN n (coinEx n) := by
  intro x hx
  simp only [coinEx, List.mem_cons, List.not_mem_nil, or_false] at hx
  rcases hx with rfl | rfl | rfl <;> rfl

theorem sim_game (v : Variant) (limits : Limits) (A : Bytes → RAdv) :
    Sim t (gameS v limits A (coinEx (params v).n))
      (gameQT v limits A (sres t (coinEx (params v).n))) Eq := by
  unfold gameS gameQT
  refine Sim.bind' (sim_kgTail v _ _ ⟨rfl, coinEx_WN _⟩) (fun ks ks' h => ?_)
  apply Sim.reveal
  rw [h.1.1]
  exact sim_play v limits _ ks.2 ks'.2 h.2 _ []
end

/-- Hidden-value link for DSM's own game (H1). The query-tree EUF-CMA game,
    with the model's `kgTail`, `sign` and `verify` against the lazy random
    oracle, is won on at most the symbolic game's tapes plus `B / 2^(8n)`
    plus the wild-guess-or-unopened-collision tapes. `S` bounds the symbolic
    run's steps and entries, `B` its compatible guess pairs. -/
theorem rom_game_hidden (v : Variant) (limits : Limits) (A : Bytes → RAdv) (R N S B : Nat)
    (hR : 256^(params v).n ∣ R)
    (hS : ∀ t s stp, (strace t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n))[s]? = some stp →
      s < S ∧ stp.1.ents.length ≤ S)
    (hB : ∀ t, pairCount (params v).n (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n) S t ≤ B) :
    tsum R N (fun t => if (run t (gameQT v limits A (sres t (coinEx (params v).n)))
        (resD t (coinSt (params v).n))).1.win then 1 else 0) * 256^(params v).n ≤
      tsum R N (fun t => if (xrun false t (gameS v limits A (coinEx (params v).n))
        (coinSt (params v).n)).1.win then 1 else 0) * 256^(params v).n +
      R^N * B +
      tsum R N (fun t => if wildColl (params v).n (gameS v limits A (coinEx (params v).n))
        (coinSt (params v).n) N t then 1 else 0) * 256^(params v).n := by
  have heq : ∀ t, (run t (gameQT v limits A (sres t (coinEx (params v).n)))
      (resD t (coinSt (params v).n))).1.win =
      (xrun true t (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n)).1.win :=
    fun t => congrArg Out.win ((sim_game (t := t) v limits A (coinSt (params v).n)).1).symm
  have h1 := real_le_sym (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n) R N (fun _ r => r.1.win)
  have h2 := hidden_bound (params v).n (gameS v limits A (coinEx (params v).n)) (coinSt (params v).n)
    R N S B hR hS hB
  simp only [heq]
  calc _ ≤ (tsum R N (fun t => if (xrun false t (gameS v limits A (coinEx (params v).n))
            (coinSt (params v).n)).1.win then 1 else 0) +
          tsum R N (fun t => if anyDis (gameS v limits A (coinEx (params v).n))
            (coinSt (params v).n) t then 1 else 0)) * 256^(params v).n :=
        Nat.mul_le_mul_right _ h1
    _ = _ + tsum R N (fun t => if anyDis (gameS v limits A (coinEx (params v).n))
            (coinSt (params v).n) t then 1 else 0) * 256^(params v).n := Nat.add_mul _ _ _
    _ ≤ _ := by rw [Nat.add_assoc]; exact Nat.add_le_add_left h2 _

#print axioms rom_game_hidden

end DSM.Rom
