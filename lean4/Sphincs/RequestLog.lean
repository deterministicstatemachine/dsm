-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.Model

/- Request logging. Every model function is generic over its monad, so it can
   be run in `LogM`, the state monad over the list of requests asked so far,
   with an oracle that appends each request to the log and answers it from a
   fixed `o : Oracle Id`. Two compositional judgements are provided:

   * `AllReq P x`: `x` only appends to the log, and every request it appends
     satisfies `P`;
   * `Good P x v`: additionally, `x` returns exactly the `Id`-model value `v`
     (the same function run directly against `o`).

   Both are closed under `pure`, `bind`, `forIn` over lists, `if` and the
   logging oracle, which is all the signer's control flow uses. -/
namespace DSM.Sphincs

abbrev LogM := StateM (List Request)

/-- The logging oracle: answer from `o`, append the request to the log. -/
def logOracle (o : Oracle Id) : Oracle LogM :=
  fun r => modifyGet fun s => (o r, s ++ [r])

theorem logOracle_run (o : Oracle Id) (r : Request) (s : List Request) :
    (logOracle o r).run s = (o r, s ++ [r]) := rfl

theorem logM_run_bind {α β : Type} (x : LogM α) (f : α → LogM β) (s : List Request) :
    (x >>= f).run s = (f (x.run s).1).run (x.run s).2 := rfl

theorem logM_run_pure {α : Type} (a : α) (s : List Request) :
    (pure a : LogM α).run s = (a, s) := rfl

theorem id_bind {α β : Type} (x : Id α) (f : α → Id β) : x >>= f = f x := rfl
theorem id_pure {α : Type} (a : α) : (pure a : Id α) = a := rfl

/-- `x` only appends to the log, and everything it appends satisfies `P`. -/
def AllReq {α : Type} (P : Request → Prop) (x : LogM α) : Prop :=
  ∀ s, ∃ L, (x.run s).2 = s ++ L ∧ ∀ r ∈ L, P r

/-- `x` returns the `Id`-model value `v`, only appends to the log, and
    everything it appends satisfies `P`. -/
def Good {α : Type} (P : Request → Prop) (x : LogM α) (v : α) : Prop :=
  ∀ s, ∃ L, x.run s = (v, s ++ L) ∧ ∀ r ∈ L, P r

namespace Good
variable {P Q : Request → Prop}

theorem pure' {α : Type} (a : α) : Good P (pure a : LogM α) a :=
  fun s => ⟨[], by rw [List.append_nil]; rfl, by simp⟩

theorem pure_id {α : Type} (a : α) : Good P (pure a : LogM α) (pure a : Id α) := pure' a

theorem bind' {α β : Type} {x : LogM α} {f : α → LogM β} {v : α} {w : β}
    (hx : Good P x v) (hf : Good P (f v) w) : Good P (x >>= f) w := by
  intro s
  obtain ⟨L₁, e₁, p₁⟩ := hx s
  obtain ⟨L₂, e₂, p₂⟩ := hf (s ++ L₁)
  refine ⟨L₁ ++ L₂, ?_, ?_⟩
  · rw [logM_run_bind, e₁]
    simpa [List.append_assoc] using e₂
  · intro r hr
    rcases List.mem_append.mp hr with h | h
    · exact p₁ r h
    · exact p₂ r h

/-- Bind against the `Id` model's own bind (which is application). -/
theorem bind_id {α β : Type} {x : LogM α} {f : α → LogM β} {v : Id α} {g : α → Id β}
    (hx : Good P x v) (hf : Good P (f v) (g v)) : Good P (x >>= f) (v >>= g) :=
  bind' hx hf

theorem oracle (o : Oracle Id) {r : Request} (hr : P r) : Good P (logOracle o r) (o r) := by
  intro s
  exact ⟨[r], logOracle_run o r s, by simp [hr]⟩

theorem ite' {α : Type} {c : Prop} [Decidable c] {x y : LogM α} {v w : α}
    (hx : c → Good P x v) (hy : ¬c → Good P y w) :
    Good P (if c then x else y) (if c then v else w) := by
  by_cases h : c
  · simp only [h, if_true]; exact hx h
  · simp only [h, if_false]; exact hy h

theorem forIn' {α β : Type} (l : List α) (init : β) {f : α → β → LogM (ForInStep β)}
    {g : α → β → Id (ForInStep β)}
    (hf : ∀ a ∈ l, ∀ b, Good P (f a b) (g a b)) :
    Good P (forIn l init f) (forIn l init g) := by
  induction l generalizing init with
  | nil => exact pure' init
  | cons a l ih =>
    rw [List.forIn_cons, List.forIn_cons]
    apply bind_id (hf a (by simp) init)
    cases g a init with
    | done b => exact pure' b
    | yield b => exact ih b (fun a' h b' => hf a' (by simp [h]) b')

theorem mono {α : Type} {x : LogM α} {v : α} (hPQ : ∀ r, P r → Q r) (hx : Good P x v) :
    Good Q x v := by
  intro s
  obtain ⟨L, e, h⟩ := hx s
  exact ⟨L, e, fun r hr => hPQ r (h r hr)⟩

theorem congr_val {α : Type} {x : LogM α} {v w : α} (hx : Good P x v) (e : v = w) :
    Good P x w := e ▸ hx

theorem allReq {α : Type} {x : LogM α} {v : α} (hx : Good P x v) : AllReq P x := by
  intro s
  obtain ⟨L, e, h⟩ := hx s
  exact ⟨L, by rw [e], h⟩

/-- Run from the empty log: the result is the model value and every logged
    request satisfies `P`. -/
theorem run_empty {α : Type} {x : LogM α} {v : α} (hx : Good P x v) :
    (x.run []).1 = v ∧ ∀ r ∈ (x.run []).2, P r := by
  obtain ⟨L, e, h⟩ := hx []
  rw [e]
  exact ⟨rfl, by simpa using h⟩
end Good

/-- The prefix-closed form: from any log whose entries satisfy `P`, the log
    after `x` still has only `P` entries. -/
theorem AllReq.preserves {α : Type} {P : Request → Prop} {x : LogM α} (hx : AllReq P x)
    (s : List Request) (hs : ∀ r ∈ s, P r) : ∀ r ∈ (x.run s).2, P r := by
  obtain ⟨L, e, h⟩ := hx s
  rw [e]
  intro r hr
  rcases List.mem_append.mp hr with h' | h'
  · exact hs r h'
  · exact h r h'

#print axioms Good.bind'
#print axioms Good.forIn'
#print axioms Good.run_empty
#print axioms AllReq.preserves
end DSM.Sphincs
