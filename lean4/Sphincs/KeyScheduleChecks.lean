-- SPDX-License-Identifier: MIT OR Apache-2.0
import Sphincs.KeyScheduleHop
open DSM.Rom DSM.Sphincs

/- The KS1 test vectors of `key_schedule::tests::ks1_test_vectors`, recomputed
   with the model's HMAC-BLAKE3 and HKDF (`KeyScheduleHop.lean`). This is an
   executed check that the model computes what the Rust code computes on these
   inputs, not a proof. -/

private def require (condition : Bool) (label : String) : IO Unit :=
  unless condition do throw (IO.userError label)

private def hexOf (b : Bytes) : String := String.join (b.map fun x =>
  let h := "0123456789abcdef".toList
  String.mk [h.getD (x.toNat / 16) '0', h.getD (x.toNat % 16) '0'])

private def seed : Bytes := List.replicate 64 0x5a
private def net : Bytes := "dsm-beta".toUTF8.toList
private def g : Bytes := List.replicate 32 0x47
private def dev : Bytes := List.replicate 32 0x44
private def aph : Bytes := List.replicate 32 0x11

private def vectors : List (String × Bytes) :=
  let w := hkdfExtract saltW seed
  let ds := expand32 w (ksInfo lDevSeed (g ++ le32 0))
  let s0 := expand32 w (ksInfo lS0 (g ++ (le32 0 ++ aph)))
  let q := hkdfExtract saltS0 s0
  let sm := expand32 q (ksInfo lSmaster (g ++ (dev ++ aph)))
  [("genesis_nonce", expand32 w (ksInfo lNonce (lp net ++ le32 0))),
   ("grk_seed", expand32 w (ksInfo lGrk (lp net ++ (le32 0 ++ le32 3)))),
   ("atta", expand32 w (ksInfo lAtta (g ++ le32 0))),
   ("device_seed", ds),
   ("s0", s0),
   ("sdk_entropy", expand32 w (ksInfo lSdk (dev ++ g))),
   ("recovery_aead_key", expand32 w (ksInfo lRecAead [])),
   ("recovery_authority_seed", expand32 w (ksInfo lRecAuth [])),
   ("ak_seed", expand32 (hkdfExtract (ksSalt "DSM/kdf/device-root/v1") ds) (ksInfo lAk aph)),
   ("smaster", sm),
   ("at_rest_key", expand32 q (ksInfo lAtRest (g ++ dev))),
   ("ml_kem_seed", Blake3.keyedHash sm mlkemInput 32)]

/-- The constants `KS1_VECTORS` in `core::identity::key_schedule`. -/
private def rust : List (String × String) :=
  [("genesis_nonce", "5e76000aee25c41c1a01de1a46837ae66eab039bfb056a57073a0cd25f859768"),
   ("grk_seed", "04b8c98b3cc835aa76591c2fc10e1c8e9c66d13da8efac2f528de9c761147cb3"),
   ("atta", "d10e83a47261119e4ceb822453e0fed6ddfe591f5b3f8be00f396ff049644291"),
   ("device_seed", "654337f2220f7ff73796e055d28ddceb6981c599c6ed8127f8ea3a1685907214"),
   ("s0", "47e318c588b79ed838e1d3b681ef66b02be4dc111bc76389a9557162e66f6604"),
   ("sdk_entropy", "589a5ca28f0c1c2e0b449cb8a3b98754b4c471134f1239e4868c49ecf7ead699"),
   ("recovery_aead_key", "1c1d49043341b1766e74183280bf8c578854158ca627269275d0fe5ee702e28c"),
   ("recovery_authority_seed", "6f50a86a1bc8782d4460bdf2085a222873f274e304863610cff0b34322396eff"),
   ("ak_seed", "3e12319bfccf9bbc9b028ffd60b7c2a51ea1d7eec63e4bdb23252d61a047c3c0"),
   ("smaster", "f35c38410205174d7170802c5573826f187febc46dd1f4932a3192a127487386"),
   ("at_rest_key", "3ba00d357efaf61ddab37275c46b8cb64a334e0a6a9f8d751c23e313f0b54b37"),
   ("ml_kem_seed", "978325675bbfaee26c23901f843b9bb03ab281f4fc50ed24a287fb5c78ebed0f")]

def main : IO Unit := do
  require (vectors.length == rust.length) "vector count"
  for ((n, v), (rn, rv)) in vectors.zip rust do
    require (n == rn) s!"vector order: {n} vs {rn}"
    require (hexOf v == rv) s!"KS1 vector {n}: model {hexOf v}, Rust {rv}"
  IO.println s!"KS1: {vectors.length} vectors match"
