//! Vault Fulfillment Mechanisms
//!
//! This module defines the fulfillment mechanisms for Deterministic Limbo Vaults (DLVs).
//! Fulfillment mechanisms specify the conditions under which a vault can be unlocked.

use std::fmt;

/// Mechanism for fulfilling vault conditions
#[derive(Debug, Clone, PartialEq)]
pub enum FulfillmentMechanism {
    /// Payment-based fulfillment mechanism
    Payment {
        /// Required payment amount
        amount: u64,
        /// Token ID to be paid with
        token_id: String,
        /// Recipient of the payment
        recipient: String,
        /// State to be used for verification
        verification_state: Vec<u8>,
    },

    /// Cryptographic condition fulfillment
    CryptoCondition {
        /// Hash of the condition
        condition_hash: Vec<u8>,
        /// Public parameters for verification
        public_params: Vec<u8>,
    },

    /// Multi-signature fulfillment mechanism
    MultiSignature {
        /// Public keys of all potential signers
        public_keys: Vec<Vec<u8>>,
        /// Number of signatures required for fulfillment
        threshold: usize,
    },

    /// State reference verification
    StateReference {
        /// List of reference state hashes
        reference_states: Vec<Vec<u8>>,
        /// Parameters for verification
        parameters: Vec<u8>,
    },

    /// Random walk verification
    RandomWalkVerification {
        /// Public verification key
        verification_key: Vec<u8>,
        /// Statement to be verified
        statement: String,
    },

    /// Dual-hashlock Bitcoin HTLC for DSM vault settlement ("Tap" construction).
    ///
    /// A BitcoinHTLC is the "tap" mechanism — a dual-hashlock HTLC that connects
    /// Bitcoin collateral (the "keg") to DSM dBTC tokens. Opening a tap deposits BTC;
    /// drawing from it finalizes a deposit; draining it sweeps all BTC back out.
    ///
    /// Per main.tex Definition 7.1, the HTLC has two spend paths:
    ///   (a) Fulfill: holder reveals preimage of `hash_lock` (h_f) via Burn proof
    ///   (b) Refund: depositor reveals preimage of `refund_hash_lock` (h_r) via budget exhaustion
    ///
    /// The DSM determines which path resolves; Bitcoin merely checks the preimage.
    /// No clock synchronization required between DSM and Bitcoin.
    BitcoinHTLC {
        /// SHA256 hash of the fulfill preimage h_f (32 bytes).
        /// h_f = SHA256(sk_V) where sk_V = BLAKE3("DSM/dlv-unlock\0" || L || C || sigma)
        hash_lock: [u8; 32],
        /// SHA256 hash of the refund preimage h_r (32 bytes).
        /// h_r = SHA256(rk_V) where rk_V = BLAKE3("DSM/dlv-refund\0" || vault_id || C_bytes || iterations_le)
        refund_hash_lock: [u8; 32],
        /// DSM state iterations before depositor can derive rk_V and reclaim
        refund_iterations: u64,
        /// Counterparty's Bitcoin compressed pubkey (33 bytes)
        bitcoin_pubkey: Vec<u8>,
        /// Expected Bitcoin payment amount in satoshis
        expected_btc_amount_sats: u64,
        /// Bitcoin network (0=mainnet, 1=testnet, 2=signet).
        /// Determines checkpoint set and difficulty floor for header chain verification.
        network: u32,
        /// Minimum Bitcoin block depth before vault transition is accepted.
        /// dBTC paper §6.4, §12.1.3: canonical value = 100 for both entry and exit.
        /// Enforced in verify_bitcoin_htlc — proofs with fewer confirmations are rejected.
        min_confirmations: u64,
    },

    /// Compound AND condition (all must be satisfied)
    And(Vec<FulfillmentMechanism>),

    /// Compound OR condition (any can be satisfied)
    Or(Vec<FulfillmentMechanism>),
}

impl fmt::Display for FulfillmentMechanism {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            // TimeRelease removed: DSM protocol is clockless; use state/iteration-based unlocks
            FulfillmentMechanism::Payment {
                amount, token_id, ..
            } => write!(f, "Payment of {amount} {token_id}"),
            FulfillmentMechanism::CryptoCondition { .. } => write!(f, "Cryptographic Condition"),
            FulfillmentMechanism::MultiSignature { threshold, .. } => {
                write!(f, "{threshold}-of-n MultiSignature")
            }
            FulfillmentMechanism::StateReference { .. } => write!(f, "State Reference"),
            FulfillmentMechanism::RandomWalkVerification { statement, .. } => {
                write!(f, "RandomWalk: {statement}")
            }
            FulfillmentMechanism::BitcoinHTLC {
                expected_btc_amount_sats,
                ..
            } => write!(f, "Bitcoin HTLC ({expected_btc_amount_sats} sats)"),
            FulfillmentMechanism::And(conditions) => {
                write!(f, "AND({} conditions)", conditions.len())
            }
            FulfillmentMechanism::Or(conditions) => {
                write!(f, "OR({} conditions)", conditions.len())
            }
        }
    }
}
