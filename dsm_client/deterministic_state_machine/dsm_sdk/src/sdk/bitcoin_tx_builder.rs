//! Bitcoin Transaction Builder — HTLC claim and sweep transactions.
//!
//! Constructs and signs Bitcoin transactions for claiming funds locked in
//! HTLC contracts during dBTC deposit and withdrawal operations.
//!
//! ## Witness structure
//!
//! For the claim path (preimage reveal):
//! ```text
//! witness: [<signature> <preimage> <TRUE (0x01)> <redeemScript>]
//! ```
//!
//! For the refund path (budget-exhaustion preimage reveal):
//! ```text
//! witness: [<signature> <preimage> <FALSE (empty)> <redeemScript>]
//! ```
//!
//! The redeem script is the raw HTLC script from `build_htlc_script`.

use bitcoin::blockdata::script::ScriptBuf;
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::blockdata::witness::Witness;
use bitcoin::hashes::Hash;
use bitcoin::{Amount, Sequence, Txid};
use dsm::types::error::DsmError;

use super::bitcoin_key_store::BitcoinKeyStore;

/// Estimated virtual size (vbytes) for a P2WSH HTLC claim transaction.
///
/// Breakdown:
/// - TX overhead: ~10 vbytes
/// - Input (P2WSH with witness): ~160 vbytes (depends on script + witness size)
/// - Output (P2WPKH): ~31 vbytes
///
/// Total: ~201 vbytes (conservative estimate)
pub const ESTIMATED_CLAIM_VSIZE: u64 = 210;

/// Estimated virtual size for a 2-output claim (sweep + change to successor HTLC).
pub const ESTIMATED_SWEEP_VSIZE: u64 = 260;

/// Signing authority for spending an HTLC claim path.
///
/// `MathOwned` vaults derive the spend key deterministically from the revealed
/// preimage plus the vault's hash lock, so the builder computes that key
/// internally instead of depending on the caller to hand in raw secret material.
pub enum HtlcSpendSigner<'a> {
    /// Sign with a wallet-managed Bitcoin key.
    Wallet {
        key_store: &'a BitcoinKeyStore,
        signing_index: u32,
    },
    /// Derive the math-owned claim key from `preimage || hash_lock`.
    MathOwned { hash_lock: &'a [u8; 32] },
}

/// Parameters for building an HTLC claim transaction.
pub struct ClaimTxParams<'a> {
    /// Transaction ID containing the HTLC output
    pub outpoint_txid: &'a [u8; 32],
    /// Output index within that transaction
    pub outpoint_vout: u32,
    /// The raw HTLC redeem script bytes
    pub htlc_script: &'a [u8],
    /// The secret that satisfies the SHA256 hash lock
    pub preimage: &'a [u8],
    /// Where to send the claimed BTC (bech32 address string)
    pub destination_addr: &'a str,
    /// Amount locked in the HTLC (in satoshis)
    pub amount_sats: u64,
    /// Fee rate in sat/vbyte
    pub fee_rate_sat_vb: u64,
    /// Signing authority for the claim path.
    pub signer: HtlcSpendSigner<'a>,
    /// Expected Bitcoin network — used to validate the destination address
    pub network: bitcoin::Network,
}

/// Build a claim transaction that spends an HTLC output by revealing the preimage.
///
/// The witness stack is: `[signature, preimage, TRUE, redeemScript]`
pub fn build_htlc_claim_tx(params: &ClaimTxParams<'_>) -> Result<Transaction, DsmError> {
    // Parse and validate the destination address against the expected network
    let dest_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = params
        .destination_addr
        .parse()
        .map_err(|e| DsmError::invalid_operation(format!("Invalid destination address: {e}")))?;

    let dest_addr = dest_addr
        .require_network(params.network)
        .map_err(|e| DsmError::invalid_operation(format!("Address network mismatch: {e}")))?;
    let dest_script = dest_addr.script_pubkey();

    // Calculate fee
    let fee = params.fee_rate_sat_vb * ESTIMATED_CLAIM_VSIZE;
    if fee >= params.amount_sats {
        return Err(DsmError::invalid_operation(format!(
            "Fee ({fee} sats) exceeds available amount ({} sats)",
            params.amount_sats
        )));
    }
    let output_amount = params.amount_sats - fee;

    // Dust output validation
    const DUST_LIMIT: u64 = 546;
    if output_amount < DUST_LIMIT {
        return Err(DsmError::invalid_operation(format!(
            "Output {output_amount} sats below dust limit ({DUST_LIMIT} sats) after {fee} sats fee"
        )));
    }

    // Build the unsigned transaction
    let txid = Txid::from_byte_array(*params.outpoint_txid);
    let outpoint = OutPoint::new(txid, params.outpoint_vout);

    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(), // SegWit: empty scriptSig
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(), // filled below
    };

    let tx_out = TxOut {
        value: Amount::from_sat(output_amount),
        script_pubkey: dest_script,
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out],
    };

    // Compute the sighash for P2WSH spending
    let htlc_script_buf = ScriptBuf::from(params.htlc_script.to_vec());
    let sighash = compute_p2wsh_sighash(
        &tx,
        0, // input index
        &htlc_script_buf,
        Amount::from_sat(params.amount_sats),
    )?;

    let sig_der = sign_claim_sighash(&params.signer, params.preimage, &sighash)?;

    // Build witness: [sig+sighash_type, preimage, TRUE, redeemScript]
    let mut sig_with_hashtype = sig_der;
    sig_with_hashtype.push(0x01); // SIGHASH_ALL

    let mut witness = Witness::new();
    witness.push(&sig_with_hashtype);
    witness.push(params.preimage);
    witness.push([0x01]); // TRUE — claim path (OP_IF branch)
    witness.push(params.htlc_script);

    tx.input[0].witness = witness;

    Ok(tx)
}

/// Parameters for building a sweep transaction with change to a successor HTLC.
pub struct SweepTxParams<'a> {
    /// Transaction ID containing the HTLC output
    pub outpoint_txid: &'a [u8; 32],
    /// Output index
    pub outpoint_vout: u32,
    /// The raw HTLC redeem script bytes
    pub htlc_script: &'a [u8],
    /// The secret
    pub preimage: &'a [u8],
    /// Where to send the claimed portion
    pub dest_addr: &'a str,
    /// Amount to claim (send to destination)
    pub claim_sats: u64,
    /// New HTLC script for the change
    pub successor_htlc_script: &'a [u8],
    /// Total amount in the HTLC
    pub total_sats: u64,
    /// Fee rate
    pub fee_rate_sat_vb: u64,
    /// Signing authority for the claim path.
    pub signer: HtlcSpendSigner<'a>,
    /// Expected Bitcoin network — used to validate the destination address
    pub network: bitcoin::Network,
}

/// Build a sweep transaction with change back to a successor HTLC.
///
/// Used for fractional redemption: claim part of the locked BTC to a destination,
/// and send the remainder to a new HTLC for continued backing.
pub fn build_sweep_and_change_tx(params: &SweepTxParams<'_>) -> Result<Transaction, DsmError> {
    let dest_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> = params
        .dest_addr
        .parse()
        .map_err(|e| DsmError::invalid_operation(format!("Invalid destination address: {e}")))?;
    let dest_address = dest_address
        .require_network(params.network)
        .map_err(|e| DsmError::invalid_operation(format!("Address network mismatch: {e}")))?;
    let dest_script = dest_address.script_pubkey();

    // Successor HTLC gets a P2WSH output
    let successor_script_buf = ScriptBuf::from(params.successor_htlc_script.to_vec());
    let successor_wsh = ScriptBuf::new_p2wsh(&successor_script_buf.wscript_hash());

    let fee = params.fee_rate_sat_vb * ESTIMATED_SWEEP_VSIZE;

    // Token conservation: the claimer pays the miner fee from their own
    // sweep output.  The remainder (successor HTLC) stays whole so the
    // on-chain collateral exactly matches the DSM-recorded balance.
    if fee >= params.claim_sats {
        return Err(DsmError::invalid_operation(format!(
            "Fee ({fee}) exceeds claim amount ({}) — claimer cannot cover tx fee",
            params.claim_sats
        )));
    }
    let claim_after_fee = params.claim_sats - fee;
    let change_sats = params.total_sats - params.claim_sats;

    // Dust output validation
    const DUST_LIMIT: u64 = 546;
    if change_sats == 0 {
        return Err(DsmError::invalid_operation(
            "Change amount is zero — use build_htlc_claim_tx instead for full claims",
        ));
    }
    if change_sats < DUST_LIMIT {
        return Err(DsmError::invalid_operation(format!(
            "Change {change_sats} sats below dust limit ({DUST_LIMIT} sats)"
        )));
    }
    if claim_after_fee < DUST_LIMIT {
        return Err(DsmError::invalid_operation(format!(
            "Claim output {} sats below dust limit ({DUST_LIMIT} sats) after {fee} sats fee",
            claim_after_fee
        )));
    }

    let txid = Txid::from_byte_array(*params.outpoint_txid);
    let outpoint = OutPoint::new(txid, params.outpoint_vout);

    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    // Output 0: claim to destination (claimer pays the miner fee)
    let claim_out = TxOut {
        value: Amount::from_sat(claim_after_fee),
        script_pubkey: dest_script,
    };

    // Output 1: change to successor HTLC
    let change_out = TxOut {
        value: Amount::from_sat(change_sats),
        script_pubkey: successor_wsh,
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![tx_in],
        output: vec![claim_out, change_out],
    };

    // Sign
    let htlc_script_buf = ScriptBuf::from(params.htlc_script.to_vec());
    let sighash = compute_p2wsh_sighash(
        &tx,
        0,
        &htlc_script_buf,
        Amount::from_sat(params.total_sats),
    )?;

    let sig_der = sign_claim_sighash(&params.signer, params.preimage, &sighash)?;
    let mut sig_with_hashtype = sig_der;
    sig_with_hashtype.push(0x01); // SIGHASH_ALL

    let mut witness = Witness::new();
    witness.push(&sig_with_hashtype);
    witness.push(params.preimage);
    witness.push([0x01]); // TRUE — claim path
    witness.push(params.htlc_script);

    tx.input[0].witness = witness;

    Ok(tx)
}

/// Estimated virtual size for an HTLC refund transaction.
///
/// Refund spends use the same witness size as fulfill spends: signature, preimage,
/// branch selector, redeem script.
pub const ESTIMATED_REFUND_VSIZE: u64 = ESTIMATED_CLAIM_VSIZE;

/// Parameters for building an HTLC refund transaction (refund hashlock path).
pub struct RefundTxParams<'a> {
    /// Transaction ID containing the HTLC output
    pub outpoint_txid: &'a [u8; 32],
    /// Output index
    pub outpoint_vout: u32,
    /// The raw HTLC redeem script bytes
    pub htlc_script: &'a [u8],
    /// The refund preimage that satisfies the refund hashlock
    pub preimage: &'a [u8],
    /// Where to send the refunded BTC
    pub refund_addr: &'a str,
    /// Amount locked in the HTLC (in satoshis)
    pub amount_sats: u64,
    /// Fee rate in sat/vbyte
    pub fee_rate_sat_vb: u64,
    /// Key store for signing
    pub key_store: &'a BitcoinKeyStore,
    /// Address index to use for signing
    pub signing_index: u32,
    /// Expected Bitcoin network
    pub network: bitcoin::Network,
}

/// Build a refund transaction that spends an HTLC output via the refund hashlock path.
///
/// The witness stack is: `[signature, preimage, FALSE, redeemScript]`
pub fn build_htlc_refund_tx(params: &RefundTxParams<'_>) -> Result<Transaction, DsmError> {
    // Parse and validate the refund address
    let refund_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = params
        .refund_addr
        .parse()
        .map_err(|e| DsmError::invalid_operation(format!("Invalid refund address: {e}")))?;

    let refund_addr = refund_addr
        .require_network(params.network)
        .map_err(|e| DsmError::invalid_operation(format!("Address network mismatch: {e}")))?;
    let refund_script = refund_addr.script_pubkey();

    // Calculate fee
    let fee = params.fee_rate_sat_vb * ESTIMATED_REFUND_VSIZE;
    if fee >= params.amount_sats {
        return Err(DsmError::invalid_operation(format!(
            "Fee ({fee} sats) exceeds available amount ({} sats)",
            params.amount_sats
        )));
    }
    let output_amount = params.amount_sats - fee;

    // Dust output validation
    const DUST_LIMIT: u64 = 546;
    if output_amount < DUST_LIMIT {
        return Err(DsmError::invalid_operation(format!(
            "Output {output_amount} sats below dust limit ({DUST_LIMIT} sats) after {fee} sats fee"
        )));
    }

    let txid = Txid::from_byte_array(*params.outpoint_txid);
    let outpoint = OutPoint::new(txid, params.outpoint_vout);

    let tx_in = TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let tx_out = TxOut {
        value: Amount::from_sat(output_amount),
        script_pubkey: refund_script,
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: vec![tx_in],
        output: vec![tx_out],
    };

    // Sign
    let htlc_script_buf = ScriptBuf::from(params.htlc_script.to_vec());
    let sighash = compute_p2wsh_sighash(
        &tx,
        0,
        &htlc_script_buf,
        Amount::from_sat(params.amount_sats),
    )?;

    let sig_der = params
        .key_store
        .sign_hash(0, params.signing_index, &sighash)?;
    let mut sig_with_hashtype = sig_der;
    sig_with_hashtype.push(0x01); // SIGHASH_ALL

    // Witness: [sig, preimage, FALSE, redeemScript] — refund hashlock path (OP_ELSE)
    let mut witness = Witness::new();
    witness.push(&sig_with_hashtype);
    witness.push(params.preimage);
    witness.push([]); // FALSE — refund path (OP_ELSE branch)
    witness.push(params.htlc_script);

    tx.input[0].witness = witness;

    Ok(tx)
}

/// Serialize a transaction to raw bytes suitable for broadcast.
pub fn serialize_raw_tx(tx: &Transaction) -> Vec<u8> {
    bitcoin::consensus::encode::serialize(tx)
}

/// Compute the transaction ID (double-SHA256 of serialized tx, reversed).
pub fn compute_txid(tx: &Transaction) -> [u8; 32] {
    let txid = tx.compute_txid();
    *txid.as_byte_array()
}

/// Estimate the virtual size for a claim transaction.
pub fn estimate_claim_vsize() -> u64 {
    ESTIMATED_CLAIM_VSIZE
}

/// Estimate the virtual size for a sweep+change transaction.
pub fn estimate_sweep_vsize() -> u64 {
    ESTIMATED_SWEEP_VSIZE
}

/// Locate the HTLC output index in a raw transaction by matching P2WSH script hash.
///
/// Given a serialized transaction and the raw HTLC redeem script, computes the
/// P2WSH script pubkey (OP_0 <SHA256(script)>) and finds the first output whose
/// script_pubkey matches.
///
/// Returns `Some(vout)` if found, `None` otherwise.
pub fn find_htlc_vout(raw_tx_bytes: &[u8], htlc_script: &[u8]) -> Option<u32> {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hashes::sha256;

    let tx: Transaction = deserialize(raw_tx_bytes).ok()?;

    // Build the expected P2WSH script pubkey: OP_0 <32-byte SHA256 of htlc_script>
    let script_hash = sha256::Hash::hash(htlc_script);
    let p2wsh = ScriptBuf::new_p2wsh(&bitcoin::WScriptHash::from_raw_hash(script_hash));

    for (i, txout) in tx.output.iter().enumerate() {
        if txout.script_pubkey == p2wsh {
            return Some(i as u32);
        }
    }
    None
}

// ──────────────────────────────────────────────────────────
// HTLC funding transaction (user wallet → HTLC P2WSH)
// ──────────────────────────────────────────────────────────

/// Estimated vsize per P2WPKH input (~68 vB: 32+4 txid/vout + 4 seq + ~27 witness)
const P2WPKH_INPUT_VSIZE: u64 = 68;
/// P2WSH output vsize (~43 vB)
const P2WSH_OUTPUT_VSIZE: u64 = 43;
/// P2WPKH output vsize (~31 vB)
const P2WPKH_OUTPUT_VSIZE: u64 = 31;
/// Transaction overhead vsize
const TX_OVERHEAD_VSIZE: u64 = 11;

/// A selected UTXO with its derivation path for signing.
pub struct SelectedUtxo {
    /// Raw txid in internal (reversed) byte order, as stored by Bitcoin Core / bitcoin crate.
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount_sats: u64,
    /// BIP84 derivation: 0 = receive, 1 = change
    pub change: u32,
    /// BIP84 derivation index
    pub index: u32,
    /// Compressed public key (33 bytes)
    pub pubkey: [u8; 33],
}

/// Parameters for building the HTLC funding transaction.
pub struct FundingTxParams<'a> {
    /// Selected UTXOs to spend (must cover amount + fee)
    pub inputs: &'a [SelectedUtxo],
    /// HTLC P2WSH address to fund
    pub htlc_address: &'a str,
    /// Exact amount to send to the HTLC (in satoshis)
    pub htlc_amount_sats: u64,
    /// Change address (P2WPKH, from user's BIP84 change derivation)
    pub change_address: &'a str,
    /// Fee rate in sat/vbyte
    pub fee_rate_sat_vb: u64,
    /// Key store for signing
    pub key_store: &'a BitcoinKeyStore,
    /// Expected Bitcoin network
    pub network: bitcoin::Network,
}

/// Estimate the fee for a funding transaction.
pub fn estimate_funding_fee(num_inputs: u64, has_change: bool, fee_rate_sat_vb: u64) -> u64 {
    let vsize = TX_OVERHEAD_VSIZE
        + num_inputs * P2WPKH_INPUT_VSIZE
        + P2WSH_OUTPUT_VSIZE
        + if has_change { P2WPKH_OUTPUT_VSIZE } else { 0 };
    vsize * fee_rate_sat_vb
}

/// Build and sign a transaction that funds an HTLC P2WSH address from the user's
/// BIP84 P2WPKH wallet UTXOs.
///
/// Witness per input: `[sig+SIGHASH_ALL, compressed_pubkey]` (standard P2WPKH).
pub fn build_htlc_funding_tx(params: &FundingTxParams<'_>) -> Result<Transaction, DsmError> {
    if params.inputs.is_empty() {
        return Err(DsmError::invalid_operation(
            "No UTXOs provided for funding".to_string(),
        ));
    }

    // Parse and validate addresses
    let htlc_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = params
        .htlc_address
        .parse()
        .map_err(|e| DsmError::invalid_operation(format!("Invalid HTLC address: {e}")))?;
    let htlc_addr = htlc_addr
        .require_network(params.network)
        .map_err(|e| DsmError::invalid_operation(format!("HTLC address network mismatch: {e}")))?;

    let change_addr: bitcoin::Address<bitcoin::address::NetworkUnchecked> = params
        .change_address
        .parse()
        .map_err(|e| DsmError::invalid_operation(format!("Invalid change address: {e}")))?;
    let change_addr = change_addr.require_network(params.network).map_err(|e| {
        DsmError::invalid_operation(format!("Change address network mismatch: {e}"))
    })?;

    // Calculate total input value
    let total_input: u64 = params.inputs.iter().map(|u| u.amount_sats).sum();

    // Estimate fee (with change output first; may drop change if dust)
    let fee_with_change =
        estimate_funding_fee(params.inputs.len() as u64, true, params.fee_rate_sat_vb);

    if total_input < params.htlc_amount_sats + fee_with_change {
        // Try without change output
        let fee_no_change =
            estimate_funding_fee(params.inputs.len() as u64, false, params.fee_rate_sat_vb);
        if total_input < params.htlc_amount_sats + fee_no_change {
            return Err(DsmError::invalid_operation(format!(
                "Insufficient funds: have {} sats, need {} + {} fee",
                total_input, params.htlc_amount_sats, fee_no_change
            )));
        }
    }

    // Build outputs
    let htlc_output = TxOut {
        value: Amount::from_sat(params.htlc_amount_sats),
        script_pubkey: htlc_addr.script_pubkey(),
    };

    let mut outputs = vec![htlc_output];

    // Calculate change
    let fee_with_change =
        estimate_funding_fee(params.inputs.len() as u64, true, params.fee_rate_sat_vb);
    let change_sats = total_input
        .saturating_sub(params.htlc_amount_sats)
        .saturating_sub(fee_with_change);

    const DUST_LIMIT: u64 = 546;
    let has_change = change_sats >= DUST_LIMIT;
    if has_change {
        outputs.push(TxOut {
            value: Amount::from_sat(change_sats),
            script_pubkey: change_addr.script_pubkey(),
        });
    }

    // Build unsigned inputs
    let tx_inputs: Vec<TxIn> = params
        .inputs
        .iter()
        .map(|utxo| {
            TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array(utxo.txid), utxo.vout),
                script_sig: ScriptBuf::new(), // SegWit: empty
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(), // filled below
            }
        })
        .collect();

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::blockdata::locktime::absolute::LockTime::ZERO,
        input: tx_inputs,
        output: outputs,
    };

    // Sign each input (BIP143 P2WPKH sighash)
    for (i, utxo) in params.inputs.iter().enumerate() {
        let sighash =
            compute_p2wpkh_sighash(&tx, i, &utxo.pubkey, Amount::from_sat(utxo.amount_sats))?;

        let sig_der = params
            .key_store
            .sign_hash(utxo.change, utxo.index, &sighash)?;

        // P2WPKH witness: [sig+SIGHASH_ALL, compressed_pubkey]
        let mut sig_with_hashtype = sig_der;
        sig_with_hashtype.push(0x01); // SIGHASH_ALL

        let mut witness = Witness::new();
        witness.push(&sig_with_hashtype);
        witness.push(utxo.pubkey);
        tx.input[i].witness = witness;
    }

    Ok(tx)
}

/// Parse a display-order (explorer) hex txid into Bitcoin internal byte order (reversed).
/// Use only at I/O boundaries where a display-hex string arrives from external sources.
/// Within the system, pass `[u8; 32]` directly.
pub fn display_txid_to_internal(hex: &str) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    if hex.len() != 64 {
        log::warn!(
            "[display_txid_to_internal] unexpected txid hex length {}, expected 64",
            hex.len()
        );
        return bytes;
    }
    for i in 0..32 {
        let hi = i * 2;
        if let Ok(b) = u8::from_str_radix(&hex[hi..hi + 2], 16) {
            bytes[31 - i] = b;
        }
    }
    bytes
}

// --- Internal ---

/// Sign a sighash directly with a raw 32-byte private key.
///
/// Used by math-owned vaults where the claim key is derived from the
/// preimage via `derive_claim_keypair`, bypassing the BitcoinKeyStore.
fn sign_with_raw_privkey(privkey: &[u8; 32], sighash: &[u8; 32]) -> Result<Vec<u8>, DsmError> {
    use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(privkey)
        .map_err(|e| DsmError::invalid_operation(format!("Invalid claim privkey: {e}")))?;
    let message = Message::from_digest(*sighash);
    let signature = secp.sign_ecdsa(&message, &secret_key);
    Ok(signature.serialize_der().to_vec())
}

fn sign_claim_sighash(
    signer: &HtlcSpendSigner<'_>,
    preimage: &[u8],
    sighash: &[u8; 32],
) -> Result<Vec<u8>, DsmError> {
    match signer {
        HtlcSpendSigner::Wallet {
            key_store,
            signing_index,
        } => key_store.sign_hash(0, *signing_index, sighash),
        HtlcSpendSigner::MathOwned { hash_lock } => {
            let (claim_privkey, _) = derive_claim_keypair(preimage, hash_lock)?;
            sign_with_raw_privkey(&claim_privkey, sighash)
        }
    }
}

/// Compute BIP143 sighash for P2WPKH spending.
///
/// In `bitcoin` crate 0.32+, `p2wpkh_signature_hash` expects the P2WPKH
/// scriptPubKey (`OP_0 <20-byte-pubkey-hash>`), NOT the P2PKH script code.
/// The crate internally derives the BIP143 script code from the P2WPKH script.
fn compute_p2wpkh_sighash(
    tx: &Transaction,
    input_index: usize,
    compressed_pubkey: &[u8; 33],
    value: Amount,
) -> Result<[u8; 32], DsmError> {
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use bitcoin::key::CompressedPublicKey;

    let cpk = CompressedPublicKey::from_slice(compressed_pubkey)
        .map_err(|e| DsmError::invalid_operation(format!("Invalid pubkey: {e}")))?;

    // P2WPKH scriptPubKey: OP_0 <20-byte-witness-pubkey-hash>
    let script_pubkey = bitcoin::ScriptBuf::new_p2wpkh(&cpk.wpubkey_hash());

    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wpkh_signature_hash(input_index, &script_pubkey, value, EcdsaSighashType::All)
        .map_err(|e| DsmError::invalid_operation(format!("P2WPKH sighash failed: {e}")))?;

    Ok(*sighash.as_byte_array())
}

/// Compute BIP143 sighash for P2WSH spending.
fn compute_p2wsh_sighash(
    tx: &Transaction,
    input_index: usize,
    redeem_script: &ScriptBuf,
    value: Amount,
) -> Result<[u8; 32], DsmError> {
    use bitcoin::sighash::{EcdsaSighashType, SighashCache};

    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wsh_signature_hash(input_index, redeem_script, value, EcdsaSighashType::All)
        .map_err(|e| DsmError::invalid_operation(format!("Sighash computation failed: {e}")))?;

    Ok(*sighash.as_byte_array())
}

/// Derive a Bitcoin claim keypair deterministically from a vault preimage.
///
/// Math-owned vaults: whoever possesses the preimage can derive the claim
/// private key and sign a sweep transaction. No separate key distribution
/// or DLV control transfer is needed.
///
/// The hash_lock (SHA256(preimage)) is used as domain binding because it:
/// - Is known before vault_id exists (needed at HTLC creation time)
/// - Is unique per vault (preimage is 32 random bytes)
/// - Is embedded in the HTLC script (natural binding)
/// - Is known at sweep time (from the vault record)
///
/// ```text
/// claim_privkey = BLAKE3_keyed(key=H("DSM/dbtc-claim\0"), data=preimage||hash_lock)
/// claim_pubkey  = secp256k1_point(claim_privkey)
/// ```
///
/// Returns `(privkey_bytes: [u8; 32], compressed_pubkey: [u8; 33])`.
pub fn derive_claim_keypair(
    preimage: &[u8],
    hash_lock: &[u8; 32],
) -> Result<([u8; 32], [u8; 33]), DsmError> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let mut input = Vec::with_capacity(preimage.len() + 32);
    input.extend_from_slice(preimage);
    input.extend_from_slice(hash_lock);
    let derived = dsm::crypto::blake3::domain_hash("DSM/dbtc-claim", &input);

    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(derived.as_bytes())
        .map_err(|e| DsmError::invalid_operation(format!("derive_claim_keypair: {e}")))?;
    let public_key = secret_key.public_key(&secp);

    let mut compressed = [0u8; 33];
    compressed.copy_from_slice(&public_key.serialize());
    Ok((*derived.as_bytes(), compressed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sdk::bitcoin_key_store::BitcoinKeyStore;
    use dsm::bitcoin::script::{build_htlc_script, sha256_hash_lock};
    use dsm::bitcoin::types::BitcoinNetwork;

    /// Test-only: generate a dummy refund hash from a fulfill hash.
    fn test_refund_hash(fulfill_hash: &[u8; 32]) -> [u8; 32] {
        sha256_hash_lock(fulfill_hash)
    }

    fn test_entropy() -> [u8; 32] {
        let mut e = [0u8; 32];
        for (i, b) in e.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
        e
    }

    #[test]
    fn build_claim_tx_produces_valid_structure() {
        let ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Signet) {
            Ok(k) => k,
            Err(e) => panic!("BitcoinKeyStore::from_entropy failed: {:?}", e),
        };
        let preimage = b"test preimage for atomic swap!!";
        let hash_lock = sha256_hash_lock(preimage);

        // Get our pubkey for the HTLC
        let pk = match ks.get_compressed_pubkey(0) {
            Ok(p) => p,
            Err(e) => panic!("get_compressed_pubkey failed: {:?}", e),
        };
        let refund_pk = [0x03; 33];

        let refund_hash = test_refund_hash(&hash_lock);
        let htlc_script = match build_htlc_script(&hash_lock, &refund_hash, &pk, &refund_pk) {
            Ok(s) => s,
            Err(e) => panic!("build_htlc_script failed: {:?}", e),
        };

        let outpoint_txid = [0xAA; 32];
        let dest = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";

        let tx = match build_htlc_claim_tx(&ClaimTxParams {
            outpoint_txid: &outpoint_txid,
            outpoint_vout: 0,
            htlc_script: &htlc_script,
            preimage,
            destination_addr: dest,
            amount_sats: 100_000,
            fee_rate_sat_vb: 2, // 2 sat/vbyte
            signer: HtlcSpendSigner::Wallet {
                key_store: &ks,
                signing_index: 0,
            },
            network: bitcoin::Network::Signet,
        }) {
            Ok(t) => t,
            Err(e) => panic!("build_htlc_claim_tx failed: {:?}", e),
        };

        // Verify structure
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);

        // Witness should have 4 items: [sig, preimage, TRUE, redeemScript]
        assert_eq!(tx.input[0].witness.len(), 4);

        // Output amount should be input minus fee
        let fee = 2 * ESTIMATED_CLAIM_VSIZE;
        assert_eq!(tx.output[0].value.to_sat(), 100_000 - fee);

        // Serialization should succeed
        let raw = serialize_raw_tx(&tx);
        assert!(!raw.is_empty());
    }

    #[test]
    fn claim_tx_rejects_fee_exceeds_amount() {
        let ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Signet) {
            Ok(k) => k,
            Err(e) => panic!("BitcoinKeyStore::from_entropy failed: {:?}", e),
        };
        let preimage = b"test preimage for atomic swap!!";
        let hash_lock = sha256_hash_lock(preimage);
        let pk = match ks.get_compressed_pubkey(0) {
            Ok(p) => p,
            Err(e) => panic!("get_compressed_pubkey failed: {:?}", e),
        };
        let refund_hash = test_refund_hash(&hash_lock);
        let htlc_script = match build_htlc_script(&hash_lock, &refund_hash, &pk, &[0x03; 33]) {
            Ok(s) => s,
            Err(e) => panic!("build_htlc_script failed: {:?}", e),
        };

        let result = build_htlc_claim_tx(&ClaimTxParams {
            outpoint_txid: &[0xAA; 32],
            outpoint_vout: 0,
            htlc_script: &htlc_script,
            preimage,
            destination_addr: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            amount_sats: 100,     // very small amount
            fee_rate_sat_vb: 100, // high fee rate — 100 * 210 = 21000 > 100
            signer: HtlcSpendSigner::Wallet {
                key_store: &ks,
                signing_index: 0,
            },
            network: bitcoin::Network::Signet,
        });

        assert!(result.is_err());
    }

    #[test]
    fn build_refund_tx_uses_refund_hashlock_branch() {
        let ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Signet) {
            Ok(k) => k,
            Err(e) => panic!("BitcoinKeyStore::from_entropy failed: {:?}", e),
        };
        let preimage = b"refund preimage for atomic swap";
        let hash_lock = sha256_hash_lock(b"fulfill preimage for atomic swap");
        let refund_hash = sha256_hash_lock(preimage);
        let pk = match ks.get_compressed_pubkey(0) {
            Ok(p) => p,
            Err(e) => panic!("get_compressed_pubkey failed: {:?}", e),
        };
        let htlc_script = match build_htlc_script(&hash_lock, &refund_hash, &pk, &pk) {
            Ok(s) => s,
            Err(e) => panic!("build_htlc_script failed: {:?}", e),
        };

        let tx = match build_htlc_refund_tx(&RefundTxParams {
            outpoint_txid: &[0xDD; 32],
            outpoint_vout: 0,
            htlc_script: &htlc_script,
            preimage,
            refund_addr: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            amount_sats: 100_000,
            fee_rate_sat_vb: 2,
            key_store: &ks,
            signing_index: 0,
            network: bitcoin::Network::Signet,
        }) {
            Ok(t) => t,
            Err(e) => panic!("build_htlc_refund_tx failed: {:?}", e),
        };

        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(tx.input[0].witness.len(), 4);

        let witness_items: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|w| w.to_vec()).collect();
        assert_eq!(witness_items[1], preimage);
        assert!(
            witness_items[2].is_empty(),
            "refund branch selector must be FALSE"
        );

        let fee = 2 * ESTIMATED_REFUND_VSIZE;
        assert_eq!(tx.output[0].value.to_sat(), 100_000 - fee);
    }

    #[test]
    fn sweep_and_change_produces_two_outputs() {
        let ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Signet) {
            Ok(k) => k,
            Err(e) => panic!("BitcoinKeyStore::from_entropy failed: {:?}", e),
        };
        let preimage = b"sweep preimage value for test!!";
        let hash_lock = sha256_hash_lock(preimage);
        let pk = match ks.get_compressed_pubkey(0) {
            Ok(p) => p,
            Err(e) => panic!("get_compressed_pubkey failed: {:?}", e),
        };
        let refund_pk = [0x03; 33];

        let refund_hash = test_refund_hash(&hash_lock);
        let htlc_script = match build_htlc_script(&hash_lock, &refund_hash, &pk, &refund_pk) {
            Ok(s) => s,
            Err(e) => panic!("build_htlc_script failed: {:?}", e),
        };

        // Successor HTLC with a new hash lock
        let new_preimage = b"successor htlc secret preimage!";
        let new_hash = sha256_hash_lock(new_preimage);
        let new_refund_hash = test_refund_hash(&new_hash);
        let successor_script = match build_htlc_script(&new_hash, &new_refund_hash, &pk, &refund_pk)
        {
            Ok(s) => s,
            Err(e) => panic!("build successor htlc_script failed: {:?}", e),
        };

        let tx = match build_sweep_and_change_tx(&SweepTxParams {
            outpoint_txid: &[0xBB; 32],
            outpoint_vout: 0,
            htlc_script: &htlc_script,
            preimage,
            dest_addr: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            claim_sats: 50_000, // claim 50k sats
            successor_htlc_script: &successor_script,
            total_sats: 200_000, // total 200k sats in HTLC
            fee_rate_sat_vb: 2,  // 2 sat/vbyte
            signer: HtlcSpendSigner::Wallet {
                key_store: &ks,
                signing_index: 0,
            },
            network: bitcoin::Network::Signet,
        }) {
            Ok(t) => t,
            Err(e) => panic!("build_sweep_and_change_tx failed: {:?}", e),
        };

        assert_eq!(tx.output.len(), 2);

        // Fee is deducted from the claim output (claimer pays)
        let fee = 2 * ESTIMATED_SWEEP_VSIZE;

        // Output 0: claim minus fee
        assert_eq!(tx.output[0].value.to_sat(), 50_000 - fee);

        // Output 1: change to successor HTLC (stays whole)
        assert_eq!(tx.output[1].value.to_sat(), 200_000 - 50_000);

        // Witness should have 4 items
        assert_eq!(tx.input[0].witness.len(), 4);
    }

    #[test]
    fn txid_is_deterministic() {
        let ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Signet) {
            Ok(k) => k,
            Err(e) => panic!("BitcoinKeyStore::from_entropy failed: {:?}", e),
        };
        let preimage = b"deterministic txid test value!!";
        let hash_lock = sha256_hash_lock(preimage);
        let pk = match ks.get_compressed_pubkey(0) {
            Ok(p) => p,
            Err(e) => panic!("get_compressed_pubkey failed: {:?}", e),
        };
        let refund_hash = test_refund_hash(&hash_lock);
        let htlc_script = match build_htlc_script(&hash_lock, &refund_hash, &pk, &[0x03; 33]) {
            Ok(s) => s,
            Err(e) => panic!("build_htlc_script failed: {:?}", e),
        };

        let tx = match build_htlc_claim_tx(&ClaimTxParams {
            outpoint_txid: &[0xCC; 32],
            outpoint_vout: 0,
            htlc_script: &htlc_script,
            preimage,
            destination_addr: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            amount_sats: 100_000,
            fee_rate_sat_vb: 1,
            signer: HtlcSpendSigner::Wallet {
                key_store: &ks,
                signing_index: 0,
            },
            network: bitcoin::Network::Signet,
        }) {
            Ok(t) => t,
            Err(e) => panic!("build_htlc_claim_tx failed: {:?}", e),
        };

        let txid1 = compute_txid(&tx);
        let txid2 = compute_txid(&tx);
        assert_eq!(txid1, txid2);
        assert_ne!(txid1, [0u8; 32]);
    }

    #[test]
    fn math_owned_claim_signer_derives_spend_key_inside_builder() {
        let preimage = b"math-owned claim preimage for builder";
        let hash_lock = sha256_hash_lock(preimage);
        let (_, claim_pubkey) = match derive_claim_keypair(preimage, &hash_lock) {
            Ok(kp) => kp,
            Err(e) => panic!("derive_claim_keypair failed: {:?}", e),
        };
        let refund_hash = test_refund_hash(&hash_lock);
        let htlc_script = match build_htlc_script(
            &hash_lock,
            &refund_hash,
            &claim_pubkey,
            &[0x03; 33],
        ) {
            Ok(s) => s,
            Err(e) => panic!("build_htlc_script failed: {:?}", e),
        };

        let tx = match build_htlc_claim_tx(&ClaimTxParams {
            outpoint_txid: &[0xAB; 32],
            outpoint_vout: 1,
            htlc_script: &htlc_script,
            preimage,
            destination_addr: "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
            amount_sats: 120_000,
            fee_rate_sat_vb: 2,
            signer: HtlcSpendSigner::MathOwned {
                hash_lock: &hash_lock,
            },
            network: bitcoin::Network::Signet,
        }) {
            Ok(tx) => tx,
            Err(e) => panic!("build_htlc_claim_tx failed: {:?}", e),
        };

        assert_eq!(tx.input[0].witness.len(), 4);
        assert_eq!(tx.input[0].witness.iter().nth(1).unwrap().to_vec(), preimage);
    }
}
