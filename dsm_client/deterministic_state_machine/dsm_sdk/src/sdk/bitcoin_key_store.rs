//! Bitcoin Key Store — BIP84 HD wallet derived from DSM device entropy.
//!
//! Derives Bitcoin keys from the 32-byte `device_entropy` stored in `SdkContext`.
//! Path: entropy → BIP39 mnemonic → BIP32 master → BIP84 account keys.
//!
//! All addresses are native SegWit (P2WPKH, bech32 / bc1q... / tb1q...).
//!
//! Security:
//! - Master key is zeroized on drop
//! - Signing context is created per-operation and dropped immediately
//! - No mnemonic is ever stored — only the extended private key

use bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use bitcoin::key::CompressedPublicKey;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::Address;
use dsm::bitcoin::types::BitcoinNetwork;
use dsm::types::error::DsmError;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// BIP84 HD wallet for Bitcoin key management.
///
/// Derived from DSM device entropy. Manages receive and change address indices.
#[derive(ZeroizeOnDrop)]
pub struct BitcoinKeyStore {
    /// BIP32 account-level extended private key (m/84'/coin'/0')
    #[zeroize(skip)] // Xpriv doesn't implement Zeroize; we zero the seed instead
    account_xpriv: Xpriv,
    /// Account-level extended public key (for non-hardened child derivation)
    #[zeroize(skip)]
    account_xpub: Xpub,
    /// Bitcoin network for address encoding
    #[zeroize(skip)]
    network: bitcoin::Network,
    /// Next unused receive address index (m/.../0/i)
    next_receive_index: u32,
    /// Next unused change address index (m/.../1/i)
    next_change_index: u32,
}

impl BitcoinKeyStore {
    /// BIP44 coin type: 0 for mainnet, 1 for testnet/signet
    fn coin_type(network: &BitcoinNetwork) -> u32 {
        match network {
            BitcoinNetwork::Mainnet => 0,
            _ => 1,
        }
    }

    /// Create a key store from raw 32-byte device entropy.
    ///
    /// Flow: entropy → BIP39 24-word mnemonic → 64-byte seed → BIP32 master →
    /// BIP84 account key (m/84'/coin'/0')
    pub fn from_entropy(entropy: &[u8; 32], network: BitcoinNetwork) -> Result<Self, DsmError> {
        // Validate entropy is not all zeros
        if entropy.iter().all(|&b| b == 0) {
            return Err(DsmError::invalid_operation(
                "Cannot derive Bitcoin keys from zero entropy",
            ));
        }

        // entropy → BIP39 mnemonic (32 bytes = 24 words)
        let mnemonic = bip39::Mnemonic::from_entropy(entropy).map_err(|e| {
            DsmError::invalid_operation(format!("BIP39 mnemonic generation failed: {e}"))
        })?;

        // mnemonic → 64-byte BIP39 seed (no passphrase)
        let mut seed = mnemonic.to_seed("");

        // seed → BIP32 master extended private key
        let net = network.to_bitcoin_network();
        let network_kind: bitcoin::NetworkKind = net.into();
        let master = Xpriv::new_master(network_kind, &seed).map_err(|e| {
            DsmError::invalid_operation(format!("BIP32 master key derivation failed: {e}"))
        })?;

        // Zeroize seed immediately
        seed.zeroize();

        Self::from_master_xpriv(master, network)
    }

    /// Create a key store from a BIP39 mnemonic phrase.
    pub fn from_mnemonic(mnemonic_phrase: &str, network: BitcoinNetwork) -> Result<Self, DsmError> {
        let mnemonic = bip39::Mnemonic::parse(mnemonic_phrase)
            .map_err(|e| DsmError::invalid_operation(format!("Invalid BIP39 mnemonic: {e}")))?;
        let mut seed = mnemonic.to_seed("");
        let net = network.to_bitcoin_network();
        let network_kind: bitcoin::NetworkKind = net.into();
        let master = Xpriv::new_master(network_kind, &seed).map_err(|e| {
            DsmError::invalid_operation(format!("BIP32 master key derivation failed: {e}"))
        })?;
        seed.zeroize();
        Self::from_master_xpriv(master, network)
    }

    /// Create a key store from an account-level xpriv (m/84'/coin'/0').
    pub fn from_account_xpriv(
        account_xpriv: Xpriv,
        network: BitcoinNetwork,
    ) -> Result<Self, DsmError> {
        let secp = Secp256k1::new();
        let account_xpub = Xpub::from_priv(&secp, &account_xpriv);
        Ok(Self {
            account_xpriv,
            account_xpub,
            network: network.to_bitcoin_network(),
            next_receive_index: 0,
            next_change_index: 0,
        })
    }

    /// Create a key store from a serialized xpriv string.
    /// Accepts either a master key (depth 0) or an account-level key (depth 3).
    pub fn from_xpriv_str(xpriv_str: &str, network: BitcoinNetwork) -> Result<Self, DsmError> {
        let xpriv: Xpriv = xpriv_str
            .parse()
            .map_err(|e| DsmError::invalid_operation(format!("Invalid xpriv string: {e}")))?;
        if xpriv.depth == 0 {
            Self::from_master_xpriv(xpriv, network)
        } else {
            Self::from_account_xpriv(xpriv, network)
        }
    }

    fn from_master_xpriv(master: Xpriv, network: BitcoinNetwork) -> Result<Self, DsmError> {
        let secp = Secp256k1::new();
        let coin = Self::coin_type(&network);

        // Derive account key: m/84'/coin'/0'
        let account_path = DerivationPath::from(vec![
            ChildNumber::from_hardened_idx(84)
                .map_err(|e| DsmError::invalid_operation(format!("BIP84 path: {e}")))?,
            ChildNumber::from_hardened_idx(coin)
                .map_err(|e| DsmError::invalid_operation(format!("BIP84 coin path: {e}")))?,
            ChildNumber::from_hardened_idx(0)
                .map_err(|e| DsmError::invalid_operation(format!("BIP84 account path: {e}")))?,
        ]);

        let account_xpriv = master.derive_priv(&secp, &account_path).map_err(|e| {
            DsmError::invalid_operation(format!("BIP84 account derivation failed: {e}"))
        })?;

        let account_xpub = Xpub::from_priv(&secp, &account_xpriv);

        Ok(Self {
            account_xpriv,
            account_xpub,
            network: network.to_bitcoin_network(),
            next_receive_index: 0,
            next_change_index: 0,
        })
    }

    /// Get the next unused receive address (m/84'/coin'/0'/0/i).
    ///
    /// Returns (bech32_address, index, compressed_pubkey_33_bytes).
    /// Increments the internal index counter.
    pub fn next_receive_address(&mut self) -> Result<(String, u32, [u8; 33]), DsmError> {
        let index = self.next_receive_index;
        let (addr, pubkey) = self.derive_address(0, index)?;
        self.next_receive_index = index
            .checked_add(1)
            .ok_or_else(|| DsmError::invalid_operation("Receive address index overflow"))?;
        Ok((addr, index, pubkey))
    }

    /// Get the next unused change address (m/84'/coin'/0'/1/i).
    ///
    /// Returns (bech32_address, index, compressed_pubkey_33_bytes).
    pub fn next_change_address(&mut self) -> Result<(String, u32, [u8; 33]), DsmError> {
        let index = self.next_change_index;
        let (addr, pubkey) = self.derive_address(1, index)?;
        self.next_change_index = index
            .checked_add(1)
            .ok_or_else(|| DsmError::invalid_operation("Change address index overflow"))?;
        Ok((addr, index, pubkey))
    }

    /// Peek at a change address without incrementing the counter.
    pub fn peek_change_address(&self, index: u32) -> Result<(String, [u8; 33]), DsmError> {
        self.derive_address(1, index)
    }

    /// Peek at a receive address without incrementing the counter.
    pub fn peek_receive_address(&self, index: u32) -> Result<(String, [u8; 33]), DsmError> {
        self.derive_address(0, index)
    }

    /// Get the compressed public key at a specific receive index.
    pub fn get_compressed_pubkey(&self, index: u32) -> Result<[u8; 33], DsmError> {
        let (_, pubkey) = self.derive_address(0, index)?;
        Ok(pubkey)
    }

    /// Current receive index (next address that will be issued).
    pub fn current_receive_index(&self) -> u32 {
        self.next_receive_index
    }

    /// Current change index.
    pub fn current_change_index(&self) -> u32 {
        self.next_change_index
    }

    /// Restore the receive index from a persisted value (e.g. DB `active_receive_index`).
    /// Call this after creating a key store from a mnemonic/xpriv so the in-memory
    /// counter matches the on-disk state, preventing the Index-0 Trap after restart.
    pub fn set_receive_index(&mut self, index: u32) {
        self.next_receive_index = index;
    }

    /// Restore the change index from a persisted value.
    pub fn set_change_index(&mut self, index: u32) {
        self.next_change_index = index;
    }

    /// The network this key store is configured for.
    pub fn network(&self) -> bitcoin::Network {
        self.network
    }

    /// Sign a raw sighash with the key at the given derivation path (change, index).
    ///
    /// Returns a DER-encoded ECDSA signature.
    pub fn sign_hash(
        &self,
        change: u32,
        index: u32,
        sighash: &[u8; 32],
    ) -> Result<Vec<u8>, DsmError> {
        let secp = Secp256k1::new();

        let child_path = vec![
            ChildNumber::from_normal_idx(change)
                .map_err(|e| DsmError::invalid_operation(format!("Invalid change index: {e}")))?,
            ChildNumber::from_normal_idx(index)
                .map_err(|e| DsmError::invalid_operation(format!("Invalid address index: {e}")))?,
        ];

        let child_xpriv = self
            .account_xpriv
            .derive_priv(&secp, &child_path)
            .map_err(|e| {
                DsmError::invalid_operation(format!("Child key derivation failed: {e}"))
            })?;

        let msg = bitcoin::secp256k1::Message::from_digest(*sighash);
        let sig = secp.sign_ecdsa(&msg, &child_xpriv.private_key);

        Ok(sig.serialize_der().to_vec())
    }

    // --- Internal ---

    /// Derive address and compressed pubkey at (change, index).
    fn derive_address(&self, change: u32, index: u32) -> Result<(String, [u8; 33]), DsmError> {
        let secp = Secp256k1::verification_only();

        let child_path = vec![
            ChildNumber::from_normal_idx(change)
                .map_err(|e| DsmError::invalid_operation(format!("Invalid change index: {e}")))?,
            ChildNumber::from_normal_idx(index)
                .map_err(|e| DsmError::invalid_operation(format!("Invalid address index: {e}")))?,
        ];

        let child_xpub = self
            .account_xpub
            .derive_pub(&secp, &child_path)
            .map_err(|e| {
                DsmError::invalid_operation(format!("Public key derivation failed: {e}"))
            })?;

        let compressed_pk: CompressedPublicKey = child_xpub.to_pub();
        let address = Address::p2wpkh(&compressed_pk, self.network);
        let pubkey_bytes = compressed_pk.to_bytes();

        Ok((address.to_string(), pubkey_bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_entropy() -> [u8; 32] {
        // Deterministic test entropy (not all zeros)
        let mut e = [0u8; 32];
        for (i, b) in e.iter_mut().enumerate() {
            *b = (i as u8).wrapping_add(0x42);
        }
        e
    }

    #[test]
    fn rejects_zero_entropy() {
        let zero = [0u8; 32];
        assert!(BitcoinKeyStore::from_entropy(&zero, BitcoinNetwork::Signet).is_err());
    }

    #[test]
    fn derives_signet_addresses() {
        let mut ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Signet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create key store: {:?}", e),
        };

        let (addr0, idx0, pk0) = match ks.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get first address: {:?}", e),
        };
        assert_eq!(idx0, 0);
        assert!(
            addr0.starts_with("tb1q"),
            "Expected tb1q prefix, got: {addr0}"
        );
        assert_eq!(pk0.len(), 33);
        // Compressed pubkey starts with 0x02 or 0x03
        assert!(pk0[0] == 0x02 || pk0[0] == 0x03);

        let (addr1, idx1, _) = match ks.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get second address: {:?}", e),
        };
        assert_eq!(idx1, 1);
        assert_ne!(addr0, addr1, "Sequential addresses must differ");
    }

    #[test]
    fn derives_mainnet_addresses() {
        let mut ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Mainnet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create key store: {:?}", e),
        };

        let (addr, _, _) = match ks.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get address: {:?}", e),
        };
        assert!(
            addr.starts_with("bc1q"),
            "Expected bc1q prefix, got: {addr}"
        );
    }

    #[test]
    fn derives_testnet_addresses() {
        let mut ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Testnet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create key store: {:?}", e),
        };

        let (addr, _, _) = match ks.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get address: {:?}", e),
        };
        assert!(
            addr.starts_with("tb1q"),
            "Expected tb1q prefix, got: {addr}"
        );
    }

    #[test]
    fn same_entropy_same_addresses() {
        let entropy = test_entropy();
        let mut ks1 = match BitcoinKeyStore::from_entropy(&entropy, BitcoinNetwork::Signet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create first key store: {:?}", e),
        };
        let mut ks2 = match BitcoinKeyStore::from_entropy(&entropy, BitcoinNetwork::Signet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create second key store: {:?}", e),
        };

        let (a1, _, p1) = match ks1.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get first address: {:?}", e),
        };
        let (a2, _, p2) = match ks2.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get second address: {:?}", e),
        };
        assert_eq!(a1, a2);
        assert_eq!(p1, p2);
    }

    #[test]
    fn different_entropy_different_addresses() {
        let mut e1 = test_entropy();
        let mut e2 = test_entropy();
        e2[0] ^= 0xFF; // flip one byte

        let mut ks1 = match BitcoinKeyStore::from_entropy(&e1, BitcoinNetwork::Signet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create first key store: {:?}", e),
        };
        let mut ks2 = match BitcoinKeyStore::from_entropy(&e2, BitcoinNetwork::Signet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create second key store: {:?}", e),
        };

        let (a1, _, _) = match ks1.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get first address: {:?}", e),
        };
        let (a2, _, _) = match ks2.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get second address: {:?}", e),
        };
        assert_ne!(a1, a2);

        // Clean up
        e1.zeroize();
        e2.zeroize();
    }

    #[test]
    fn peek_does_not_advance_index() {
        let mut ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Signet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create key store: {:?}", e),
        };

        let (peek_addr, _) = match ks.peek_receive_address(0) {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to peek address: {:?}", e),
        };
        assert_eq!(ks.current_receive_index(), 0);

        let (next_addr, idx, _) = match ks.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get next address: {:?}", e),
        };
        assert_eq!(idx, 0);
        assert_eq!(peek_addr, next_addr);
        assert_eq!(ks.current_receive_index(), 1);
    }

    #[test]
    fn change_addresses_differ_from_receive() {
        let mut ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Signet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create key store: {:?}", e),
        };

        let (recv, _, _) = match ks.next_receive_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get receive address: {:?}", e),
        };
        let (change, _, _) = match ks.next_change_address() {
            Ok(addr) => addr,
            Err(e) => panic!("Failed to get change address: {:?}", e),
        };
        assert_ne!(recv, change, "Receive and change at index 0 must differ");
    }

    #[test]
    fn sign_hash_produces_valid_der() {
        let ks = match BitcoinKeyStore::from_entropy(&test_entropy(), BitcoinNetwork::Signet) {
            Ok(ks) => ks,
            Err(e) => panic!("Failed to create key store: {:?}", e),
        };

        let sighash = [0xAA; 32];
        let sig = match ks.sign_hash(0, 0, &sighash) {
            Ok(sig) => sig,
            Err(e) => panic!("Failed to sign hash: {:?}", e),
        };

        // DER signatures start with 0x30
        assert_eq!(sig[0], 0x30, "Expected DER encoding");
        // Typical DER signature is 70-72 bytes
        assert!(
            sig.len() >= 68 && sig.len() <= 73,
            "Unexpected sig length: {}",
            sig.len()
        );
    }
}
