// SPDX-License-Identifier: MIT OR Apache-2.0

import CryptoKit
import Foundation
import Security

/// The device's sealing of the DSM wallet seed (owner, 2026-11-01).
///
/// Rust (`sdk::seed_vault`) hands the BIP39 wallet seed to `seal` and gets
/// ciphertext back; `open` reverses it on a cold start so the signer rebuilds
/// without the mnemonic. The AES-256 key lives in the Keychain, available
/// only while this device is unlocked, never synchronized and never carried
/// to another device by a backup; it never enters Rust. What keeps a locked
/// wallet closed is the app lock Rust checks, not this key.
///
/// The blob is `nonce(12) ‖ ciphertext ‖ tag(16)`, the layout Android's
/// `KeystoreVault` writes. A Keychain that refuses is an error to Rust, never a
/// software key in its place.
enum SeedVault {
    enum Failure: Error, CustomStringConvertible {
        case keychain(OSStatus, String)
        case blob(String)

        var description: String {
            switch self {
            case .keychain(let status, let what): return "the Keychain refused to \(what): status \(status)"
            case .blob(let why): return why
            }
        }
    }

    private static let service = "com.dsm.wallet.seed-vault"
    private static let account = "dsm_seed_vault_key_v1"

    private static func query() -> [CFString: Any] {
        [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: service,
            kSecAttrAccount: account,
        ]
    }

    /// The sealing key, made on first use.
    private static func key() throws -> SymmetricKey {
        var lookup = query()
        lookup[kSecReturnData] = kCFBooleanTrue
        lookup[kSecMatchLimit] = kSecMatchLimitOne
        var found: CFTypeRef?
        let status = SecItemCopyMatching(lookup as CFDictionary, &found)
        switch status {
        case errSecSuccess:
            guard let raw = found as? Data, raw.count == 32 else {
                throw Failure.blob("the stored sealing key is not 32 bytes")
            }
            return SymmetricKey(data: raw)
        case errSecItemNotFound:
            return try makeKey()
        default:
            throw Failure.keychain(status, "read the sealing key")
        }
    }

    private static func makeKey() throws -> SymmetricKey {
        let fresh = SymmetricKey(size: .bits256)
        let raw = fresh.withUnsafeBytes { Data($0) }
        var item = query()
        item[kSecValueData] = raw
        item[kSecAttrAccessible] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        let status = SecItemAdd(item as CFDictionary, nil)
        switch status {
        case errSecSuccess:
            return fresh
        case errSecDuplicateItem:
            // Another call made it first: read that one.
            return try key()
        default:
            throw Failure.keychain(status, "store the sealing key")
        }
    }

    /// Seal `plaintext` under the device's key.
    static func seal(_ plaintext: Data) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: try key())
        guard let combined = sealed.combined else {
            throw Failure.blob("the sealed box has no combined form")
        }
        return combined
    }

    /// Open a blob `seal` made on this device.
    static func open(_ blob: Data) throws -> Data {
        guard blob.count > 12 + 16 else {
            throw Failure.blob("sealed blob too short: \(blob.count) bytes")
        }
        let box = try AES.GCM.SealedBox(combined: blob)
        return try AES.GCM.open(box, using: try key())
    }

    /// Drop the sealing key: every blob it sealed is unrecoverable. For a
    /// full wallet wipe.
    static func wipeKey() throws {
        let status = SecItemDelete(query() as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure.keychain(status, "delete the sealing key")
        }
    }
}
