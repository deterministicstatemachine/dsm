// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

/// The page's preferences and the identity pointers a cold start restores,
/// in the app's defaults, as `dsm_prefs` holds them on Android. Which keys the
/// page may read and write is Rust's to say (`dsm_ffi_preference_key` answers
/// a key only when the page keeps it), so a page script cannot repoint the
/// identity through this store.
enum Preferences {
    private static let defaults = UserDefaults.standard

    /// The identity pointers `IdentityHandler` keeps, as Base32 Crockford.
    enum IdentityKey: String {
        case deviceId = "device_id_bytes"
        case genesisHash = "genesis_hash_bytes"
        case genesisEnvelope = "genesis_envelope_bytes"
    }

    /// `getPreference`: the page's value for the key its payload names, or no bytes.
    static func getPreference(payload: Data) throws -> Data {
        guard let key = DsmSdk.preferenceKey(payload) else {
            throw BridgeFailure.invalidPayload("getPreference: not a preference the page keeps")
        }
        guard let value = defaults.string(forKey: key) else { return Data() }
        return Data(value.utf8)
    }

    /// `setPreference`: the page's value for the key its payload names; answers nothing.
    static func setPreference(payload: Data) throws -> Data {
        guard let key = DsmSdk.preferenceKey(payload) else {
            throw BridgeFailure.invalidPayload("setPreference: not a preference the page keeps")
        }
        let value = DsmSdk.preferenceHasValue(payload) ? DsmSdk.preferenceValue(payload) : ""
        defaults.set(value, forKey: key)
        return Data()
    }

    static func identity(_ key: IdentityKey) -> String? {
        defaults.string(forKey: key.rawValue)
    }

    static func setIdentity(_ key: IdentityKey, _ value: String) {
        defaults.set(value, forKey: key.rawValue)
    }

    static func clearIdentity() {
        for key in [IdentityKey.deviceId, .genesisHash, .genesisEnvelope] {
            defaults.removeObject(forKey: key.rawValue)
        }
    }
}
