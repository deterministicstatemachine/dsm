// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

/// Canonical mnemonic-rooted Genesis v2 identity, as `BridgeIdentityHandler.kt`
/// crosses it. The page obtains a mnemonic (`generateMnemonic`), shows it
/// for backup, then calls `createGenesisV2`, which routes to Rust's
/// `system.createGenesisV2`: Rust derives the wallet seed, runs genesis,
/// installs the state and initializes the SDK context. The host keeps only
/// the public identity pointers, for the cold start that re-primes them
/// through `restore_identity_context`.
final class IdentityHandler {
    static let shared = IdentityHandler()

    private enum Context { case uninitialized, initialized }

    private let lock = NSLock()
    private var context = Context.uninitialized

    var sdkContextInitialized: Bool {
        lock.lock()
        defer { lock.unlock() }
        return context == .initialized
    }

    private func setContext(_ next: Context) {
        lock.lock()
        context = next
        lock.unlock()
    }

    /// A fresh BIP39 mnemonic for display and backup: its UTF-8.
    func generateMnemonic() throws -> Data {
        let answer = try DsmSdk.routerQuery("system.generateMnemonic", args: DsmSdk.argPack(body: Data()))
        return DsmSdk.resultPackBody(answer)
    }

    /// Wallet creation from the backed-up mnemonic: the page's
    /// `WalletCreateGenesisV2Request`, handed to the route as it came. Answers
    /// the framed genesis envelope; Rust's own error envelope is forwarded.
    func createGenesisV2(request: Data) throws -> Data {
        guard !request.isEmpty else {
            throw BridgeFailure.invalidPayload("createGenesisV2: mnemonic is required")
        }
        do {
            let envelope = try DsmSdk.routerInvoke("system.createGenesisV2", args: DsmSdk.argPack(body: request))
            let errorCode = DsmSdk.errorCode(of: envelope)
            if errorCode != 0 {
                DsmLog.warn("IdentityHandler", "createGenesisV2: Rust answered error envelope code=\(errorCode)")
                return envelope
            }
            guard let identity = DsmSdk.genesisCreatedIdentity(envelope) else {
                throw BridgeFailure.invalidPayload("createGenesisV2: the envelope installs no 32-byte identity")
            }
            Preferences.setIdentity(.deviceId, Base32Crockford.encode(identity.deviceId))
            Preferences.setIdentity(.genesisHash, Base32Crockford.encode(identity.genesisHash))
            Preferences.setIdentity(.genesisEnvelope, Base32Crockford.encode(envelope))
            // The Rust route already initialized the SDK context (the wallet is unlocked this session).
            setContext(.initialized)
            DsmLog.info("IdentityHandler", "createGenesisV2: identity persisted and SDK context initialized")
            // The appliance has an identity now; the radio follows it.
            DispatchQueue.main.async { WalletViewController.active?.startBleForIdentity() }
            return envelope
        } catch {
            DsmLog.error("IdentityHandler", "createGenesisV2 failed: \(error)")
            Preferences.clearIdentity()
            setContext(.uninitialized)
            throw error
        }
    }

    /// Cold-start rehydration through `restore_identity_context`. Answers
    /// whether the identity is restorable now; a wallet still locked on a
    /// cold start is not, and the page prompts for unlock or genesis.
    func bootstrapFromDefaults() -> Bool {
        if sdkContextInitialized {
            return sdkContextInitialized
        }
        guard let deviceIdText = Preferences.identity(.deviceId),
              let genesisText = Preferences.identity(.genesisHash),
              !deviceIdText.isEmpty, !genesisText.isEmpty else {
            DsmLog.info("IdentityHandler", "bootstrap: no persisted identity")
            return sdkContextInitialized
        }
        let deviceId = Base32Crockford.decode(deviceIdText)
        let genesis = Base32Crockford.decode(genesisText)
        guard deviceId.count == 32, genesis.count == 32 else {
            DsmLog.warn("IdentityHandler", "bootstrap: persisted identity malformed")
            return sdkContextInitialized
        }
        if let why = DsmSdk.restoreIdentityContext(deviceId: deviceId, genesisHash: genesis) {
            // Fail closed: most often the wallet is locked (no cached wallet seed) on a cold start.
            DsmLog.info("IdentityHandler", "bootstrap: restore unavailable (wallet locked?): \(why)")
            return sdkContextInitialized
        }
        setContext(.initialized)
        DsmLog.info("IdentityHandler", "bootstrap: identity context restored")
        return sdkContextInitialized
    }
}
