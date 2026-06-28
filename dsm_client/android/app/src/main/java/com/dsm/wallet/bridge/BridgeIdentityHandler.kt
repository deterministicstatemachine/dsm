// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import android.content.SharedPreferences
import android.util.Log
import com.google.protobuf.ByteString
import com.dsm.native.DsmNativeException
import dsm.types.proto.Envelope
import dsm.types.proto.ArgPack
import dsm.types.proto.Codec
import dsm.types.proto.IngressRequest
import dsm.types.proto.IngressResponse
import dsm.types.proto.ResultPack
import dsm.types.proto.RestoreIdentityContextOp
import dsm.types.proto.RouterQueryOp
import dsm.types.proto.StartupRequest
import dsm.types.proto.StartupResponse
import dsm.types.proto.WalletCreateGenesisV2Request
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Canonical mnemonic-rooted Genesis v2 identity handler (whitepaper §2.5).
 *
 * Genesis is driven by the BIP39 mnemonic, NOT by silicon enrollment: the frontend obtains a
 * mnemonic ([generateMnemonic]), shows it for backup, then calls [createGenesisV2], which routes
 * to the Rust `system.createGenesisV2` handler. Rust derives `wallet_seed`, caches it in the
 * unlocked session, runs `create_genesis_v2`, installs the state, persists the public GenesisV2
 * record, and initializes the SDK context. There is NO C-DBRW, NO AntiCloneGate/silicon
 * enrollment, NO storage-node MPC, NO random genesis entropy, and NO persisted s0/Smaster.
 * Anti-clone (offline bearer only) is the Boot Fenced Fused Anchor, never this path.
 *
 * Cold start ([bootstrapFromPrefs]) re-primes the persisted identity via `restore_identity_context`;
 * operations that need signing re-derive their keys from the unlocked wallet seed and fail closed
 * when the wallet is locked.
 */
internal object BridgeIdentityHandler {
    private const val KEY_HAS_IDENTITY = "has_identity"
    private const val KEY_FRONTEND_DEVICE_ID = "device_id"
    private const val KEY_FRONTEND_GENESIS_HASH = "genesis_hash"
    private const val KEY_GENESIS_CREATED = "genesis_created"

    private data class GenesisEnvelopeInstallInput(
        val envelopeBytes: ByteArray,
        val deviceIdBytes: ByteArray,
        val genesisHashBytes: ByteArray,
    )

    private fun getFramedErrorEnvelopeCode(envelopeBytes: ByteArray): Int {
        if (envelopeBytes.isEmpty()) {
            return 0
        }
        val rawEnvelope = if (envelopeBytes.first() == 0x03.toByte() && envelopeBytes.size > 1) {
            envelopeBytes.copyOfRange(1, envelopeBytes.size)
        } else {
            envelopeBytes
        }
        return try {
            Unified.isErrorEnvelope(rawEnvelope)
        } catch (_: Throwable) {
            0
        }
    }

    /** Dispatch a router query through the native ingress boundary, returning the raw ok-bytes. */
    private fun routerQuery(method: String, argPackBytes: ByteArray): ByteArray {
        val ingressRequest = IngressRequest.newBuilder()
            .setRouterQuery(
                RouterQueryOp.newBuilder()
                    .setMethod(method)
                    .setArgs(ByteString.copyFrom(argPackBytes))
                    .build()
            )
            .build()
        val ingressResponse =
            IngressResponse.parseFrom(Unified.dispatchIngress(ingressRequest.toByteArray()))
        return when (ingressResponse.resultCase) {
            IngressResponse.ResultCase.OK_BYTES -> ingressResponse.okBytes.toByteArray()
            IngressResponse.ResultCase.ERROR ->
                throw IllegalStateException(ingressResponse.error.message)
            else -> throw IllegalStateException("$method returned no result")
        }
    }

    private fun dispatchStartupOrThrow(request: StartupRequest): ByteArray {
        val response = StartupResponse.parseFrom(
            NativeBoundaryBridge.startup(request.toByteArray())
        )
        return when (response.resultCase) {
            StartupResponse.ResultCase.OK_BYTES -> response.okBytes.toByteArray()
            StartupResponse.ResultCase.ERROR -> throw IllegalStateException(response.error.message)
            else -> throw IllegalStateException("startup returned no result")
        }
    }

    private fun clearGenesisArtifacts(
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        logTag: String,
    ) {
        prefs.edit()
            .remove(keyDeviceId)
            .remove(keyGenesisHash)
            .remove(keyGenesisEnvelope)
            .remove(KEY_HAS_IDENTITY)
            .remove(KEY_FRONTEND_DEVICE_ID)
            .remove(KEY_FRONTEND_GENESIS_HASH)
            .remove(KEY_GENESIS_CREATED)
            .apply()
        sdkContextInitialized.set(false)
        Log.w(logTag, "clearGenesisArtifacts: cleared partial genesis state")
    }

    private fun parseGenesisEnvelopeInstallInput(envelopeBytes: ByteArray): GenesisEnvelopeInstallInput {
        if (envelopeBytes.isEmpty()) {
            throw IllegalArgumentException("genesis envelope empty")
        }
        val rawEnvelope = if (envelopeBytes.first() == 0x03.toByte() && envelopeBytes.size > 1) {
            envelopeBytes.copyOfRange(1, envelopeBytes.size)
        } else {
            envelopeBytes
        }
        val envelope = Envelope.parseFrom(rawEnvelope)
        if (envelope.payloadCase != Envelope.PayloadCase.GENESIS_CREATED_RESPONSE) {
            throw IllegalArgumentException("expected genesisCreatedResponse envelope, got ${envelope.payloadCase}")
        }
        val payload = envelope.genesisCreatedResponse
        val deviceIdBytes = payload.deviceId.toByteArray()
        val genesisHashBytes = payload.genesisHash.v.toByteArray()
        if (deviceIdBytes.size != 32) {
            throw IllegalArgumentException("genesis envelope missing 32-byte device_id")
        }
        if (genesisHashBytes.size != 32) {
            throw IllegalArgumentException("genesis envelope missing 32-byte genesis_hash")
        }
        return GenesisEnvelopeInstallInput(
            envelopeBytes = envelopeBytes,
            deviceIdBytes = deviceIdBytes,
            genesisHashBytes = genesisHashBytes,
        )
    }

    /**
     * Generate a fresh BIP39 mnemonic via `system.generateMnemonic` for display/backup at wallet
     * creation. Returns the mnemonic UTF-8 bytes. The wallet seed is derived + cached only when
     * the (backed-up) mnemonic is passed to [createGenesisV2].
     */
    fun generateMnemonic(): ByteArray {
        val arg = ArgPack.newBuilder()
            .setCodec(Codec.CODEC_PROTO)
            .setBody(ByteString.EMPTY)
            .build()
        val okBytes = routerQuery("system.generateMnemonic", arg.toByteArray())
        return ResultPack.parseFrom(okBytes).body.toByteArray()
    }

    /**
     * Canonical mnemonic-rooted wallet creation. Routes to `system.createGenesisV2`, which derives
     * + caches `wallet_seed` from the mnemonic and runs `create_genesis_v2` (install + persist v2
     * record + AppState identity + SDK context, all Rust-side). On success this persists the public
     * identity (device_id / genesis_hash / envelope) to prefs for cold-start rehydration. Returns
     * the framed genesis envelope (forwarded verbatim to the frontend).
     */
    fun createGenesisV2(
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        mnemonic: String,
        locale: String,
        networkId: String,
    ): ByteArray {
        if (mnemonic.trim().isEmpty()) {
            Log.e(logTag, "createGenesisV2: mnemonic is required")
            return ByteArray(0)
        }
        return try {
            val req = WalletCreateGenesisV2Request.newBuilder()
                .setMnemonic(mnemonic)
                .setLocale(locale)
                .setNetworkId(networkId)
                .build()
            val arg = ArgPack.newBuilder()
                .setCodec(Codec.CODEC_PROTO)
                .setBody(ByteString.copyFrom(req.toByteArray()))
                .build()
            val envelopeBytes = routerQuery("system.createGenesisV2", arg.toByteArray())

            val errorCode = getFramedErrorEnvelopeCode(envelopeBytes)
            if (errorCode != 0) {
                Log.w(logTag, "createGenesisV2: native returned error envelope code=$errorCode")
                return envelopeBytes
            }

            val install = parseGenesisEnvelopeInstallInput(envelopeBytes)
            prefs.edit()
                .putString(keyDeviceId, BridgeEncoding.base32CrockfordEncode(install.deviceIdBytes))
                .putString(keyGenesisHash, BridgeEncoding.base32CrockfordEncode(install.genesisHashBytes))
                .putString(keyGenesisEnvelope, BridgeEncoding.base32CrockfordEncode(envelopeBytes))
                .putBoolean(KEY_GENESIS_CREATED, true)
                .apply()
            // The Rust route already initialized the SDK context (wallet unlocked this session).
            sdkContextInitialized.set(true)
            Log.i(logTag, "createGenesisV2: identity persisted + SDK context initialized")
            envelopeBytes
        } catch (t: Throwable) {
            Log.e(logTag, "createGenesisV2 failed", t)
            clearGenesisArtifacts(
                prefs = prefs,
                sdkContextInitialized = sdkContextInitialized,
                keyDeviceId = keyDeviceId,
                keyGenesisHash = keyGenesisHash,
                keyGenesisEnvelope = keyGenesisEnvelope,
                logTag = logTag,
            )
            if (t is DsmNativeException) {
                throw t
            }
            ByteArray(0)
        }
    }

    /**
     * Cold-start identity rehydration. Re-primes the persisted identity via
     * `restore_identity_context` (device_id + genesis_hash; no silicon, no binding key). Signing
     * operations re-derive their keys from the unlocked wallet seed and fail closed when the wallet
     * is locked, so a `false` return means "identity not (yet) restorable — prompt unlock/genesis".
     */
    fun bootstrapFromPrefs(
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
    ): Boolean {
        if (sdkContextInitialized.get()) {
            Log.i(logTag, "bootstrapFromPrefs: already initialized")
            return true
        }

        val deviceIdStr = prefs.getString(keyDeviceId, null)
        val genesisHashStr = prefs.getString(keyGenesisHash, null)
        if (deviceIdStr.isNullOrEmpty() || genesisHashStr.isNullOrEmpty()) {
            Log.i(logTag, "bootstrapFromPrefs: no persisted identity found")
            return false
        }

        val deviceIdBytes =
            try { BridgeEncoding.base32CrockfordDecode(deviceIdStr) } catch (_: Throwable) { ByteArray(0) }
        val genesisHashBytes =
            try { BridgeEncoding.base32CrockfordDecode(genesisHashStr) } catch (_: Throwable) { ByteArray(0) }
        if (deviceIdBytes.size != 32 || genesisHashBytes.size != 32) {
            Log.w(logTag, "bootstrapFromPrefs: persisted identity malformed")
            return false
        }

        return try {
            dispatchStartupOrThrow(
                StartupRequest.newBuilder()
                    .setRestoreIdentityContext(
                        RestoreIdentityContextOp.newBuilder()
                            .setDeviceId(ByteString.copyFrom(deviceIdBytes))
                            .setGenesisHash(ByteString.copyFrom(genesisHashBytes))
                    )
                    .build()
            )
            sdkContextInitialized.set(true)
            Log.i(logTag, "bootstrapFromPrefs: identity context restored")
            true
        } catch (t: Throwable) {
            // Fail closed: most commonly the wallet is locked (no cached wallet seed) on cold start.
            Log.i(logTag, "bootstrapFromPrefs: restore unavailable (wallet locked?); prompt unlock: ${t.message}")
            if (t is DsmNativeException) {
                throw t
            }
            false
        }
    }
}
