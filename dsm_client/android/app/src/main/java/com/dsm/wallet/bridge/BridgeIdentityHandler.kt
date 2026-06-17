// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.google.protobuf.ByteString
import com.dsm.native.DsmNativeException
import dsm.types.proto.Envelope
import dsm.types.proto.BootstrapFinalizeResponse
import dsm.types.proto.BootstrapMeasurementReport
import dsm.types.proto.ArgPack
import dsm.types.proto.Codec
import dsm.types.proto.EnvelopeOp
import dsm.types.proto.IngressRequest
import dsm.types.proto.IngressResponse
import dsm.types.proto.RestoreIdentityContextOp
import dsm.types.proto.RouterQueryOp
import dsm.types.proto.StartupRequest
import dsm.types.proto.StartupResponse
import dsm.types.proto.SystemGenesisRequest
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Genesis + bootstrap bridge.
 *
 * The SDK (Rust) owns the device-birth nonce + commitment end-to-end
 * (`rules.instructions.md`: Rust is the sole crypto authority, Kotlin is
 * transport-only).  This handler therefore carries NO crypto and NO binding
 * material: it triggers genesis, persists the resulting identity handles
 * (device_id / genesis_hash) so resume can re-trigger restore, and relays the
 * bootstrap-control phase signals.  Genesis is sub-second — there is no device
 * enrollment, anti-clone gate, or trust measurement on this path.
 */
internal object BridgeIdentityHandler {
    private const val KEY_HAS_IDENTITY = "has_identity"
    private const val KEY_FRONTEND_DEVICE_ID = "device_id"
    private const val KEY_FRONTEND_GENESIS_HASH = "genesis_hash"
    private const val KEY_GENESIS_CREATED = "genesis_created"

    private val genesisLifecycleInFlight = AtomicBoolean(false)
    private val genesisLifecycleInvalidated = AtomicBoolean(false)

    private class GenesisInterruptedException(message: String) : IllegalStateException(message)

    private data class GenesisEnvelopeInstallInput(
        val envelopeBytes: ByteArray,
        val deviceIdBytes: ByteArray,
        val genesisHashBytes: ByteArray,
        val entropyBytes: ByteArray,
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

    private fun sendBootstrapMeasurementReport(
        report: BootstrapMeasurementReport,
    ): ByteArray {
        // Envelope.headers is required by Rust-side envelope validation
        // (dsm::envelope::validate_headers_wire).  device_id + chain_tip
        // are both 32-byte length-checked fields; chain_tip is reserved
        // for SDK use and MUST be all-zeros from the frontend.  When the
        // report itself carries a device_id (FINALIZE path), reuse it
        // for the header; otherwise the early-signal path passes zeros
        // (the validator only enforces length, not value).
        val headerDeviceId: ByteString = if (report.deviceId.size() == 32) {
            report.deviceId
        } else {
            ByteString.copyFrom(ByteArray(32))
        }
        val headerGenesisHash: ByteString = if (report.genesisHash.size() == 32) {
            report.genesisHash
        } else {
            ByteString.copyFrom(ByteArray(32))
        }
        val headers = dsm.types.proto.Headers.newBuilder()
            .setDeviceId(headerDeviceId)
            .setChainTip(ByteString.copyFrom(ByteArray(32)))
            .setGenesisHash(headerGenesisHash)
            .build()
        val envelope = Envelope.newBuilder()
            .setVersion(3)
            .setHeaders(headers)
            .setMessageId(ByteString.copyFrom(ByteArray(16)))
            .setBootstrapMeasurementReport(report)
            .build()
        val rawEnvelope = envelope.toByteArray()
        val envelopeBytes = ByteArray(1 + rawEnvelope.size)
        envelopeBytes[0] = 0x03
        System.arraycopy(rawEnvelope, 0, envelopeBytes, 1, rawEnvelope.size)

        val ingressRequest = IngressRequest.newBuilder()
            .setEnvelope(
                EnvelopeOp.newBuilder()
                    .setEnvelopeBytes(ByteString.copyFrom(envelopeBytes))
                    .build()
            )
            .build()

        val ingressResponse = IngressResponse.parseFrom(Unified.dispatchIngress(ingressRequest.toByteArray()))
        return when (ingressResponse.resultCase) {
            IngressResponse.ResultCase.OK_BYTES -> ingressResponse.okBytes.toByteArray()
            IngressResponse.ResultCase.ERROR -> throw IllegalStateException(ingressResponse.error.message)
            else -> throw IllegalStateException("bootstrap ingress returned no result")
        }
    }

    private fun decodeBootstrapFinalizeResponseEnvelope(
        envelopeBytes: ByteArray,
    ): BootstrapFinalizeResponse {
        if (envelopeBytes.isEmpty()) {
            throw IllegalArgumentException("bootstrap finalize envelope empty")
        }
        val rawEnvelope = if (envelopeBytes.first() == 0x03.toByte() && envelopeBytes.size > 1) {
            envelopeBytes.copyOfRange(1, envelopeBytes.size)
        } else {
            envelopeBytes
        }
        val envelope = Envelope.parseFrom(rawEnvelope)
        if (envelope.payloadCase != Envelope.PayloadCase.BOOTSTRAP_FINALIZE_RESPONSE) {
            throw IllegalArgumentException(
                "expected bootstrapFinalizeResponse envelope, got ${envelope.payloadCase}"
            )
        }
        return envelope.bootstrapFinalizeResponse
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

    private fun ensureGenesisNotInvalidated(
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
    ) {
        if (!genesisLifecycleInvalidated.get()) {
            return
        }
        clearGenesisArtifacts(
            prefs = prefs,
            sdkContextInitialized = sdkContextInitialized,
            keyDeviceId = keyDeviceId,
            keyGenesisHash = keyGenesisHash,
            keyGenesisEnvelope = keyGenesisEnvelope,
            logTag = logTag,
        )
        throw GenesisInterruptedException(
            "Device setup was interrupted. Do not leave the screen until finished. Initialization was wiped and must be started again."
        )
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
        val entropyBytes = payload.deviceEntropy.toByteArray()
        if (deviceIdBytes.size != 32) {
            throw IllegalArgumentException("genesis envelope missing 32-byte device_id")
        }
        if (genesisHashBytes.size != 32) {
            throw IllegalArgumentException("genesis envelope missing 32-byte genesis_hash")
        }
        if (entropyBytes.size != 32) {
            throw IllegalArgumentException("genesis envelope missing 32-byte device_entropy")
        }
        return GenesisEnvelopeInstallInput(
            envelopeBytes = envelopeBytes,
            deviceIdBytes = deviceIdBytes,
            genesisHashBytes = genesisHashBytes,
            entropyBytes = entropyBytes,
        )
    }

    /**
     * Fast cold-start path (subsequent boots after genesis): hand the persisted
     * identity handles to Rust, which re-derives the device-birth `AttA` from
     * the commitment it persisted at genesis and re-installs the signing
     * context.  No host-side measurement, anchor, or trust check.
     */
    private fun restoreIdentityContextDirect(
        prefs: SharedPreferences,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
    ): Boolean {
        val deviceIdStr = prefs.getString(keyDeviceId, null)
        val genesisHashStr = prefs.getString(keyGenesisHash, null)
        if (deviceIdStr.isNullOrEmpty() || genesisHashStr.isNullOrEmpty()) {
            Log.i(logTag, "restoreIdentityContextDirect: no persisted identity found")
            return false
        }

        val deviceIdBytes = try { BridgeEncoding.base32CrockfordDecode(deviceIdStr) } catch (_: Throwable) { ByteArray(0) }
        val genesisHashBytes = try { BridgeEncoding.base32CrockfordDecode(genesisHashStr) } catch (_: Throwable) { ByteArray(0) }
        if (deviceIdBytes.size != 32 || genesisHashBytes.size != 32) {
            Log.w(logTag, "restoreIdentityContextDirect: persisted identity malformed")
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
            Log.i(logTag, "restoreIdentityContextDirect: restored identity context")
            true
        } catch (t: Throwable) {
            Log.w(logTag, "restoreIdentityContextDirect failed; bootstrap required", t)
            false
        }
    }

    private fun requestGenesisEnvelopeViaIngress(
        locale: String,
        networkId: String,
        entropyBytes: ByteArray,
    ): ByteArray {
        val args = ArgPack.newBuilder()
            .setCodec(Codec.CODEC_PROTO)
            .setBody(
                ByteString.copyFrom(
                    // No device-birth binding fields: the SDK generates
                    // and persists the device-birth nonce commitment itself.
                    SystemGenesisRequest.newBuilder()
                        .setLocale(locale)
                        .setNetworkId(networkId)
                        .setDeviceEntropy(ByteString.copyFrom(entropyBytes))
                        .build()
                        .toByteArray()
                )
            )
            .build()

        val ingressRequest = IngressRequest.newBuilder()
            .setRouterQuery(
                RouterQueryOp.newBuilder()
                    .setMethod("system.genesis")
                    .setArgs(ByteString.copyFrom(args.toByteArray()))
                    .build()
            )
            .build()

        val ingressResponse = IngressResponse.parseFrom(Unified.dispatchIngress(ingressRequest.toByteArray()))
        return when (ingressResponse.resultCase) {
            IngressResponse.ResultCase.OK_BYTES -> ingressResponse.okBytes.toByteArray()
            IngressResponse.ResultCase.ERROR -> throw IllegalStateException(ingressResponse.error.message)
            else -> throw IllegalStateException("system.genesis returned no result")
        }
    }

    private fun installGenesisEnvelope(
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        installInput: GenesisEnvelopeInstallInput,
    ): ByteArray {
        val envelopeBytes = installInput.envelopeBytes
        Log.i(logTag, "installGenesisEnvelope: envelope size=${envelopeBytes.size}")

        ensureGenesisNotInvalidated(
            prefs = prefs,
            sdkContextInitialized = sdkContextInitialized,
            logTag = logTag,
            keyDeviceId = keyDeviceId,
            keyGenesisHash = keyGenesisHash,
            keyGenesisEnvelope = keyGenesisEnvelope,
        )

        val errorCode = getFramedErrorEnvelopeCode(envelopeBytes)
        if (errorCode != 0) {
            Log.w(logTag, "installGenesisEnvelope: native returned error envelope code=$errorCode; forwarding without bootstrap")
            return envelopeBytes
        }

        val deviceIdBytes = installInput.deviceIdBytes
        val genesisHashBytes = installInput.genesisHashBytes
        val deviceIdB32 = BridgeEncoding.base32CrockfordEncode(deviceIdBytes)
        val genesisHashB32 = BridgeEncoding.base32CrockfordEncode(genesisHashBytes)
        val envelopeB32 = BridgeEncoding.base32CrockfordEncode(envelopeBytes)

        prefs.edit()
            .putString(keyDeviceId, deviceIdB32)
            .putString(keyGenesisHash, genesisHashB32)
            .putString(keyGenesisEnvelope, envelopeB32)
            .apply()

        Log.i(logTag, "installGenesisEnvelope: identity persisted (deviceId/genesisHash/envelope stored as b32)")

        ensureGenesisNotInvalidated(
            prefs = prefs,
            sdkContextInitialized = sdkContextInitialized,
            logTag = logTag,
            keyDeviceId = keyDeviceId,
            keyGenesisHash = keyGenesisHash,
            keyGenesisEnvelope = keyGenesisEnvelope,
        )

        // FINALIZE: tell Rust to install the signing context.  Rust re-derives
        // `AttA` from the device-birth nonce commitment it persisted during
        // `system.genesis` — the report carries only the identity handles.
        val finalizeEnvelope = sendBootstrapMeasurementReport(
            BootstrapMeasurementReport.newBuilder()
                .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_FINALIZE)
                .setDeviceId(ByteString.copyFrom(deviceIdBytes))
                .setGenesisHash(ByteString.copyFrom(genesisHashBytes))
                .build()
        )

        val finalize = decodeBootstrapFinalizeResponseEnvelope(finalizeEnvelope)
        sdkContextInitialized.set(
            finalize.result == BootstrapFinalizeResponse.Result.BOOTSTRAP_RESULT_READY
        )
        return finalizeEnvelope
    }

    fun bootstrapFromPrefs(
        context: Context,
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

        if (restoreIdentityContextDirect(
                prefs = prefs,
                logTag = logTag,
                keyDeviceId = keyDeviceId,
                keyGenesisHash = keyGenesisHash,
            )) {
            sdkContextInitialized.set(true)
            return true
        }

        try {
            val deviceIdStr = prefs.getString(keyDeviceId, null)
            val genesisHashStr = prefs.getString(keyGenesisHash, null)

            if (!deviceIdStr.isNullOrEmpty() && !genesisHashStr.isNullOrEmpty()) {
                val deviceIdBytes = try { BridgeEncoding.base32CrockfordDecode(deviceIdStr) } catch (_: Throwable) { ByteArray(0) }
                val genesisHashBytes = try { BridgeEncoding.base32CrockfordDecode(genesisHashStr) } catch (_: Throwable) { ByteArray(0) }

                if (deviceIdBytes.size == 32 && genesisHashBytes.size == 32) {
                    // Signal that bootstrap is starting so the session manager
                    // returns "securing_device" (the UI shows progress instead
                    // of "needs_genesis") while Rust re-installs the context.
                    try {
                        sendBootstrapMeasurementReport(
                            BootstrapMeasurementReport.newBuilder()
                                .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_STARTED)
                                .setDeviceId(ByteString.copyFrom(deviceIdBytes))
                                .setGenesisHash(ByteString.copyFrom(genesisHashBytes))
                                .build()
                        )
                    } catch (_: Throwable) { /* non-fatal; progress screen is best-effort */ }

                    // RESUME_FINALIZE: Rust re-derives `AttA` from the persisted
                    // device-birth nonce commitment and re-installs the context
                    // (also re-registers storage-node auth). Identity handles only.
                    val finalizeEnvelope = sendBootstrapMeasurementReport(
                        BootstrapMeasurementReport.newBuilder()
                            .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_RESUME_FINALIZE)
                            .setDeviceId(ByteString.copyFrom(deviceIdBytes))
                            .setGenesisHash(ByteString.copyFrom(genesisHashBytes))
                            .build()
                    )
                    val finalize = decodeBootstrapFinalizeResponseEnvelope(finalizeEnvelope)
                    val ready = finalize.result == BootstrapFinalizeResponse.Result.BOOTSTRAP_RESULT_READY
                    sdkContextInitialized.set(ready)
                    Log.i(logTag, "bootstrapFromPrefs: Rust finalize result=${finalize.result} ready=$ready")
                    return ready
                }
            } else {
                Log.i(logTag, "bootstrapFromPrefs: no persisted identity found")
            }
        } catch (t: Throwable) {
            Log.e(logTag, "bootstrapFromPrefs failed", t)
            if (t is DsmNativeException) {
                throw t
            }
        }
        return false
    }

    fun createGenesis(
        context: Context,
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        locale: String,
        networkId: String,
        entropyBytes: ByteArray
    ): ByteArray {
        if (entropyBytes.size != 32) {
            Log.e(logTag, "createGenesis: entropy must be 32 bytes, got ${entropyBytes.size}")
            return ByteArray(0)
        }

        genesisLifecycleInFlight.set(true)
        genesisLifecycleInvalidated.set(false)

        // Flip Rust's BOOTSTRAP_SECURING=true before genesis so the session
        // manager reports "securing_device" and the UI leaves the Initialize
        // screen immediately.  Device id / genesis hash aren't known yet; the
        // Rust handler accepts empty bytes for BOOTSTRAP_PHASE_STARTED.
        try {
            sendBootstrapMeasurementReport(
                BootstrapMeasurementReport.newBuilder()
                    .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_STARTED)
                    .build()
            )
        } catch (t: Throwable) {
            Log.w(logTag, "createGenesis: early BOOTSTRAP_PHASE_STARTED signal failed (continuing)", t)
        }

        val result = try {
            val cachedDevId = prefs.getString(keyDeviceId, null)
            val cachedGenHash = prefs.getString(keyGenesisHash, null)

            if (!cachedDevId.isNullOrEmpty() && !cachedGenHash.isNullOrEmpty()) {
                Log.i(logTag, "createGenesis: identity already exists, clearing for fresh genesis")
                clearGenesisArtifacts(
                    prefs = prefs,
                    sdkContextInitialized = sdkContextInitialized,
                    keyDeviceId = keyDeviceId,
                    keyGenesisHash = keyGenesisHash,
                    keyGenesisEnvelope = keyGenesisEnvelope,
                    logTag = logTag,
                )
            }

            ensureGenesisNotInvalidated(
                prefs = prefs,
                sdkContextInitialized = sdkContextInitialized,
                logTag = logTag,
                keyDeviceId = keyDeviceId,
                keyGenesisHash = keyGenesisHash,
                keyGenesisEnvelope = keyGenesisEnvelope,
            )

            val envelopeBytes = requestGenesisEnvelopeViaIngress(
                locale,
                networkId,
                entropyBytes,
            )
            if (envelopeBytes.isEmpty()) {
                Log.e(logTag, "createGenesis: ingress returned empty envelope")
                return ByteArray(0)
            }
            val installInput = parseGenesisEnvelopeInstallInput(envelopeBytes)
            val finalizeEnvelope = installGenesisEnvelope(
                prefs = prefs,
                sdkContextInitialized = sdkContextInitialized,
                logTag = logTag,
                keyDeviceId = keyDeviceId,
                keyGenesisHash = keyGenesisHash,
                keyGenesisEnvelope = keyGenesisEnvelope,
                installInput = installInput,
            )
            val finalize = decodeBootstrapFinalizeResponseEnvelope(finalizeEnvelope)
            if (finalize.result != BootstrapFinalizeResponse.Result.BOOTSTRAP_RESULT_READY) {
                return finalizeEnvelope
            }
            envelopeBytes
        } catch (t: Throwable) {
            Log.e(logTag, "createGenesis failed", t)
            clearGenesisArtifacts(
                prefs = prefs,
                sdkContextInitialized = sdkContextInitialized,
                keyDeviceId = keyDeviceId,
                keyGenesisHash = keyGenesisHash,
                keyGenesisEnvelope = keyGenesisEnvelope,
                logTag = logTag,
            )
            if (t is GenesisInterruptedException || t is DsmNativeException || t is SecurityException) {
                throw t
            }
            ByteArray(0)
        } finally {
            genesisLifecycleInFlight.set(false)
            genesisLifecycleInvalidated.set(false)
        }
        return result
    }

}
