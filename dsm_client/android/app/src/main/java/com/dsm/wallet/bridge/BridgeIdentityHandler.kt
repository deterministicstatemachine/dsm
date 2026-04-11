package com.dsm.wallet.bridge

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.google.protobuf.ByteString
import com.dsm.native.DsmNativeException
import com.dsm.wallet.security.AccessLevel
import com.dsm.wallet.security.AntiCloneGate
import com.dsm.wallet.security.AntiCloneGateException
import com.dsm.wallet.security.HardwareAnchorResult
import dsm.types.proto.Envelope
import dsm.types.proto.BootstrapFinalizeResponse
import dsm.types.proto.BootstrapMeasurementReport
import dsm.types.proto.ArgPack
import dsm.types.proto.Codec
import dsm.types.proto.EnvelopeOp
import dsm.types.proto.IngressRequest
import dsm.types.proto.IngressResponse
import dsm.types.proto.RouterQueryOp
import dsm.types.proto.SystemGenesisRequest
import java.util.concurrent.atomic.AtomicBoolean

internal object BridgeIdentityHandler {
    private const val KEY_HAS_IDENTITY = "has_identity"
    private const val KEY_FRONTEND_DEVICE_ID = "device_id"
    private const val KEY_FRONTEND_GENESIS_HASH = "genesis_hash"
    private const val KEY_GENESIS_CREATED = "genesis_created"
    /**
     * Base32-Crockford encoded 32-byte C-DBRW reference anchor (`AC_D`),
     * returned by [`AntiCloneGate.enroll`] and cached for subsequent boots
     * so `bootstrapFromPrefs` can reuse the same `cdbrw_hw_entropy` input
     * without triggering a fresh K-trial enrollment on every app start.
     * Cleared alongside the rest of the genesis state on
     * [`clearGenesisArtifacts`].
     */
    private const val KEY_CDBRW_ANCHOR = "cdbrw_reference_anchor"

    private val genesisLifecycleInFlight = AtomicBoolean(false)
    private val genesisLifecycleInvalidated = AtomicBoolean(false)

    private class GenesisInterruptedException(message: String) : IllegalStateException(message)

    private data class GenesisEnvelopeInstallInput(
        val envelopeBytes: ByteArray,
        val deviceIdBytes: ByteArray,
        val genesisHashBytes: ByteArray,
        val entropyBytes: ByteArray,
    )

    private data class BootstrapMeasurements(
        val trustLevel: BootstrapMeasurementReport.TrustLevel,
        val hwEntropy: ByteArray,
        val envEntropy: ByteArray,
        val dbrwSalt: ByteArray,
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

    private fun mapTrustLevel(accessLevel: AccessLevel): BootstrapMeasurementReport.TrustLevel {
        return when (accessLevel) {
            AccessLevel.FULL_ACCESS -> BootstrapMeasurementReport.TrustLevel.BOOTSTRAP_TRUST_LEVEL_FULL_ACCESS
            AccessLevel.PIN_REQUIRED -> BootstrapMeasurementReport.TrustLevel.BOOTSTRAP_TRUST_LEVEL_PIN_REQUIRED
            AccessLevel.READ_ONLY -> BootstrapMeasurementReport.TrustLevel.BOOTSTRAP_TRUST_LEVEL_READ_ONLY
            AccessLevel.BLOCKED -> BootstrapMeasurementReport.TrustLevel.BOOTSTRAP_TRUST_LEVEL_BLOCKED
        }
    }

    private fun sendBootstrapMeasurementReport(
        report: BootstrapMeasurementReport,
    ): ByteArray {
        val envelope = Envelope.newBuilder()
            .setVersion(3)
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

    private fun clearGenesisArtifacts(
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        keyDbrwSalt: String,
        logTag: String,
    ) {
        prefs.edit()
            .remove(keyDeviceId)
            .remove(keyGenesisHash)
            .remove(keyGenesisEnvelope)
            .remove(keyDbrwSalt)
            .remove(KEY_CDBRW_ANCHOR)
            .remove(KEY_HAS_IDENTITY)
            .remove(KEY_FRONTEND_DEVICE_ID)
            .remove(KEY_FRONTEND_GENESIS_HASH)
            .remove(KEY_GENESIS_CREATED)
            .apply()
        sdkContextInitialized.set(false)
        Log.w(logTag, "clearGenesisArtifacts: cleared partial genesis + DBRW state")
    }

    private fun ensureGenesisNotInvalidated(
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        keyDbrwSalt: String,
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
            keyDbrwSalt = keyDbrwSalt,
            logTag = logTag,
        )
        throw GenesisInterruptedException(
            "Device securing was interrupted. Do not leave the screen until finished. Initialization was wiped and must be started again so DBRW is not corrupted."
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

    private fun collectBootstrapMeasurements(
        context: Context,
        prefs: SharedPreferences,
        logTag: String,
        keyDbrwSalt: String,
    ): BootstrapMeasurements {
        // Genesis install path: the `cdbrw_hw_entropy` that K_DBRW is derived
        // from comes from a fresh K-trial enrollment — the Rust writer
        // persists the reference snapshot to `dsm_silicon_fp_v4.bin` and
        // hands us back the 32-byte `AC_D` anchor. We cache it in prefs so
        // `bootstrapFromPrefs` can replay the same anchor on subsequent
        // boots without another full enrollment cycle.
        val hwResult = AntiCloneGate.enroll(context) { completed, total ->
            val pct = ((completed * 100) / total).coerceIn(0, 100)
            try {
                sendBootstrapMeasurementReport(
                    BootstrapMeasurementReport.newBuilder()
                        .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_PROGRESS)
                        .setProgressPercent(pct)
                        .build()
                )
            } catch (_: Throwable) { /* non-fatal; progress UI is best-effort */ }
        }
        val hwEntropy = hwResult.anchor ?: throw IllegalStateException(
            "collectBootstrapMeasurements: cdbrw.enroll returned no anchor"
        )
        val envEntropy = AntiCloneGate.buildEnvironmentBytes()
        val dbrwSalt = ByteArray(32)
        java.security.SecureRandom().nextBytes(dbrwSalt)
        prefs.edit()
            .putString(keyDbrwSalt, BridgeEncoding.base32CrockfordEncode(dbrwSalt))
            .putString(KEY_CDBRW_ANCHOR, BridgeEncoding.base32CrockfordEncode(hwEntropy))
            .apply()
        Log.i(
            logTag,
            "collectBootstrapMeasurements: persisted DBRW salt and cached reference anchor " +
                "(access=${hwResult.accessLevel})"
        )
        return BootstrapMeasurements(
            trustLevel = mapTrustLevel(hwResult.accessLevel),
            hwEntropy = hwEntropy,
            envEntropy = envEntropy,
            dbrwSalt = dbrwSalt,
        )
    }

    /**
     * Resume path (subsequent boots after genesis): surface a fresh trust
     * verdict from the Rust access gate WITHOUT running another full K-trial
     * enrollment. On the happy path the reference anchor was cached in
     * [`KEY_CDBRW_ANCHOR`] after the initial `collectBootstrapMeasurements`,
     * and we only run a single orbit probe via [`AntiCloneGate.measureTrust`]
     * to refresh the trust snapshot.
     *
     * If the anchor cache is missing (e.g. prefs were wiped but the bin file
     * survived, or the app is upgrading from the old Kotlin enrollment path)
     * we fall back to a fresh enrollment — expensive but correct, and the
     * anchor is re-cached so the next boot takes the fast path again.
     */
    private fun resumeCdbrwTrust(
        context: Context,
        prefs: SharedPreferences,
        logTag: String,
        deviceIdBytes: ByteArray,
        genesisHashBytes: ByteArray,
    ): HardwareAnchorResult {
        val cachedAnchorB32 = prefs.getString(KEY_CDBRW_ANCHOR, null)
        val cachedAnchor: ByteArray? = if (!cachedAnchorB32.isNullOrEmpty()) {
            try {
                val decoded = BridgeEncoding.base32CrockfordDecode(cachedAnchorB32)
                if (decoded.size == 32) decoded else null
            } catch (_: Throwable) {
                null
            }
        } else {
            null
        }

        return if (cachedAnchor != null) {
            Log.i(logTag, "resumeCdbrwTrust: using cached reference anchor, running single-probe trust check")
            try {
                AntiCloneGate.measureTrust(context, cachedAnchor)
            } catch (e: AntiCloneGateException) {
                Log.e(logTag, "resumeCdbrwTrust: measure_trust failed, falling back to fresh enrollment", e)
                reenrollAndCache(context, prefs, logTag, deviceIdBytes, genesisHashBytes)
            }
        } else {
            Log.w(
                logTag,
                "resumeCdbrwTrust: no cached anchor in prefs, running fresh K-trial enrollment",
            )
            reenrollAndCache(context, prefs, logTag, deviceIdBytes, genesisHashBytes)
        }
    }

    private fun reenrollAndCache(
        context: Context,
        prefs: SharedPreferences,
        logTag: String,
        deviceIdBytes: ByteArray,
        genesisHashBytes: ByteArray,
    ): HardwareAnchorResult {
        val result = AntiCloneGate.enroll(context) { completed, total ->
            val pct = ((completed * 100) / total).coerceIn(0, 100)
            try {
                sendBootstrapMeasurementReport(
                    BootstrapMeasurementReport.newBuilder()
                        .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_PROGRESS)
                        .setDeviceId(ByteString.copyFrom(deviceIdBytes))
                        .setGenesisHash(ByteString.copyFrom(genesisHashBytes))
                        .setProgressPercent(pct)
                        .build()
                )
            } catch (_: Throwable) { /* non-fatal */ }
        }
        val anchor = result.anchor
            ?: throw IllegalStateException("reenrollAndCache: cdbrw.enroll returned no anchor")
        prefs.edit()
            .putString(KEY_CDBRW_ANCHOR, BridgeEncoding.base32CrockfordEncode(anchor))
            .apply()
        Log.i(logTag, "reenrollAndCache: re-cached reference anchor (access=${result.accessLevel})")
        return result
    }

    private fun loadOrCreateDbrwSalt(
        prefs: SharedPreferences,
        keyDbrwSalt: String,
        logTag: String,
    ): ByteArray {
        val existing = prefs.getString(keyDbrwSalt, null)
        if (!existing.isNullOrEmpty()) {
            try {
                val decoded = BridgeEncoding.base32CrockfordDecode(existing)
                if (decoded.size == 32) {
                    Log.i(logTag, "loadOrCreateDbrwSalt: loaded persisted DBRW salt")
                    return decoded
                }
            } catch (_: Throwable) {
                Log.w(logTag, "loadOrCreateDbrwSalt: invalid persisted DBRW salt, regenerating")
            }
        }

        val fresh = ByteArray(32)
        java.security.SecureRandom().nextBytes(fresh)
        prefs.edit().putString(keyDbrwSalt, BridgeEncoding.base32CrockfordEncode(fresh)).apply()
        Log.i(logTag, "loadOrCreateDbrwSalt: generated and persisted new DBRW salt")
        return fresh
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
        context: Context,
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        keyDbrwSalt: String,
        installInput: GenesisEnvelopeInstallInput,
    ): ByteArray {
        val envelopeBytes = installInput.envelopeBytes
        Log.i(logTag, "installGenesisEnvelope: envelope size=${envelopeBytes.size}")
        if (envelopeBytes.isNotEmpty()) {
            val previewLen = kotlin.math.min(24, envelopeBytes.size)
            val prefixB32 = BridgeEncoding.base32CrockfordEncode(
                envelopeBytes.copyOfRange(0, previewLen)
            ).take(32)
            Log.i(logTag, "installGenesisEnvelope: envelope prefix (b32): $prefixB32")
        }

        ensureGenesisNotInvalidated(
            prefs = prefs,
            sdkContextInitialized = sdkContextInitialized,
            logTag = logTag,
            keyDeviceId = keyDeviceId,
            keyGenesisHash = keyGenesisHash,
            keyGenesisEnvelope = keyGenesisEnvelope,
            keyDbrwSalt = keyDbrwSalt,
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

        sendBootstrapMeasurementReport(
            BootstrapMeasurementReport.newBuilder()
                .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_STARTED)
                .setDeviceId(ByteString.copyFrom(deviceIdBytes))
                .setGenesisHash(ByteString.copyFrom(genesisHashBytes))
                .build()
        )

        ensureGenesisNotInvalidated(
            prefs = prefs,
            sdkContextInitialized = sdkContextInitialized,
            logTag = logTag,
            keyDeviceId = keyDeviceId,
            keyGenesisHash = keyGenesisHash,
            keyGenesisEnvelope = keyGenesisEnvelope,
            keyDbrwSalt = keyDbrwSalt,
        )

        val measurements = collectBootstrapMeasurements(
            context = context,
            prefs = prefs,
            logTag = logTag,
            keyDbrwSalt = keyDbrwSalt,
        )

        ensureGenesisNotInvalidated(
            prefs = prefs,
            sdkContextInitialized = sdkContextInitialized,
            logTag = logTag,
            keyDeviceId = keyDeviceId,
            keyGenesisHash = keyGenesisHash,
            keyGenesisEnvelope = keyGenesisEnvelope,
            keyDbrwSalt = keyDbrwSalt,
        )

        val finalizeEnvelope = sendBootstrapMeasurementReport(
            BootstrapMeasurementReport.newBuilder()
                .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_FINALIZE)
                .setDeviceId(ByteString.copyFrom(deviceIdBytes))
                .setGenesisHash(ByteString.copyFrom(genesisHashBytes))
                .setCdbrwHwEntropy(ByteString.copyFrom(measurements.hwEntropy))
                .setCdbrwEnvFingerprint(ByteString.copyFrom(measurements.envEntropy))
                .setCdbrwSalt(ByteString.copyFrom(measurements.dbrwSalt))
                .setTrustLevel(measurements.trustLevel)
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
        keyDbrwSalt: String
    ): Boolean {
        if (sdkContextInitialized.get()) {
            Log.i(logTag, "bootstrapFromPrefs: already initialized")
            return true
        }

        try {
            val deviceIdStr = prefs.getString(keyDeviceId, null)
            val genesisHashStr = prefs.getString(keyGenesisHash, null)

            if (!deviceIdStr.isNullOrEmpty() && !genesisHashStr.isNullOrEmpty()) {
                val deviceIdBytes = try { BridgeEncoding.base32CrockfordDecode(deviceIdStr) } catch (_: Throwable) { ByteArray(0) }
                val genesisHashBytes = try { BridgeEncoding.base32CrockfordDecode(genesisHashStr) } catch (_: Throwable) { ByteArray(0) }

                if (deviceIdBytes.size == 32 && genesisHashBytes.size == 32) {
                    // Signal to Rust that C-DBRW securing is starting.
                    // This sets BOOTSTRAP_SECURING=true so the session manager returns
                    // "securing_device" phase — the progress screen shows immediately
                    // instead of staying on "needs_genesis" for the full 34s derivation.
                    try {
                        sendBootstrapMeasurementReport(
                            BootstrapMeasurementReport.newBuilder()
                                .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_STARTED)
                                .setDeviceId(ByteString.copyFrom(deviceIdBytes))
                                .setGenesisHash(ByteString.copyFrom(genesisHashBytes))
                                .build()
                        )
                    } catch (_: Throwable) { /* non-fatal; progress screen is best-effort */ }

                    val hwAnchorResult = resumeCdbrwTrust(
                        context = context,
                        prefs = prefs,
                        logTag = logTag,
                        deviceIdBytes = deviceIdBytes,
                        genesisHashBytes = genesisHashBytes,
                    )
                    val hwEntropy = hwAnchorResult.anchor ?: throw IllegalStateException(
                        "bootstrapFromPrefs: cdbrw anchor unavailable after resume"
                    )
                    val envEntropy = AntiCloneGate.buildEnvironmentBytes()
                    val dbrwSalt = loadOrCreateDbrwSalt(
                        prefs = prefs,
                        keyDbrwSalt = keyDbrwSalt,
                        logTag = logTag,
                    )
                    val finalizeEnvelope = sendBootstrapMeasurementReport(
                        BootstrapMeasurementReport.newBuilder()
                            .setPhase(BootstrapMeasurementReport.Phase.BOOTSTRAP_PHASE_RESUME_FINALIZE)
                            .setDeviceId(ByteString.copyFrom(deviceIdBytes))
                            .setGenesisHash(ByteString.copyFrom(genesisHashBytes))
                            .setCdbrwHwEntropy(ByteString.copyFrom(hwEntropy))
                            .setCdbrwEnvFingerprint(ByteString.copyFrom(envEntropy))
                            .setCdbrwSalt(ByteString.copyFrom(dbrwSalt))
                            .setTrustLevel(mapTrustLevel(hwAnchorResult.accessLevel))
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
        keyDbrwSalt: String,
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

        val result = try {
            val cachedDevId = prefs.getString(keyDeviceId, null)
            val cachedGenHash = prefs.getString(keyGenesisHash, null)

            if (!cachedDevId.isNullOrEmpty() && !cachedGenHash.isNullOrEmpty()) {
                Log.i(logTag, "createGenesis: identity already exists, clearing for fresh genesis")
                prefs.edit().clear().apply()
            }

            val envelopeBytes = requestGenesisEnvelopeViaIngress(locale, networkId, entropyBytes)
            if (envelopeBytes.isEmpty()) {
                Log.e(logTag, "createGenesis: ingress returned empty envelope")
                return ByteArray(0)
            }
            val installInput = parseGenesisEnvelopeInstallInput(envelopeBytes)
            val finalizeEnvelope = installGenesisEnvelope(
                context = context,
                prefs = prefs,
                sdkContextInitialized = sdkContextInitialized,
                logTag = logTag,
                keyDeviceId = keyDeviceId,
                keyGenesisHash = keyGenesisHash,
                keyGenesisEnvelope = keyGenesisEnvelope,
                keyDbrwSalt = keyDbrwSalt,
                installInput = installInput,
            )
            val finalize = decodeBootstrapFinalizeResponseEnvelope(finalizeEnvelope)
            if (finalize.result != BootstrapFinalizeResponse.Result.BOOTSTRAP_RESULT_READY) {
                return finalizeEnvelope
            }
            envelopeBytes
        } catch (t: Throwable) {
            Log.e(logTag, "createGenesis failed", t)
            if (genesisLifecycleInvalidated.get()) {
                clearGenesisArtifacts(
                    prefs = prefs,
                    sdkContextInitialized = sdkContextInitialized,
                    keyDeviceId = keyDeviceId,
                    keyGenesisHash = keyGenesisHash,
                    keyGenesisEnvelope = keyGenesisEnvelope,
                    keyDbrwSalt = keyDbrwSalt,
                    logTag = logTag,
                )
            }
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

    fun captureDeviceBindingForGenesisEnvelope(
        context: Context,
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        keyDbrwSalt: String,
        genesisEnvelopeBytes: ByteArray,
    ): ByteArray {
        genesisLifecycleInFlight.set(true)
        genesisLifecycleInvalidated.set(false)

        val result = try {
            val cachedDevId = prefs.getString(keyDeviceId, null)
            val cachedGenHash = prefs.getString(keyGenesisHash, null)
            if (!cachedDevId.isNullOrEmpty() && !cachedGenHash.isNullOrEmpty()) {
                Log.i(logTag, "captureDeviceBindingForGenesisEnvelope: identity already exists, clearing for fresh install")
                prefs.edit().clear().apply()
            }

            val installInput = parseGenesisEnvelopeInstallInput(genesisEnvelopeBytes)
            val installedEnvelope = installGenesisEnvelope(
                context = context,
                prefs = prefs,
                sdkContextInitialized = sdkContextInitialized,
                logTag = logTag,
                keyDeviceId = keyDeviceId,
                keyGenesisHash = keyGenesisHash,
                keyGenesisEnvelope = keyGenesisEnvelope,
                keyDbrwSalt = keyDbrwSalt,
                installInput = installInput,
            )
            val errorCode = getFramedErrorEnvelopeCode(installedEnvelope)
            if (errorCode != 0) {
                throw IllegalStateException("captureDeviceBindingForGenesisEnvelope: refusing to install error envelope code=$errorCode")
            }
            installedEnvelope
        } catch (t: Throwable) {
            Log.e(logTag, "captureDeviceBindingForGenesisEnvelope failed", t)
            if (genesisLifecycleInvalidated.get()) {
                clearGenesisArtifacts(
                    prefs = prefs,
                    sdkContextInitialized = sdkContextInitialized,
                    keyDeviceId = keyDeviceId,
                    keyGenesisHash = keyGenesisHash,
                    keyGenesisEnvelope = keyGenesisEnvelope,
                    keyDbrwSalt = keyDbrwSalt,
                    logTag = logTag,
                )
            }
            if (t is GenesisInterruptedException || t is DsmNativeException || t is SecurityException) {
                throw t
            }
            throw IllegalStateException("captureDeviceBindingForGenesisEnvelope failed: ${t.message}", t)
        } finally {
            genesisLifecycleInFlight.set(false)
            genesisLifecycleInvalidated.set(false)
        }

        return result
    }
}
