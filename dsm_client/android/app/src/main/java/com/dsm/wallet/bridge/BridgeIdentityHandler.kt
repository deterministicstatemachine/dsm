package com.dsm.wallet.bridge

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.google.protobuf.ByteString
import com.dsm.native.DsmNativeException
import com.dsm.wallet.security.AccessLevel
import com.dsm.wallet.security.AntiCloneGate
import com.dsm.wallet.security.SiliconFingerprint
import dsm.types.proto.DeviceBindingCaptureResult
import dsm.types.proto.Envelope
import dsm.types.proto.IngressRequest
import dsm.types.proto.MarkGenesisSecuringOp
import java.util.concurrent.atomic.AtomicBoolean

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

    /**
     * Build + dispatch a MarkGenesisSecuring ingress request. This is the cross-platform
     * seam — the same op is reachable from iOS via dsm_dispatch_ingress_request once the
     * iOS host is wired. Blocks the calling thread on the JNI call so the Rust flag flip
     * is visible before the next line runs. NativeBoundaryBridge's post-hook schedules
     * publishCurrentSessionState on the UI thread after the mark lands; subsequent
     * BleEventRelay.dispatchEnvelope calls share the same UI-thread FIFO, preserving
     * the "Rust flag set → session.state published → lifecycle envelope fired" ordering
     * that kills the bounce-to-initialize race.
     */
    private fun markGenesisSecuring(phase: MarkGenesisSecuringOp.Phase, logTag: String) {
        try {
            val request = IngressRequest.newBuilder()
                .setMarkGenesisSecuring(
                    MarkGenesisSecuringOp.newBuilder().setPhase(phase).build()
                )
                .build()
            NativeBoundaryBridge.ingress(request.toByteArray())
        } catch (t: Throwable) {
            Log.w(logTag, "markGenesisSecuring($phase) ingress call failed", t)
        }
    }

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

        // envelopeBytes is already a Rust-authored framed Envelope v3 — relay directly.
        BleEventRelay.dispatchEnvelope(envelopeBytes)

        run {
            val envelopeB32 = BridgeEncoding.base32CrockfordEncode(envelopeBytes)
            prefs.edit()
                .putString(keyGenesisEnvelope, envelopeB32)
                .apply()
            Log.i(logTag, "installGenesisEnvelope: persisted genesis envelope (b32) early")
        }

        val deviceIdBytes = installInput.deviceIdBytes
        val genesisHashBytes = installInput.genesisHashBytes
        val entropyBytes = installInput.entropyBytes

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
            keyDbrwSalt = keyDbrwSalt,
        )

        val sdkInitOk = Unified.initializeSdkContext(deviceIdBytes, genesisHashBytes, entropyBytes)
        if (!sdkInitOk) {
            Log.e(logTag, "installGenesisEnvelope: failed to initialize SDK context")
            return ByteArray(0)
        }

        // Run silicon fingerprint enrollment with progress reporting.
        // This is the one-time heavy operation (~15-20s, 21 trials).
        // Subsequent boots use fast mode (no hardware probing).
        // STRICT ORDER (see docs/plans/2026-04-10-rust-authoritative-securing-phase.md Task 4):
        // 1. dispatchIngress(MarkGenesisSecuring STARTED) — Rust flips securing_in_progress
        //    synchronously, then NativeBoundaryBridge post-hook posts a fresh session.state
        //    publish to the UI thread queue.
        // 2. createGenesisSecuringDeviceEnvelope dispatch — also hits the UI thread queue
        //    after the publish because of step 1's post-hook, so useNativeSessionBridge
        //    observes securing_device BEFORE the bar renders.
        markGenesisSecuring(MarkGenesisSecuringOp.Phase.PHASE_STARTED, logTag)
        UnifiedNativeApi.createGenesisSecuringDeviceEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
        Log.i(logTag, "installGenesisEnvelope: starting silicon fingerprint enrollment...")

        val siliconFp = SiliconFingerprint()
        try {
            siliconFp.enroll(context) { completed, total ->
                val pct = ((completed * 100) / total).coerceIn(0, 100)
                UnifiedNativeApi.createGenesisSecuringProgressEnvelope(pct).let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
            }
        } catch (e: Exception) {
            Log.e(logTag, "installGenesisEnvelope: silicon FP enrollment failed", e)
            throw SecurityException("installGenesisEnvelope: C-DBRW enrollment failed", e)
        }

        UnifiedNativeApi.createGenesisSecuringCompleteEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
        Log.i(logTag, "installGenesisEnvelope: silicon fingerprint enrollment complete")

        ensureGenesisNotInvalidated(
            prefs = prefs,
            sdkContextInitialized = sdkContextInitialized,
            logTag = logTag,
            keyDeviceId = keyDeviceId,
            keyGenesisHash = keyGenesisHash,
            keyGenesisEnvelope = keyGenesisEnvelope,
            keyDbrwSalt = keyDbrwSalt,
        )

        // Enrollment must produce a valid C-DBRW anchor before bootstrap continues.
        val hwResult = AntiCloneGate.getStableHwAnchorWithTrust(context)
        if (hwResult.accessLevel == AccessLevel.READ_ONLY || hwResult.accessLevel == AccessLevel.BLOCKED) {
            throw SecurityException("installGenesisEnvelope: C-DBRW verification rejected the enrolled device state")
        }
        val hwEntropy = hwResult.anchor ?: throw IllegalStateException("Hardware anchor not available")
        val envEntropy = AntiCloneGate.getEnvironmentFingerprint(context)
        val dbrwSalt = ByteArray(32)
        java.security.SecureRandom().nextBytes(dbrwSalt)
        prefs.edit().putString(keyDbrwSalt, BridgeEncoding.base32CrockfordEncode(dbrwSalt)).apply()
        Log.i(logTag, "installGenesisEnvelope: persisted DBRW salt")

        com.dsm.native.DsmNative.sdkBootstrapStrict(
            deviceIdBytes,
            genesisHashBytes,
            hwEntropy,
            envEntropy,
            dbrwSalt
        )

        Log.i(logTag, "installGenesisEnvelope: DBRW initialized successfully with hardware entropy")

        ensureGenesisNotInvalidated(
            prefs = prefs,
            sdkContextInitialized = sdkContextInitialized,
            logTag = logTag,
            keyDeviceId = keyDeviceId,
            keyGenesisHash = keyGenesisHash,
            keyGenesisEnvelope = keyGenesisEnvelope,
            keyDbrwSalt = keyDbrwSalt,
        )

        try {
            val routerInstalled = Unified.ensureAppRouterInstalled()
            Log.i(logTag, "installGenesisEnvelope: AppRouter installation result = $routerInstalled")
            if (!routerInstalled) {
                Log.w(logTag, "installGenesisEnvelope: AppRouter installation returned false")
            }
        } catch (e: Exception) {
            Log.w(logTag, "installGenesisEnvelope: AppRouter installation failed", e)
        }

        try {
            Unified.getTransportHeadersV3()
            Log.i(logTag, "installGenesisEnvelope: transport headers populated successfully")
        } catch (e: Exception) {
            Log.w(logTag, "installGenesisEnvelope: failed to populate transport headers", e)
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

        sdkContextInitialized.set(true)
        UnifiedNativeApi.createGenesisOkEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }

        Log.i(logTag, "installGenesisEnvelope: atomic post-genesis initialization completed successfully")
        return envelopeBytes
    }

    fun handleHostPauseDuringGenesis(
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        keyDbrwSalt: String,
    ) {
        if (!genesisLifecycleInFlight.get()) {
            return
        }
        genesisLifecycleInvalidated.set(true)
        clearGenesisArtifacts(
            prefs = prefs,
            sdkContextInitialized = sdkContextInitialized,
            keyDeviceId = keyDeviceId,
            keyGenesisHash = keyGenesisHash,
            keyGenesisEnvelope = keyGenesisEnvelope,
            keyDbrwSalt = keyDbrwSalt,
            logTag = logTag,
        )
        UnifiedNativeApi.createGenesisSecuringAbortedEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
        UnifiedNativeApi.createGenesisErrorEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
        Log.w(logTag, "handleHostPauseDuringGenesis: app left during DBRW securing; wiped partial state")
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
            try {
                val installed = Unified.ensureAppRouterInstalled()
                Log.i(logTag, "bootstrapFromPrefs: AppRouter re-check result = $installed")
            } catch (e: Throwable) {
                Log.w(logTag, "bootstrapFromPrefs: Failed to ensure AppRouter installed on re-check", e)
            }
            return true
        }

        try {
            val deviceIdStr = prefs.getString(keyDeviceId, null)
            val genesisHashStr = prefs.getString(keyGenesisHash, null)

            if (!deviceIdStr.isNullOrEmpty() && !genesisHashStr.isNullOrEmpty()) {
                val deviceIdBytes = try { BridgeEncoding.base32CrockfordDecode(deviceIdStr) } catch (_: Throwable) { ByteArray(0) }
                val genesisHashBytes = try { BridgeEncoding.base32CrockfordDecode(genesisHashStr) } catch (_: Throwable) { ByteArray(0) }

                if (deviceIdBytes.size == 32 && genesisHashBytes.size == 32) {
                    val ok = Unified.initializeSdkContext(deviceIdBytes, genesisHashBytes, genesisHashBytes)
                    if (ok) {
                        sdkContextInitialized.set(true)
                        Log.i(logTag, "bootstrapFromPrefs: SDK context initialized")

                        val hwAnchorResult = AntiCloneGate.getStableHwAnchorWithTrust(context)
                        when (hwAnchorResult.accessLevel) {
                            AccessLevel.FULL_ACCESS -> Log.i(logTag, "bootstrapFromPrefs: DBRW hardware validation passed (full access)")
                            AccessLevel.PIN_REQUIRED -> Log.w(logTag, "bootstrapFromPrefs: DBRW hardware validation degraded (PIN required) - allowing with reduced trust")
                            AccessLevel.READ_ONLY -> throw SecurityException("bootstrapFromPrefs: C-DBRW health rejected device state")
                            AccessLevel.BLOCKED -> throw SecurityException("bootstrapFromPrefs: C-DBRW hardware validation blocked")
                        }

                        val hwEntropy = hwAnchorResult.anchor
                            ?: throw SecurityException("bootstrapFromPrefs: C-DBRW anchor unavailable")
                        val envEntropy = AntiCloneGate.getEnvironmentFingerprint(context)
                        val dbrwSalt: ByteArray = run {
                            val existing = prefs.getString(keyDbrwSalt, null)
                            if (!existing.isNullOrEmpty()) {
                                try {
                                    val decoded = BridgeEncoding.base32CrockfordDecode(existing)
                                    if (decoded.size == 32) {
                                        Log.i(logTag, "bootstrapFromPrefs: loaded persisted DBRW salt")
                                        return@run decoded
                                    }
                                } catch (_: Throwable) { }
                            }
                            val fresh = ByteArray(32)
                            java.security.SecureRandom().nextBytes(fresh)
                            prefs.edit().putString(keyDbrwSalt, BridgeEncoding.base32CrockfordEncode(fresh)).apply()
                            Log.i(logTag, "bootstrapFromPrefs: generated and persisted new DBRW salt")
                            fresh
                        }
                        com.dsm.native.DsmNative.sdkBootstrapStrict(
                            deviceIdBytes,
                            genesisHashBytes,
                            hwEntropy,
                            envEntropy,
                            dbrwSalt
                        )
                        Log.i(logTag, "bootstrapFromPrefs: DBRW initialization completed (access level: ${hwAnchorResult.accessLevel})")

                        try {
                            val installed = Unified.ensureAppRouterInstalled()
                            Log.i(logTag, "bootstrapFromPrefs: AppRouter installation result = $installed")
                        } catch (e: Throwable) {
                            Log.w(logTag, "bootstrapFromPrefs: Failed to ensure AppRouter installed", e)
                        }

                        return true
                    } else {
                        Log.w(logTag, "bootstrapFromPrefs: Unified.initializeSdkContext returned false")
                    }
                }
            } else {
                Log.i(logTag, "bootstrapFromPrefs: no persisted identity found")
            }
        } catch (t: Throwable) {
            Log.e(logTag, "bootstrapFromPrefs failed", t)
            if (t is DsmNativeException || t is SecurityException) {
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
        UnifiedNativeApi.createGenesisStartedEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }

        val result = try {
            val cachedDevId = prefs.getString(keyDeviceId, null)
            val cachedGenHash = prefs.getString(keyGenesisHash, null)

            if (!cachedDevId.isNullOrEmpty() && !cachedGenHash.isNullOrEmpty()) {
                Log.i(logTag, "createGenesis: identity already exists, clearing for fresh genesis")
                prefs.edit().clear().apply()
            }

            val envelopeBytes = com.dsm.native.DsmNative.createGenesisStrict(locale, networkId, entropyBytes)
            if (envelopeBytes.isEmpty()) {
                Log.e(logTag, "createGenesis: JNI returned empty envelope")
                return ByteArray(0)
            }
            val installInput = parseGenesisEnvelopeInstallInput(envelopeBytes)
            installGenesisEnvelope(
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
        } catch (t: Throwable) {
            Log.e(logTag, "createGenesis failed", t)
            UnifiedNativeApi.createGenesisErrorEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
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
    ): DeviceBindingCaptureResult {
        genesisLifecycleInFlight.set(true)
        genesisLifecycleInvalidated.set(false)
        UnifiedNativeApi.createGenesisStartedEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }

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
            DeviceBindingCaptureResult.newBuilder()
                .setInstalled(true)
                .setDeviceId(ByteString.copyFrom(installInput.deviceIdBytes))
                .setGenesisHash(ByteString.copyFrom(installInput.genesisHashBytes))
                .build()
        } catch (t: Throwable) {
            Log.e(logTag, "captureDeviceBindingForGenesisEnvelope failed", t)
            UnifiedNativeApi.createGenesisErrorEnvelope().let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
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
