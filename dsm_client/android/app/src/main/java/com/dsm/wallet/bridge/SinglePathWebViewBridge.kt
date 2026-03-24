// File: android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt
@file:Suppress("KotlinJniMissingFunction", "UNUSED_PARAMETER")

package com.dsm.wallet.bridge

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import java.util.Locale
import com.dsm.native.DsmNative
import com.dsm.native.DsmNativeException
import java.util.concurrent.atomic.AtomicBoolean
import com.dsm.wallet.bridge.ble.BleCoordinator
import com.dsm.wallet.security.AntiCloneGate
import com.dsm.wallet.security.AccessLevel

// ============================================================================
// DSM APP INTEGRATION BOUNDARY -- WebView RPC Dispatcher
// ============================================================================
//
// Central routing layer between the WebView frontend and the Rust SDK.
// All communication flows through handleBinaryRpc(method, payload).
//
// TRANSPORT:
//   Binary MessagePort ONLY. All @JavascriptInterface methods have been
//   removed. The WebView sends [8-byte msgId][BridgeRpcRequest proto]
//   and receives [0x03][Envelope v3 proto] responses.
//
// METHOD ROUTING (50+ methods, grouped by domain):
//   Bootstrap:  "sdkBootstrap"
//   Protocol:   "processEnvelopeV3"
//   AppRouter:  "appRouterQuery", "appRouterInvoke"
//   Bilateral:  "bilateralOfflineSend", "bilateralAcceptByCommitment", ...
//   BLE:        "bleCommand", "getBleStats", "retryBle", ...
//   Contacts:   "contactAdd", "contactRemove", "handleContactQrV3"
//   System:     "getTransportHeaders", "setSystemBarColor", "setPreference"
//   Recovery:   appRouter routes "recovery.*", "nfc.ring.write"
//
// ERROR CODES (returned in response envelope):
//   0 = success
//   1 = SDK not bootstrapped (SDK_READY = false)
//   2 = protobuf decode error
//   3 = native JNI error (Rust panic caught)
//
// ADDING A NEW RPC METHOD:
//   1. Add a case in handleBinaryRpc() matching the method string.
//   2. Add the JNI export in unified_protobuf_bridge.rs (Rust).
//   3. Add the external fun declaration in UnifiedNativeApi.kt.
//   4. Add the frontend wrapper in WebViewBridge.ts.
//
// See docs/INTEGRATION_GUIDE.md for the full developer onboarding guide.
// ============================================================================

/**
 * BINARY MESSAGE PORT BRIDGE ONLY
 *
 * All @JavascriptInterface methods have been removed.
 * Frontend communicates exclusively via MessagePort binary protocol.
 *
 * This class provides:
 * 1. Binary RPC routing via handleBinaryRpc()
 * 2. Internal helpers for identity/genesis operations
 * 3. SDK context initialization
 */
class SinglePathWebViewBridge(private val context: Context) {
    fun getContext(): Context = context

    companion object {
        private const val TAG = "SinglePathWebViewBridge"
        private const val PREFS_NAME = "dsm_prefs"
        // Canonical identity keys (app-wide).
        // Values are stored as Base32 Crockford strings (standard boundary encoding).
        private const val KEY_DEVICE_ID = "device_id_bytes"
        private const val KEY_GENESIS_HASH = "genesis_hash_bytes"
        private const val KEY_GENESIS_ENVELOPE = "genesis_envelope_bytes"
        private const val KEY_DBRW_SALT = "dbrw_salt_bytes"



        private fun readPersistedBytesOrEmpty(p: SharedPreferences, key: String): ByteArray {
            val s = p.getString(key, null)
            if (s.isNullOrBlank()) return ByteArray(0)
            return try {
                BridgeEncoding.base32CrockfordDecode(s)
            } catch (_: Throwable) {
                ByteArray(0)
            }
        }



        // Enhanced error handling with specific error codes
        private const val ERROR_BRIDGE_NOT_INITIALIZED = 1
        private const val ERROR_INVALID_PAYLOAD = 2
        private const val ERROR_NATIVE_EXCEPTION = 3
        private const val ERROR_NETWORK_ERROR = 4
        private const val ERROR_PERMISSION_DENIED = 5
        private const val ERROR_INVALID_STATE = 6
        private const val ERROR_TIMEOUT = 7
        private const val ERROR_UNKNOWN_METHOD = 8
        
        @Volatile private var instance: SinglePathWebViewBridge? = null
        private val sdkContextInitialized = AtomicBoolean(false)
        private val routerReqCounter = java.util.concurrent.atomic.AtomicLong(1L)

        private fun nextRouterReqId(): ByteArray {
            val id = routerReqCounter.getAndIncrement()
            val buf = ByteArray(8)
            val bb = java.nio.ByteBuffer.wrap(buf).order(java.nio.ByteOrder.BIG_ENDIAN)
            bb.putLong(id)
            return buf
        }
        
        fun getInstance(context: Context): SinglePathWebViewBridge {
            return instance ?: synchronized(this) {
                instance ?: SinglePathWebViewBridge(context.applicationContext).also { instance = it }
            }
        }

        /**
         * Ensure the MessagePort binary bridge singleton is initialized.
         * Some call sites used to hold an instance reference without assigning the companion
         * `instance`, which breaks handleBinaryRpc().
         */
        fun ensureInitialized(context: Context): SinglePathWebViewBridge {
            return SinglePathWebViewBridge.getInstance(context)
        }

        /**
         * Formal schema validation for bridge payloads.
         * Validates payload structure against expected format for each method.
         */
        private fun validateBridgePayload(method: String, payload: ByteArray): Boolean {
            return BridgePayloadValidator.validate(method, payload)
        }

        /**
         * Debug interceptor for bridge calls.
         * Provides readable logging without external decoders as recommended in critique.
         */
        private fun logBridgeCall(method: String, payload: ByteArray, response: ByteArray?, error: Throwable?) {
            BridgeLogger.logBridgeCall(method, payload, response, error)
        }

        /**
         * Bytes-only RPC dispatcher for the WebMessagePort bridge.
         * 
         * Contract:
         * - input is method string and raw payload bytes
         * - output is protobuf BridgeRpcResponse bytes
         * - uses Base32-Crockford for MessagePort string transport
         * - strict single-path transport
         * - no @JavascriptInterface methods
         */
        fun handleBinaryRpc(method: String, payload: ByteArray): ByteArray {
            val inst = instance ?: return BridgeEnvelopeCodec.createErrorResponse(
                ERROR_BRIDGE_NOT_INITIALIZED,
                "Bridge not initialized"
            ) { bytes -> BridgeEncoding.base32CrockfordEncode(bytes) }

            return try {
                // Validate payload structure before processing
                if (!validateBridgePayload(method, payload)) {
                    val error = BridgeEnvelopeCodec.createErrorResponse(
                        ERROR_INVALID_PAYLOAD,
                        "Invalid payload structure for method '$method'"
                    ) { bytes -> BridgeEncoding.base32CrockfordEncode(bytes) }
                    logBridgeCall(method, payload, error, null)
                    return error
                }

                val result = handleBinaryRpcInternal(inst, method, payload)
                logBridgeCall(method, payload, result, null)
                BridgeEnvelopeCodec.createSuccessResponse(result)
            } catch (e: IllegalArgumentException) {
                val error = BridgeEnvelopeCodec.createErrorResponse(
                    ERROR_INVALID_PAYLOAD,
                    "Invalid payload: ${e.message}"
                ) { bytes -> BridgeEncoding.base32CrockfordEncode(bytes) }
                logBridgeCall(method, payload, error, e)
                error
            } catch (e: SecurityException) {
                val error = BridgeEnvelopeCodec.createErrorResponse(
                    ERROR_PERMISSION_DENIED,
                    "Permission denied: ${e.message}"
                ) { bytes -> BridgeEncoding.base32CrockfordEncode(bytes) }
                logBridgeCall(method, payload, error, e)
                error
            } catch (e: DsmNativeException) {
                val error = BridgeEnvelopeCodec.createErrorResponse(
                    ERROR_NATIVE_EXCEPTION,
                    "Native error: ${e.message}"
                ) { bytes -> BridgeEncoding.base32CrockfordEncode(bytes) }
                logBridgeCall(method, payload, error, e)
                error
            } catch (e: java.net.SocketTimeoutException) {
                val error = BridgeEnvelopeCodec.createErrorResponse(
                    ERROR_TIMEOUT,
                    "Network timeout: ${e.message}"
                ) { bytes -> BridgeEncoding.base32CrockfordEncode(bytes) }
                logBridgeCall(method, payload, error, e)
                error
            } catch (e: java.io.IOException) {
                val error = BridgeEnvelopeCodec.createErrorResponse(
                    ERROR_NETWORK_ERROR,
                    "Network error: ${e.message}"
                ) { bytes -> BridgeEncoding.base32CrockfordEncode(bytes) }
                logBridgeCall(method, payload, error, e)
                error
            } catch (e: IllegalStateException) {
                val error = BridgeEnvelopeCodec.createErrorResponse(
                    ERROR_INVALID_STATE,
                    "Invalid state: ${e.message}"
                ) { bytes -> BridgeEncoding.base32CrockfordEncode(bytes) }
                logBridgeCall(method, payload, error, e)
                error
            } catch (t: Throwable) {
                val error = BridgeEnvelopeCodec.createErrorResponse(
                    ERROR_NATIVE_EXCEPTION,
                    "Unexpected error: ${t.message ?: "unknown"}"
                ) { bytes -> base32CrockfordEncode(bytes) }
                logBridgeCall(method, payload, error, t)
                error
            }
        }

        /**
         * Parse envelope response and extract payload data.
         * STRICT: Only accepts valid protobuf envelopes.
         */
        private fun parseEnvelopeResponse(responseBytes: ByteArray): Pair<Boolean, ByteArray> {
            return BridgeEnvelopeCodec.parseEnvelopeResponse(responseBytes)
        }

        /**
         * Raw bytes RPC dispatcher (for internal use).
         * Returns the raw response data from protobuf envelope, not envelope-wrapped.
         */
        fun handleBinaryRpcRaw(method: String, payload: ByteArray): ByteArray {
            val envelopeResponse = handleBinaryRpc(method, payload)
            return try {
                val (isSuccess, data) = parseEnvelopeResponse(envelopeResponse)
                if (isSuccess) {
                    data
                } else {
                    ByteArray(0) // Error case
                }
            } catch (e: Exception) {
                Log.w(TAG, "handleBinaryRpcRaw: failed to parse envelope", e)
                ByteArray(0)
            }
        }

        /** Escape control characters in strings for diagnostic payloads. */
        private fun escapeForString(s: String?): String {
            if (s == null) return ""
            return s.replace("\\", "\\\\")
                    .replace("\"", "\\\"")
                    .replace("\n", "\\n")
                    .replace("\r", "\\r")
                    .replace("\t", "\\t")
        }

        fun createErrorResponse(method: String, errorCode: Int, message: String): ByteArray {
            return BridgeEnvelopeCodec.createErrorResponse(errorCode, message) { bytes ->
                base32CrockfordEncode(bytes)
            }
        }

        private fun handleBinaryRpcInternal(inst: SinglePathWebViewBridge, method: String, payload: ByteArray): ByteArray {
            return when (method) {
                // --- Native QR scanner (Android ML Kit / camera activity) ---
                // JS expects a 1-byte boolean response for availability.
                // Launch result is delivered via CustomEvent("dsm-event") topic "qr_scan_result".
                "hasNativeQrScanner" -> {
                    try {
                        // If the activity exists, we treat native scanning as available.
                        // (Camera permission flow is handled by the activity itself.)
                        val pm = inst.context.packageManager
                        val intent = android.content.Intent(inst.context, com.dsm.wallet.ui.QrScannerActivity::class.java)
                        val resolved = intent.resolveActivity(pm) != null
                        byteArrayOf(if (resolved) 1 else 0)
                    } catch (e: Throwable) {
                        Log.w(TAG, "hasNativeQrScanner: failed to resolve activity", e)
                        byteArrayOf(0)
                    }
                }

                "startNativeQrScanner" -> {
                    try {
                        // Prefer launching through the active MainActivity so the result callback can
                        // dispatch back into the WebView as a dsm-event.
                        val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                        if (act != null) {
                            act.runOnUiThread {
                                try {
                                    act.launchNativeQrScanner { qrText: String? ->
                                        // Dispatch via JS evaluation (topic: qr_scan_result)
                                        act.dispatchQrScanResult(qrText)
                                    }
                                } catch (e: Throwable) {
                                    Log.w(TAG, "startNativeQrScanner: inner exception", e)
                                    act.dispatchQrScanResult(null)
                                }
                            }
                        }
                    } catch (e: Throwable) {
                        Log.w(TAG, "startNativeQrScanner: failed to launch scanner", e)
                    }
                    // Empty response is fine; result comes via event.
                    ByteArray(0)
                }

                // device_id bytes via JNI → Rust (Invariant #7: spine path, not prefs).
                "getDeviceIdBin" -> {
                    try {
                        Unified.getDeviceIdBin()
                    } catch (_: Throwable) {
                        ByteArray(0)
                    }
                }

                // genesis_hash bytes via JNI → Rust (Invariant #7: spine path, not prefs).
                "getGenesisHashBin" -> {
                    try {
                        Unified.getGenesisHashBin()
                    } catch (_: Throwable) {
                        ByteArray(0)
                    }
                }

                // signing public key bytes (JNI). Returns empty if not available.
                "getSigningPublicKeyBin" -> {
                    try {
                        Unified.getSigningPublicKeyBin()
                    } catch (_: Throwable) {
                        ByteArray(0)
                    }
                }

                // strict balances (JNI). Returns FramedEnvelopeV3 bytes or empty on error.
                "getAllBalancesStrict" -> {
                    try {
                        Unified.getAllBalancesStrict()
                    } catch (t: Throwable) {
                        Log.w(TAG, "getAllBalancesStrict failed", t)
                        ByteArray(0)
                    }
                }

                // strict wallet history (JNI). Returns FramedEnvelopeV3 bytes or empty on error.
                "getWalletHistoryStrict" -> {
                    try {
                        Unified.getWalletHistoryStrict()
                    } catch (t: Throwable) {
                        Log.w(TAG, "getWalletHistoryStrict failed", t)
                        ByteArray(0)
                    }
                }

                // genesis_envelope bytes (prefs-only). Used for cold-start rehydration.
                // Returns empty if not present.
                "getPersistedGenesisEnvelope" -> {
                    val p = inst.prefs()
                    readPersistedBytesOrEmpty(p, KEY_GENESIS_ENVELOPE)
                }

                // Resolve BLE address from native mapping (bytes-only).
                // Payload: 32-byte device_id. Response: UTF-8 address bytes or empty.
                "resolveBleAddressForDeviceId" -> {
                    if (payload.size != 32) return ByteArray(0)
                    UnifiedContactBridge.resolveBleAddressForDeviceIdBin(payload)
                }

                // Diagnostics: append raw payload to persisted bridge log
                "diagnosticsLog" -> {
                    BridgeLogger.logDiagnosticsPayload(payload)
                    ByteArray(0)
                }

                // Diagnostics: export persisted bridge log (last ~5MB)
                "getDiagnosticsLog" -> {
                    BridgeLogger.readLogBytes()
                }

                // Diagnostics: Architecture Info
                "getArchitectureInfo" -> {
                    BridgeDiagnosticsHandler.getArchitectureInfo(::escapeForString)
                }

                // Preferences are storage-only and not part of protocol/crypto layer.
                // Wire format: protobuf PreferencePayload.
                // - getPreference payload: key set, value omitted
                // - setPreference payload: key + value
                // Returns:
                // - getPreference: UTF-8 value bytes, or empty for null/missing
                // - setPreference: empty on success
                "getPreference" -> {
                    BridgePreferencesHandler.getPreference(inst.prefs(), payload)
                }

                "setPreference" -> {
                    BridgePreferencesHandler.setPreference(inst.prefs(), payload)
                }

                // Unified router calls - pass full framed payload to Rust
                "appRouterInvoke" -> {
                    val result = BridgeRouterHandler.appRouterInvoke(payload, ::nextRouterReqId, TAG)
                    // State may have mutated — refresh NFC capsule if backup enabled.
                    try { UnifiedNativeApi.maybeRefreshNfcCapsule() } catch (_: Throwable) {}
                    result
                }
                
                "appRouterQuery" -> BridgeRouterHandler.appRouterQuery(payload, ::nextRouterReqId)

                // Transport headers (bytes-only). Must be available early for identity/QR/faucet.
                // This bypasses the appRouter to avoid decode ambiguity (Error envelope vs Headers).
                "getTransportHeadersV3Bin" -> BridgeRouterHandler.getTransportHeadersV3Bin(
                    isSdkReady = { sdkContextInitialized.get() },
                    bootstrap = { inst.bootstrapFromPrefs() }
                )

                "createGenesisBin" -> {
                    val parsed = try {
                        dsm.types.proto.CreateGenesisPayload.parseFrom(payload)
                    } catch (e: com.google.protobuf.InvalidProtocolBufferException) {
                        throw IllegalArgumentException("createGenesisBin: invalid protobuf payload: ${e.message}")
                    }
                    val locale = parsed.locale
                    val networkId = parsed.networkId
                    val entropy = parsed.entropy.toByteArray()
                    if (entropy.size != 32) throw IllegalArgumentException("createGenesisBin: entropy must be 32 bytes")
                    val result = inst.createGenesis(locale, networkId, entropy)
                    // State mutated (genesis created) — refresh NFC capsule if backup enabled.
                    try { UnifiedNativeApi.maybeRefreshNfcCapsule() } catch (_: Throwable) {}
                    result
                }

                // Rust-driven pairing orchestration: scan all unpaired contacts automatically
                "startPairingAll" -> {
                    // Invariant #7: identity check via JNI → Rust, not prefs side channel.
                    // BLE identity publication requires BOTH device_id and genesis_hash.
                    val hasIdentity = try {
                        Unified.getDeviceIdBin().size == 32 && Unified.getGenesisHashBin().size == 32
                    } catch (_: Throwable) { false }
                    if (!hasIdentity) {
                        Log.w(TAG, "startPairingAll: identity not ready, aborting")
                        return ByteArray(0)
                    }
                    // Ensure BLE permissions are granted before starting the loop
                    BridgeBleHandler.requestBlePermissions()
                    // Ensure BleCoordinator is initialized before Rust calls startBlePairing*
                    try {
                        val ctx = com.dsm.wallet.ui.MainActivity.getActiveInstance()?.applicationContext
                        if (ctx != null) {
                            BleCoordinator.getInstance(ctx)
                            Log.i(TAG, "startPairingAll: BleCoordinator ensured")
                        } else {
                            Log.w(TAG, "startPairingAll: no context for BleCoordinator init")
                        }
                    } catch (t: Throwable) {
                        Log.w(TAG, "startPairingAll: BleCoordinator init failed", t)
                    }
                    try {
                        Unified.startPairingAll()
                    } catch (t: Throwable) {
                        Log.w(TAG, "startPairingAll failed", t)
                    }
                    ByteArray(0)
                }

                "stopPairingAll" -> {
                    try {
                        Unified.stopPairingAll()
                    } catch (t: Throwable) {
                        Log.w(TAG, "stopPairingAll failed", t)
                    }
                    ByteArray(0)
                }

                "requestBlePermissions" -> {
                    BridgeBleHandler.requestBlePermissions()
                    ByteArray(0)
                }

                "openBluetoothSettings" -> {
                    try {
                        val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                        act?.runOnUiThread {
                            try {
                                val intent = android.content.Intent(android.provider.Settings.ACTION_BLUETOOTH_SETTINGS)
                                act.startActivity(intent)
                            } catch (e: Throwable) {
                                Log.w(TAG, "openBluetoothSettings: failed to launch intent", e)
                            }
                        }
                    } catch (e: Throwable) {
                        Log.w(TAG, "openBluetoothSettings: failed", e)
                    }
                    ByteArray(0)
                }

                "acceptBilateralByCommitment" -> {
                    if (payload.size != 32) {
                        Log.w(TAG, "acceptBilateralByCommitment: expected 32 bytes, got ${payload.size}")
                        return ByteArray(0)
                    }
                    try {
                        Unified.acceptBilateralByCommitment(payload)
                    } catch (t: Throwable) {
                        Log.w(TAG, "acceptBilateralByCommitment failed", t)
                        ByteArray(0)
                    }
                }

                "rejectBilateralByCommitment" -> {
                    val parsed = BridgeEnvelopeCodec.decodeBilateralPayload(payload)
                        ?: return ByteArray(0)
                    try {
                        Unified.rejectBilateralByCommitment(parsed.commitment, parsed.reason ?: "")
                    } catch (t: Throwable) {
                        Log.w(TAG, "rejectBilateralByCommitment failed", t)
                        ByteArray(0)
                    }
                }

                "setBleIdentityForAdvertising" -> {
                    val parsed = try {
                        dsm.types.proto.BleIdentityPayload.parseFrom(payload)
                    } catch (e: com.google.protobuf.InvalidProtocolBufferException) {
                        Log.w(TAG, "setBleIdentityForAdvertising: invalid payload: ${e.message}")
                        return ByteArray(0)
                    }
                    val genesisHash = parsed.genesisHash.toByteArray()
                    val deviceId = parsed.deviceId.toByteArray()
                    if (genesisHash.size != 32 || deviceId.size != 32) {
                        Log.w(TAG, "setBleIdentityForAdvertising: invalid field lengths genesis=${genesisHash.size} device=${deviceId.size}")
                        return ByteArray(0)
                    }
                    // Kotlin MUST NOT concatenate raw bytes — encodeIdentityCharValue is the canonical encoder.
                    val out = Unified.encodeIdentityCharValue(genesisHash, deviceId)
                    if (out.isEmpty()) {
                        Log.w(TAG, "setBleIdentityForAdvertising: encodeIdentityCharValue returned empty")
                        return ByteArray(0)
                    }
                    BridgeBleHandler.setBleIdentityForAdvertising(out, TAG)
                }

                "handleContactQrV3" -> {
                    try {
                        Log.d(TAG, "handleBinaryRpc: handleContactQrV3 invoked payloadLen=${payload.size}")
                        val result = UnifiedContactBridge.handleContactQrV3(payload)
                        Log.d(TAG, "handleBinaryRpc: handleContactQrV3 resultLen=${result.size}")
                        result
                    } catch (t: Throwable) {
                        Log.w(TAG, "handleContactQrV3 failed", t)
                        // Return empty bytes on error; frontend will handle via timeout/events
                        ByteArray(0)
                    }
                }

                // Generic Envelope v3 processing (online transfers, DBRW export, etc.)
                "processEnvelopeV3" -> {
                    try {
                        val result = Unified.processEnvelopeV3(payload)
                        // State may have mutated — refresh NFC capsule if backup enabled.
                        // Rust decides whether to actually create one (no-op if disabled).
                        try { UnifiedNativeApi.maybeRefreshNfcCapsule() } catch (_: Throwable) {}
                        result
                    } catch (t: Throwable) {
                        Log.w(TAG, "processEnvelopeV3 failed", t)
                        ByteArray(0)
                    }
                }

                else -> throw IllegalArgumentException("Unknown binary RPC method: $method")
            }
        }

        // Proto decoding is handled by generated dsm.types.proto.* classes
        // (android/app/src/main/proto/dsm_app.proto → Gradle protobuf plugin, java_package="dsm.types.proto").
        // Kotlin MUST NOT implement custom wire decoders — use parseFrom() from generated classes.
        
        /**
         * Native -> WebView push channel (bytes-only).
         *
         * In binary-only mode, the WebView is connected via a MessagePort managed by MainActivity.
         * BleEventRelay (and JNI callbacks) call into here reflectively.
         */
        @JvmStatic
        fun postBinary(topic: String, payload: ByteArray) {
            try {
                Log.d(TAG, "postBinary: forwarding topic=$topic payloadBytes=${payload.size}")
                // MainActivity is responsible for posting via MessagePort (ArrayBuffer)
                com.dsm.wallet.ui.MainActivity.dispatchDsmEventToWebView(topic, payload)
            } catch (t: Throwable) {
                Log.w(TAG, "postBinary: unable to dispatch to WebView (topic=$topic, len=${payload.size}): ${t.message}")
            }
        }
        
        // Base32-Crockford encoding for safe binary transport
        @JvmStatic
        fun base32CrockfordEncode(bytes: ByteArray): String {
            return BridgeEncoding.base32CrockfordEncode(bytes)
        }
        
        @JvmStatic
        fun base32CrockfordDecode(str: String): ByteArray {
            return BridgeEncoding.base32CrockfordDecode(str)
        }
        
    }
    @Volatile private var ready = false
    
    init {
        ready = true
        Log.i(TAG, "SinglePathWebViewBridge initialized (binary MessagePort only)")
    }
    
    // Instance helpers
    fun setReady() { ready = true }
    fun getBridgeStatus(): Int = if (ready) 3 else 0
    
    private fun prefs(): SharedPreferences {
        return context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }
    
    
    /**
     * Initialize SDK context from persisted identity in SharedPreferences.
     * Called by MainActivity after genesis or on app startup.
     */
    fun bootstrapFromPrefs(): Boolean {
        return BridgeIdentityHandler.bootstrapFromPrefs(
            context = context,
            prefs = prefs(),
            sdkContextInitialized = sdkContextInitialized,
            logTag = TAG,
            keyDeviceId = KEY_DEVICE_ID,
            keyGenesisHash = KEY_GENESIS_HASH,
            keyDbrwSalt = KEY_DBRW_SALT
        )
    }
    
    /**
     * Create genesis via JNI.
     * Returns protobuf-encoded Envelope bytes on success, empty on error.
     * Automatically parses envelope, persists identity, initializes SDK context, and populates transport headers.
     */
    fun createGenesis(locale: String, networkId: String, entropyBytes: ByteArray): ByteArray {
        if (!ready) {
            Log.e(TAG, "createGenesis: bridge not ready")
            return ByteArray(0)
        }
        return BridgeIdentityHandler.createGenesis(
            context = context,
            prefs = prefs(),
            sdkContextInitialized = sdkContextInitialized,
            logTag = TAG,
            keyDeviceId = KEY_DEVICE_ID,
            keyGenesisHash = KEY_GENESIS_HASH,
            keyGenesisEnvelope = KEY_GENESIS_ENVELOPE,
            keyDbrwSalt = KEY_DBRW_SALT,
            locale = locale,
            networkId = networkId,
            entropyBytes = entropyBytes
        )
    }

    fun handleHostPause() {
        BridgeIdentityHandler.handleHostPauseDuringGenesis(
            prefs = prefs(),
            sdkContextInitialized = sdkContextInitialized,
            logTag = TAG,
            keyDeviceId = KEY_DEVICE_ID,
            keyGenesisHash = KEY_GENESIS_HASH,
            keyGenesisEnvelope = KEY_GENESIS_ENVELOPE,
            keyDbrwSalt = KEY_DBRW_SALT
        )
    }
}
