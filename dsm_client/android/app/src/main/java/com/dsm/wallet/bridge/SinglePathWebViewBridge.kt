// SPDX-License-Identifier: MIT OR Apache-2.0

// File: android/app/src/main/java/com/dsm/wallet/bridge/SinglePathWebViewBridge.kt
@file:Suppress("KotlinJniMissingFunction", "UNUSED_PARAMETER")

package com.dsm.wallet.bridge

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import com.dsm.native.DsmNativeException
import java.util.concurrent.atomic.AtomicBoolean
import com.dsm.wallet.bridge.ble.BleCoordinator
import dsm.types.proto.WalletCreateGenesisV2Request

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
// METHOD ROUTING (grouped by boundary):
//   Shared boundary: "nativeBoundaryIngress" (the startup boundary is crossed
//   natively, by BridgeIdentityHandler; the WebView never sends it)
//   Private host boundary: "nativeHostRequest"
//   Platform-bound helpers stay behind the same binary MessagePort dispatcher.
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
                 // device_id bytes via JNI → Rust (Invariant #7: spine path, not prefs).
                 // genesis_hash bytes via JNI → Rust (Invariant #7: spine path, not prefs).
                 // signing public key bytes (JNI). Returns empty if not available.
                 // Canonical mnemonic-rooted Genesis v2 (whitepaper §2.5): generate a mnemonic for
                // backup, then create the wallet from it. No silicon enrollment, no random entropy.
                "generateMnemonic" -> {
                    inst.generateMnemonic()
                }

                "createGenesisV2" -> {
                    val req = WalletCreateGenesisV2Request.parseFrom(payload)
                    inst.createGenesisV2(mnemonic = req.mnemonic)
                }

                // strict balances (JNI): FramedEnvelopeV3 bytes; a failure is the dispatcher's error response.
                "getAllBalancesStrict" -> {
                    Unified.getAllBalancesStrict()
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

                // Diagnostics: write the debug report (the summary in the payload, the
                // app log, the bridge log) and open the share sheet with it. Answers the
                // report's size in bytes, as decimal UTF-8.
                // After an approved connect that a link brought: back to the app that
                // sent it. One byte: 1 when the wallet stepped back, 0 when no link
                // opened it.
                "returnToConnectCaller" -> {
                    val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                        ?: throw IllegalStateException("returnToConnectCaller: no active activity")
                    val stepped = act.returnToConnectCaller()
                    byteArrayOf(if (stepped) 1 else 0)
                }

                // Opens the share sheet with a text the user chose to share (their
                // contact code, from the Simple skin's Receive page). Answers nothing.
                "shareText" -> {
                    val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                        ?: throw IllegalStateException("shareText: no active activity")
                    val text = String(payload, Charsets.UTF_8)
                    require(text.isNotEmpty() && text.length <= 4096) { "shareText: a text to share is 1 to 4096 characters" }
                    act.runOnUiThread {
                        val send = android.content.Intent(android.content.Intent.ACTION_SEND).apply {
                            type = "text/plain"
                            putExtra(android.content.Intent.EXTRA_TEXT, text)
                        }
                        act.startActivity(android.content.Intent.createChooser(send, "Share your DSM code"))
                    }
                    ByteArray(0)
                }

                // Opens the phone's contact picker (DSM Amendment A17). Answers nothing
                // now; the picked contact arrives as a PHONE_CONTACT_PICKED host event.
                "pickPhoneContact" -> {
                    val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                        ?: throw IllegalStateException("pickPhoneContact: no active activity")
                    act.pickPhoneContact()
                    ByteArray(0)
                }

                // A linked phone contact's photo, by its lookup key (UTF-8): the
                // image bytes, or none. Read for display; the page keeps no copy.
                "phoneContactPhoto" -> {
                    val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                        ?: throw IllegalStateException("phoneContactPhoto: no active activity")
                    com.dsm.wallet.ui.PhoneContacts.photo(act, String(payload, Charsets.UTF_8))
                }

                // The bars' colours for the skin in use: "light" or "dark" as UTF-8.
                // Answers nothing; the page's look is all it changes.
                "setSystemBars" -> {
                    val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                        ?: throw IllegalStateException("setSystemBars: no active activity")
                    val look = String(payload, Charsets.UTF_8)
                    require(look == "light" || look == "dark" || look == "device") { "setSystemBars: no look named $look" }
                    act.setSystemBars(look)
                    ByteArray(0)
                }

                "shareDiagnosticsReport" -> {
                    val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                        ?: throw IllegalStateException("shareDiagnosticsReport: no active activity")
                    val report = DiagnosticsReport.write(act, String(payload, Charsets.UTF_8))
                    DiagnosticsReport.share(act, report)
                    report.length().toString().toByteArray(Charsets.UTF_8)
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

                "nativeBoundaryIngress" -> {
                    NativeBoundaryBridge.ingress(payload)
                }

                "nativeHostRequest" -> {
                    NativeHostBridge.hostRequest(payload)
                }

                // Transport headers (bytes-only). Must be available early for identity/QR/faucet.
                // Empty means Rust reports NO_IDENTITY (status 0); a failure to restore the
                // identity or to read the status is the dispatcher's error response.
                "getTransportHeadersV3Bin" -> {
                    if (!sdkContextInitialized.get()) {
                        inst.bootstrapFromPrefs()
                    }
                    if (Unified.getTransportHeadersV3Status().toInt() >= 1) {
                        Unified.getTransportHeadersV3()
                    } else {
                        ByteArray(0)
                    }
                }

                "requestBlePermissions" -> {
                    BridgeBleHandler.requestBlePermissions()
                    ByteArray(0)
                }

                "openBluetoothSettings" -> {
                    val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                        ?: throw IllegalStateException("openBluetoothSettings: no active activity")
                    act.runOnUiThread {
                        try {
                            val intent = android.content.Intent(android.provider.Settings.ACTION_BLUETOOTH_SETTINGS)
                            act.startActivity(intent)
                        } catch (e: Throwable) {
                            // The launch runs after this answer went out; the UI thread can only log it.
                            Log.w(TAG, "openBluetoothSettings: failed to launch intent", e)
                        }
                    }
                    ByteArray(0)
                }

                "acceptBilateralByCommitment" -> {
                    require(payload.size == 32) {
                        "acceptBilateralByCommitment: expected 32 bytes, got ${payload.size}"
                    }
                    Unified.acceptBilateralByCommitment(payload)
                }

                "rejectBilateralByCommitment" -> {
                    val parsed = BridgeEnvelopeCodec.decodeBilateralPayload(payload)
                        ?: throw IllegalArgumentException("rejectBilateralByCommitment: payload is not a BilateralPayload")
                    Unified.rejectBilateralByCommitment(parsed.commitment, parsed.reason ?: "")
                }

                "cancelBilateralByCommitment" -> {
                    val parsed = BridgeEnvelopeCodec.decodeBilateralPayload(payload)
                        ?: throw IllegalArgumentException("cancelBilateralByCommitment: payload is not a BilateralPayload")
                    Unified.cancelBilateralByCommitment(parsed.commitment, parsed.reason ?: "")
                }

                // Generic Envelope v3 processing (online transfers, DBRW export, etc.)
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
                if (!com.dsm.wallet.ui.MainActivity.dispatchDsmEventToWebView(topic, payload)) {
                    throw IllegalStateException("WebView dispatch unavailable for topic=$topic")
                }
            } catch (t: Throwable) {
                Log.w(TAG, "postBinary: unable to dispatch to WebView (topic=$topic, len=${payload.size}): ${t.message}")
                throw t
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
            prefs = prefs(),
            sdkContextInitialized = sdkContextInitialized,
            logTag = TAG,
            keyDeviceId = KEY_DEVICE_ID,
            keyGenesisHash = KEY_GENESIS_HASH,
        )
    }

    /** Generate a fresh BIP39 mnemonic for display/backup (canonical Genesis v2). */
    fun generateMnemonic(): ByteArray = BridgeIdentityHandler.generateMnemonic()

    /**
     * Canonical mnemonic-rooted Genesis v2 wallet creation. The (backed-up) mnemonic is the sole
     * root. Returns framed Envelope v3 bytes: Rust's own error envelope is forwarded, and any
     * other failure is the dispatcher's error response.
     */
    fun createGenesisV2(mnemonic: String): ByteArray {
        return BridgeIdentityHandler.createGenesisV2(
            prefs = prefs(),
            sdkContextInitialized = sdkContextInitialized,
            logTag = TAG,
            keyDeviceId = KEY_DEVICE_ID,
            keyGenesisHash = KEY_GENESIS_HASH,
            keyGenesisEnvelope = KEY_GENESIS_ENVELOPE,
            mnemonic = mnemonic,
        )
    }

}
