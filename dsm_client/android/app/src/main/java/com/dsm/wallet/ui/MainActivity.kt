package com.dsm.wallet.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.Ndef
import android.os.Build
import android.os.IBinder
import android.os.Bundle
import android.util.Log
import android.view.Gravity
import android.view.View
import android.webkit.ConsoleMessage
import android.webkit.PermissionRequest
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebResourceResponse
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.FrameLayout
import androidx.activity.OnBackPressedCallback
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.annotation.VisibleForTesting
import androidx.appcompat.app.AppCompatActivity
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import androidx.core.view.WindowCompat
import androidx.core.view.WindowInsetsControllerCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.webkit.WebMessageCompat
import androidx.webkit.WebMessagePortCompat
import androidx.webkit.WebViewAssetLoader
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import com.dsm.wallet.BuildConfig
import com.dsm.wallet.bridge.BleEventRelay
import com.dsm.wallet.bridge.SinglePathWebViewBridge
import com.dsm.wallet.bridge.Unified
import com.dsm.wallet.bridge.ble.BleCoordinator
import com.dsm.wallet.mcp.McpService
import com.dsm.wallet.permissions.BluetoothPermissionHelper
import com.dsm.wallet.security.AccessLevel
import com.dsm.wallet.service.BleBackgroundService
import com.dsm.wallet.session.NativeFirstCutoverReset
import dsm.types.proto.SessionHardwareFactsProto
import java.io.ByteArrayInputStream
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.InputStream
import java.lang.ref.WeakReference
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale

class MainActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {
    @Volatile private var mcpStarted = false

    // Dedicated single-thread executor for long-running genesis/enrollment work.
    // This keeps the main thread free during the ~60s C-DBRW silicon fingerprint
    // enrollment that happens on first boot, preventing ANR.
    private val genesisExecutor: java.util.concurrent.ExecutorService =
        java.util.concurrent.Executors.newSingleThreadExecutor { r ->
            Thread(r, "dsm-genesis-worker").also { it.isDaemon = true }
        }

    // Background thread pool for default RPC dispatch (moves bridge calls off UI thread).
    // Prevents "Skipped N frames" ANR when storage.sync or other heavy RPCs run.
    private val bridgeExecutor: java.util.concurrent.ExecutorService =
        java.util.concurrent.Executors.newFixedThreadPool(4) { r ->
            Thread(r, "dsm-bridge-worker").also { it.isDaemon = true }
        }

    private val cameraPermCode = 2001
    private val runtimePermCode = 2002
    lateinit var btPermLauncher: ActivityResultLauncher<Array<String>> 
    private var btPermsRequested = false
    private val tag = "MainActivity"
    
    // Callback for runtime BLE permission requests from bridge
    @Volatile var blePermissionCallback: ((Boolean) -> Unit)? = null
    
    // Native QR scanner launcher and callback
    lateinit var qrScannerLauncher: ActivityResultLauncher<Intent>
    @Volatile var qrScanCallback: ((String?) -> Unit)? = null
    @Volatile private var qrScannerActive = false
    @Volatile private var walletRefreshHint = 0L
    @Volatile private var isAppForeground = true
    // NFC inline reader state (ring reads happen on MainActivity, not a separate Activity)
    @Volatile private var nfcReaderActive = false
    private var nfcAdapter: NfcAdapter? = null
    // Bluetooth enable prompt launcher
    lateinit var btEnableLauncher: ActivityResultLauncher<Intent>

    private lateinit var rootContainer: FrameLayout
    private lateinit var webView: WebView
    private var statusBarScrim: View? = null
    private lateinit var bridge: SinglePathWebViewBridge
    private lateinit var assetLoader: WebViewAssetLoader
    @Volatile private var dsmPort: WebMessagePortCompat? = null
    @Volatile private var pendingJsPort: WebMessagePortCompat? = null
    @Volatile private var bleBackgroundService: BleBackgroundService? = null
    private var bleServiceBound = false
    private val bleServiceConnection = object : android.content.ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as? BleBackgroundService.LocalBinder
            bleBackgroundService = binder?.getService()
            bleServiceBound = bleBackgroundService != null
            Log.i(tag, "BLE service bound: $bleServiceBound")
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            bleBackgroundService = null
            bleServiceBound = false
            Log.w(tag, "BLE service disconnected")
        }
    }

    companion object {
        private const val EVENT_DISPATCH_TAG = "DsmEventDispatch"

        // Weak reference to the currently active activity instance to avoid memory leaks.
        @Volatile
        private var activeInstance: WeakReference<MainActivity>? = null

        /**
         * Best-effort access for bridge-initiated UI actions.
         */
        @JvmStatic
        fun getActiveInstance(): MainActivity? = activeInstance?.get()

        /**
         * Dispatch a native event into the WebView via MessagePort (ArrayBuffer).
         *
         * Payload is raw protobuf bytes (no base32/json/hex).
         */
        @JvmStatic
        fun dispatchDsmEventToWebView(topic: String, payload: ByteArray) {
            val inst = getActiveInstance()
            if (inst == null) {
                Log.w(EVENT_DISPATCH_TAG, "dispatchDsmEventToWebView: no active MainActivity (topic=$topic)")
                return
            }
            inst.dispatchDsmEventOnUi(topic, payload)
        }

        /**
         * Test-only bridge harness that mirrors MessagePort request/response framing.
         *
         * Input format:  [8-byte message_id][BridgeRpcRequest protobuf]
         * Output format: [8-byte message_id][BridgeRpcResponse protobuf]
         */
        @VisibleForTesting
        @JvmStatic
        fun processBridgeRequestForTest(context: Context, framedRequest: ByteArray): ByteArray {
            if (framedRequest.size < 8) return ByteArray(0)

            val messageId = java.nio.ByteBuffer.wrap(framedRequest, 0, 8)
                .order(java.nio.ByteOrder.BIG_ENDIAN)
                .long
            val requestBytes = framedRequest.copyOfRange(8, framedRequest.size)

            val response = try {
                val parsed = com.dsm.wallet.bridge.BridgeEnvelopeCodec.parseBridgeRequest(requestBytes)
                com.dsm.wallet.bridge.SinglePathWebViewBridge.ensureInitialized(context)
                com.dsm.wallet.bridge.SinglePathWebViewBridge.handleBinaryRpc(parsed.method, parsed.payload)
            } catch (t: Throwable) {
                com.dsm.wallet.bridge.SinglePathWebViewBridge.createErrorResponse(
                    "processBridgeRequestForTest",
                    2,
                    "Bridge test harness error: ${t.message ?: "unknown"}"
                )
            }

            val out = ByteArray(8 + response.size)
            java.nio.ByteBuffer.wrap(out, 0, 8).order(java.nio.ByteOrder.BIG_ENDIAN).putLong(messageId)
            System.arraycopy(response, 0, out, 8, response.size)
            return out
        }
    }

    /**
     * Dispatch QR scan result into WebView via binary MessagePort.
     * Payload is UTF-8 encoded QR text (empty = cancelled/no result).
     */
    fun dispatchQrScanResult(qrText: String?) {
        val payload = (qrText ?: "").toByteArray(Charsets.UTF_8)
        dispatchDsmEventOnUi("qr_scan_result", payload)
    }

    /**
     * Dispatch custom event to WebView via binary MessagePort.
     * Payload is UTF-8 encoded detail string.
     */
    fun dispatchCustomEventToWebView(eventName: String, detail: String) {
        val safeName = sanitizeEventName(eventName)
        dispatchDsmEventOnUi(safeName, detail.toByteArray(Charsets.UTF_8))
    }

    /**
     * Enable NFC reader mode on this activity so the ring can be read inline
     * without leaving the WebView. Called from BridgeRouterHandler on nfc.ring.read.
     */
    fun startNfcReader() {
        runOnUiThread {
            val adapter = nfcAdapter ?: NfcAdapter.getDefaultAdapter(this)
            nfcAdapter = adapter
            if (adapter == null || !adapter.isEnabled) {
                Log.w(tag, "startNfcReader: NFC not available or disabled")
                return@runOnUiThread
            }
            if (nfcReaderActive) {
                Log.d(tag, "startNfcReader: already active")
                return@runOnUiThread
            }
            nfcReaderActive = true
            adapter.enableReaderMode(
                this,
                this,
                NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B,
                null
            )
            Log.i(tag, "startNfcReader: reader mode enabled")
        }
    }

    /**
     * Disable NFC reader mode. Called when the user navigates away from the
     * "WAITING FOR RING" screen, or when a read completes.
     */
    fun stopNfcReader() {
        runOnUiThread {
            if (!nfcReaderActive) return@runOnUiThread
            nfcReaderActive = false
            try {
                nfcAdapter?.disableReaderMode(this)
            } catch (t: Throwable) {
                Log.w(tag, "stopNfcReader: disableReaderMode failed", t)
            }
            Log.i(tag, "stopNfcReader: reader mode disabled")
        }
    }

    /**
     * NfcAdapter.ReaderCallback — called on a binder thread when a tag is discovered.
     * Reads the NDEF capsule record and dispatches it through BleEventRelay → WebView.
     * The user never leaves the WebView.
     */
    override fun onTagDiscovered(tag: Tag) {
        if (!nfcReaderActive) return

        bridgeExecutor.execute {
            try {
                val ndef = Ndef.get(tag)
                if (ndef == null) {
                    Log.w(this.tag, "onTagDiscovered: tag has no NDEF support")
                    return@execute
                }

                ndef.connect()
                val ndefMessage: NdefMessage? = try {
                    ndef.ndefMessage
                } finally {
                    ndef.close()
                }

                if (ndefMessage == null) {
                    Log.w(this.tag, "onTagDiscovered: tag has no NDEF message")
                    return@execute
                }

                val record = extractCapsuleRecord(listOf(ndefMessage))
                if (record == null) {
                    Log.w(this.tag, "onTagDiscovered: no matching capsule record")
                    return@execute
                }

                val payload = record.payload
                val envelope = com.dsm.wallet.bridge.UnifiedNativeApi.createNfcRecoveryCapsuleEnvelope(payload)
                if (envelope.isNotEmpty()) {
                    BleEventRelay.dispatchEnvelope(envelope)
                }
                Log.i(this.tag, "onTagDiscovered: dispatched recovery capsule (${payload.size} bytes)")

                // Auto-stop reader after successful read
                runOnUiThread {
                    nfcReaderActive = false
                    try {
                        nfcAdapter?.disableReaderMode(this)
                    } catch (_: Throwable) {}
                }
            } catch (e: Exception) {
                Log.w(this.tag, "onTagDiscovered: NFC read failed: ${e.message}")
            }
        }
    }

    private fun extractCapsuleRecord(messages: List<NdefMessage>): NdefRecord? {
        for (m in messages) {
            for (r in m.records) {
                if (r.tnf == NdefRecord.TNF_WELL_KNOWN && r.type.contentEquals(NdefRecord.RTD_TEXT)) {
                    return r
                }
                if (r.tnf == NdefRecord.TNF_MIME_MEDIA) {
                    val mime = try { String(r.type, Charsets.US_ASCII) } catch (_: Throwable) { "" }
                    if (mime.equals("application/vnd.dsm.recovery", ignoreCase = true)) {
                        return r
                    }
                }
            }
        }
        return null
    }

    private fun dispatchDsmEventOnUi(topic: String, payload: ByteArray) {
        // Always hop to UI thread for WebView MessagePort dispatch.
        runOnUiThread {
            try {
                val shouldRefreshSessionHint = topic == "dsm-wallet-refresh" || topic == "inbox.updated"
                if (shouldRefreshSessionHint) {
                    walletRefreshHint += 1L
                }
                val port = dsmPort
                if (port == null) {
                    Log.w(EVENT_DISPATCH_TAG, "dispatch failed (no MessagePort) topic=$topic")
                    return@runOnUiThread
                }
                if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_ARRAY_BUFFER)) {
                    Log.w(EVENT_DISPATCH_TAG, "dispatch failed: ArrayBuffer not supported")
                    return@runOnUiThread
                }

                // Canonical async event payload: protobuf AppRouterPayload(method_name=topic, args=payload)
                // This removes previous 0x02 topic frame wrapping.
                val eventBytes = com.dsm.wallet.bridge.BridgeEnvelopeCodec.encodeAppRouterPayload(topic, payload)

                if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_PORT_POST_MESSAGE)) {
                    port.postMessage(WebMessageCompat(eventBytes))
                }
                if (shouldRefreshSessionHint) {
                    publishSessionState("walletRefresh")
                }
            } catch (e: Throwable) {
                Log.w(EVENT_DISPATCH_TAG, "dispatch failed (topic=$topic): ${e.message}")
            }
        }
    }

    /** Identity check via JNI → Rust (Invariant #7: no prefs side channel). */
    private fun hasIdentityViaRust(): Boolean {
        return try {
            Unified.getDeviceIdBin().size == 32
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Collect hardware facts, push to Rust, relay Rust's session state bytes to WebView.
     * Rust owns ALL session state computation (phase, identity, lock, env config).
     * Kotlin is a hardware-facts collector and byte relay — it never decodes or modifies
     * the AppSessionStateProto bytes returned by Rust.
     */
    private fun publishSessionState(reason: String = "") {
        val adapter = getBluetoothAdapterSafely(this)
        val service = bleBackgroundService
        val facts = SessionHardwareFactsProto.newBuilder()
            .setAppForeground(isAppForeground && !isFinishing && !isDestroyed)
            .setBleEnabled(adapter?.isEnabled == true)
            .setBlePermissions(NativeFirstCutoverReset.hasBlePermissions(this))
            .setBleScanning(service?.isScanningActive() == true)
            .setBleAdvertising(service?.isAdvertisingActive() == true)
            .setQrAvailable(true)
            .setQrActive(qrScannerActive)
            .setCameraPermission(NativeFirstCutoverReset.hasCameraPermission(this))
            .build()
            .toByteArray()

        val snapshotBytes = try {
            Unified.updateSessionHardwareFacts(facts)
        } catch (t: Throwable) {
            Log.e(tag, "publishSessionState: Rust updateSessionHardwareFacts failed: ${t.message}")
            // Fallback: get snapshot without updating facts (Rust may not be loaded yet)
            try { Unified.getSessionSnapshot() } catch (_: Throwable) { return }
        }

        Log.d(tag, "publishSessionState: reason=$reason bytes=${snapshotBytes.size}")
        dispatchDsmEventOnUi("session.state", snapshotBytes)
    }

    fun publishCurrentSessionState(reason: String = "native") {
        publishSessionState(reason)
    }

    fun setBleAdvertisingDesired(desired: Boolean) {
        bleBackgroundService?.setAdvertisingDesired(desired)
    }

    private fun setSessionFatalError(message: String?) {
        if (message.isNullOrBlank()) {
            try { Unified.clearSessionFatalError() } catch (_: Throwable) {}
            publishSessionState("fatalCleared")
        } else {
            try { Unified.setSessionFatalError(message) } catch (_: Throwable) {}
            publishSessionState("fatalError")
        }
    }

    private fun invokeNativeRouterInvoke(method: String, args: ByteArray = ByteArray(0)) {
        bridgeExecutor.execute {
            try {
                val payload = com.dsm.wallet.bridge.BridgeEnvelopeCodec.encodeAppRouterPayload(method, args)
                com.dsm.wallet.bridge.SinglePathWebViewBridge.handleBinaryRpcRaw("appRouterInvoke", payload)
            } catch (t: Throwable) {
                Log.w(tag, "invokeNativeRouterInvoke failed for $method", t)
            }
        }
    }

    private fun bleCoordinator(): BleCoordinator = BleCoordinator.getInstance(applicationContext)


    private fun isAllowlistedExternalHost(host: String): Boolean =
        host == "tile.openstreetmap.org" || host.endsWith(".tile.openstreetmap.org") ||
        host == "localhost" || host == "127.0.0.1"

    @VisibleForTesting
    internal fun proxyWithCorsForTest(request: WebResourceRequest): WebResourceResponse? {
        return proxyWithCorsInternal(request)
    }

    private fun proxyWithCorsInternal(request: WebResourceRequest): WebResourceResponse? {
        val url = request.url?.toString() ?: return null
        val host = request.url?.host ?: return null
        if (!isAllowlistedExternalHost(host)) return null
        return try {
            val conn = (URL(url).openConnection() as HttpURLConnection).apply {
                connectTimeout = 10_000
                readTimeout = 15_000
                requestMethod = request.method
                for ((k, v) in request.requestHeaders) {
                    if (k.isNullOrBlank()) continue
                    setRequestProperty(k, v)
                }
            }
            val code = conn.responseCode
            val rawContentType = conn.contentType ?: "application/octet-stream"
            val parts = rawContentType.split(';').map { it.trim() }
            val mime = parts.firstOrNull()?.ifBlank { "application/octet-stream" } ?: "application/octet-stream"
            val charset = parts.firstOrNull { it.startsWith("charset=", ignoreCase = true) }
                ?.substringAfter('=')
                ?.ifBlank { null }
                ?: "utf-8"

            val stream: InputStream = try {
                conn.inputStream
            } catch (_: Throwable) {
                conn.errorStream ?: ByteArrayInputStream(ByteArray(0))
            }

            val headers = mutableMapOf<String, String>()
            headers["Access-Control-Allow-Origin"] = "https://appassets.androidplatform.net"
            headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
            headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"

            WebResourceResponse(mime, charset, code, conn.responseMessage ?: "OK", headers, stream)
        } catch (_: Throwable) {
            null
        }
    }

    private fun installDsmBinaryBridge(wv: WebView) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.CREATE_WEB_MESSAGE_CHANNEL)) {
            Log.e(tag, "WebViewFeature.CREATE_WEB_MESSAGE_CHANNEL not supported")
            return
        }
        val ports = WebViewCompat.createWebMessageChannel(wv)
        val nativePort = ports[0]
        val jsPort = ports[1]
        
        dsmPort = nativePort
        
        if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_PORT_SET_MESSAGE_CALLBACK)) {
            nativePort.setWebMessageCallback(object : WebMessagePortCompat.WebMessageCallbackCompat() {
                override fun onMessage(port: WebMessagePortCompat, message: WebMessageCompat?) {
                    if (message != null) handleDsmPortMessage(port, message)
                }
            })
        }
        
        pendingJsPort = jsPort
        Log.i(tag, "DSM MessagePort created, will deliver after page loads")
    }

    private fun handleDsmPortMessage(port: WebMessagePortCompat, message: WebMessageCompat) {
        try {
            if (!WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_ARRAY_BUFFER)) {
                Log.w(tag, "DSM bridge: ArrayBuffer not supported; dropping message")
                return
            }
            if (message.type != WebMessageCompat.TYPE_ARRAY_BUFFER) {
                Log.w(tag, "DSM bridge: non-binary MessagePort payload received; dropping")
                return
            }
            val req: ByteArray = message.arrayBuffer
            if (req.isEmpty()) return

            Log.i(tag, "DSM bridge: received message bytes=${req.size}")

            run {
                val previewLen = minOf(req.size, 24)
                val prefixB32 = if (previewLen > 0) {
                    SinglePathWebViewBridge.base32CrockfordEncode(req.copyOfRange(0, previewLen)).take(32)
                } else {
                    ""
                }
                Log.i(tag, "DSM bridge: request payload bytes=${req.size} b32Prefix=${prefixB32}")
            }

            if (req.size < 8) return // Need at least 8 bytes msgId

            // Extract message ID (first 8 bytes as u64 BigInt - deterministic counter)
            val messageId = java.nio.ByteBuffer.wrap(req, 0, 8).order(java.nio.ByteOrder.BIG_ENDIAN).long

            val requestBytes = req.copyOfRange(8, req.size)
            
            // Validate requestBytes looks like a protobuf before parsing
            if (requestBytes.isEmpty()) {
                Log.w(tag, "DSM bridge: empty request bytes after message ID")
                return
            }
            if (requestBytes.size > 1024 * 1024) { // 1MB limit
                Log.w(tag, "DSM bridge: request too large: ${requestBytes.size} bytes")
                return
            }
            
            val bridgeReq = try {
                com.dsm.wallet.bridge.BridgeEnvelopeCodec.parseBridgeRequest(requestBytes)
            } catch (t: Throwable) {
                Log.e(tag, "DSM bridge: failed to parse BridgeRpcRequest (size=${requestBytes.size}, firstBytes=${requestBytes.copyOfRange(0, minOf(16, requestBytes.size)).joinToString("") { String.format("%02x", it) }})", t)
                val errorResponse = com.dsm.wallet.bridge.SinglePathWebViewBridge.createErrorResponse(
                    "invalid_request",
                    2,
                    "Invalid bridge request: ${t.message}"
                )
                val responseWithId = ByteArray(8 + errorResponse.size)
                java.nio.ByteBuffer.wrap(responseWithId, 0, 8).order(java.nio.ByteOrder.BIG_ENDIAN).putLong(messageId)
                System.arraycopy(errorResponse, 0, responseWithId, 8, errorResponse.size)
                if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_PORT_POST_MESSAGE)) {
                    port.postMessage(WebMessageCompat(responseWithId))
                }
                return
            }

            val method = bridgeReq.method
            val body = bridgeReq.payload

            Log.i(tag, "DSM bridge: parsed messageId=$messageId method='$method' bodyBytes=${body.size}")

            // Biometric auth is async — return ACK immediately; result arrives via binary event.
            if (method == "biometric.auth") {
                Log.i(tag, "DSM bridge: biometric.auth — launching BiometricPrompt")
                val ackResponse = ByteArray(8)
                java.nio.ByteBuffer.wrap(ackResponse, 0, 8).order(java.nio.ByteOrder.BIG_ENDIAN).putLong(messageId)
                if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_PORT_POST_MESSAGE)) {
                    port.postMessage(WebMessageCompat(ackResponse))
                }
                runOnUiThread { showBiometricPrompt() }
                return
            }

            // System bar color update: payload is UTF-8 "bgHex|darkHex".
            if (method == "setSystemBarColors") {
                try {
                    val parts = String(body, Charsets.UTF_8).split("|", limit = 2)
                    if (parts.size == 2) {
                        applySystemBarColors(parts[0], parts[1])
                    }
                } catch (t: Throwable) {
                    Log.w(tag, "DSM bridge: setSystemBarColors failed: ${t.message}")
                }
                val ackResponse = ByteArray(8)
                java.nio.ByteBuffer.wrap(ackResponse, 0, 8).order(java.nio.ByteOrder.BIG_ENDIAN).putLong(messageId)
                if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_PORT_POST_MESSAGE)) {
                    port.postMessage(WebMessageCompat(ackResponse))
                }
                return
            }

            // createGenesisBin includes silicon fingerprint enrollment (~60s on first boot).
            // Running it on the main thread causes ANR. Dispatch to background executor;
            // port.postMessage is thread-safe and can be called from any thread.
            if (method == "createGenesisBin") {
                genesisExecutor.execute {
                    val respBytes: ByteArray = try {
                        SinglePathWebViewBridge.handleBinaryRpc(method, body)
                    } catch (t: Throwable) {
                        Log.e(tag, "DSM bridge: method '$method' failed", t)
                        com.dsm.wallet.bridge.SinglePathWebViewBridge.createErrorResponse(method, 3, "Native error: ${t.message}")
                    }
                    Log.i(tag, "DSM bridge: method '$method' response size: ${respBytes.size} bytes")
                    val responseWithId = ByteArray(8 + respBytes.size)
                    java.nio.ByteBuffer.wrap(responseWithId, 0, 8).order(java.nio.ByteOrder.BIG_ENDIAN).putLong(messageId)
                    System.arraycopy(respBytes, 0, responseWithId, 8, respBytes.size)
                    Log.i(tag, "DSM bridge: posting response with messageId=$messageId payloadBytes=${responseWithId.size}")
                    if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_PORT_POST_MESSAGE)) {
                        port.postMessage(WebMessageCompat(responseWithId))
                    }
                }
                return
            }

            // Default RPC dispatch: move off UI thread to prevent "Skipped N frames" ANR.
            // port.postMessage is thread-safe and can be called from any thread.
            bridgeExecutor.execute {
                val respBytes: ByteArray = try {
                    SinglePathWebViewBridge.handleBinaryRpc(method, body)
                } catch (t: Throwable) {
                    Log.e(tag, "DSM bridge: method '$method' failed", t)
                    com.dsm.wallet.bridge.SinglePathWebViewBridge.createErrorResponse(method, 3, "Native error: ${t.message}")
                }
                Log.i(tag, "DSM bridge: method '$method' response size: ${respBytes.size} bytes")

                // Optional: native-side deterministic safety routing (Error.source_tag == 11)
                try {
                    val (ok, data) = com.dsm.wallet.bridge.BridgeEnvelopeCodec.parseEnvelopeResponse(respBytes)
                    if (ok) {
                        com.dsm.wallet.bridge.BridgeEnvelopeCodec.extractDeterministicSafetyMessageFromEnvelope(data)?.let {
                            dispatchDsmEventOnUi("dsm.deterministicSafety", it.toByteArray(Charsets.UTF_8))
                        }
                    }
                } catch (_: Throwable) {
                    // ignore parse errors (response may not be an Envelope)
                }

                // Prepend message ID to response (8 bytes u64)
                val responseWithId = ByteArray(8 + respBytes.size)
                java.nio.ByteBuffer.wrap(responseWithId, 0, 8).order(java.nio.ByteOrder.BIG_ENDIAN).putLong(messageId)
                System.arraycopy(respBytes, 0, responseWithId, 8, respBytes.size)

                Log.i(tag, "DSM bridge: posting response with messageId=$messageId payloadBytes=${responseWithId.size}")

                if (WebViewFeature.isFeatureSupported(WebViewFeature.WEB_MESSAGE_PORT_POST_MESSAGE)) {
                    port.postMessage(WebMessageCompat(responseWithId))
                }
            }
        } catch (t: Throwable) {
            Log.e(tag, "DSM bridge: onMessage error", t)
        }
    }
    
    fun launchNativeQrScanner(callback: (String?) -> Unit) {
        Log.i(tag, "launchNativeQrScanner: starting native scanner")
        qrScanCallback = callback
        try {
            qrScannerActive = true
            publishSessionState("qrStart")
            val intent = Intent(this, QrScannerActivity::class.java)
            qrScannerLauncher.launch(intent)
        } catch (t: Throwable) {
            qrScannerActive = false
            qrScanCallback = null
            Log.e(tag, "launchNativeQrScanner: failed to launch scanner", t)
            publishSessionState("qrLaunchFailed")
            callback(null)
        }
    }

    private fun getBluetoothAdapterSafely(ctx: Context): android.bluetooth.BluetoothAdapter? {
        @SuppressLint("MissingPermission")
        val mgr = ctx.getSystemService(Context.BLUETOOTH_SERVICE) as? android.bluetooth.BluetoothManager ?: return null
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val hasConnect = ContextCompat.checkSelfPermission(ctx, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED
            if (hasConnect) mgr.adapter else null
        } else mgr.adapter
    }

    private fun ensureBluetoothEnabled() {
        try {
            val adapter = getBluetoothAdapterSafely(this)
            if (adapter == null) {
                Log.w(tag, "ensureBluetoothEnabled: Bluetooth adapter unavailable (permission or hardware)")
                return
            }
            if (!adapter.isEnabled) {
                Log.i(tag, "ensureBluetoothEnabled: Bluetooth disabled; requesting enable")
                val intent = Intent(android.bluetooth.BluetoothAdapter.ACTION_REQUEST_ENABLE)
                btEnableLauncher.launch(intent)
            }
        } catch (t: Throwable) {
            Log.w(tag, "ensureBluetoothEnabled: failed to request enable", t)
        }
    }

    fun requestBlePermissionsFromUi() {
        val neededBt = BluetoothPermissionHelper.requiredPermissions()
        if (!BluetoothPermissionHelper.hasAll(this, neededBt)) {
            btPermLauncher.launch(neededBt)
        } else {
            ensureBluetoothEnabled()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // Drop the launch theme as soon as the activity starts so the splash artwork
        // does not remain as the live window background after the first frame.
        setTheme(com.dsm.wallet.R.style.Theme_DsmClient)
        super.onCreate(savedInstanceState)

        // Fade-in/fade-out transition from the Irrefutable Labs splash screen
        @Suppress("DEPRECATION")
        overridePendingTransition(com.dsm.wallet.R.anim.splash_fade_in, com.dsm.wallet.R.anim.splash_fade_out)
        NativeFirstCutoverReset.resetIfNeeded(this)

        // Force system bars to near-black (95% solid) permanently across all themes.
        // Grain texture and overlay effects can't extend to native bars, so keep them
        // dark to match the stateboy-shell area surrounding the screen.
        val barColor = android.graphics.Color.parseColor("#0D0D0D")
        val wic = WindowInsetsControllerCompat(window, window.decorView)
        wic.isAppearanceLightStatusBars = false
        wic.isAppearanceLightNavigationBars = false
        if (Build.VERSION.SDK_INT < 35) {
            @Suppress("DEPRECATION")
            window.statusBarColor = barColor
            @Suppress("DEPRECATION")
            window.navigationBarColor = barColor
        }

        // Beta diagnostics: persist bridge logs for export
        try {
            com.dsm.wallet.bridge.BridgeLogger.setLogFile(File(filesDir, "bridge_diagnostics.log"))
        } catch (_: Throwable) {
            // ignore
        }
        
        // P0: JNI library compatibility check (before ANY other native library operations)
        // If DsmInitProvider detected UnsatisfiedLinkError, route to compatibility screen immediately
        val systemPrefs = getSharedPreferences("dsm_system", Context.MODE_PRIVATE)
        if (systemPrefs.getBoolean("jni_incompatible", false)) {
            val errorMessage = systemPrefs.getString("jni_error_message", "Unknown library load error")
            Log.e(tag, "JNI library incompatible - routing to IncompatibleDeviceScreen: $errorMessage")
            
            val intent = Intent(this, com.dsm.wallet.IncompatibleDeviceScreen::class.java)
            intent.putExtra("error_message", errorMessage)
            startActivity(intent)
            finish()
            return
        }
        
        // P1.1: Architecture compatibility check (must happen before any native library loading)
        // Check CPU architecture, ABI, and JVM compatibility early to prevent cryptic crashes
        try {
            val archChecker = com.dsm.wallet.diagnostics.ArchitectureChecker
            if (archChecker.isDeviceBlocked()) {
                val errorMsg = archChecker.getBlockingErrorMessage()
                Log.e(tag, "ARCHITECTURE CHECK FAILED - device incompatible:\n$errorMsg")
                
                // Show blocking dialog with clear explanation
                android.app.AlertDialog.Builder(this)
                    .setTitle("Incompatible Device")
                    .setMessage(errorMsg)
                    .setCancelable(false)
                    .setPositiveButton("Exit") { _, _ -> finishAffinity() }
                    .setNegativeButton("Learn More") { _, _ ->
                        // Open architecture guide
                        val intent = Intent(Intent.ACTION_VIEW, 
                            Uri.parse("https://github.com/DSM-Deterministic-State-Machine/deterministic-state-machine/blob/main/docs/ARCHITECTURE.md"))
                        startActivity(intent)
                        finishAffinity()
                    }
                    .show()
                return
            } else {
                val compat = archChecker.checkCompatibility()
                Log.i(tag, "Architecture check passed: ${compat.message}")
                if (compat.deviceArch == "armeabi-v7a") {
                    // Show warning for ARMv7 (suboptimal but supported)
                    Log.w(tag, "ARMv7 device detected - performance may be reduced")
                    // Optional: show non-blocking toast about performance
                }
            }
        } catch (t: Throwable) {
            Log.e(tag, "Architecture check exception", t)
            // Continue anyway - don't block on checker failure
        }
        
        // DBRW validation removed from onCreate — bootstrapFromPrefs() now handles
        // anchor computation using fast mode (no hardware probing). The heavy enrollment
        // runs once during genesis setup with a dedicated progress screen.

        requestRuntimePermissions()

        btPermLauncher = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { result ->
            val denied = result.filterValues { !it }.keys
            val allGranted = denied.isEmpty()
            if (denied.isNotEmpty()) {
                Log.w(tag, "Bluetooth permissions denied: $denied")
            } else {
                Log.i(tag, "Bluetooth permissions granted.")
                ensureBluetoothEnabled()
            }
            blePermissionCallback?.invoke(allGranted)
            blePermissionCallback = null
            publishSessionState("blePermissions")
        }

        btEnableLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
            val adapter = getBluetoothAdapterSafely(this)
            val enabled = adapter?.isEnabled == true
            Log.i(tag, "Bluetooth enable activity result: enabled=$enabled")
            if (enabled) {
                val neededBt = BluetoothPermissionHelper.requiredPermissions()
                if (!BluetoothPermissionHelper.hasAll(this, neededBt)) {
                    btPermLauncher.launch(neededBt)
                }
            }
            publishSessionState("bluetoothEnableResult")
        }
        
        qrScannerLauncher = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            qrScannerActive = false
            val data = if (result.resultCode == RESULT_OK) {
                result.data?.getStringExtra(QrScannerActivity.EXTRA_QR_DATA)
            } else {
                null
            }
            Log.i(tag, "QR scanner result: code=${result.resultCode} hasData=${data != null}")
            val cb = qrScanCallback
            qrScanCallback = null
            publishSessionState("qrResult")
            cb?.invoke(data)
        }

        val neededBt = BluetoothPermissionHelper.requiredPermissions()
        if (!BluetoothPermissionHelper.hasAll(this, neededBt) && !btPermsRequested) {
            btPermsRequested = true
            btPermLauncher.launch(neededBt)
        }

        try { Class.forName("com.dsm.wallet.bridge.Unified") } catch (_: Throwable) {}

        bridge = SinglePathWebViewBridge.ensureInitialized(this)

        rootContainer = FrameLayout(this).apply {
            setBackgroundColor(Color.BLACK)
            layoutParams = FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT,
            )
        }
        webView = WebView(this)
        rootContainer.addView(
            webView,
            FrameLayout.LayoutParams(
                FrameLayout.LayoutParams.MATCH_PARENT,
                FrameLayout.LayoutParams.MATCH_PARENT,
            )
        )
        if (Build.VERSION.SDK_INT >= 35) {
            val statusBarOverlapPx = (resources.displayMetrics.density * 2f).toInt().coerceAtLeast(1)
            statusBarScrim = View(this).apply {
                // Android 15 enforces transparent status bars; draw our own protection
                // layer so the top bar matches the translucent dark bottom nav.
                setBackgroundColor(Color.parseColor("#CC0D0D0D"))
                importantForAccessibility = View.IMPORTANT_FOR_ACCESSIBILITY_NO
            }
            rootContainer.addView(
                statusBarScrim,
                FrameLayout.LayoutParams(
                    FrameLayout.LayoutParams.MATCH_PARENT,
                    0,
                    Gravity.TOP,
                )
            )
            ViewCompat.setOnApplyWindowInsetsListener(rootContainer) { _, insets ->
                val topInset = insets.getInsets(WindowInsetsCompat.Type.statusBars()).top
                statusBarScrim?.layoutParams = (statusBarScrim?.layoutParams as? FrameLayout.LayoutParams)?.apply {
                    // Add a tiny overlap below the status bar to hide the 1px seam that
                    // can appear between the scrim and WebView content on some devices.
                    height = topInset + statusBarOverlapPx
                }
                insets
            }
        }
        setContentView(rootContainer)
        setupWebView(webView)


        initDsmAndSignalReady()
        handleBackPress()
        
        com.dsm.wallet.EventPoller.start()
    }

    override fun onResume() {
        super.onResume()
        activeInstance = WeakReference(this)
        isAppForeground = true
        publishSessionState("resume")
        if (hasIdentityViaRust()) {
            invokeNativeRouterInvoke("inbox.resume")
        }
    }

    override fun onPause() {
        super.onPause()
        isAppForeground = false

        // Stop NFC reader mode so the ring never triggers when the app is backgrounded.
        if (nfcReaderActive) {
            nfcReaderActive = false
            try { nfcAdapter?.disableReaderMode(this) } catch (_: Throwable) {}
        }

        try {
            if (::bridge.isInitialized) {
                bridge.handleHostPause()
            }
        } catch (t: Throwable) {
            Log.w(tag, "onPause: failed to notify genesis interruption guard", t)
        }
        // Rust receives app_foreground=false via publishSessionState and decides lock policy
        publishSessionState("pause")
        // Do not stop advertising here; background service owns BLE state.
    }

    /**
     * System bars are permanently near-black (#0D0D0D), set once in onCreate().
     * Bridge RPC "setSystemBarColors" still routes here but is intentionally a no-op.
     */
    fun applySystemBarColors(@Suppress("UNUSED_PARAMETER") bgHex: String, @Suppress("UNUSED_PARAMETER") darkHex: String) {
        // No-op: bars are permanently dark. Kept so the bridge route doesn't error.
    }

    private fun showBiometricPrompt() {
        val executor = ContextCompat.getMainExecutor(this)
        val callback = object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                // Payload: [0x01] = success
                dispatchDsmEventOnUi("dsm-biometric-result", byteArrayOf(0x01))
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                // Payload: [0x00][errorCode as u16 BE][UTF-8 error message]
                val msgBytes = errString.toString().toByteArray(Charsets.UTF_8)
                val payload = ByteArray(3 + msgBytes.size)
                payload[0] = 0x00
                payload[1] = ((errorCode shr 8) and 0xFF).toByte()
                payload[2] = (errorCode and 0xFF).toByte()
                System.arraycopy(msgBytes, 0, payload, 3, msgBytes.size)
                dispatchDsmEventOnUi("dsm-biometric-result", payload)
            }
            override fun onAuthenticationFailed() {
                // Finger not recognised — BiometricPrompt shows retry UI automatically.
            }
        }
        val prompt = BiometricPrompt(this, executor, callback)
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("DSM Wallet")
            .setSubtitle("Authenticate to unlock")
            .setNegativeButtonText("Use PIN / Combo")
            .build()
        prompt.authenticate(promptInfo)
    }

    override fun onStart() {
        super.onStart()
        val intent = Intent(this, BleBackgroundService::class.java)
        try {
            bindService(intent, bleServiceConnection, Context.BIND_AUTO_CREATE)
        } catch (t: Throwable) {
            Log.w(tag, "onStart: bindService failed", t)
        }
    }

    override fun onStop() {
        super.onStop()
        if (bleServiceBound) {
            try {
                unbindService(bleServiceConnection)
            } catch (t: Throwable) {
                Log.w(tag, "onStop: unbindService failed", t)
            }
            bleServiceBound = false
            bleBackgroundService = null
        }
    }

    override fun onPostResume() {
        super.onPostResume()
        if (!mcpStarted) {
            startForegroundMcp()
            mcpStarted = true
        }
    }
    
    override fun onDestroy() {
        if (activeInstance?.get() === this) {
            activeInstance = null
        }
        super.onDestroy()
        com.dsm.wallet.EventPoller.stop()
    }



    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        try { if (::bridge.isInitialized) outState.putInt("bridge_status", bridge.getBridgeStatus()) } catch (_: Throwable) {}
    }

    override fun onRestoreInstanceState(savedInstanceState: Bundle) {
        super.onRestoreInstanceState(savedInstanceState)
        val status = try { savedInstanceState.getInt("bridge_status", 0) } catch (_: Throwable) { 0 }
        try {
            signalBridgeReady()
            if (status == 3) {
                dispatchDsmEventOnUi("dsm-identity-ready", ByteArray(0))
            }
            publishSessionState("restore")
        } catch (_: Throwable) {}
    }

    private fun startForegroundMcp() {
        ContextCompat.startForegroundService(this, Intent(this, McpService::class.java))
    }


    private val permLauncher = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { grants ->
        Log.d(tag, "Permission callback: $grants")
        val blePermsGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            grants[Manifest.permission.BLUETOOTH_CONNECT] == true &&
            grants[Manifest.permission.BLUETOOTH_SCAN] == true &&
            grants[Manifest.permission.BLUETOOTH_ADVERTISE] == true
        } else {
            true
        }
        
        if (blePermsGranted) {
            Log.i(tag, "BLE permissions granted, reinitializing BLE service...")
            try {
                val svc = bleBackgroundService
                if (svc == null) {
                    BleBackgroundService.start(this@MainActivity)
                }
                val gattResult = svc?.ensureGattServerStarted() ?: false
                Log.i(tag, "Bluetooth permissions granted: GATT server ensure-start result=$gattResult")
            } catch (t: Throwable) {
                Log.e(tag, "Failed to reinitialize BLE after permissions granted", t)
            }
        } else {
            Log.w(tag, "BLE permissions not granted: $grants")
        }
    }

    private fun requestRuntimePermissions() {
        val perms = mutableListOf(Manifest.permission.CAMERA)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) perms.add(Manifest.permission.POST_NOTIFICATIONS)
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            perms.add(Manifest.permission.BLUETOOTH_CONNECT)
            perms.add(Manifest.permission.BLUETOOTH_SCAN)
            perms.add(Manifest.permission.BLUETOOTH_ADVERTISE)
        }

        Log.d(tag, "requestRuntimePermissions: Requesting $perms")
        permLauncher.launch(perms.toTypedArray())
    }

    /** Copy an APK asset to [targetDir] if the asset exists and the target is absent or stale. */
    private fun materializeAssetIfBundled(name: String, targetDir: File) {
        val dest = File(targetDir, name)
        try {
            assets.open(name).use { input ->
                FileOutputStream(dest, false).use { output -> input.copyTo(output) }
            }
            Log.i(tag, "Materialized asset $name → ${dest.absolutePath} (${dest.length()} bytes)")
        } catch (_: java.io.FileNotFoundException) {
            // Asset not bundled (e.g., local-dev builds without ca.crt) — no-op.
        } catch (t: Throwable) {
            Log.w(tag, "Failed to materialize asset $name: ${t.message}")
        }
    }

    private fun materializeEnvConfig(): File? {
        val assetName = "dsm_env_config.toml"
        val files = applicationContext.filesDir
        val outFile = File(files, assetName)

        // Materialize bundled assets that the SDK reads from filesDir.
        // ca.crt is the self-signed CA for AWS storage node TLS certs.
        materializeAssetIfBundled("ca.crt", files)

        fun firstExisting(vararg candidates: File?): File? = candidates.firstOrNull { it != null && it.exists() }

        val overrideCandidates = mutableListOf<File?>()
        overrideCandidates += File(files, "dsm_env_config.override.toml")
        overrideCandidates += File(files, "dsm_env_config.local.toml")
        try { overrideCandidates += File(getExternalFilesDir(null), "dsm_env_config.toml") } catch (_: Throwable) {}
        try {
            val dl = android.os.Environment.getExternalStoragePublicDirectory(android.os.Environment.DIRECTORY_DOWNLOADS)
            overrideCandidates += File(dl, "dsm_env_config.toml")
        } catch (_: Throwable) {}

        val override = firstExisting(*overrideCandidates.toTypedArray())
        if (override != null) {
            try {
                if (override.exists() && override.canRead() && override.length() > 0L) {
                    Log.i(tag, "Using developer override env config at ${override.absolutePath}")
                    return override
                } else {
                    Log.w(tag, "Found override config at ${override.absolutePath} but it is not readable or empty; ignoring")
                }
            } catch (t: Throwable) {
                Log.w(tag, "Found override config at ${override.absolutePath} but validation failed: ${t.message}; ignoring")
            }
        }

        val maxAttempts = 3
        var lastErr: Throwable? = null
        for (attempt in 1..maxAttempts) {
            try {
                assets.open(assetName).use { input -> FileOutputStream(outFile, false).use { output -> input.copyTo(output) } }
                if (outFile.exists() && outFile.canRead() && outFile.length() > 0L) {
                    Log.i(tag, "Materialized default env config to ${outFile.absolutePath} (attempt $attempt)")
                    return outFile
                } else {
                    Log.w(tag, "Materialized env config appears invalid (missing/zero length) after attempt $attempt: ${outFile.absolutePath}")
                    lastErr = IOException("Invalid file after copy (size=${outFile.length()})")
                }
            } catch (ioe: IOException) {
                lastErr = ioe
                Log.w(tag, "Attempt $attempt: Failed to materialize $assetName: ${ioe.message}")
            }
        }

        Log.e(tag, "Materialize env config failed after $maxAttempts attempts: ${lastErr?.message}")
        val errorMsg = "Failed to load configuration: ${lastErr?.message ?: "unknown"}"
        try { Unified.setSessionFatalError(errorMsg) } catch (_: Throwable) {}
        runOnUiThread {
            try {
                val errType = when {
                    lastErr?.message?.contains("FileNotFoundException") == true -> "ASSET_NOT_FOUND"
                    lastErr?.message?.contains("IOException") == true -> "IO_ERROR"
                    else -> "UNKNOWN_ERROR"
                }
                val helpMessage = when (errType) {
                    "ASSET_NOT_FOUND" -> "The configuration file is missing from app assets. Reinstall the app or check BETA_DEVICE_PREPARATION.md"
                    "IO_ERROR" -> "Cannot write configuration file. Check device storage space and app permissions."
                    else -> "See logs for details or consult BETA_QUICK_TROUBLESHOOTING.md"
                }
                // Payload: UTF-8 "type|message|help"
                val msg = "Failed to load configuration: ${lastErr?.message ?: "unknown"}"
                val payload = "$errType|$msg|$helpMessage".toByteArray(Charsets.UTF_8)
                dispatchDsmEventOnUi("dsm-env-config-error", payload)
                publishSessionState("envConfigMaterializeFailed")
            } catch (_: Throwable) {
                Log.w(tag, "Failed to dispatch dsm-env-config-error event to WebView")
            }
        }
        return null
    }
    
    /**
     * Sanitize a string for safe use as a binary event topic name.
     * Only allows alphanumeric, dash, dot, and underscore characters.
     */
    private fun sanitizeEventName(name: String): String {
        return name.filter { it.isLetterOrDigit() || it == '-' || it == '.' || it == '_' }
    }

    private fun signalBridgeReady() {
        Log.i(tag, "signalBridgeReady: Dispatching events to JS...")
        BleEventRelay.markBridgeReady(this)
        dispatchDsmEventOnUi("dsm-bridge-ready", ByteArray(0))
        // Delay session state publish so JS has time to process the MessagePort
        // delivery and install its onmessage handler. webView.post {} is insufficient
        // because the JS engine may not have yielded between port receipt and the
        // incoming data message. 100ms is conservative transport-layer delay (Invariant #4 allowed).
        webView.postDelayed({
            publishSessionState("bridgeReady")
        }, 100)
        Log.i(tag, "signalBridgeReady: COMPLETE")
    }

    private fun initDsmAndSignalReady() {
        Thread {
            try {
                Log.i(tag, "initDsmAndSignalReady: Starting initialization...")
                
                val baseDir = filesDir.path
                Log.i(tag, "initDsmAndSignalReady: Base dir = $baseDir")
                Unified.initStorageBaseDir(baseDir.toByteArray(Charsets.UTF_8))
                
                val cfg = materializeEnvConfig()
                if (cfg != null) {
                    // Validate config file is readable and has content
                    if (!cfg.exists() || !cfg.canRead()) {
                        Log.e(tag, "initDsmAndSignalReady: Config file exists but is not readable: ${cfg.absolutePath}")
                        try { Unified.setSessionFatalError("Configuration file found but not readable.") } catch (_: Throwable) {}
                        dispatchDsmEventOnUi("dsm-env-config-error",
                            "UNREADABLE_CONFIG|Configuration file found but not readable. Please check file permissions and try reinstalling the app.".toByteArray(Charsets.UTF_8))
                        publishSessionState("envUnreadable")
                        return@Thread
                    }

                    if (cfg.length() == 0L) {
                        Log.e(tag, "initDsmAndSignalReady: Config file is empty: ${cfg.absolutePath}")
                        try { Unified.setSessionFatalError("Configuration file is empty.") } catch (_: Throwable) {}
                        dispatchDsmEventOnUi("dsm-env-config-error",
                            "EMPTY_CONFIG|Configuration file is empty. Please redeploy the configuration file from assets.".toByteArray(Charsets.UTF_8))
                        publishSessionState("envEmpty")
                        return@Thread
                    }

                    Log.i(tag, "initDsmAndSignalReady: Config path = ${cfg.absolutePath}")
                    Unified.initDsmSdk(cfg.absolutePath)
                    try { Unified.clearSessionFatalError() } catch (_: Throwable) {}
                    Log.i(tag, "initDsmAndSignalReady: DSM_ENV_CONFIG_PATH set via initDsmSdk")
                    Log.i(tag, "initDsmAndSignalReady: waiting for dsm-bridge-ready event (event-driven)")
                } else {
                    Log.e(tag, "initDsmAndSignalReady: No env config found; cannot initialize DSM")
                    try { Unified.setSessionFatalError("Configuration file not found.") } catch (_: Throwable) {}
                    dispatchDsmEventOnUi("dsm-env-config-error",
                        "MISSING_CONFIG|Configuration file not found. Please ensure dsm_env_config.toml is deployed to app assets before launching.|See BETA_DEVICE_PREPARATION.md for configuration deployment instructions.".toByteArray(Charsets.UTF_8))
                    publishSessionState("envMissing")
                    // Don't proceed with SDK initialization if config is missing
                    return@Thread
                }
                
                Log.i(tag, "initDsmAndSignalReady: Calling initSdk...")
                Unified.initSdk(baseDir)
                Log.i(tag, "initDsmAndSignalReady: SDK initialized; switching to UI thread...")
                
                Log.i(tag, "initDsmAndSignalReady: event-driven bridge mode enabled; will rely on dsm-bridge-ready signal")
                try {
                    val status = Unified.getAppRouterStatus()
                    Log.i(tag, "initDsmAndSignalReady: getAppRouterStatus() returned $status")
                } catch (t: Throwable) {
                    Log.w(tag, "initDsmAndSignalReady: getAppRouterStatus() not available", t)
                }

                try {
                    val deviceIdBin = try { Unified.getDeviceIdBin() } catch (_: Throwable) { byteArrayOf() }
                    val genesis = ByteArray(32)
                    val tip = ByteArray(32)
                    if (deviceIdBin.size == 32) {
                        val b0x = Unified.computeB0xAddress(genesis, deviceIdBin, tip)
                        Log.i(tag, "initDsmAndSignalReady: computeB0xAddress (diag) = $b0x")
                    } else {
                        Log.i(tag, "initDsmAndSignalReady: computeB0xAddress skipped (missing device id)")
                    }
                } catch (t: Throwable) {
                    Log.w(tag, "initDsmAndSignalReady: computeB0xAddress failed", t)
                }

                // CRITICAL: Bootstrap FIRST (background thread) — sets up DBRW +
                // SDK context that bilateral SDK init depends on.
                // All heavy JNI calls stay here; only lightweight signals go to UI thread.
                var bootstrapped = false
                try {
                    Log.i(tag, "initDsmAndSignalReady: Bootstrapping from prefs (background thread)...")
                    bootstrapped = bridge.bootstrapFromPrefs()
                    Log.i(tag, "initDsmAndSignalReady: Bootstrap result = $bootstrapped")
                } catch (t: Throwable) {
                    Log.e(tag, "initDsmAndSignalReady: Bootstrap error", t)
                }

                // Bilateral SDK init runs calibrate_device_performance() which is
                // CPU-bound (adaptive BLAKE3 loop, 500-2000ms on slow devices).
                // Keep it on this background thread — never on the UI thread.
                // Runs AFTER bootstrap so DBRW is initialized.
                if (bootstrapped) {
                    try {
                        Log.i(tag, "initDsmAndSignalReady: Initializing bilateral SDK (background thread)...")
                        val bilateralInitialized = com.dsm.native.DsmNative.initializeBilateralSdk()
                        if (bilateralInitialized) {
                            Log.i(tag, "initDsmAndSignalReady: Bilateral SDK initialized successfully")
                        } else {
                            Log.w(tag, "initDsmAndSignalReady: Bilateral SDK initialization returned false")
                        }
                    } catch (t: Throwable) {
                        Log.e(tag, "initDsmAndSignalReady: Bilateral SDK init error", t)
                    }
                }

                // Fetch identity bytes via JNI → Rust (Invariant #7: no prefs side channel)
                val deviceIdBytes = try { Unified.getDeviceIdBin() } catch (_: Throwable) { byteArrayOf() }
                val genesisHashBytes = try { Unified.getGenesisHashBin() } catch (_: Throwable) { byteArrayOf() }

                // UI thread: only lightweight signals and service binding (no JNI)
                val capturedBootstrapped = bootstrapped
                val capturedDeviceId = deviceIdBytes
                val capturedGenesis = genesisHashBytes
                runOnUiThread {
                    try {
                        Log.i(tag, "initDsmAndSignalReady: Setting bridge ready...")
                        bridge.setReady()

                        if (capturedBootstrapped) {
                            Log.i(tag, "initDsmAndSignalReady: Identity exists, dispatching dsm-identity-ready")
                            dispatchDsmEventOnUi("dsm-identity-ready", ByteArray(0))
                            // Rust SessionManager handles initial lock state from SDK_READY + has_identity
                            invokeNativeRouterInvoke("inbox.startPoller")
                        }

                        if (capturedDeviceId.size == 32 && capturedGenesis.size == 32) {
                            try {
                                BleBackgroundService.start(this@MainActivity)
                            } catch (t: Throwable) {
                                Log.w(tag, "initDsmAndSignalReady: BleBackgroundService.start failed before identity publish", t)
                            }
                            // GATT server init + identity write are synchronous Bluetooth
                            // framework calls (100-500ms). Run on a background thread to
                            // avoid blocking the UI thread on slower chipsets (MediaTek).
                            Thread {
                                try {
                                    val coordinator = bleCoordinator()
                                    val gattReady = coordinator.ensureGattServerStarted()
                                    Log.i(tag, "initDsmAndSignalReady: GATT server ensure-started: $gattReady")
                                    coordinator.setIdentityValue(capturedGenesis, capturedDeviceId)
                                    Log.i(tag, "initDsmAndSignalReady: BLE identity set (genesis + deviceId)")
                                } catch (t: Throwable) {
                                    Log.w(tag, "initDsmAndSignalReady: GATT/identity setup failed", t)
                                }
                            }.start()
                            try {
                                BleBackgroundService.start(this@MainActivity)
                                Log.i(tag, "initDsmAndSignalReady: BleBackgroundService.start invoked")
                            } catch (t: Throwable) {
                                Log.w(tag, "initDsmAndSignalReady: BleBackgroundService.start failed", t)
                            }
                        } else {
                            Log.i(tag, "initDsmAndSignalReady: BLE identity not yet present in persisted bytes; skipping setIdentityValue")
                        }
                        publishSessionState("initComplete")
                    } catch (t: Throwable) {
                        Log.e(tag, "initDsmAndSignalReady failed", t)
                    }
                }
            } catch (t: Throwable) {
                Log.e(tag, "initDsmAndSignalReady failed", t)
            }
        }.start()
    }

    private fun handleBackPress() {
        onBackPressedDispatcher.addCallback(this, object : OnBackPressedCallback(true) {
            override fun handleOnBackPressed() {
                if (::webView.isInitialized && webView.canGoBack()) webView.goBack() else finish()
            }
        })
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == runtimePermCode || requestCode == cameraPermCode) {
            val summary = permissions.zip(grantResults.toTypedArray()).joinToString(", ") { (p, r) ->
                val state = if (r == PackageManager.PERMISSION_GRANTED) "granted" else "denied"
                "$p=$state"
            }
            Log.d(tag, "onRequestPermissionsResult: $summary")
        }
        if (requestCode == 7001 || requestCode == 7002) {
            val allGranted = grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }
            if (!allGranted) {
                Log.w(tag, "Bluetooth permissions not granted")
                // Payload: [0x00] = denied
                dispatchDsmEventOnUi("bluetooth-permissions", byteArrayOf(0x00))
            } else {
                Log.i(tag, "Bluetooth permissions granted, notifying WebView")
                // BLE ops are NOT auto-started here. The UI must explicitly request
                // scanning/advertising via bridge RPC (device.ble.scan.start, device.ble.advertise.start).
                // Payload: [0x01] = granted
                dispatchDsmEventOnUi("bluetooth-permissions", byteArrayOf(0x01))
            }
            publishSessionState("runtimePermissions")
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun setupWebView(wv: WebView) {
        assetLoader = WebViewAssetLoader.Builder()
            .setDomain("appassets.androidplatform.net")
            .addPathHandler("/assets/", WebViewAssetLoader.AssetsPathHandler(this))
            .build()

        try { WebView.setWebContentsDebuggingEnabled(BuildConfig.DEBUG) } catch (_: Throwable) {}

        wv.setBackgroundColor(Color.BLACK)
        wv.settings.apply {
            javaScriptEnabled = true
            domStorageEnabled = true
            @Suppress("DEPRECATION")
            savePassword = false
            @Suppress("DEPRECATION")
            saveFormData = false

            allowFileAccess = false
            builtInZoomControls = false
            displayZoomControls = false
        }

        installDsmBinaryBridge(wv)

        wv.webChromeClient = object : WebChromeClient() {
            // Suppress the default blue page-loading progress bar.
            // All loading feedback is handled by the React UI with themed colors.
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                // No-op: suppress default WebView progress indicator
            }

            override fun onConsoleMessage(consoleMessage: ConsoleMessage?): Boolean {
                consoleMessage?.let { Log.i("WebViewConsole", it.message()) }
                return true
            }

            override fun onPermissionRequest(request: PermissionRequest?) {
                try {
                    if (request == null) return
                    // SECURITY: Only grant camera permission (needed for QR scanning).
                    // Deny all other WebView permissions (microphone, geolocation, etc.)
                    // to prevent JavaScript from accessing device resources without user consent.
                    val allowed = request.resources.filter { resource ->
                        resource == PermissionRequest.RESOURCE_VIDEO_CAPTURE &&
                        ContextCompat.checkSelfPermission(
                            this@MainActivity,
                            Manifest.permission.CAMERA
                        ) == PackageManager.PERMISSION_GRANTED
                    }.toTypedArray()

                    if (allowed.isNotEmpty()) {
                        request.grant(allowed)
                    } else {
                        request.deny()
                    }
                } catch (_: Throwable) {
                    request?.deny()
                }
            }
        }

        wv.webViewClient = object : WebViewClient() {
            override fun onPageFinished(view: WebView?, url: String?) {
                try {
                    pendingJsPort?.let { port ->
                        val target = view ?: wv
                        target.post {
                            try {
                                if (WebViewFeature.isFeatureSupported(WebViewFeature.POST_WEB_MESSAGE)) {
                                    val msg = WebMessageCompat("", arrayOf(port))
                                    WebViewCompat.postWebMessage(target, msg, "https://appassets.androidplatform.net".toUri())
                                    pendingJsPort = null
                                    Log.i(tag, "Delivered DSM MessagePort to page")
                                }
                            } catch (t: Throwable) {
                                Log.w(tag, "Failed to deliver MessagePort to page", t)
                            } finally {
                                // Signal readiness only after MessagePort delivery attempt to avoid
                                // frontend race where bridge-ready fires before port is assigned.
                                signalBridgeReady()
                            }
                        }
                        return
                    }
                    // No pending port (already delivered) — safe to signal immediately.
                    signalBridgeReady()
                } catch (t: Throwable) {
                    Log.w(tag, "onPageFinished error", t)
                }
            }

            override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
                request?.url?.let { uri ->
                    return assetLoader.shouldInterceptRequest(uri)
                }
                return super.shouldInterceptRequest(view, request)
            }

            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                try {
                    val uri = request?.url
                    if (uri != null && uri.scheme == "dsm" && uri.host == "native") {
                        val path = uri.path ?: ""
                        if (path == "/qr/start") {
                            Log.i(tag, "WebView requested native QR scan")
                            launchNativeQrScanner { qrText: String? ->
                                dispatchQrScanResult(qrText)
                            }
                            return true
                        }
                    }
                } catch (t: Throwable) {
                    Log.w(tag, "shouldOverrideUrlLoading: error", t)
                }
                return false
            }
        }

        val initialUrl = "https://appassets.androidplatform.net/assets/index.html"
        try {
            wv.loadUrl(initialUrl)
        } catch (t: Throwable) {
            Log.e(tag, "Failed to load WebView URL: $initialUrl", t)
        }
    }
}
