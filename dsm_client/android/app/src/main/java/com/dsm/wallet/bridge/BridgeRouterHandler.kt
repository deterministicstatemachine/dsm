package com.dsm.wallet.bridge

import android.util.Log

internal object BridgeRouterHandler {

    fun appRouterInvoke(payload: ByteArray, nextReqId: () -> ByteArray, logTag: String): ByteArray {
        val parsed = BridgeEnvelopeCodec.decodeAppRouterPayload(payload)
            ?: throw IllegalArgumentException("appRouterInvoke: invalid AppRouterPayload")
        val name = parsed.methodName
        val args = parsed.args

        try {
            val previewBytes = payload.copyOfRange(0, kotlin.math.min(payload.size, 24))
            val b32 = BridgeEncoding.base32CrockfordEncode(previewBytes)
            val preview = if (b32.length > 16) b32.substring(0, 16) + "..." else b32
            Log.d(logTag, "appRouterInvoke: framed_bytes=${payload.size} b32=$preview")
        } catch (_: Throwable) {
            Log.d(logTag, "appRouterInvoke: framed_bytes=${payload.size} b32=<error>")
        }

        val nativeFramedPayload = BridgeEnvelopeCodec.encodeAppRouterPayload(name, args)
        val reqId = nextReqId()

        when (name) {
            "identity.genesis.create" -> {
                val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                // Genesis sub-state ("securing_device") is communicated via DBRW progress events,
                // not session phase. Rust session phase stays at "needs_genesis" until completion.
                val outBytes = SinglePathWebViewBridge.handleBinaryRpcRaw("createGenesisBin", args)
                val out = ByteArray(reqId.size + outBytes.size)
                System.arraycopy(reqId, 0, out, 0, reqId.size)
                System.arraycopy(outBytes, 0, out, reqId.size, outBytes.size)
                act?.runOnUiThread { act.publishCurrentSessionState("identity.genesis.create") }
                return out
            }
            "device.qr.scan.start" -> {
                SinglePathWebViewBridge.handleBinaryRpcRaw("startNativeQrScanner", ByteArray(0))
                val out = ByteArray(reqId.size)
                System.arraycopy(reqId, 0, out, 0, reqId.size)
                com.dsm.wallet.ui.MainActivity.getActiveInstance()?.let { act -> act.runOnUiThread {
                    act.publishCurrentSessionState("device.qr.scan.start")
                }}
                return out
            }
            "device.ble.scan.start" -> {
                val ctx = com.dsm.wallet.ui.MainActivity.getActiveInstance()?.baseContext
                val ok = if (ctx != null) com.dsm.wallet.bridge.ble.BleCoordinator.getInstance(ctx).startScanning() else false
                Log.i(logTag, "device.ble.scan.start: result=$ok")
                val outBytes = byteArrayOf(if (ok) 1 else 0)
                val out = ByteArray(reqId.size + outBytes.size)
                System.arraycopy(reqId, 0, out, 0, reqId.size)
                System.arraycopy(outBytes, 0, out, reqId.size, outBytes.size)
                com.dsm.wallet.ui.MainActivity.getActiveInstance()?.let { act -> act.runOnUiThread {
                    act.publishCurrentSessionState("device.ble.scan.start")
                }}
                return out
            }
            "device.ble.scan.stop" -> {
                val ctx = com.dsm.wallet.ui.MainActivity.getActiveInstance()?.baseContext
                if (ctx != null) com.dsm.wallet.bridge.ble.BleCoordinator.getInstance(ctx).stopScanning()
                Log.i(logTag, "device.ble.scan.stop")
                val out = ByteArray(reqId.size + 1)
                System.arraycopy(reqId, 0, out, 0, reqId.size)
                out[reqId.size] = 1
                com.dsm.wallet.ui.MainActivity.getActiveInstance()?.let { act -> act.runOnUiThread {
                    act.publishCurrentSessionState("device.ble.scan.stop")
                }}
                return out
            }
            "device.ble.advertise.start" -> {
                val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                val ctx = act?.baseContext
                val ok = if (ctx != null) com.dsm.wallet.bridge.ble.BleCoordinator.getInstance(ctx).startAdvertising() else false
                Log.i(logTag, "device.ble.advertise.start: result=$ok")
                // Persist advertising desire in background service so it survives backgrounding
                if (ok) {
                    act?.setBleAdvertisingDesired(true)
                }
                val outBytes = byteArrayOf(if (ok) 1 else 0)
                val out = ByteArray(reqId.size + outBytes.size)
                System.arraycopy(reqId, 0, out, 0, reqId.size)
                System.arraycopy(outBytes, 0, out, reqId.size, outBytes.size)
                act?.let { a -> a.runOnUiThread {
                    a.publishCurrentSessionState("device.ble.advertise.start")
                }}
                return out
            }
            "device.ble.advertise.stop" -> {
                val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                val ctx = act?.baseContext
                if (ctx != null) com.dsm.wallet.bridge.ble.BleCoordinator.getInstance(ctx).stopAdvertising()
                act?.setBleAdvertisingDesired(false)
                Log.i(logTag, "device.ble.advertise.stop")
                val out = ByteArray(reqId.size + 1)
                System.arraycopy(reqId, 0, out, 0, reqId.size)
                out[reqId.size] = 1
                act?.let { a -> a.runOnUiThread {
                    a.publishCurrentSessionState("device.ble.advertise.stop")
                }}
                return out
            }
            // session.lock / session.unlock — fall through to Rust via appRouterInvoke.
            // Rust SessionManager owns lock state; Kotlin relays the response.
            "session.lock", "session.unlock" -> {
                // Forward to Rust, then publish updated session state
                val nativeFramedPayload2 = BridgeEnvelopeCodec.encodeAppRouterPayload(name, args)
                val nativeResp = Unified.appRouterInvokeFramedSafe(nativeFramedPayload2)
                // appRouterInvokeFramedSafe propagates exceptions; result is raw Envelope v3
                val result = ByteArray(reqId.size + nativeResp.size)
                System.arraycopy(reqId, 0, result, 0, reqId.size)
                System.arraycopy(nativeResp, 0, result, reqId.size, nativeResp.size)
                // Publish updated session state to WebView
                com.dsm.wallet.ui.MainActivity.getActiveInstance()?.let { act -> act.runOnUiThread {
                    act.publishCurrentSessionState(name)
                }}
                return result
            }
            "nfc.ring.read" -> {
                // NFC ring read flow (Invariant: Rust first, Kotlin operates hardware).
                //
                // 1. Forward to Rust for authorization.
                // 2. If authorized, enable reader mode on MainActivity (inline — no Activity switch).
                // 3. Return the Rust FramedEnvelopeV3 to the caller.

                val nativeFramedPayload2 = BridgeEnvelopeCodec.encodeAppRouterPayload(name, args)
                val rustResponse = Unified.appRouterInvokeFramedSafe(nativeFramedPayload2)

                val isError = Unified.isErrorEnvelope(rustResponse) != 0
                if (!isError) {
                    com.dsm.wallet.ui.MainActivity.getActiveInstance()?.startNfcReader()
                    Log.i(logTag, "nfc.ring.read: Enabled inline NFC reader on MainActivity")
                } else {
                    Log.w(logTag, "nfc.ring.read: Rust rejected read request")
                }

                val result = ByteArray(reqId.size + rustResponse.size)
                System.arraycopy(reqId, 0, result, 0, reqId.size)
                System.arraycopy(rustResponse, 0, result, reqId.size, rustResponse.size)
                return result
            }
            "nfc.ring.stopRead" -> {
                // Stop NFC reader mode on MainActivity.
                com.dsm.wallet.ui.MainActivity.getActiveInstance()?.stopNfcReader()
                Log.i(logTag, "nfc.ring.stopRead: Disabled NFC reader")

                // No Rust round-trip needed — this is a pure hardware teardown.
                val ack = BridgeEnvelopeCodec.encodeAppRouterPayload("nfc.ring.stopRead", ByteArray(0))
                val result = ByteArray(reqId.size + ack.size)
                System.arraycopy(reqId, 0, result, 0, reqId.size)
                System.arraycopy(ack, 0, result, reqId.size, ack.size)
                return result
            }
            "nfc.ring.write" -> {
                // NFC ring write flow (Invariant: Rust first, Kotlin operates hardware).
                //
                // 1. Forward the route to Rust via appRouterInvokeFramedSafe so Rust can
                //    validate state (NFC enabled, capsule pending) and return a proper
                //    FramedEnvelopeV3 response.
                // 2. If Rust responds with success, Kotlin launches NfcWriteActivity
                //    (hardware layer).  The activity uses Rust JNI calls for NDEF
                //    formatting (prepareNfcWritePayload) and capsule cleanup
                //    (clearPendingRecoveryCapsule).
                // 3. The Rust FramedEnvelopeV3 is returned to the caller (TypeScript)
                //    which decodes it to detect errors or confirm the activity launched.

                val nativeFramedPayload2 = BridgeEnvelopeCodec.encodeAppRouterPayload(name, args)
                val rustResponse = Unified.appRouterInvokeFramedSafe(nativeFramedPayload2)

                // Check if Rust authorised the NFC write (isErrorEnvelope returns non-zero on error).
                val isError = Unified.isErrorEnvelope(rustResponse) != 0
                if (!isError) {
                    // Rust authorised the write — launch the NFC write activity (UI/hardware).
                    val ctx = com.dsm.wallet.ui.MainActivity.getActiveInstance()
                    val intent = android.content.Intent(ctx, com.dsm.wallet.recovery.NfcWriteActivity::class.java)
                    ctx?.startActivity(intent)
                    Log.i(logTag, "nfc.ring.write: Launched NfcWriteActivity per Rust authorization")
                } else {
                    Log.w(logTag, "nfc.ring.write: Rust rejected write request")
                }

                // Return the Rust FramedEnvelopeV3 to the caller (TypeScript will decode it).
                val result = ByteArray(reqId.size + rustResponse.size)
                System.arraycopy(reqId, 0, result, 0, reqId.size)
                System.arraycopy(rustResponse, 0, result, reqId.size, rustResponse.size)
                return result
            }
        }

        return when (name) {
            "bilateralOfflineSend" -> {
                if (args.size < 4) throw IllegalArgumentException("bilateralOfflineSend: args too short")
                val alen = ((args[0].toInt() and 0xFF) shl 24) or
                    ((args[1].toInt() and 0xFF) shl 16) or
                    ((args[2].toInt() and 0xFF) shl 8) or
                    (args[3].toInt() and 0xFF)
                if (alen < 0 || 4 + alen > args.size) throw IllegalArgumentException("bilateralOfflineSend: bad ble address")
                val addr = args.copyOfRange(4, 4 + alen).toString(Charsets.UTF_8)
                val env = args.copyOfRange(4 + alen, args.size)
                val nativeResp = Unified.bilateralOfflineSendSafe(addr, env)
                // bilateralOfflineSendSafe is a clean passthrough; Rust prepends 0x03 framing.
                // Prefix reqId for JS correlation (WebView strips first 8 bytes)
                val out = ByteArray(reqId.size + nativeResp.size)
                System.arraycopy(reqId, 0, out, 0, reqId.size)
                System.arraycopy(nativeResp, 0, out, reqId.size, nativeResp.size)
                out
            }
            else -> {
                // Best-effort: log inner appRouterInvoke method (frame-only; no protobuf parsing)
                try {
                    if (args.size >= 4) {
                        val innerLen = ((args[0].toInt() and 0xFF) shl 24) or
                            ((args[1].toInt() and 0xFF) shl 16) or
                            ((args[2].toInt() and 0xFF) shl 8) or
                            (args[3].toInt() and 0xFF)
                        if (innerLen > 0 && 4 + innerLen <= args.size) {
                            val inner = args.copyOfRange(4, 4 + innerLen).toString(Charsets.UTF_8)
                            Log.d(logTag, "appRouterInvoke: inner_method=$inner")
                        }
                    }
                } catch (_: Throwable) {
                    // ignore logging parse failures
                }
                // appRouterInvokeFramed expects AppRouterPayload bytes with no reqId prefix.
                val nativeResp = Unified.appRouterInvokeFramedSafe(nativeFramedPayload)
                // appRouterInvokeFramedSafe propagates exceptions; result is raw Envelope v3
                // Prefix reqId for JS correlation (WebView strips first 8 bytes)
                val out = ByteArray(reqId.size + nativeResp.size)
                System.arraycopy(reqId, 0, out, 0, reqId.size)
                System.arraycopy(nativeResp, 0, out, reqId.size, nativeResp.size)
                out
            }
        }
    }

    fun appRouterQuery(payload: ByteArray, nextReqId: () -> ByteArray): ByteArray {
        val parsed = BridgeEnvelopeCodec.decodeAppRouterPayload(payload)
            ?: throw IllegalArgumentException("appRouterQuery: invalid AppRouterPayload")
        val path = parsed.methodName
        val params = parsed.args

        val reqId = nextReqId()
        // Native expects [8-byte reqId][AppRouterPayload bytes].
        val pathFramed = BridgeEnvelopeCodec.encodeAppRouterPayload(path, params)
        val framed = ByteArray(reqId.size + pathFramed.size)
        System.arraycopy(reqId, 0, framed, 0, reqId.size)
        System.arraycopy(pathFramed, 0, framed, reqId.size, pathFramed.size)

        val nativeResp = Unified.appRouterQueryFramedSafe(framed)
        // appRouterQueryFramedSafe throws on null; returns [reqId (8)][Envelope v3 bytes] directly.
        // Rust already prepends reqId; JS callBin strips the first 8 bytes, leaving [0x03][Envelope].
        return nativeResp
    }

    fun getTransportHeadersV3Bin(
        isSdkReady: () -> Boolean,
        bootstrap: () -> Unit
    ): ByteArray {
        if (!isSdkReady()) {
            try {
                bootstrap()
            } catch (_: Throwable) {
                // fall through
            }
        }
        val st = try { Unified.getTransportHeadersV3Status().toInt() } catch (_: Throwable) { -1 }
        return if (st >= 1) {
            Unified.getTransportHeadersV3()
        } else {
            ByteArray(0)
        }
    }
}
