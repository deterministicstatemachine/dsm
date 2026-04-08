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
            // session.lock / session.unlock — fall through to Rust via appRouterInvoke.
            // Rust SessionManager owns lock state; Kotlin relays the response.
            "session.lock", "session.unlock" -> {
                // Forward to Rust, then publish updated session state
                val nativeResp = Unified.appRouterInvokeFramedSafe(nativeFramedPayload)
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
        }

        Log.d(logTag, "appRouterInvoke: method=$name")

        // appRouterInvokeFramed expects AppRouterPayload bytes with no reqId prefix.
        val nativeResp = Unified.appRouterInvokeFramedSafe(nativeFramedPayload)
        // appRouterInvokeFramedSafe propagates exceptions; result is raw Envelope v3
        // Prefix reqId for JS correlation (WebView strips first 8 bytes)
        val out = ByteArray(reqId.size + nativeResp.size)
        System.arraycopy(reqId, 0, out, 0, reqId.size)
        System.arraycopy(nativeResp, 0, out, reqId.size, nativeResp.size)
        return out
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
