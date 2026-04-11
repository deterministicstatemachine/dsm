package com.dsm.wallet.bridge

import android.util.Log
import com.google.protobuf.InvalidProtocolBufferException
import com.dsm.wallet.ui.MainActivity
import dsm.types.proto.IngressRequest

internal object NativeBoundaryBridge {
    private const val TAG = "NativeBoundaryBridge"

    fun startup(requestBytes: ByteArray): ByteArray {
        return Unified.dispatchStartup(requestBytes)
    }

    fun ingress(requestBytes: ByteArray): ByteArray {
        val response = Unified.dispatchIngress(requestBytes)
        runBestEffortPostIngressHooks(requestBytes)
        return response
    }

    private fun runBestEffortPostIngressHooks(requestBytes: ByteArray) {
        val request = try {
            IngressRequest.parseFrom(requestBytes)
        } catch (e: InvalidProtocolBufferException) {
            Log.w(TAG, "ingress: unable to parse request for post-hooks", e)
            return
        }

        when (request.operationCase) {
            IngressRequest.OperationCase.ROUTER_INVOKE -> {
                try {
                    UnifiedNativeApi.maybeRefreshNfcCapsule()
                } catch (_: Throwable) {
                    // no-op
                }
                val method = request.routerInvoke.method
                if (method == "session.lock" || method == "session.unlock") {
                    MainActivity.getActiveInstance()?.runOnUiThread {
                        MainActivity.getActiveInstance()?.publishCurrentSessionState(method)
                    }
                }
            }
            IngressRequest.OperationCase.ENVELOPE -> {
                try {
                    UnifiedNativeApi.maybeRefreshNfcCapsule()
                } catch (_: Throwable) {
                    // no-op
                }
            }
            IngressRequest.OperationCase.MARK_GENESIS_SECURING -> {
                // Rust already flipped securing_in_progress inside dispatchIngress above.
                // Republish session.state so any subscriber relying on the old snapshot
                // (useNativeSessionBridge in the WebView) observes the new phase BEFORE
                // the caller fires the next lifecycle envelope. UI-thread FIFO preserves
                // ordering vs. the subsequent BleEventRelay dispatch on the caller side.
                val phaseName = request.markGenesisSecuring.phase.name
                MainActivity.getActiveInstance()?.runOnUiThread {
                    MainActivity.getActiveInstance()
                        ?.publishCurrentSessionState("genesisSecuring:$phaseName")
                }
            }
            else -> {
                // no-op
            }
        }
    }
}
