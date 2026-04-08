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
            else -> {
                // no-op
            }
        }
    }
}
