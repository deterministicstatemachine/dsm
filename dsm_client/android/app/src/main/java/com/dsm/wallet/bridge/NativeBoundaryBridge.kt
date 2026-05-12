package com.dsm.wallet.bridge

import android.util.Log
import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import com.dsm.wallet.ui.MainActivity
import dsm.types.proto.IngressRequest
import dsm.types.proto.RouterInvokeOp
import dsm.types.proto.RouterQueryOp

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

    fun routerInvoke(method: String, args: ByteArray = ByteArray(0)): ByteArray {
        val request = IngressRequest.newBuilder()
            .setRouterInvoke(
                RouterInvokeOp.newBuilder()
                    .setMethod(method)
                    .setArgs(ByteString.copyFrom(args))
                    .build()
            )
            .build()
        return ingress(request.toByteArray())
    }

    fun routerQuery(method: String, args: ByteArray = ByteArray(0)): ByteArray {
        val request = IngressRequest.newBuilder()
            .setRouterQuery(
                RouterQueryOp.newBuilder()
                    .setMethod(method)
                    .setArgs(ByteString.copyFrom(args))
                    .build()
            )
            .build()
        return ingress(request.toByteArray())
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
