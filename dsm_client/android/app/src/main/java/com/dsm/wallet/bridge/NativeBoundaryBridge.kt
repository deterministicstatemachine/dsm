// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import com.google.protobuf.ByteString
import dsm.types.proto.IngressRequest
import dsm.types.proto.RouterInvokeOp
import dsm.types.proto.RouterQueryOp

internal object NativeBoundaryBridge {
    fun startup(requestBytes: ByteArray): ByteArray {
        return Unified.dispatchStartup(requestBytes)
    }

    fun ingress(requestBytes: ByteArray): ByteArray {
        return Unified.dispatchIngress(requestBytes)
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
}
