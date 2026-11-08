// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import android.util.Log
import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import com.dsm.wallet.ui.MainActivity
import dsm.types.proto.NativeHostAck
import dsm.types.proto.NativeHostRequest
import dsm.types.proto.NativeHostRequestKind
import dsm.types.proto.NativeHostResponse

/**
 * The private host boundary: the host request the frontend sends (QR scan start). Every
 * other kind is answered as unsupported.
 */
internal object NativeHostBridge {
    private const val TAG = "NativeHostBridge"

    fun hostRequest(requestBytes: ByteArray): ByteArray {
        val request = try {
            NativeHostRequest.parseFrom(requestBytes)
        } catch (e: InvalidProtocolBufferException) {
            return errorResponse(400, "nativeHostRequest: invalid protobuf payload: ${e.message}").toByteArray()
        }

        val response = try {
            handleRequest(request)
        } catch (t: Throwable) {
            Log.e(TAG, "hostRequest failed for ${request.kind}", t)
            errorResponse(500, t.message ?: "native host request failed")
        }

        return response.toByteArray()
    }

    private fun handleRequest(request: NativeHostRequest): NativeHostResponse {
        return when (request.kind) {
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_QR_START_SCAN -> {
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "QR scanner unavailable: no active activity")
                act.runOnUiThread {
                    act.launchNativeQrScanner { qrText: String? ->
                        act.dispatchQrScanResult(qrText)
                    }
                    act.publishCurrentSessionState("host_control.qr.start_scan")
                }
                okAck()
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_CAPABILITIES_GET,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_QR_STOP_SCAN,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_PERMISSIONS_REQUEST,
            NativeHostRequestKind.UNRECOGNIZED,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_UNSPECIFIED -> {
                errorResponse(501, "unsupported native host request kind: ${request.kind}")
            }
        }
    }

    private fun okAck(): NativeHostResponse {
        return okBytes(
            NativeHostAck.newBuilder()
                .setSuccess(true)
                .build()
                .toByteArray()
        )
    }

    private fun okBytes(bytes: ByteArray): NativeHostResponse {
        return NativeHostResponse.newBuilder()
            .setOkBytes(ByteString.copyFrom(bytes))
            .build()
    }

    private fun errorResponse(code: Int, message: String): NativeHostResponse {
        return NativeHostResponse.newBuilder()
            .setError(
                dsm.types.proto.Error.newBuilder()
                    .setCode(code)
                    .setMessage(message)
                    .setIsRecoverable(true)
                    .build()
            )
            .build()
    }
}
