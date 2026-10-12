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
import dsm.types.proto.NfcTagReadResult
import dsm.types.proto.NfcTagWritePayload
import dsm.types.proto.NfcTagWriteResult

/**
 * The private host boundary: the four host requests the frontend sends (QR scan start, NFC
 * reader start and stop, NFC tag write). Every other kind is answered as unsupported.
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

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_NFC_READER_START -> {
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "NFC unavailable: no active activity")
                val started = act.startNfcReader()
                if (!started) {
                    return errorResponse(503, "NFC unavailable: NFC not enabled on device")
                }
                okBytes(
                    NfcTagReadResult.newBuilder()
                        .setReaderStarted(true)
                        .build()
                        .toByteArray()
                )
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_NFC_READER_STOP -> {
                MainActivity.getActiveInstance()?.stopNfcReader()
                okAck()
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_NFC_TAG_WRITE_PAYLOAD -> {
                Log.i(TAG, "NFC_DIAG: writePayload request received")
                try {
                    NfcTagWritePayload.parseFrom(request.payload)
                } catch (e: InvalidProtocolBufferException) {
                    Log.e(TAG, "NFC_DIAG: writePayload invalid proto: ${e.message}")
                    return errorResponse(400, "nfc.tag.write_payload: invalid payload: ${e.message}")
                }
                val act = MainActivity.getActiveInstance()
                if (act == null) {
                    Log.e(TAG, "NFC_DIAG: writePayload no active activity")
                    return errorResponse(503, "nfc.tag.write_payload: no active activity")
                }
                // Write inline — no separate Activity. The user stays in the WebView.
                Log.i(TAG, "NFC_DIAG: calling startNfcWriter()")
                val launched = act.startNfcWriter()
                Log.i(TAG, "NFC_DIAG: startNfcWriter returned=$launched")
                if (!launched) {
                    return errorResponse(503, "nfc.tag.write_payload: NFC not enabled on device")
                }
                okBytes(
                    NfcTagWriteResult.newBuilder()
                        .setLaunched(true)
                        .build()
                        .toByteArray()
                )
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_CAPABILITIES_GET,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_QR_STOP_SCAN,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_PERMISSIONS_REQUEST,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_NFC_TAG_READ_PAYLOAD,
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
