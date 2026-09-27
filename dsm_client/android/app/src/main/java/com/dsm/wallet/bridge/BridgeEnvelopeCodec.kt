// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import dsm.types.proto.AppRouterPayload
import dsm.types.proto.BilateralPayload
import dsm.types.proto.BridgeRpcRequest
import dsm.types.proto.BridgeRpcResponse
import dsm.types.proto.Envelope
import dsm.types.proto.ErrorResponse
import dsm.types.proto.PreferencePayload
import dsm.types.proto.SuccessResponse

/**
 * The bridge's wire shapes, decoded and encoded by the generated protobuf classes
 * of `proto/dsm_app.proto` (`dsm.types.proto`). Kotlin implements no wire decoder
 * of its own: every field number and wire type is the generated parser's.
 */
internal object BridgeEnvelopeCodec {

    data class BridgeRequest(val method: String, val payload: ByteArray)

    data class DsmErrorInfo(val sourceTag: Int, val message: String)

    data class BridgeRpcError(val errorCode: Int, val message: String, val debugB32: String?)

    data class AppRouterRequest(val methodName: String, val args: ByteArray)

    data class PreferenceRequest(val key: String, val value: String?)

    data class BilateralRequest(val commitment: ByteArray, val reason: String?)

    private const val METHOD_MAX_BYTES = 128

    /** Rust's source tag on a deterministic-safety refusal. */
    private const val SOURCE_TAG_DETERMINISTIC_SAFETY = 11

    /**
     * Decodes a `BridgeRpcRequest`. The method must be present, at most 128 bytes
     * and an identifier (letters, digits, `_`, `.`, `-`). The payload is the oneof
     * member's content: the inner bytes of the bytes, string and BLE payloads, and
     * the message's own bytes for the typed payloads the dispatcher decodes itself.
     */
    fun parseBridgeRequest(requestBytes: ByteArray): BridgeRequest {
        val req = try {
            BridgeRpcRequest.parseFrom(requestBytes)
        } catch (e: InvalidProtocolBufferException) {
            throw IllegalArgumentException("BridgeRpcRequest does not decode: ${e.message}", e)
        }
        val method = req.method
        if (method.isEmpty()) {
            throw IllegalArgumentException("BridgeRpcRequest.method missing")
        }
        val methodBytes = method.toByteArray(Charsets.UTF_8).size
        if (methodBytes > METHOD_MAX_BYTES) {
            throw IllegalArgumentException("BridgeRpcRequest.method too long: $methodBytes bytes (max $METHOD_MAX_BYTES)")
        }
        if (!method.all { it.isLetterOrDigit() || it in "_.-" }) {
            throw IllegalArgumentException("BridgeRpcRequest.method invalid characters: '$method'")
        }
        val payload = when (req.payloadCase) {
            BridgeRpcRequest.PayloadCase.EMPTY,
            BridgeRpcRequest.PayloadCase.PAYLOAD_NOT_SET -> ByteArray(0)
            BridgeRpcRequest.PayloadCase.BYTES -> req.bytes.data.toByteArray()
            BridgeRpcRequest.PayloadCase.STRING -> req.string.value.toByteArray(Charsets.UTF_8)
            BridgeRpcRequest.PayloadCase.PREFERENCE -> req.preference.toByteArray()
            BridgeRpcRequest.PayloadCase.APP_ROUTER -> req.appRouter.toByteArray()
            BridgeRpcRequest.PayloadCase.BLE_CONTACT -> req.bleContact.pairingData.toByteArray()
            BridgeRpcRequest.PayloadCase.BLE_ADDRESS -> req.bleAddress.deviceId.toByteArray()
            BridgeRpcRequest.PayloadCase.BILATERAL -> req.bilateral.toByteArray()
        }
        return BridgeRequest(method, payload)
    }

    /** The message of a deterministic-safety refusal carried by an `Envelope`, else null. */
    fun extractDeterministicSafetyMessageFromEnvelope(envelopeBytes: ByteArray): String? {
        val err = extractErrorInfoFromEnvelope(envelopeBytes) ?: return null
        return if (err.sourceTag == SOURCE_TAG_DETERMINISTIC_SAFETY) err.message else null
    }

    /** (isSuccess, payload): the success data, or the `ErrorResponse` bytes. */
    fun parseEnvelopeResponse(responseBytes: ByteArray): Pair<Boolean, ByteArray> {
        val resp = try {
            BridgeRpcResponse.parseFrom(responseBytes)
        } catch (e: InvalidProtocolBufferException) {
            throw IllegalArgumentException("BridgeRpcResponse does not decode: ${e.message}", e)
        }
        return when (resp.resultCase) {
            BridgeRpcResponse.ResultCase.SUCCESS -> Pair(true, resp.success.data.toByteArray())
            BridgeRpcResponse.ResultCase.ERROR -> Pair(false, resp.error.toByteArray())
            BridgeRpcResponse.ResultCase.RESULT_NOT_SET ->
                throw IllegalArgumentException("BridgeRpcResponse missing result")
        }
    }

    fun decodeBridgeRpcError(errorBytes: ByteArray): BridgeRpcError? {
        val err = try {
            ErrorResponse.parseFrom(errorBytes)
        } catch (_: InvalidProtocolBufferException) {
            return null
        }
        if (err.errorCode == 0 && err.message.isEmpty() && err.debugB32.isEmpty()) return null
        return BridgeRpcError(err.errorCode, err.message, err.debugB32.ifEmpty { null })
    }

    fun encodeAppRouterPayload(methodName: String, args: ByteArray): ByteArray =
        AppRouterPayload.newBuilder()
            .setMethodName(methodName)
            .setArgs(ByteString.copyFrom(args))
            .build()
            .toByteArray()

    fun decodeAppRouterPayload(payloadBytes: ByteArray): AppRouterRequest? {
        val p = try {
            AppRouterPayload.parseFrom(payloadBytes)
        } catch (_: InvalidProtocolBufferException) {
            return null
        }
        if (p.methodName.isBlank()) return null
        return AppRouterRequest(p.methodName, p.args.toByteArray())
    }

    fun decodePreferencePayload(payloadBytes: ByteArray): PreferenceRequest? {
        val p = try {
            PreferencePayload.parseFrom(payloadBytes)
        } catch (_: InvalidProtocolBufferException) {
            return null
        }
        if (p.key.isBlank()) return null
        return PreferenceRequest(p.key, if (p.hasValue()) p.value else null)
    }

    fun decodeBilateralPayload(payloadBytes: ByteArray): BilateralRequest? {
        val p = try {
            BilateralPayload.parseFrom(payloadBytes)
        } catch (_: InvalidProtocolBufferException) {
            return null
        }
        val commitment = p.commitment.toByteArray()
        if (commitment.size != 32) return null
        return BilateralRequest(commitment, if (p.hasReason()) p.reason else null)
    }

    fun createSuccessResponse(data: ByteArray): ByteArray =
        BridgeRpcResponse.newBuilder()
            .setSuccess(SuccessResponse.newBuilder().setData(ByteString.copyFrom(data)))
            .build()
            .toByteArray()

    /** The debug string encodes the error without itself; an encoder that fails leaves it empty. */
    fun createErrorResponse(
        errorCode: Int,
        message: String,
        debugEncoder: (ByteArray) -> String
    ): ByteArray {
        val preimage = ErrorResponse.newBuilder()
            .setErrorCode(errorCode)
            .setMessage(message)
            .build()
            .toByteArray()
        val debug = try { debugEncoder(preimage) } catch (_: Throwable) { "" }
        val error = ErrorResponse.newBuilder()
            .setErrorCode(errorCode)
            .setMessage(message)
            .setDebugB32(debug)
            .build()
        return BridgeRpcResponse.newBuilder().setError(error).build().toByteArray()
    }

    private fun extractErrorInfoFromEnvelope(bytes: ByteArray): DsmErrorInfo? {
        val env = try {
            Envelope.parseFrom(bytes)
        } catch (_: InvalidProtocolBufferException) {
            return null
        }
        val error = when {
            env.hasError() -> env.error
            env.hasUniversalRx() -> env.universalRx.resultsList.firstOrNull { it.hasError() }?.error
            else -> null
        } ?: return null
        if (error.sourceTag == 0 && error.message.isEmpty()) return null
        return DsmErrorInfo(error.sourceTag, error.message)
    }
}
