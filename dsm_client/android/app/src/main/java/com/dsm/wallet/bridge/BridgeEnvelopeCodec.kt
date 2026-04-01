package com.dsm.wallet.bridge

import java.io.ByteArrayOutputStream

internal object BridgeEnvelopeCodec {

    data class BridgeRequest(val method: String, val payload: ByteArray)

    data class DsmErrorInfo(val sourceTag: Int, val message: String)

    data class BridgeRpcError(val errorCode: Int, val message: String, val debugB32: String?)

    data class AppRouterRequest(val methodName: String, val args: ByteArray)

    data class PreferenceRequest(val key: String, val value: String?)

    data class BilateralRequest(val commitment: ByteArray, val reason: String?)

    fun parseBridgeRequest(requestBytes: ByteArray): BridgeRequest {
        var offset = 0
        var method = ""
        var payload = ByteArray(0)
        var payloadFound = false

        while (offset < requestBytes.size) {
            val (key, keyOff) = readVarint(requestBytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()

            when (fieldNumber) {
                1 -> {
                    if (wireType != 2) throw IllegalArgumentException("BridgeRpcRequest.method wrong wire type")
                    val (bytes, off) = readLengthDelimited(requestBytes, offset)
                    if (bytes.size > 128) {
                        throw IllegalArgumentException("BridgeRpcRequest.method too long: ${bytes.size} bytes (max 128)")
                    }
                    offset = off
                    method = bytes.toString(Charsets.UTF_8)
                    // Additional validation: method should be a valid identifier
                    if (method.isEmpty() || !method.all { it.isLetterOrDigit() || it in "_.-" }) {
                        throw IllegalArgumentException("BridgeRpcRequest.method invalid characters: '$method'")
                    }
                }
                2, 3, 4, 5, 6, 7, 8, 9, 10, 11 -> {
                    if (wireType != 2) throw IllegalArgumentException("BridgeRpcRequest.payload wrong wire type")
                    if (payloadFound) throw IllegalArgumentException("BridgeRpcRequest has multiple payloads")
                    payloadFound = true
                    val (bytes, off) = readLengthDelimited(requestBytes, offset)
                    offset = off
                    payload = decodePayload(fieldNumber, bytes)
                }
                else -> {
                    offset = skipField(wireType, requestBytes, offset)
                }
            }
        }

        return BridgeRequest(method, payload)
    }

    fun extractDeterministicSafetyMessageFromEnvelope(envelopeBytes: ByteArray): String? {
        val err = extractErrorInfoFromEnvelope(envelopeBytes) ?: return null
        return if (err.sourceTag == 11) err.message else null
    }

    fun parseEnvelopeResponse(responseBytes: ByteArray): Pair<Boolean, ByteArray> {
        return parseBridgeRpcResponse(responseBytes)
    }

    fun decodeBridgeRpcError(errorBytes: ByteArray): BridgeRpcError? {
        var offset = 0
        var errorCode = 0
        var message = ""
        var debugB32: String? = null

        while (offset < errorBytes.size) {
            val (key, keyOff) = readVarint(errorBytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()

            when (fieldNumber) {
                1 -> {
                    if (wireType != 0) return null
                    val (value, off) = readVarint(errorBytes, offset)
                    offset = off
                    errorCode = value.toInt()
                }
                2 -> {
                    if (wireType != 2) return null
                    val (bytes, off) = readLengthDelimited(errorBytes, offset)
                    offset = off
                    message = bytes.toString(Charsets.UTF_8)
                }
                3 -> {
                    if (wireType != 2) return null
                    val (bytes, off) = readLengthDelimited(errorBytes, offset)
                    offset = off
                    debugB32 = bytes.toString(Charsets.UTF_8)
                }
                else -> {
                    offset = skipField(wireType, errorBytes, offset)
                }
            }
        }

        return if (errorCode != 0 || message.isNotEmpty() || !debugB32.isNullOrEmpty()) {
            BridgeRpcError(errorCode, message, debugB32)
        } else {
            null
        }
    }

    fun encodeAppRouterPayload(methodName: String, args: ByteArray): ByteArray {
        val methodBytes = methodName.toByteArray(Charsets.UTF_8)

        val out = ByteArrayOutputStream()
        // field 1 (method_name), wire type 2
        out.write(0x0A)
        out.write(encodeVarint32(methodBytes.size))
        out.write(methodBytes)

        // field 2 (args), wire type 2
        out.write(0x12)
        out.write(encodeVarint32(args.size))
        out.write(args)
        return out.toByteArray()
    }

    fun decodeAppRouterPayload(payloadBytes: ByteArray): AppRouterRequest? {
        var offset = 0
        var methodName = ""
        var args = ByteArray(0)
        while (offset < payloadBytes.size) {
            val (key, keyOff) = readVarint(payloadBytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()
            when (fieldNumber) {
                1 -> {
                    if (wireType != 2) return null
                    val (bytes, off) = readLengthDelimited(payloadBytes, offset)
                    offset = off
                    methodName = bytes.toString(Charsets.UTF_8)
                }
                2 -> {
                    if (wireType != 2) return null
                    val (bytes, off) = readLengthDelimited(payloadBytes, offset)
                    offset = off
                    args = bytes
                }
                else -> {
                    offset = skipField(wireType, payloadBytes, offset)
                }
            }
        }
        if (methodName.isBlank()) return null
        return AppRouterRequest(methodName, args)
    }

    fun decodePreferencePayload(payloadBytes: ByteArray): PreferenceRequest? {
        var offset = 0
        var key = ""
        var value: String? = null
        while (offset < payloadBytes.size) {
            val (tag, keyOff) = readVarint(payloadBytes, offset)
            offset = keyOff
            val fieldNumber = (tag ushr 3).toInt()
            val wireType = (tag and 0x07).toInt()
            when (fieldNumber) {
                1 -> {
                    if (wireType != 2) return null
                    val (bytes, off) = readLengthDelimited(payloadBytes, offset)
                    offset = off
                    key = bytes.toString(Charsets.UTF_8)
                }
                2 -> {
                    if (wireType != 2) return null
                    val (bytes, off) = readLengthDelimited(payloadBytes, offset)
                    offset = off
                    value = bytes.toString(Charsets.UTF_8)
                }
                else -> {
                    offset = skipField(wireType, payloadBytes, offset)
                }
            }
        }
        if (key.isBlank()) return null
        return PreferenceRequest(key, value)
    }

    fun decodeBilateralPayload(payloadBytes: ByteArray): BilateralRequest? {
        var offset = 0
        var commitment = ByteArray(0)
        var reason: String? = null
        while (offset < payloadBytes.size) {
            val (tag, keyOff) = readVarint(payloadBytes, offset)
            offset = keyOff
            val fieldNumber = (tag ushr 3).toInt()
            val wireType = (tag and 0x07).toInt()
            when (fieldNumber) {
                1 -> {
                    if (wireType != 2) return null
                    val (bytes, off) = readLengthDelimited(payloadBytes, offset)
                    offset = off
                    commitment = bytes
                }
                2 -> {
                    if (wireType != 2) return null
                    val (bytes, off) = readLengthDelimited(payloadBytes, offset)
                    offset = off
                    reason = bytes.toString(Charsets.UTF_8)
                }
                else -> {
                    offset = skipField(wireType, payloadBytes, offset)
                }
            }
        }
        if (commitment.size != 32) return null
        return BilateralRequest(commitment, reason)
    }

    fun createSuccessResponse(data: ByteArray): ByteArray {
        // SuccessResponse { bytes data = 1 }
        val successStream = ByteArrayOutputStream()
        successStream.write(0x0A) // field 1, wire type 2
        val dataLenVarint = encodeVarint32(data.size)
        successStream.write(dataLenVarint)
        successStream.write(data)
        val successBytes = successStream.toByteArray()

        // BridgeRpcResponse: field 1 = success
        val bridgeStream = ByteArrayOutputStream()
        bridgeStream.write(0x0A)
        bridgeStream.write(encodeVarint32(successBytes.size))
        bridgeStream.write(successBytes)
        return bridgeStream.toByteArray()
    }

    fun createErrorResponse(
        errorCode: Int,
        message: String,
        debugEncoder: (ByteArray) -> String
    ): ByteArray {
        val msgBytes = message.toByteArray(Charsets.UTF_8)

        val preimageStream = ByteArrayOutputStream()
        preimageStream.write(0x08) // field 1, wire type 0
        preimageStream.write(encodeVarint32(errorCode))
        preimageStream.write(0x12) // field 2, wire type 2
        preimageStream.write(encodeVarint32(msgBytes.size))
        preimageStream.write(msgBytes)
        preimageStream.write(0x1A) // field 3, wire type 2 (empty debug)
        preimageStream.write(encodeVarint32(0))

        val errorPreimageBytes = preimageStream.toByteArray()
        val debugStr = try { debugEncoder(errorPreimageBytes) } catch (_: Throwable) { "" }
        val debugBytes = debugStr.toByteArray(Charsets.UTF_8)

        val errStream = ByteArrayOutputStream()
        errStream.write(0x08) // field 1, wire type 0
        errStream.write(encodeVarint32(errorCode))
        errStream.write(0x12) // field 2, wire type 2
        errStream.write(encodeVarint32(msgBytes.size))
        errStream.write(msgBytes)
        errStream.write(0x1A) // field 3, wire type 2
        errStream.write(encodeVarint32(debugBytes.size))
        errStream.write(debugBytes)

        val errorBytes = errStream.toByteArray()

        // BridgeRpcResponse: field 2 = error
        val bridgeStream = ByteArrayOutputStream()
        bridgeStream.write(0x12)
        bridgeStream.write(encodeVarint32(errorBytes.size))
        bridgeStream.write(errorBytes)
        return bridgeStream.toByteArray()
    }

    private fun parseBridgeRpcResponse(bytes: ByteArray): Pair<Boolean, ByteArray> {
        var offset = 0
        var isSuccess: Boolean? = null
        var payload = ByteArray(0)

        while (offset < bytes.size) {
            val (key, keyOff) = readVarint(bytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()

            when (fieldNumber) {
                1 -> {
                    if (wireType != 2) throw IllegalArgumentException("BridgeRpcResponse.success wrong wire type")
                    if (isSuccess != null) throw IllegalArgumentException("BridgeRpcResponse has multiple results")
                    val (msgBytes, off) = readLengthDelimited(bytes, offset)
                    offset = off
                    payload = parseSuccessPayload(msgBytes)
                    isSuccess = true
                }
                2 -> {
                    if (wireType != 2) throw IllegalArgumentException("BridgeRpcResponse.error wrong wire type")
                    if (isSuccess != null) throw IllegalArgumentException("BridgeRpcResponse has multiple results")
                    val (msgBytes, off) = readLengthDelimited(bytes, offset)
                    offset = off
                    payload = msgBytes
                    isSuccess = false
                }
                else -> {
                    offset = skipField(wireType, bytes, offset)
                }
            }
        }

        if (isSuccess == null) throw IllegalArgumentException("BridgeRpcResponse missing result")
        return Pair(isSuccess == true, payload)
    }

    private fun extractErrorInfoFromEnvelope(bytes: ByteArray): DsmErrorInfo? {
        var offset = 0
        while (offset < bytes.size) {
            val (key, keyOff) = readVarint(bytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()

            when (fieldNumber) {
                99 -> {
                    if (wireType != 2) return null
                    val (errBytes, _) = readLengthDelimited(bytes, offset)
                    return parseErrorInfo(errBytes)
                }
                11 -> {
                    if (wireType != 2) {
                        offset = skipField(wireType, bytes, offset)
                    } else {
                        val (rxBytes, off) = readLengthDelimited(bytes, offset)
                        offset = off
                        val err = parseUniversalRxForError(rxBytes)
                        if (err != null) return err
                    }
                }
                else -> {
                    offset = skipField(wireType, bytes, offset)
                }
            }
        }
        return null
    }

    private fun parseUniversalRxForError(bytes: ByteArray): DsmErrorInfo? {
        var offset = 0
        while (offset < bytes.size) {
            val (key, keyOff) = readVarint(bytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()

            if (fieldNumber == 1 && wireType == 2) {
                val (opBytes, off) = readLengthDelimited(bytes, offset)
                offset = off
                val err = parseOpResultForError(opBytes)
                if (err != null) return err
            } else {
                offset = skipField(wireType, bytes, offset)
            }
        }
        return null
    }

    private fun parseOpResultForError(bytes: ByteArray): DsmErrorInfo? {
        var offset = 0
        while (offset < bytes.size) {
            val (key, keyOff) = readVarint(bytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()
            if (fieldNumber == 5 && wireType == 2) {
                val (errBytes, _) = readLengthDelimited(bytes, offset)
                return parseErrorInfo(errBytes)
            }
            offset = skipField(wireType, bytes, offset)
        }
        return null
    }

    private fun parseErrorInfo(bytes: ByteArray): DsmErrorInfo? {
        var offset = 0
        var message = ""
        var sourceTag = 0
        while (offset < bytes.size) {
            val (key, keyOff) = readVarint(bytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()
            when (fieldNumber) {
                2 -> {
                    if (wireType != 2) return null
                    val (msgBytes, off) = readLengthDelimited(bytes, offset)
                    offset = off
                    message = msgBytes.toString(Charsets.UTF_8)
                }
                4 -> {
                    if (wireType != 0) return null
                    val (tag, off) = readVarint(bytes, offset)
                    offset = off
                    sourceTag = tag.toInt()
                }
                else -> {
                    offset = skipField(wireType, bytes, offset)
                }
            }
        }
        return if (sourceTag != 0 || message.isNotEmpty()) DsmErrorInfo(sourceTag, message) else null
    }

    private fun parseSuccessPayload(bytes: ByteArray): ByteArray {
        var offset = 0
        var data = ByteArray(0)
        while (offset < bytes.size) {
            val (key, keyOff) = readVarint(bytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()
            if (fieldNumber == 1) {
                if (wireType != 2) throw IllegalArgumentException("SuccessResponse.data wrong wire type")
                val (msgBytes, off) = readLengthDelimited(bytes, offset)
                offset = off
                data = msgBytes
            } else {
                offset = skipField(wireType, bytes, offset)
            }
        }
        return data
    }

    private fun decodePayload(fieldNumber: Int, bytes: ByteArray): ByteArray {
        return when (fieldNumber) {
            2 -> ByteArray(0)
            3 -> parseBytesPayload(bytes)
            4 -> parseStringPayload(bytes)
            5 -> parsePreferencePayload(bytes)
            6 -> parseAppRouterPayload(bytes)
            7 -> parseCreateGenesisPayload(bytes)
            8 -> parseSingleBytesPayload(bytes)
            9 -> parseSingleBytesPayload(bytes)
            10 -> parseBleIdentityPayload(bytes)
            11 -> parseBilateralPayload(bytes)
            else -> ByteArray(0)
        }
    }

    private fun parseBytesPayload(bytes: ByteArray): ByteArray {
        var offset = 0
        var out = ByteArray(0)
        while (offset < bytes.size) {
            val (key, keyOff) = readVarint(bytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()
            if (fieldNumber == 1) {
                if (wireType != 2) throw IllegalArgumentException("BytesPayload.data wrong wire type")
                val (msgBytes, off) = readLengthDelimited(bytes, offset)
                offset = off
                out = msgBytes
            } else {
                offset = skipField(wireType, bytes, offset)
            }
        }
        return out
    }

    private fun parseStringPayload(bytes: ByteArray): ByteArray {
        var offset = 0
        var out = ByteArray(0)
        while (offset < bytes.size) {
            val (key, keyOff) = readVarint(bytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()
            if (fieldNumber == 1) {
                if (wireType != 2) throw IllegalArgumentException("StringPayload.value wrong wire type")
                val (msgBytes, off) = readLengthDelimited(bytes, offset)
                offset = off
                out = msgBytes
            } else {
                offset = skipField(wireType, bytes, offset)
            }
        }
        return out
    }

    private fun parsePreferencePayload(bytes: ByteArray): ByteArray {
        // Keep canonical protobuf bytes for downstream typed decoders.
        return bytes
    }

    private fun parseAppRouterPayload(bytes: ByteArray): ByteArray {
        // Keep canonical protobuf bytes for downstream typed decoders.
        return bytes
    }

    private fun parseCreateGenesisPayload(bytes: ByteArray): ByteArray {
        // Keep canonical protobuf bytes for downstream typed decoders.
        return bytes
    }

    private fun parseSingleBytesPayload(bytes: ByteArray): ByteArray {
        return parseBytesPayload(bytes)
    }

    private fun parseBleIdentityPayload(bytes: ByteArray): ByteArray {
        // Keep canonical protobuf bytes for downstream typed decoders.
        return bytes
    }

    private fun parseBilateralPayload(bytes: ByteArray): ByteArray {
        // Keep canonical protobuf bytes for downstream typed decoders.
        return bytes
    }

    private fun readVarint(bytes: ByteArray, start: Int): Pair<Long, Int> {
        var shift = 0
        var result = 0L
        var offset = start
        while (offset < bytes.size) {
            val b = bytes[offset].toInt() and 0xFF
            result = result or ((b and 0x7F).toLong() shl shift)
            offset += 1
            if (b and 0x80 == 0) break
            shift += 7
            if (shift > 63) throw IllegalArgumentException("varint too long")
            if (offset >= bytes.size && (b and 0x80) != 0) throw IllegalArgumentException("truncated varint")
        }
        return Pair(result, offset)
    }

    private fun readLengthDelimited(bytes: ByteArray, start: Int): Pair<ByteArray, Int> {
        val (len, off) = readVarint(bytes, start)
        val l = len.toInt()
        if (l < 0 || off + l > bytes.size) throw IllegalArgumentException("invalid length-delimited size")
        val out = bytes.copyOfRange(off, off + l)
        return Pair(out, off + l)
    }

    private fun skipField(wireType: Int, bytes: ByteArray, start: Int): Int {
        return when (wireType) {
            0 -> readVarint(bytes, start).second
            1 -> {
                val off = start + 8
                if (off > bytes.size) throw IllegalArgumentException("truncated fixed64")
                off
            }
            2 -> readLengthDelimited(bytes, start).second
            5 -> {
                val off = start + 4
                if (off > bytes.size) throw IllegalArgumentException("truncated fixed32")
                off
            }
            else -> throw IllegalArgumentException("unsupported wire type: $wireType")
        }
    }

    private fun encodeVarint32(valueIn: Int): ByteArray {
        var v = valueIn
        val baos = ByteArrayOutputStream()
        while (true) {
            if (v and 0x7F.inv() == 0) {
                baos.write(v)
                break
            } else {
                baos.write((v and 0x7F) or 0x80)
                v = v ushr 7
            }
        }
        return baos.toByteArray()
    }
}
