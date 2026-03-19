package com.dsm.wallet.bridge

import org.junit.Test

class BridgeEnvelopeCodecBilateralPayloadTest {
    /**
     * Verify that parseBridgeRequest correctly extracts a bilateral payload
     * from a BridgeRpcRequest and that the payload is returned as canonical
     * protobuf bytes (passthrough for downstream typed decoders).
     */
    @Test
    fun testBilateralRejectPayloadFormatCommitmentFirst() {
        val commitment = ByteArray(32) { (it + 1).toByte() }
        val reason = "nope"
        val bilateralProtoBytes = encodeBilateralPayload(commitment, reason)
        val reqBytes = encodeBridgeRpcRequestWithBilateral("rejectBilateralByCommitment", bilateralProtoBytes)

        val parsed = BridgeEnvelopeCodec.parseBridgeRequest(reqBytes)
        val payload = parsed.payload

        // parseBilateralPayload returns canonical protobuf bytes unchanged (passthrough).
        // Verify the payload is the original bilateral proto bytes, not a flattened binary format.
        assert(payload.contentEquals(bilateralProtoBytes)) {
            "Bilateral payload must be canonical protobuf bytes (passthrough), " +
            "not a flattened binary format. Got ${payload.size} bytes, expected ${bilateralProtoBytes.size} bytes."
        }

        // Verify roundtrip: re-parse the protobuf bytes and extract fields
        val (parsedCommitment, parsedReason) = decodeBilateralPayload(payload)
        assert(parsedCommitment.contentEquals(commitment)) {
            "Roundtrip commitment mismatch"
        }
        assert(parsedReason == reason) {
            "Roundtrip reason mismatch: expected '$reason', got '$parsedReason'"
        }
    }

    private fun encodeBridgeRpcRequestWithBilateral(method: String, bilateralBytes: ByteArray): ByteArray {
        val methodField = encodeLengthDelimitedField(1, method.toByteArray(Charsets.UTF_8))
        val bilateralField = encodeLengthDelimitedField(11, bilateralBytes)
        return methodField + bilateralField
    }

    private fun encodeBilateralPayload(commitment: ByteArray, reason: String): ByteArray {
        val commitmentField = encodeLengthDelimitedField(1, commitment)
        val reasonField = encodeLengthDelimitedField(2, reason.toByteArray(Charsets.UTF_8))
        return commitmentField + reasonField
    }

    /**
     * Decode a bilateral payload protobuf to extract commitment and reason fields.
     * Field 1 = commitment (bytes), Field 2 = reason (string).
     */
    private fun decodeBilateralPayload(bytes: ByteArray): Pair<ByteArray, String> {
        var offset = 0
        var commitment = ByteArray(0)
        var reason = ""

        while (offset < bytes.size) {
            val (key, keyOff) = readVarint(bytes, offset)
            offset = keyOff
            val fieldNumber = (key ushr 3).toInt()
            val wireType = (key and 0x07).toInt()

            if (wireType != 2) break // length-delimited only

            val (len, lenOff) = readVarint(bytes, offset)
            offset = lenOff
            val fieldBytes = bytes.copyOfRange(offset, offset + len.toInt())
            offset += len.toInt()

            when (fieldNumber) {
                1 -> commitment = fieldBytes
                2 -> reason = String(fieldBytes, Charsets.UTF_8)
            }
        }

        return Pair(commitment, reason)
    }

    private fun encodeLengthDelimitedField(fieldNumber: Int, value: ByteArray): ByteArray {
        val key = (fieldNumber shl 3) or 2
        val keyVarint = encodeVarint(key)
        val lenVarint = encodeVarint(value.size)
        return keyVarint + lenVarint + value
    }

    private fun encodeVarint(valueIn: Int): ByteArray {
        var v = valueIn
        val out = ArrayList<Byte>()
        while (true) {
            if (v and 0x7F.inv() == 0) {
                out.add(v.toByte())
                break
            } else {
                out.add(((v and 0x7F) or 0x80).toByte())
                v = v ushr 7
            }
        }
        return out.toByteArray()
    }

    private fun readVarint(bytes: ByteArray, start: Int): Pair<Long, Int> {
        var shift = 0
        var result = 0L
        var offset = start
        while (offset < bytes.size) {
            val b = bytes[offset].toInt() and 0xFF
            result = result or ((b.toLong() and 0x7F) shl shift)
            offset++
            if (b and 0x80 == 0) break
            shift += 7
        }
        return Pair(result, offset)
    }
}
