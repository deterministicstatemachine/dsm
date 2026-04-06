package com.dsm.wallet.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.nio.ByteBuffer
import java.nio.ByteOrder

@RunWith(JUnit4::class)
class BridgeEnvelopeCodecTest {

    // ── Protobuf wire-format helpers ───────────────────────────────────────

    private fun encodeVarint(valueIn: Int): ByteArray {
        var v = valueIn
        val out = mutableListOf<Byte>()
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

    private fun encodeLenField(fieldNumber: Int, value: ByteArray): ByteArray {
        val tag = (fieldNumber shl 3) or 2
        return encodeVarint(tag) + encodeVarint(value.size) + value
    }

    private fun encodeVarintField(fieldNumber: Int, value: Int): ByteArray {
        val tag = (fieldNumber shl 3) or 0
        return encodeVarint(tag) + encodeVarint(value)
    }

    private fun encodeFixed64Field(fieldNumber: Int, value: Long): ByteArray {
        val tag = (fieldNumber shl 3) or 1
        val buf = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN).putLong(value).array()
        return encodeVarint(tag) + buf
    }

    private fun encodeFixed32Field(fieldNumber: Int, value: Int): ByteArray {
        val tag = (fieldNumber shl 3) or 5
        val buf = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN).putInt(value).array()
        return encodeVarint(tag) + buf
    }

    private fun makeRequest(
        method: String,
        payloadFieldNumber: Int? = null,
        payloadBytes: ByteArray? = null
    ): ByteArray {
        val methodField = encodeLenField(1, method.toByteArray(Charsets.UTF_8))
        return if (payloadFieldNumber != null && payloadBytes != null) {
            methodField + encodeLenField(payloadFieldNumber, payloadBytes)
        } else {
            methodField
        }
    }

    // ── parseBridgeRequest: happy paths ────────────────────────────────────

    @Test
    fun parseBridgeRequest_methodOnly() {
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("hello"))
        assertEquals("hello", req.method)
        assertEquals(0, req.payload.size)
    }

    @Test
    fun parseBridgeRequest_methodWithDots() {
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("app.router.call"))
        assertEquals("app.router.call", req.method)
    }

    @Test
    fun parseBridgeRequest_methodWithUnderscoresAndHyphens() {
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("get_status-v2"))
        assertEquals("get_status-v2", req.method)
    }

    @Test
    fun parseBridgeRequest_methodExactly128Bytes() {
        val method128 = "a".repeat(128)
        val bytes = encodeLenField(1, method128.toByteArray(Charsets.UTF_8))
        val req = BridgeEnvelopeCodec.parseBridgeRequest(bytes)
        assertEquals(method128, req.method)
    }

    @Test
    fun parseBridgeRequest_emptyInput_defaultValues() {
        val req = BridgeEnvelopeCodec.parseBridgeRequest(ByteArray(0))
        assertEquals("", req.method)
        assertEquals(0, req.payload.size)
    }

    @Test
    fun parseBridgeRequest_emptyPayloadType() {
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("test", 2, ByteArray(0)))
        assertEquals("test", req.method)
        assertEquals(0, req.payload.size)
    }

    @Test
    fun parseBridgeRequest_bytesPayload() {
        val innerData = byteArrayOf(0x01, 0x02, 0x03)
        val innerProto = encodeLenField(1, innerData)
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("getData", 3, innerProto))
        assertEquals("getData", req.method)
        assertArrayEquals(innerData, req.payload)
    }

    @Test
    fun parseBridgeRequest_stringPayload() {
        val innerStr = "hello world".toByteArray(Charsets.UTF_8)
        val innerProto = encodeLenField(1, innerStr)
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("getString", 4, innerProto))
        assertEquals("getString", req.method)
        assertArrayEquals(innerStr, req.payload)
    }

    @Test
    fun parseBridgeRequest_preferencePayloadPassthrough() {
        val prefProto = encodeLenField(1, "theme".toByteArray()) +
            encodeLenField(2, "dark".toByteArray())
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("setPref", 5, prefProto))
        assertArrayEquals(prefProto, req.payload)
    }

    @Test
    fun parseBridgeRequest_appRouterPayloadPassthrough() {
        val routerProto = encodeLenField(1, "doThing".toByteArray()) +
            encodeLenField(2, byteArrayOf(0x42))
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("route", 6, routerProto))
        assertArrayEquals(routerProto, req.payload)
    }

    @Test
    fun parseBridgeRequest_singleBytesPayloadField8() {
        val innerData = byteArrayOf(0xAA.toByte(), 0xBB.toByte())
        val innerProto = encodeLenField(1, innerData)
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("f8", 8, innerProto))
        assertArrayEquals(innerData, req.payload)
    }

    @Test
    fun parseBridgeRequest_singleBytesPayloadField9() {
        val innerData = byteArrayOf(0xCC.toByte())
        val innerProto = encodeLenField(1, innerData)
        val req = BridgeEnvelopeCodec.parseBridgeRequest(makeRequest("f9", 9, innerProto))
        assertArrayEquals(innerData, req.payload)
    }

    // ── parseBridgeRequest: unknown field skipping ─────────────────────────

    @Test
    fun parseBridgeRequest_unknownVarintFieldSkipped() {
        val bytes = makeRequest("test") + encodeVarintField(99, 999)
        assertEquals("test", BridgeEnvelopeCodec.parseBridgeRequest(bytes).method)
    }

    @Test
    fun parseBridgeRequest_unknownLenFieldSkipped() {
        val bytes = makeRequest("test") + encodeLenField(50, byteArrayOf(0x01, 0x02))
        assertEquals("test", BridgeEnvelopeCodec.parseBridgeRequest(bytes).method)
    }

    @Test
    fun parseBridgeRequest_unknownFixed64FieldSkipped() {
        val bytes = makeRequest("test") + encodeFixed64Field(55, 0x1234567890ABCDEFL)
        assertEquals("test", BridgeEnvelopeCodec.parseBridgeRequest(bytes).method)
    }

    @Test
    fun parseBridgeRequest_unknownFixed32FieldSkipped() {
        val bytes = makeRequest("test") + encodeFixed32Field(55, 0x12345678)
        assertEquals("test", BridgeEnvelopeCodec.parseBridgeRequest(bytes).method)
    }

    // ── parseBridgeRequest: error cases ────────────────────────────────────

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_methodTooLong() {
        val longMethod = "a".repeat(129)
        BridgeEnvelopeCodec.parseBridgeRequest(
            encodeLenField(1, longMethod.toByteArray(Charsets.UTF_8))
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_methodEmpty() {
        BridgeEnvelopeCodec.parseBridgeRequest(encodeLenField(1, ByteArray(0)))
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_methodInvalidChars() {
        BridgeEnvelopeCodec.parseBridgeRequest(
            encodeLenField(1, "hello world".toByteArray(Charsets.UTF_8))
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_methodWrongWireType() {
        BridgeEnvelopeCodec.parseBridgeRequest(encodeVarintField(1, 42))
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_payloadWrongWireType() {
        val bytes = encodeLenField(1, "test".toByteArray()) + encodeVarintField(5, 42)
        BridgeEnvelopeCodec.parseBridgeRequest(bytes)
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_duplicatePayloads() {
        val methodField = encodeLenField(1, "test".toByteArray())
        val payload1 = encodeLenField(3, encodeLenField(1, byteArrayOf(1)))
        val payload2 = encodeLenField(4, encodeLenField(1, byteArrayOf(2)))
        BridgeEnvelopeCodec.parseBridgeRequest(methodField + payload1 + payload2)
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_truncatedVarint() {
        BridgeEnvelopeCodec.parseBridgeRequest(byteArrayOf(0x80.toByte()))
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_truncatedLengthDelimited() {
        BridgeEnvelopeCodec.parseBridgeRequest(byteArrayOf(0x0A, 0x0A, 0x41, 0x42))
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_varintTooLong() {
        val bytes = ByteArray(11) { 0x80.toByte() }.also { it[10] = 0x01 }
        BridgeEnvelopeCodec.parseBridgeRequest(bytes)
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseBridgeRequest_unsupportedWireType3() {
        val tag = (99 shl 3) or 3 // start-group, not supported by skipField
        BridgeEnvelopeCodec.parseBridgeRequest(encodeVarint(tag))
    }

    // ── decodeBridgeRpcError ──────────────────────────────────────────────

    @Test
    fun decodeBridgeRpcError_allFields() {
        val bytes = encodeVarintField(1, 404) +
            encodeLenField(2, "not found".toByteArray()) +
            encodeLenField(3, "ABC123".toByteArray())
        val err = BridgeEnvelopeCodec.decodeBridgeRpcError(bytes)!!
        assertEquals(404, err.errorCode)
        assertEquals("not found", err.message)
        assertEquals("ABC123", err.debugB32)
    }

    @Test
    fun decodeBridgeRpcError_codeOnly() {
        val err = BridgeEnvelopeCodec.decodeBridgeRpcError(encodeVarintField(1, 500))!!
        assertEquals(500, err.errorCode)
        assertEquals("", err.message)
        assertNull(err.debugB32)
    }

    @Test
    fun decodeBridgeRpcError_messageOnly() {
        val err = BridgeEnvelopeCodec.decodeBridgeRpcError(
            encodeLenField(2, "server error".toByteArray())
        )!!
        assertEquals(0, err.errorCode)
        assertEquals("server error", err.message)
    }

    @Test
    fun decodeBridgeRpcError_debugOnly() {
        val err = BridgeEnvelopeCodec.decodeBridgeRpcError(
            encodeLenField(3, "DEBUG".toByteArray())
        )!!
        assertEquals("DEBUG", err.debugB32)
    }

    @Test
    fun decodeBridgeRpcError_emptyInput_returnsNull() {
        assertNull(BridgeEnvelopeCodec.decodeBridgeRpcError(ByteArray(0)))
    }

    @Test
    fun decodeBridgeRpcError_allDefaultValues_returnsNull() {
        assertNull(BridgeEnvelopeCodec.decodeBridgeRpcError(encodeVarintField(1, 0)))
    }

    @Test
    fun decodeBridgeRpcError_wrongWireTypeForCode_returnsNull() {
        assertNull(BridgeEnvelopeCodec.decodeBridgeRpcError(encodeLenField(1, byteArrayOf(1))))
    }

    @Test
    fun decodeBridgeRpcError_wrongWireTypeForMessage_returnsNull() {
        val bytes = encodeVarintField(1, 1) + encodeVarintField(2, 42)
        assertNull(BridgeEnvelopeCodec.decodeBridgeRpcError(bytes))
    }

    @Test
    fun decodeBridgeRpcError_unknownFieldsSkipped() {
        val bytes = encodeVarintField(1, 1) +
            encodeLenField(2, "err".toByteArray()) +
            encodeVarintField(99, 42)
        val err = BridgeEnvelopeCodec.decodeBridgeRpcError(bytes)!!
        assertEquals(1, err.errorCode)
        assertEquals("err", err.message)
    }

    // ── parseEnvelopeResponse ─────────────────────────────────────────────

    @Test
    fun parseEnvelopeResponse_success() {
        val data = byteArrayOf(0x0A, 0x0B, 0x0C)
        val (isSuccess, payload) = BridgeEnvelopeCodec.parseEnvelopeResponse(
            BridgeEnvelopeCodec.createSuccessResponse(data)
        )
        assertTrue(isSuccess)
        assertArrayEquals(data, payload)
    }

    @Test
    fun parseEnvelopeResponse_successEmptyData() {
        val (isSuccess, payload) = BridgeEnvelopeCodec.parseEnvelopeResponse(
            BridgeEnvelopeCodec.createSuccessResponse(ByteArray(0))
        )
        assertTrue(isSuccess)
        assertEquals(0, payload.size)
    }

    @Test
    fun parseEnvelopeResponse_error() {
        val (isSuccess, _) = BridgeEnvelopeCodec.parseEnvelopeResponse(
            BridgeEnvelopeCodec.createErrorResponse(500, "fail") { "" }
        )
        assertFalse(isSuccess)
    }

    @Test
    fun parseEnvelopeResponse_errorRoundTrip() {
        val responseBytes = BridgeEnvelopeCodec.createErrorResponse(404, "not found") {
            BridgeEncoding.base32CrockfordEncode(it)
        }
        val (isSuccess, errorPayload) = BridgeEnvelopeCodec.parseEnvelopeResponse(responseBytes)
        assertFalse(isSuccess)

        val err = BridgeEnvelopeCodec.decodeBridgeRpcError(errorPayload)!!
        assertEquals(404, err.errorCode)
        assertEquals("not found", err.message)
        assertNotNull(err.debugB32)
        assertTrue(err.debugB32!!.isNotEmpty())
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseEnvelopeResponse_missingResult() {
        BridgeEnvelopeCodec.parseEnvelopeResponse(ByteArray(0))
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseEnvelopeResponse_multipleResults() {
        val successInner = encodeLenField(1, byteArrayOf(0x01))
        val success = encodeLenField(1, successInner)
        val error = encodeLenField(2, byteArrayOf(0x08, 0x01))
        BridgeEnvelopeCodec.parseEnvelopeResponse(success + error)
    }

    @Test(expected = IllegalArgumentException::class)
    fun parseEnvelopeResponse_successWrongWireType() {
        BridgeEnvelopeCodec.parseEnvelopeResponse(encodeVarintField(1, 42))
    }

    @Test
    fun parseEnvelopeResponse_unknownFieldsSkipped() {
        val data = byteArrayOf(0x0A, 0x0B)
        val responseBytes = BridgeEnvelopeCodec.createSuccessResponse(data) +
            encodeVarintField(99, 42)
        val (isSuccess, payload) = BridgeEnvelopeCodec.parseEnvelopeResponse(responseBytes)
        assertTrue(isSuccess)
        assertArrayEquals(data, payload)
    }

    // ── createSuccessResponse / createErrorResponse ──────────────────────

    @Test
    fun createSuccessResponse_largePayloadRoundTrip() {
        val data = ByteArray(10_000) { (it % 256).toByte() }
        val (isSuccess, payload) = BridgeEnvelopeCodec.parseEnvelopeResponse(
            BridgeEnvelopeCodec.createSuccessResponse(data)
        )
        assertTrue(isSuccess)
        assertArrayEquals(data, payload)
    }

    @Test
    fun createErrorResponse_debugEncoderIsCalled() {
        var debugInput: ByteArray? = null
        BridgeEnvelopeCodec.createErrorResponse(1, "test") { bytes ->
            debugInput = bytes
            "encoded"
        }
        assertNotNull(debugInput)
        assertTrue(debugInput!!.isNotEmpty())
    }

    @Test
    fun createErrorResponse_debugEncoderThrows_emptyDebug() {
        val response = BridgeEnvelopeCodec.createErrorResponse(1, "test") {
            throw RuntimeException("encoder broke")
        }
        val (isSuccess, errorPayload) = BridgeEnvelopeCodec.parseEnvelopeResponse(response)
        assertFalse(isSuccess)
        val err = BridgeEnvelopeCodec.decodeBridgeRpcError(errorPayload)!!
        assertEquals("", err.debugB32)
    }

    // ── encodeAppRouterPayload / decodeAppRouterPayload ──────────────────

    @Test
    fun appRouterPayload_roundTrip() {
        val args = byteArrayOf(0x01, 0x02, 0x03)
        val decoded = BridgeEnvelopeCodec.decodeAppRouterPayload(
            BridgeEnvelopeCodec.encodeAppRouterPayload("doSomething", args)
        )!!
        assertEquals("doSomething", decoded.methodName)
        assertArrayEquals(args, decoded.args)
    }

    @Test
    fun appRouterPayload_emptyArgs() {
        val decoded = BridgeEnvelopeCodec.decodeAppRouterPayload(
            BridgeEnvelopeCodec.encodeAppRouterPayload("ping", ByteArray(0))
        )!!
        assertEquals("ping", decoded.methodName)
        assertEquals(0, decoded.args.size)
    }

    @Test
    fun decodeAppRouterPayload_blankMethodName_returnsNull() {
        val encoded = encodeLenField(1, "   ".toByteArray()) + encodeLenField(2, byteArrayOf(1))
        assertNull(BridgeEnvelopeCodec.decodeAppRouterPayload(encoded))
    }

    @Test
    fun decodeAppRouterPayload_emptyInput_returnsNull() {
        assertNull(BridgeEnvelopeCodec.decodeAppRouterPayload(ByteArray(0)))
    }

    @Test
    fun decodeAppRouterPayload_wrongWireType_returnsNull() {
        assertNull(BridgeEnvelopeCodec.decodeAppRouterPayload(encodeVarintField(1, 42)))
    }

    @Test
    fun decodeAppRouterPayload_unknownFieldsSkipped() {
        val encoded = BridgeEnvelopeCodec.encodeAppRouterPayload("test", byteArrayOf(0x42)) +
            encodeVarintField(99, 42)
        assertEquals("test", BridgeEnvelopeCodec.decodeAppRouterPayload(encoded)!!.methodName)
    }

    // ── decodePreferencePayload ──────────────────────────────────────────

    @Test
    fun decodePreferencePayload_keyAndValue() {
        val bytes = encodeLenField(1, "theme".toByteArray()) +
            encodeLenField(2, "dark".toByteArray())
        val pref = BridgeEnvelopeCodec.decodePreferencePayload(bytes)!!
        assertEquals("theme", pref.key)
        assertEquals("dark", pref.value)
    }

    @Test
    fun decodePreferencePayload_keyOnly() {
        val pref = BridgeEnvelopeCodec.decodePreferencePayload(
            encodeLenField(1, "theme".toByteArray())
        )!!
        assertEquals("theme", pref.key)
        assertNull(pref.value)
    }

    @Test
    fun decodePreferencePayload_blankKey_returnsNull() {
        assertNull(
            BridgeEnvelopeCodec.decodePreferencePayload(encodeLenField(1, "   ".toByteArray()))
        )
    }

    @Test
    fun decodePreferencePayload_emptyInput_returnsNull() {
        assertNull(BridgeEnvelopeCodec.decodePreferencePayload(ByteArray(0)))
    }

    // ── decodeBilateralPayload ───────────────────────────────────────────

    @Test
    fun decodeBilateralPayload_commitmentAndReason() {
        val commitment = ByteArray(32) { (it * 7).toByte() }
        val bytes = encodeLenField(1, commitment) +
            encodeLenField(2, "reason text".toByteArray())
        val req = BridgeEnvelopeCodec.decodeBilateralPayload(bytes)!!
        assertArrayEquals(commitment, req.commitment)
        assertEquals("reason text", req.reason)
    }

    @Test
    fun decodeBilateralPayload_commitmentOnly() {
        val commitment = ByteArray(32) { 0xFF.toByte() }
        val req = BridgeEnvelopeCodec.decodeBilateralPayload(encodeLenField(1, commitment))!!
        assertArrayEquals(commitment, req.commitment)
        assertNull(req.reason)
    }

    @Test
    fun decodeBilateralPayload_wrongCommitmentSize_returnsNull() {
        assertNull(
            BridgeEnvelopeCodec.decodeBilateralPayload(encodeLenField(1, ByteArray(16) { 1 }))
        )
    }

    @Test
    fun decodeBilateralPayload_emptyInput_returnsNull() {
        assertNull(BridgeEnvelopeCodec.decodeBilateralPayload(ByteArray(0)))
    }

    // ── extractDeterministicSafetyMessageFromEnvelope ─────────────────────

    @Test
    fun extractSafetyMessage_emptyEnvelope_returnsNull() {
        assertNull(
            BridgeEnvelopeCodec.extractDeterministicSafetyMessageFromEnvelope(ByteArray(0))
        )
    }

    @Test
    fun extractSafetyMessage_noErrorInfo_returnsNull() {
        assertNull(
            BridgeEnvelopeCodec.extractDeterministicSafetyMessageFromEnvelope(
                encodeVarintField(1, 42)
            )
        )
    }

    @Test
    fun extractSafetyMessage_field99_sourceTag11_returnsMessage() {
        val errorInfo = encodeLenField(2, "safety violation".toByteArray()) +
            encodeVarintField(4, 11)
        val envelope = encodeLenField(99, errorInfo)
        assertEquals(
            "safety violation",
            BridgeEnvelopeCodec.extractDeterministicSafetyMessageFromEnvelope(envelope)
        )
    }

    @Test
    fun extractSafetyMessage_field99_differentSourceTag_returnsNull() {
        val errorInfo = encodeLenField(2, "other error".toByteArray()) +
            encodeVarintField(4, 5)
        assertNull(
            BridgeEnvelopeCodec.extractDeterministicSafetyMessageFromEnvelope(
                encodeLenField(99, errorInfo)
            )
        )
    }

    @Test
    fun extractSafetyMessage_field11_nestedPath_returnsMessage() {
        val errorInfo = encodeLenField(2, "deep error".toByteArray()) +
            encodeVarintField(4, 11)
        val opResult = encodeLenField(5, errorInfo)
        val universalRx = encodeLenField(1, opResult)
        val envelope = encodeLenField(11, universalRx)
        assertEquals(
            "deep error",
            BridgeEnvelopeCodec.extractDeterministicSafetyMessageFromEnvelope(envelope)
        )
    }
}
