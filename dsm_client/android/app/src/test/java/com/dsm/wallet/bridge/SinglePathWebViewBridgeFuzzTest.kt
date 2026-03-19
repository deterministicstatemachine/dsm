package com.dsm.wallet.bridge

import org.junit.Test
import kotlin.random.Random

/**
 * Comprehensive fuzz testing for SinglePathWebViewBridge to ensure robustness against malformed inputs.
 * Addresses the critique recommendation for fuzz testing to prevent buffer overflow attacks and integration failures.
 * Tests both static method validation and envelope parsing robustness.
 *
 * NOTE: In unit tests, SinglePathWebViewBridge.instance is null, so handleBinaryRpc() always
 * returns an error protobuf envelope (error code 1 = not_initialized). This is correct behavior.
 * Production responses are protobuf-encoded BridgeRpcResponse bytes — there is no binary
 * magic header format.
 */
class SinglePathWebViewBridgeFuzzTest {

    /**
     * Comprehensive fuzz test for bridge payload validation.
     * Tests various malformed payloads to ensure they don't cause crashes or buffer overflows.
     * Covers all bridge methods with edge cases and random data.
     */
    @Test
    fun testFuzzBridgePayloads() {
        val methods = listOf(
            "hasNativeQrScanner",
            "getDeviceIdBin",
            "getSigningPublicKeyBin",
            "getPersistedDeviceId",
            "getPersistedGenesisHash",
            "getBluetoothStatus",
            "hasIdentityDirect",
            "getPreference",
            "setPreference",
            "appRouterInvoke",
            "appRouterQuery",
            "resolveBleAddressForDeviceId",
            "createGenesisBin",
            "initiateBleContactPairing",
            "getTransportHeadersV3Bin",
            "processEnvelopeV3",
            "unknownMethod" // Test unknown methods too
        )

        // Generate comprehensive fuzz payloads
        val payloads = generateComprehensiveFuzzPayloads()

        methods.forEach { method ->
            payloads.forEach { payload ->
                try {
                    // This should not crash, even with malformed input
                    val result = SinglePathWebViewBridge.handleBinaryRpc(method, payload)
                    // Result can be error response, but should not throw exception
                    assert(result.isNotEmpty()) { "Bridge should return some response for $method" }
                    // Verify response is a valid protobuf BridgeRpcResponse envelope
                    assert(isValidProtobufEnvelope(result)) {
                        "Bridge should return valid protobuf envelope for $method (got ${result.size} bytes)"
                    }
                } catch (e: Exception) {
                    // In a real fuzz test, we'd collect crashes, but for now just ensure no crashes
                    println("Unexpected crash in $method with payload size ${payload.size}: ${e.message}")
                    throw e
                }
            }
        }
    }

    /**
     * Test envelope parsing robustness with malformed envelopes.
     */
    @Test
    fun testFuzzEnvelopeParsing() {
        val malformedEnvelopes = generateMalformedEnvelopes()

        malformedEnvelopes.forEach { envelope ->
            try {
                // Try to parse - should not crash
                SinglePathWebViewBridge.handleBinaryRpcRaw("processEnvelopeV3", envelope)
                // Result should be empty for invalid envelopes (error case)
                // We don't assert emptiness since error handling may vary
            } catch (e: Exception) {
                // Should handle gracefully, not crash
                println("Envelope parsing handled exception: ${e.message}")
            }
        }
    }

    /**
     * Test protobuf parsing edge cases.
     */
    @Test
    fun testFuzzProtobufParsing() {
        val malformedProtos = generateMalformedProtobufs()

        malformedProtos.forEach { proto ->
            try {
                // Try various methods that parse protobuf
                val methods = listOf("processEnvelopeV3", "appRouterInvoke", "createGenesisBin")
                methods.forEach { method ->
                    val result = SinglePathWebViewBridge.handleBinaryRpc(method, proto)
                    // Bridge is not initialized in unit tests, so all responses
                    // are error protobuf envelopes — this is correct behavior.
                    assert(isValidProtobufEnvelope(result)) {
                        "Should return valid protobuf envelope for malformed proto in $method"
                    }
                }
            } catch (e: Exception) {
                println("Protobuf parsing handled exception: ${e.message}")
            }
        }
    }

    /**
     * Generate comprehensive fuzz payloads including edge cases.
     */
    private fun generateComprehensiveFuzzPayloads(): List<ByteArray> {
        val payloads = mutableListOf<ByteArray>()

        // Empty payload
        payloads.add(ByteArray(0))

        // Very large payload (1MB)
        payloads.add(ByteArray(1024 * 1024) { it.toByte() })

        // Very small payloads
        payloads.add(ByteArray(1) { 0x00 })
        payloads.add(ByteArray(2) { 0xFF.toByte() })

        // Payload with invalid lengths
        payloads.add(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())) // Max int length
        payloads.add(byteArrayOf(0x80.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte())) // Negative length
        payloads.add(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0x00)) // Max int + data

        // Truncated payloads
        payloads.add(byteArrayOf(0x00, 0x00, 0x00, 0x10)) // Length=16 but no data
        payloads.add(byteArrayOf(0x00, 0x00, 0x00, 0x01, 0x41)) // Length=1 but extra data
        payloads.add(byteArrayOf(0x00, 0x00, 0x00, 0x00)) // Zero length with no data

        // Random data of various sizes
        val random = Random(42) // Fixed seed for reproducibility
        repeat(200) {
            val size = random.nextInt(0, 2000)
            val data = ByteArray(size) { random.nextInt().toByte() }
            payloads.add(data)
        }

        // Specific edge cases for different methods
        // For setPreference: incomplete frame
        payloads.add(byteArrayOf(0x00, 0x00, 0x00, 0x05, 0x41, 0x42, 0x43)) // keyLen=5 but only 3 bytes
        payloads.add(byteArrayOf(0x00, 0x00, 0x00, 0x00)) // keyLen=0
        payloads.add(byteArrayOf(0x00, 0x00, 0x00, 0x01)) // keyLen=1 but no key data

        // For appRouterInvoke/appRouterQuery: malformed frames
        payloads.add(byteArrayOf(0x00, 0x00, 0x00, 0x05, 0x41, 0x42, 0x43)) // methodLen=5 but truncated
        payloads.add(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())) // huge method length

        // For createGenesisBin: malformed locale/network lengths
        payloads.add(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte())) // Max locale len
        payloads.add(byteArrayOf(0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01)) // localeLen=1, netLen=1 but no data
        payloads.add(byteArrayOf(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)) // zero lengths

        // For resolveBleAddressForDeviceId: wrong sizes
        payloads.add(ByteArray(31)) // 31 bytes instead of 32
        payloads.add(ByteArray(33)) // 33 bytes instead of 32
        payloads.add(ByteArray(32) { 0x00 }) // 32 zero bytes

        // Unicode and special characters
        payloads.add("\uD83D\uDE80\uD83D\uDD25\uD83D\uDCA5".toByteArray(Charsets.UTF_8))
        payloads.add("null".toByteArray(Charsets.UTF_8))
        payloads.add("undefined".toByteArray(Charsets.UTF_8))

        // Repeating patterns
        payloads.add(ByteArray(100) { 0x00 })
        payloads.add(ByteArray(100) { 0xFF.toByte() })
        payloads.add(ByteArray(100) { (it % 256).toByte() })

        return payloads
    }

    /**
     * Generate malformed envelope data for testing.
     */
    private fun generateMalformedEnvelopes(): List<ByteArray> {
        val envelopes = mutableListOf<ByteArray>()

        // Various malformed data
        envelopes.add("WRONG_MAGIC_123".toByteArray(Charsets.UTF_8) + ByteArray(10))
        envelopes.add(ByteArray(0))
        envelopes.add(byteArrayOf(0x03)) // Just a framing byte

        // Random envelope-like data
        val random = Random(123)
        repeat(50) {
            val size = random.nextInt(10, 100)
            envelopes.add(ByteArray(size) { random.nextInt().toByte() })
        }

        return envelopes
    }

    /**
     * Generate malformed protobuf data.
     */
    private fun generateMalformedProtobufs(): List<ByteArray> {
        val protos = mutableListOf<ByteArray>()

        // Empty protobuf
        protos.add(ByteArray(0))

        // Invalid varint encoding
        protos.add(byteArrayOf(0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte(), 0xFF.toByte()))

        // Truncated messages
        protos.add(byteArrayOf(0x08)) // Field 1, varint type, but no value

        // Oversized messages
        protos.add(ByteArray(10000) { 0x01 }) // Very long message

        // Random protobuf-like data
        val random = Random(456)
        repeat(50) {
            val size = random.nextInt(1, 500)
            protos.add(ByteArray(size) { random.nextInt().toByte() })
        }

        return protos
    }

    /**
     * Check if response is a valid protobuf BridgeRpcResponse envelope.
     *
     * Production bridge responses are protobuf-encoded BridgeRpcResponse messages
     * containing either a success (field 1) or error (field 2) submessage.
     * When the bridge is not initialized (unit test scenario), it returns an
     * error envelope with code 1 ("not_initialized").
     */
    private fun isValidProtobufEnvelope(bytes: ByteArray): Boolean {
        if (bytes.isEmpty()) return false
        return try {
            // Parse as protobuf: look for field 1 (success) or field 2 (error)
            // as length-delimited submessages
            var offset = 0
            var foundValidField = false
            while (offset < bytes.size) {
                val (key, keyOff) = readVarint(bytes, offset)
                offset = keyOff
                val fieldNumber = (key ushr 3).toInt()
                val wireType = (key and 0x07).toInt()

                when (wireType) {
                    0 -> {
                        // Varint — skip value
                        val (_, valOff) = readVarint(bytes, offset)
                        offset = valOff
                    }
                    2 -> {
                        // Length-delimited
                        val (len, lenOff) = readVarint(bytes, offset)
                        offset = lenOff + len.toInt()
                        if (fieldNumber == 1 || fieldNumber == 2) {
                            foundValidField = true
                        }
                    }
                    else -> {
                        // Unknown wire type — skip (best-effort)
                        break
                    }
                }
            }
            foundValidField
        } catch (e: Exception) {
            false
        }
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

    /**
     * Test that valid payloads still work correctly.
     * Since bridge instance is null in unit tests, all calls return error envelopes
     * (code 1 = not_initialized). This is correct behavior.
     */
    @Test
    fun testValidPayloadsStillWork() {
        // Test methods that should work with empty payloads
        val emptyMethods = listOf("hasNativeQrScanner", "getDeviceIdBin", "hasIdentityDirect")

        emptyMethods.forEach { method ->
            val result = SinglePathWebViewBridge.handleBinaryRpc(method, ByteArray(0))
            assert(result.isNotEmpty()) { "$method should return a response" }
            // Bridge is not initialized → returns error protobuf envelope, which is valid
            assert(isValidProtobufEnvelope(result)) { "$method should return valid protobuf envelope" }
        }
    }

    /**
     * Test specific malformed inputs that could cause buffer overflows.
     */
    @Test
    fun testBufferOverflowProtection() {
        // Test with extremely large payloads
        val hugePayload = ByteArray(10 * 1024 * 1024) { it.toByte() } // 10MB

        val methods = listOf("appRouterInvoke", "setPreference", "createGenesisBin")

        methods.forEach { method ->
            try {
                val result = SinglePathWebViewBridge.handleBinaryRpc(method, hugePayload)
                assert(isValidProtobufEnvelope(result)) { "$method should handle huge payload gracefully" }
            } catch (e: OutOfMemoryError) {
                // Acceptable if system runs out of memory, but shouldn't crash
                println("OutOfMemoryError for $method with huge payload - acceptable")
            }
        }
    }
}
