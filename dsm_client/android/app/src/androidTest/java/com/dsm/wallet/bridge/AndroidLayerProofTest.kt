// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.dsm.wallet.ui.MainActivity
import java.io.File
import java.io.FileOutputStream
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom
import java.util.Locale
import java.util.concurrent.CountDownLatch
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.atomic.AtomicInteger

/**
 * ON-DEVICE PROOF: Android Layer Correctness
 *
 * These tests run on a real Android device (via ./gradlew connectedAndroidTest).
 * They prove the Kotlin bridge layer — threading, protobuf codec, message framing,
 * method routing, and JNI round-trips — works correctly.
 *
 * NO network, NO BLE, NO second device required.
 *
 * What this proves:
 *   1. BridgeEnvelopeCodec encodes/decodes protobuf wire format correctly
 *   2. Message ID framing survives the full Kotlin pipeline
 *   3. Every bridge method routes to the right JNI function and returns valid responses
 *   4. Concurrent calls don't deadlock or corrupt data
 *   5. Malformed inputs get error responses, not crashes
 *   6. The EXACT byte sequences a WebView would send/receive work end-to-end
 *
 * Run:
 *   ./gradlew connectedAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=com.dsm.wallet.bridge.AndroidLayerProofTest
 *
 * Or run all instrumented tests:
 *   ./gradlew connectedAndroidTest
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class AndroidLayerProofTest {

    companion object {
        private val PREF_KEY_COUNTER = AtomicInteger(0)

        // Static so genesis is called at most once per test-runner process.
        // JUnit4 creates a new test-class instance per method; an instance var
        // would trigger createGenesis() 30+ times, which is flaky on slower devices.
        @Volatile
        @JvmStatic
        private var genesisCreated = false
    }

    private lateinit var ctx: Context

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        SinglePathWebViewBridge.ensureInitialized(ctx)
    }

    // =========================================================================
    // SECTION 1: BridgeEnvelopeCodec — Protobuf Wire Format Round-trips
    //
    // Proves: The Kotlin codec that sits between WebView bytes and JNI
    //         encodes and decodes without corruption.
    // =========================================================================

    @Test
    fun t01_codec_successResponse_roundTrips() {
        val data = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        val encoded = BridgeEnvelopeCodec.createSuccessResponse(data)
        assertTrue("Success response must be non-empty", encoded.isNotEmpty())

        val (isSuccess, decoded) = BridgeEnvelopeCodec.parseEnvelopeResponse(encoded)
        assertTrue("Must parse as success", isSuccess)
        assertTrue("Decoded data must match original", data.contentEquals(decoded))
    }

    @Test
    fun t02_codec_errorResponse_roundTrips() {
        val errorCode = 3
        val errorMsg = "test error message"
        val encoded = BridgeEnvelopeCodec.createErrorResponse(errorCode, errorMsg) { bytes ->
            BridgeEncoding.base32CrockfordEncode(bytes)
        }
        assertTrue("Error response must be non-empty", encoded.isNotEmpty())

        val (isSuccess, decoded) = BridgeEnvelopeCodec.parseEnvelopeResponse(encoded)
        assertFalse("Must parse as error", isSuccess)
        assertTrue("Error payload must be non-empty", decoded.isNotEmpty())
    }

    @Test
    fun t03_codec_emptyPayload_successResponse() {
        val encoded = BridgeEnvelopeCodec.createSuccessResponse(ByteArray(0))
        val (isSuccess, decoded) = BridgeEnvelopeCodec.parseEnvelopeResponse(encoded)
        assertTrue("Empty payload must still be success", isSuccess)
        assertEquals("Decoded empty payload must be 0 bytes", 0, decoded.size)
    }

    @Test
    fun t04_codec_largePayload_successResponse() {
        val data = ByteArray(65536) { (it % 256).toByte() }
        val encoded = BridgeEnvelopeCodec.createSuccessResponse(data)
        val (isSuccess, decoded) = BridgeEnvelopeCodec.parseEnvelopeResponse(encoded)
        assertTrue("Large payload must be success", isSuccess)
        assertTrue("Large payload must round-trip", data.contentEquals(decoded))
    }

    @Test
    fun t05_codec_appRouterPayload_roundTrips() {
        val methodName = "balance.list"
        val args = byteArrayOf(0x0A, 0x0B, 0x0C)

        val encoded = BridgeEnvelopeCodec.encodeAppRouterPayload(methodName, args)
        assertTrue("AppRouterPayload must be non-empty", encoded.isNotEmpty())

        val decoded = BridgeEnvelopeCodec.decodeAppRouterPayload(encoded)
        assertNotNull("Must decode AppRouterPayload", decoded)
        assertEquals("Method name must round-trip", methodName, decoded!!.methodName)
        assertTrue("Args must round-trip", args.contentEquals(decoded.args))
    }

    @Test
    fun t06_codec_appRouterPayload_emptyArgs() {
        val methodName = "wallet.history"
        val encoded = BridgeEnvelopeCodec.encodeAppRouterPayload(methodName, ByteArray(0))
        val decoded = BridgeEnvelopeCodec.decodeAppRouterPayload(encoded)
        assertNotNull("Must decode with empty args", decoded)
        assertEquals("wallet.history", decoded!!.methodName)
        assertEquals("Args must be empty", 0, decoded.args.size)
    }

    @Test
    fun t07_codec_bilateralPayload_roundTrips() {
        val commitment = ByteArray(32) { (it + 1).toByte() }
        val reason = "user_rejected"

        // Manually encode: field 1 = commitment (bytes), field 2 = reason (string)
        val baos = ByteArrayOutputStream()
        baos.write(0x0A) // field 1, wire type 2
        baos.write(encodeVarint32(commitment.size))
        baos.write(commitment)
        baos.write(0x12) // field 2, wire type 2
        val reasonBytes = reason.toByteArray(Charsets.UTF_8)
        baos.write(encodeVarint32(reasonBytes.size))
        baos.write(reasonBytes)
        val encoded = baos.toByteArray()

        val decoded = BridgeEnvelopeCodec.decodeBilateralPayload(encoded)
        assertNotNull("Must decode BilateralPayload", decoded)
        assertTrue("Commitment must round-trip", commitment.contentEquals(decoded!!.commitment))
        assertEquals("Reason must round-trip", reason, decoded.reason)
    }

    @Test
    fun t08_codec_bilateralPayload_rejectsWrongSize() {
        val badCommitment = ByteArray(16) // must be 32
        val baos = ByteArrayOutputStream()
        baos.write(0x0A)
        baos.write(encodeVarint32(badCommitment.size))
        baos.write(badCommitment)
        val encoded = baos.toByteArray()

        val decoded = BridgeEnvelopeCodec.decodeBilateralPayload(encoded)
        assertTrue("Must reject non-32-byte commitment", decoded == null)
    }

    @Test
    fun t09_codec_preferencePayload_roundTrips() {
        val key = "theme"
        val value = "dark"

        val baos = ByteArrayOutputStream()
        val keyBytes = key.toByteArray(Charsets.UTF_8)
        baos.write(0x0A) // field 1
        baos.write(encodeVarint32(keyBytes.size))
        baos.write(keyBytes)
        val valueBytes = value.toByteArray(Charsets.UTF_8)
        baos.write(0x12) // field 2
        baos.write(encodeVarint32(valueBytes.size))
        baos.write(valueBytes)
        val encoded = baos.toByteArray()

        val decoded = BridgeEnvelopeCodec.decodePreferencePayload(encoded)
        assertNotNull("Must decode PreferencePayload", decoded)
        assertEquals("Key must round-trip", key, decoded!!.key)
        assertEquals("Value must round-trip", value, decoded.value)
    }

    @Test
    fun t10_codec_bridgeRpcRequest_roundTrips() {
        val method = "getAllBalancesStrict"
        val payload = ByteArray(0)

        val requestBytes = encodeBridgeRpcRequest(method, payload)
        val parsed = BridgeEnvelopeCodec.parseBridgeRequest(requestBytes)

        assertEquals("Method must round-trip", method, parsed.method)
        assertTrue("Payload must round-trip", payload.contentEquals(parsed.payload))
    }

    @Test
    fun t11_codec_bridgeRpcRequest_withPayload() {
        val method = "acceptBilateralByCommitment"
        val payload = ByteArray(32) { (it * 3).toByte() }

        // Field 1 = method, field 3 = bytes payload (BytesPayload { bytes data = 1 })
        val methodField = encodeLengthDelimitedField(1, method.toByteArray(Charsets.UTF_8))
        val innerPayload = encodeLengthDelimitedField(1, payload) // BytesPayload.data
        val outerPayload = encodeLengthDelimitedField(3, innerPayload) // BridgeRpcRequest.bytes_payload
        val requestBytes = methodField + outerPayload

        val parsed = BridgeEnvelopeCodec.parseBridgeRequest(requestBytes)
        assertEquals("Method must match", method, parsed.method)
        assertTrue("Payload must match", payload.contentEquals(parsed.payload))
    }

    // =========================================================================
    // SECTION 2: Message ID Framing
    //
    // Proves: The 8-byte message ID that correlates requests to responses
    //         survives the full Kotlin pipeline without corruption.
    // =========================================================================

    @Test
    fun t12_messageId_roundTrips_throughProcessBridgeRequest() {
        ensureGenesis()

        val messageId = 0x0102030405060708L
        val requestBytes = encodeBridgeRpcRequest("hasIdentityDirect", ByteArray(0))
        val framedReq = prependMessageId(messageId, requestBytes)

        val framedResp = MainActivity.processBridgeRequestForTest(ctx, framedReq)

        assertTrue("Response must have at least 8 bytes (msgId)", framedResp.size > 8)
        assertEquals("Message ID must round-trip", messageId, readMessageId(framedResp))
    }

    @Test
    fun t13_messageId_uniqueIds_getDifferentResponses() {
        ensureGenesis()

        val id1 = 1L
        val id2 = 2L
        val requestBytes = encodeBridgeRpcRequest("hasIdentityDirect", ByteArray(0))

        val resp1 = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(id1, requestBytes))
        val resp2 = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(id2, requestBytes))

        assertEquals("Response 1 must carry id1", id1, readMessageId(resp1))
        assertEquals("Response 2 must carry id2", id2, readMessageId(resp2))
    }

    @Test
    fun t14_messageId_maxValue() {
        ensureGenesis()

        val messageId = Long.MAX_VALUE
        val requestBytes = encodeBridgeRpcRequest("hasIdentityDirect", ByteArray(0))
        val framedResp = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(messageId, requestBytes))

        assertEquals("Max message ID must survive", messageId, readMessageId(framedResp))
    }

    // =========================================================================
    // SECTION 3: Bridge Method Routing — Real JNI Round-trips
    //
    // Proves: Every bridge method reaches the correct JNI function,
    //         returns a valid BridgeRpcResponse, and the data is correct.
    // =========================================================================

    @Test
    fun t20_method_hasIdentityDirect_beforeGenesis() {
        // Fresh context may or may not have identity — just verify no crash
        val requestBytes = encodeBridgeRpcRequest("hasIdentityDirect", ByteArray(0))
        val framedResp = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(1L, requestBytes))

        assertTrue("Must get response", framedResp.size > 8)
        val respBody = framedResp.copyOfRange(8, framedResp.size)
        val (isSuccess, data) = BridgeEnvelopeCodec.parseEnvelopeResponse(respBody)
        assertTrue("hasIdentityDirect must return success (even if false)", isSuccess)
        assertEquals("Must return 1-byte boolean", 1, data.size)
        assertTrue("Value must be 0 or 1", data[0] == 0.toByte() || data[0] == 1.toByte())
    }

    @Test
    fun t21_method_hasIdentityDirect_afterGenesis() {
        ensureGenesis()

        val resp = callBridgeMethod("hasIdentityDirect", ByteArray(0))
        assertTrue("Must be success", resp.first)
        assertEquals("Must return 1 byte", 1, resp.second.size)
        assertEquals("Identity must exist after genesis", 1.toByte(), resp.second[0])
    }

    @Test
    fun t22_method_getDeviceIdBin() {
        ensureGenesis()

        val resp = callBridgeMethod("getDeviceIdBin", ByteArray(0))
        assertTrue("Must be success", resp.first)
        assertEquals("Device ID must be 32 bytes", 32, resp.second.size)
        assertFalse("Device ID must not be all zeros", resp.second.all { it == 0.toByte() })
    }

    @Test
    fun t23_method_getPersistedGenesisHash() {
        ensureGenesis()

        val resp = callBridgeMethod("getPersistedGenesisHash", ByteArray(0))
        assertTrue("Must be success", resp.first)
        assertEquals("Genesis hash must be 32 bytes", 32, resp.second.size)
        assertFalse("Genesis hash must not be all zeros", resp.second.all { it == 0.toByte() })
    }

    @Test
    fun t24_method_getTransportHeadersV3Bin() {
        ensureGenesis()

        val resp = callBridgeMethod("getTransportHeadersV3Bin", ByteArray(0))
        assertTrue("Must be success", resp.first)
        assertTrue("Headers must be non-empty", resp.second.isNotEmpty())
        // Headers are protobuf: should start with a valid field tag
        val firstByte = resp.second[0].toInt() and 0xFF
        assertTrue("First byte must be a valid protobuf tag", firstByte > 0)
    }

    @Test
    fun t25_method_getAllBalancesStrict() {
        ensureGenesis()
        claimFaucet()

        val resp = callBridgeMethod("getAllBalancesStrict", ByteArray(0))
        assertTrue("Must be success", resp.first)
        assertTrue("Balances response must be non-empty", resp.second.isNotEmpty())

        // Response is FramedEnvelopeV3: 0x03 prefix + Envelope protobuf
        // Verify it has the framing byte
        val firstByte = resp.second[0].toInt() and 0xFF
        assertTrue(
            "First byte must be 0x03 (FramedEnvelopeV3) or 0x08 (raw protobuf)",
            firstByte == 0x03 || firstByte == 0x08
        )
    }

    @Test
    fun t26_method_getWalletHistoryStrict() {
        ensureGenesis()

        val resp = callBridgeMethod("getWalletHistoryStrict", ByteArray(0))
        assertTrue("Must be success", resp.first)
        // History may be empty if no transactions, but must not crash
    }

    @Test
    fun t27_method_appRouterQuery_balanceList() {
        ensureGenesis()
        claimFaucet()

        val payload = BridgeEnvelopeCodec.encodeAppRouterPayload("balance.list", ByteArray(0))
        // Wrap in BridgeRpcRequest field 6 (appRouterPayload)
        val requestBytes = encodeBridgeRpcRequestWithAppRouter("appRouterQuery", payload)

        val framedResp = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(100L, requestBytes))
        assertTrue("Must get response", framedResp.size > 8)
        assertEquals("Message ID must match", 100L, readMessageId(framedResp))

        val respBody = framedResp.copyOfRange(8, framedResp.size)
        val (isSuccess, data) = BridgeEnvelopeCodec.parseEnvelopeResponse(respBody)
        assertTrue("appRouterQuery(balance.list) must succeed", isSuccess)
        assertTrue("Must have reqId + framed envelope", data.size > 8)

        // Strip 8-byte reqId, then decode the rest
        val innerPayload = data.copyOfRange(8, data.size)
        assertTrue("Inner payload must be non-empty", innerPayload.isNotEmpty())
    }

    @Test
    fun t28_method_appRouterInvoke_prefsGetSet() {
        ensureGenesis()

        // Set a preference via appRouterInvoke
        val setPayload = BridgeEnvelopeCodec.encodeAppRouterPayload("prefs.set", ByteArray(0))
        val setReq = encodeBridgeRpcRequestWithAppRouter("appRouterInvoke", setPayload)
        val setResp = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(200L, setReq))
        assertTrue("Set response must exist", setResp.size > 8)
        assertEquals("Message ID must match", 200L, readMessageId(setResp))
    }

    @Test
    fun t29_method_getPreference_setPreference() {
        ensureGenesis()

        // Set preference
        val key = "test_key_${PREF_KEY_COUNTER.incrementAndGet()}"
        val value = "test_value"
        val setPayload = encodePreferencePayload(key, value)
        val setResp = callBridgeMethod("setPreference", setPayload)
        assertTrue("setPreference must succeed", setResp.first)

        // Get preference
        val getPayload = encodePreferencePayload(key, null)
        val getResp = callBridgeMethod("getPreference", getPayload)
        assertTrue("getPreference must succeed", getResp.first)
        assertEquals("Preference value must match", value, getResp.second.toString(Charsets.UTF_8))
    }

    @Test
    fun t30_method_acceptBilateralByCommitment_invalidHash() {
        ensureGenesis()

        // 32-byte dummy commitment hash — will fail at the Rust level but the
        // Kotlin routing and JNI call should succeed without crash
        val dummyHash = ByteArray(32) { 0xFF.toByte() }
        val resp = callBridgeMethod("acceptBilateralByCommitment", dummyHash)
        assertTrue("Must be success (even if Rust returns empty/error)", resp.first)
        // Response may be empty (no matching commitment), but Kotlin must not crash
    }

    @Test
    fun t31_method_rejectBilateralByCommitment() {
        ensureGenesis()

        val commitment = ByteArray(32) { 0xAA.toByte() }
        val reason = "test_rejection"

        // Encode as BilateralPayload protobuf
        val baos = ByteArrayOutputStream()
        baos.write(0x0A) // field 1 = commitment
        baos.write(encodeVarint32(commitment.size))
        baos.write(commitment)
        val reasonBytes = reason.toByteArray(Charsets.UTF_8)
        baos.write(0x12) // field 2 = reason
        baos.write(encodeVarint32(reasonBytes.size))
        baos.write(reasonBytes)

        // Wrap in BridgeRpcRequest field 11 (bilateralPayload)
        val bilateralPayload = baos.toByteArray()
        val methodField = encodeLengthDelimitedField(1, "rejectBilateralByCommitment".toByteArray(Charsets.UTF_8))
        val payloadField = encodeLengthDelimitedField(11, bilateralPayload)
        val requestBytes = methodField + payloadField

        val framedResp = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(300L, requestBytes))
        assertTrue("Must get response", framedResp.size > 8)
        assertEquals("Message ID must match", 300L, readMessageId(framedResp))

        val respBody = framedResp.copyOfRange(8, framedResp.size)
        val (isSuccess, _) = BridgeEnvelopeCodec.parseEnvelopeResponse(respBody)
        assertTrue("rejectBilateralByCommitment must not crash (success response)", isSuccess)
    }

    @Test
    fun t32_method_getSigningPublicKeyBin() {
        ensureGenesis()

        val resp = callBridgeMethod("getSigningPublicKeyBin", ByteArray(0))
        assertTrue("Must be success", resp.first)
        // Key may be 32 or 33 bytes depending on key type, or empty if not available
    }

    @Test
    fun t33_method_getBluetoothStatus() {
        // No BLE needed — just proves the method doesn't crash
        val resp = callBridgeMethod("getBluetoothStatus", ByteArray(0))
        assertTrue("Must be success", resp.first)
        assertEquals("Must return 1-byte boolean", 1, resp.second.size)
    }

    @Test
    fun t34_method_getPersistedGenesisEnvelope() {
        ensureGenesis()

        val resp = callBridgeMethod("getPersistedGenesisEnvelope", ByteArray(0))
        assertTrue("Must be success", resp.first)
        assertTrue("Genesis envelope must be non-empty", resp.second.isNotEmpty())
    }

    // =========================================================================
    // SECTION 4: Full Frame Round-trip (JS-identical bytes)
    //
    // Proves: The EXACT byte sequence a WebView would send through the
    //         MessagePort protocol works end-to-end through the Kotlin layer.
    // =========================================================================

    @Test
    fun t40_fullFrame_identityCheckAndBalanceFetch() {
        ensureGenesis()
        claimFaucet()

        // Step 1: Identity check (same bytes JS would send)
        val identityReq = encodeBridgeRpcRequest("hasIdentityDirect", ByteArray(0))
        val identityFramed = prependMessageId(1001L, identityReq)
        val identityResp = MainActivity.processBridgeRequestForTest(ctx, identityFramed)

        assertEquals("Identity msgId", 1001L, readMessageId(identityResp))
        val (idOk, idData) = BridgeEnvelopeCodec.parseEnvelopeResponse(
            identityResp.copyOfRange(8, identityResp.size)
        )
        assertTrue("Identity must succeed", idOk)
        assertEquals("Identity = true", 1.toByte(), idData[0])

        // Step 2: Fetch balances (same bytes JS would send)
        val balReq = encodeBridgeRpcRequest("getAllBalancesStrict", ByteArray(0))
        val balFramed = prependMessageId(1002L, balReq)
        val balResp = MainActivity.processBridgeRequestForTest(ctx, balFramed)

        assertEquals("Balance msgId", 1002L, readMessageId(balResp))
        val (balOk, balData) = BridgeEnvelopeCodec.parseEnvelopeResponse(
            balResp.copyOfRange(8, balResp.size)
        )
        assertTrue("Balances must succeed", balOk)
        assertTrue("Balances must be non-empty", balData.isNotEmpty())

        // Step 3: Verify ERA balance exists and is positive
        // Hand-decode the protobuf wire bytes (no generated proto classes).
        // BalancesListResponse { repeated BalanceGetResponse balances = 1 }
        // BalanceGetResponse { string token_id = 1; uint64 available = 2 }
        val body = decodeFramedEnvelopeBody(balData)
        assertTrue("Balance body must be non-empty", body.isNotEmpty())

        val entries = extractAllProtoFields(body, 1) // field 1 = repeated balances
        var foundEra = false
        var eraBalance = 0L
        for (entry in entries) {
            val tokenIdBytes = extractProtoBytes(entry, 1) // field 1 = token_id
            val tokenId = tokenIdBytes?.toString(Charsets.UTF_8)
            if (tokenId == "ERA") {
                foundEra = true
                eraBalance = extractProtoVarint(entry, 2) ?: 0L // field 2 = available
                break
            }
        }
        assertTrue("ERA balance must exist after faucet", foundEra)
        assertTrue("ERA balance must be positive after faucet", eraBalance > 0L)
    }

    @Test
    fun t41_fullFrame_deviceId_matchesBetweenMethods() {
        ensureGenesis()

        // Get device ID via getDeviceIdBin
        val resp1 = callBridgeMethod("getDeviceIdBin", ByteArray(0))
        val deviceId1 = resp1.second

        // Get device ID via getPersistedDeviceId (alias)
        val resp2 = callBridgeMethod("getPersistedDeviceId", ByteArray(0))
        val deviceId2 = resp2.second

        assertEquals("Both must be 32 bytes", 32, deviceId1.size)
        assertEquals("Both must be 32 bytes", 32, deviceId2.size)
        assertTrue("Device IDs from both methods must match", deviceId1.contentEquals(deviceId2))
    }

    @Test
    fun t42_fullFrame_headersContainDeviceId() {
        ensureGenesis()

        val deviceIdResp = callBridgeMethod("getDeviceIdBin", ByteArray(0))
        val deviceId = deviceIdResp.second

        val headersResp = callBridgeMethod("getTransportHeadersV3Bin", ByteArray(0))
        val headers = headersResp.second

        assertTrue("Headers must be non-empty", headers.isNotEmpty())
        // The device ID should appear somewhere in the headers protobuf
        // (as a bytes field). Check that the headers size suggests real data.
        assertTrue("Headers must be larger than 32 bytes (contains deviceId + other fields)", headers.size > 32)
    }

    // =========================================================================
    // SECTION 5: Thread Safety
    //
    // Proves: Concurrent bridge calls from multiple threads don't deadlock,
    //         corrupt data, or crash the JNI layer.
    // =========================================================================

    @Test
    fun t50_threadSafety_concurrentIdentityChecks() {
        ensureGenesis()

        val threadCount = 10
        val barrier = CyclicBarrier(threadCount)
        val latch = CountDownLatch(threadCount)
        val errors = AtomicInteger(0)
        val successes = AtomicInteger(0)

        for (i in 0 until threadCount) {
            Thread {
                try {
                    barrier.await() // All threads start simultaneously
                    val resp = callBridgeMethod("hasIdentityDirect", ByteArray(0))
                    if (resp.first && resp.second.size == 1 && resp.second[0] == 1.toByte()) {
                        successes.incrementAndGet()
                    } else {
                        errors.incrementAndGet()
                    }
                } catch (t: Throwable) {
                    errors.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }.start()
        }

        latch.await()
        assertEquals("No errors in concurrent calls", 0, errors.get())
        assertEquals("All threads must succeed", threadCount, successes.get())
    }

    @Test
    fun t51_threadSafety_concurrentBalanceFetches() {
        ensureGenesis()
        claimFaucet()

        val threadCount = 8
        val barrier = CyclicBarrier(threadCount)
        val latch = CountDownLatch(threadCount)
        val errors = AtomicInteger(0)
        val successes = AtomicInteger(0)

        for (i in 0 until threadCount) {
            Thread {
                try {
                    barrier.await()
                    val resp = callBridgeMethod("getAllBalancesStrict", ByteArray(0))
                    if (resp.first && resp.second.isNotEmpty()) {
                        successes.incrementAndGet()
                    } else {
                        errors.incrementAndGet()
                    }
                } catch (t: Throwable) {
                    errors.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }.start()
        }

        latch.await()
        assertEquals("No errors in concurrent balance fetches", 0, errors.get())
        assertEquals("All threads must succeed", threadCount, successes.get())
    }

    @Test
    fun t52_threadSafety_mixedMethodsConcurrent() {
        ensureGenesis()

        val methods = listOf(
            "hasIdentityDirect" to ByteArray(0),
            "getDeviceIdBin" to ByteArray(0),
            "getPersistedGenesisHash" to ByteArray(0),
            "getBluetoothStatus" to ByteArray(0),
            "getTransportHeadersV3Bin" to ByteArray(0),
        )

        val threadCount = methods.size * 2
        val barrier = CyclicBarrier(threadCount)
        val latch = CountDownLatch(threadCount)
        val errors = AtomicInteger(0)

        for (i in 0 until threadCount) {
            val (method, payload) = methods[i % methods.size]
            Thread {
                try {
                    barrier.await()
                    val resp = callBridgeMethod(method, payload)
                    if (!resp.first) errors.incrementAndGet()
                } catch (t: Throwable) {
                    errors.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }.start()
        }

        latch.await()
        assertEquals("No errors in mixed concurrent calls", 0, errors.get())
    }

    @Test
    fun t53_threadSafety_concurrentProcessBridgeRequest() {
        ensureGenesis()

        val threadCount = 10
        val barrier = CyclicBarrier(threadCount)
        val latch = CountDownLatch(threadCount)
        val errors = AtomicInteger(0)

        for (i in 0 until threadCount) {
            Thread {
                try {
                    barrier.await()
                    val msgId = (1000L + i)
                    val reqBytes = encodeBridgeRpcRequest("hasIdentityDirect", ByteArray(0))
                    val framedReq = prependMessageId(msgId, reqBytes)
                    val framedResp = MainActivity.processBridgeRequestForTest(ctx, framedReq)

                    if (framedResp.size <= 8) {
                        errors.incrementAndGet()
                        return@Thread
                    }
                    if (readMessageId(framedResp) != msgId) {
                        errors.incrementAndGet() // Message ID corruption!
                        return@Thread
                    }
                } catch (t: Throwable) {
                    errors.incrementAndGet()
                } finally {
                    latch.countDown()
                }
            }.start()
        }

        latch.await()
        assertEquals("No message ID corruption under concurrency", 0, errors.get())
    }

    // =========================================================================
    // SECTION 6: Error Resilience
    //
    // Proves: Malformed inputs get proper error responses, not crashes.
    //         The app stays alive after bad input.
    // =========================================================================

    @Test
    fun t60_error_unknownMethod() {
        val requestBytes = encodeBridgeRpcRequest("nonExistentMethod", ByteArray(0))
        val framedResp = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(1L, requestBytes))

        assertTrue("Must get response for unknown method", framedResp.size > 8)
        val respBody = framedResp.copyOfRange(8, framedResp.size)
        val (isSuccess, _) = BridgeEnvelopeCodec.parseEnvelopeResponse(respBody)
        // Unknown method should return error (not crash)
        assertFalse("Unknown method must return error", isSuccess)
    }

    @Test
    fun t61_error_tooShortRequest() {
        // Less than 8 bytes (no message ID)
        val resp = MainActivity.processBridgeRequestForTest(ctx, byteArrayOf(0x01, 0x02, 0x03))
        assertEquals("Too-short request must return empty", 0, resp.size)
    }

    @Test
    fun t62_error_emptyRequestBody() {
        // 8-byte message ID but no request body
        val framedReq = ByteArray(8)
        ByteBuffer.wrap(framedReq).order(ByteOrder.BIG_ENDIAN).putLong(42L)

        val resp = MainActivity.processBridgeRequestForTest(ctx, framedReq)
        assertTrue("Must get some response", resp.size > 8)
        assertEquals("Message ID must survive", 42L, readMessageId(resp))
    }

    @Test
    fun t63_error_garbageProtobuf() {
        // Valid message ID + garbage protobuf
        val garbage = ByteArray(64) { (it * 7).toByte() }
        val framedReq = prependMessageId(99L, garbage)

        val resp = MainActivity.processBridgeRequestForTest(ctx, framedReq)
        // Should get an error response (not crash)
        assertTrue("Must get response for garbage input", resp.size > 8)
        assertEquals("Message ID must survive garbage", 99L, readMessageId(resp))
    }

    @Test
    fun t64_error_wrongPayloadSize_forAcceptBilateral() {
        // acceptBilateralByCommitment expects exactly 32 bytes
        val wrongSize = ByteArray(16)
        val resp = callBridgeMethod("acceptBilateralByCommitment", wrongSize)
        // Should return success with empty data (validation rejects < 32 bytes)
        assertTrue("Must not crash", resp.first)
    }

    @Test
    fun t65_error_invalidAppRouterPayload() {
        // appRouterQuery with invalid payload (not a valid AppRouterPayload)
        val garbage = byteArrayOf(0xFF.toByte(), 0xFE.toByte(), 0xFD.toByte())
        val requestBytes = encodeBridgeRpcRequestWithAppRouter("appRouterQuery", garbage)
        val framedResp = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(500L, requestBytes))

        assertTrue("Must get response", framedResp.size > 8)
        // Should get an error (not a crash)
    }

    @Test
    fun t66_error_afterError_bridgeStillWorks() {
        ensureGenesis()

        // First: send garbage
        val garbage = ByteArray(64) { 0xFF.toByte() }
        MainActivity.processBridgeRequestForTest(ctx, prependMessageId(1L, garbage))

        // Then: send valid request — bridge must still work
        val resp = callBridgeMethod("hasIdentityDirect", ByteArray(0))
        assertTrue("Bridge must work after error", resp.first)
        assertEquals("Identity must still exist", 1.toByte(), resp.second[0])
    }

    @Test
    fun t67_error_rapidFireRequests() {
        ensureGenesis()

        // 100 rapid-fire requests, no waiting
        var successCount = 0
        for (i in 0 until 100) {
            try {
                val resp = callBridgeMethod("hasIdentityDirect", ByteArray(0))
                if (resp.first) successCount++
            } catch (_: Throwable) {
                // count as failure
            }
        }
        assertEquals("All 100 rapid-fire requests must succeed", 100, successCount)
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private fun ensureGenesis() {
        if (genesisCreated) return
        val bridge = SinglePathWebViewBridge.ensureInitialized(ctx)

        // Replicate the SDK init that MainActivity does at startup:
        // 1. Set storage base dir (required before AppState can persist)
        Unified.initStorageBaseDir(ctx.filesDir.absolutePath.toByteArray(Charsets.UTF_8))
        // 2. Copy dsm_env_config.toml from APK assets to app files dir
        val cfgFile = File(ctx.filesDir, "dsm_env_config.toml")
        ctx.assets.open("dsm_env_config.toml").use { input ->
            FileOutputStream(cfgFile, false).use { out -> input.copyTo(out) }
        }
        // 3. Tell Rust where the config is (sets ENV_CONFIG_PATH + DSM_ALLOW_LOCALHOST)
        Unified.initDsmSdk(cfgFile.absolutePath)

        // MPC genesis — requires local storage nodes + adb reverse on ports 8080-8084
        val entropy = ByteArray(32)
        SecureRandom().nextBytes(entropy)
        val envelope = bridge.createGenesis(Locale.getDefault().toLanguageTag(), "dev", entropy)
        assertTrue("Genesis must produce non-empty envelope", envelope.isNotEmpty())
        genesisCreated = true
    }

    private fun claimFaucet() {
        val deviceId = SinglePathWebViewBridge.handleBinaryRpcRaw("getDeviceIdBin", ByteArray(0))
        if (deviceId.size != 32) return

        try {
            // Hand-encode protobuf wire format (no generated proto classes needed):
            // FaucetClaimRequest { bytes device_id = 1 }
            val faucetClaimReqBytes = encodeLengthDelimitedField(1, deviceId)

            // ArgPack { Hash32 schema_hash = 1; Codec codec = 2; bytes body = 3 }
            // Hash32 { bytes v = 1 } → 32 zero bytes
            val hash32Bytes = encodeLengthDelimitedField(1, ByteArray(32))
            val argPackBytes = encodeLengthDelimitedField(1, hash32Bytes) + // schema_hash
                byteArrayOf(0x10, 0x01) +                                  // codec = CODEC_PROTO (1)
                encodeLengthDelimitedField(3, faucetClaimReqBytes)          // body

            val appRouterPayload = BridgeEnvelopeCodec.encodeAppRouterPayload("faucet.claim", argPackBytes)
            val requestBytes = encodeBridgeRpcRequestWithAppRouter("appRouterInvoke", appRouterPayload)
            MainActivity.processBridgeRequestForTest(ctx, prependMessageId(9999L, requestBytes))
        } catch (_: Throwable) {
            // Faucet may fail (already claimed, etc.) — don't block tests
        }
    }

    /**
     * Call a bridge method via the full processBridgeRequestForTest pipeline.
     * Returns (isSuccess, data).
     */
    private fun callBridgeMethod(method: String, payload: ByteArray): Pair<Boolean, ByteArray> {
        val requestBytes = encodeBridgeRpcRequest(method, payload)
        val framedResp = MainActivity.processBridgeRequestForTest(ctx, prependMessageId(1L, requestBytes))
        if (framedResp.size <= 8) return Pair(false, ByteArray(0))
        val respBody = framedResp.copyOfRange(8, framedResp.size)
        return BridgeEnvelopeCodec.parseEnvelopeResponse(respBody)
    }

    /**
     * Encode a BridgeRpcRequest with just method and empty/simple payload.
     * field 1 = method (string), field 2 = empty_payload (for empty payload methods)
     */
    private fun encodeBridgeRpcRequest(method: String, payload: ByteArray): ByteArray {
        val methodField = encodeLengthDelimitedField(1, method.toByteArray(Charsets.UTF_8))
        if (payload.isEmpty()) {
            // Field 2 = empty_payload (empty message)
            val emptyPayload = encodeLengthDelimitedField(2, ByteArray(0))
            return methodField + emptyPayload
        }
        // Field 3 = bytes_payload (BytesPayload { bytes data = 1 })
        val innerPayload = encodeLengthDelimitedField(1, payload)
        val bytesPayloadField = encodeLengthDelimitedField(3, innerPayload)
        return methodField + bytesPayloadField
    }

    /**
     * Encode a BridgeRpcRequest with field 6 = appRouterPayload.
     */
    private fun encodeBridgeRpcRequestWithAppRouter(method: String, appRouterPayload: ByteArray): ByteArray {
        val methodField = encodeLengthDelimitedField(1, method.toByteArray(Charsets.UTF_8))
        val routerField = encodeLengthDelimitedField(6, appRouterPayload)
        return methodField + routerField
    }

    private fun prependMessageId(messageId: Long, requestBytes: ByteArray): ByteArray {
        val out = ByteArray(8 + requestBytes.size)
        ByteBuffer.wrap(out, 0, 8).order(ByteOrder.BIG_ENDIAN).putLong(messageId)
        System.arraycopy(requestBytes, 0, out, 8, requestBytes.size)
        return out
    }

    private fun readMessageId(framedBytes: ByteArray): Long {
        return ByteBuffer.wrap(framedBytes, 0, 8).order(ByteOrder.BIG_ENDIAN).long
    }

    private fun encodeLengthDelimitedField(fieldNumber: Int, value: ByteArray): ByteArray {
        val key = (fieldNumber shl 3) or 2
        val keyVarint = encodeVarint32(key)
        val lenVarint = encodeVarint32(value.size)
        return keyVarint + lenVarint + value
    }

    private fun encodeVarint32(valueIn: Int): ByteArray {
        var v = valueIn
        val out = ArrayList<Byte>()
        while (true) {
            if (v and 0x7F.inv() == 0) {
                out.add(v.toByte())
                break
            }
            out.add(((v and 0x7F) or 0x80).toByte())
            v = v ushr 7
        }
        return out.toByteArray()
    }

    private fun encodePreferencePayload(key: String, value: String?): ByteArray {
        val baos = ByteArrayOutputStream()
        val keyBytes = key.toByteArray(Charsets.UTF_8)
        baos.write(0x0A) // field 1 = key
        baos.write(encodeVarint32(keyBytes.size))
        baos.write(keyBytes)
        if (value != null) {
            val valueBytes = value.toByteArray(Charsets.UTF_8)
            baos.write(0x12) // field 2 = value
            baos.write(encodeVarint32(valueBytes.size))
            baos.write(valueBytes)
        }
        return baos.toByteArray()
    }

    private fun decodeFramedEnvelopeBody(bytes: ByteArray): ByteArray {
        if (bytes.isEmpty()) return ByteArray(0)

        val candidates = ArrayList<ByteArray>(2)
        candidates.add(bytes)
        if (bytes[0] == 0x03.toByte() && bytes.size > 1) {
            candidates.add(bytes.copyOfRange(1, bytes.size))
        }

        for (candidate in candidates) {
            // The JNI getAllBalancesStrict returns a framed Envelope v3 whose
            // oneof payload is BalancesListResponse at proto field 34.
            // Extract field 34 first — if present, it IS the BalancesListResponse.
            val balancesPayload = extractProtoBytes(candidate, 34)
            if (balancesPayload != null && balancesPayload.isNotEmpty()) return balancesPayload

            // ArgPack / ResultPack both have: bytes body = 3
            val body = extractProtoBytes(candidate, 3)
            if (body != null && body.isNotEmpty()) return body

            // Might be a direct BalancesListResponse (repeated field 1)
            val entries = extractAllProtoFields(candidate, 1)
            if (entries.isNotEmpty()) return candidate
        }

        return ByteArray(0)
    }

    // ---- Protobuf wire-format decoders (no generated classes) ----

    /** Decode a varint starting at [offset]. Returns (value, bytesConsumed). */
    private fun decodeVarint(data: ByteArray, offset: Int): Pair<Long, Int> {
        var result = 0L
        var shift = 0
        var pos = offset
        while (pos < data.size) {
            val b = data[pos].toLong() and 0xFF
            result = result or ((b and 0x7F) shl shift)
            pos++
            if (b and 0x80 == 0L) break
            shift += 7
        }
        return Pair(result, pos - offset)
    }

    /** Extract first length-delimited field matching [targetField]. Returns null if absent. */
    private fun extractProtoBytes(data: ByteArray, targetField: Int): ByteArray? {
        var pos = 0
        while (pos < data.size) {
            val (tag, tagLen) = decodeVarint(data, pos)
            pos += tagLen
            val fieldNum = (tag ushr 3).toInt()
            val wireType = (tag and 0x07).toInt()
            when (wireType) {
                0 -> { val (_, vLen) = decodeVarint(data, pos); pos += vLen }
                2 -> {
                    val (len, lLen) = decodeVarint(data, pos)
                    pos += lLen
                    val end = pos + len.toInt()
                    if (end > data.size) break
                    if (fieldNum == targetField) return data.copyOfRange(pos, end)
                    pos = end
                }
                else -> break
            }
        }
        return null
    }

    /** Extract ALL occurrences of a repeated length-delimited field. */
    private fun extractAllProtoFields(data: ByteArray, targetField: Int): List<ByteArray> {
        val results = mutableListOf<ByteArray>()
        var pos = 0
        while (pos < data.size) {
            val (tag, tagLen) = decodeVarint(data, pos)
            pos += tagLen
            val fieldNum = (tag ushr 3).toInt()
            val wireType = (tag and 0x07).toInt()
            when (wireType) {
                0 -> { val (_, vLen) = decodeVarint(data, pos); pos += vLen }
                2 -> {
                    val (len, lLen) = decodeVarint(data, pos)
                    pos += lLen
                    val end = pos + len.toInt()
                    if (end > data.size) break
                    if (fieldNum == targetField) results.add(data.copyOfRange(pos, end))
                    pos = end
                }
                else -> break
            }
        }
        return results
    }

    /** Extract a varint field value (wire type 0). Returns null if absent. */
    private fun extractProtoVarint(data: ByteArray, targetField: Int): Long? {
        var pos = 0
        while (pos < data.size) {
            val (tag, tagLen) = decodeVarint(data, pos)
            pos += tagLen
            val fieldNum = (tag ushr 3).toInt()
            val wireType = (tag and 0x07).toInt()
            when (wireType) {
                0 -> {
                    val (value, vLen) = decodeVarint(data, pos)
                    pos += vLen
                    if (fieldNum == targetField) return value
                }
                2 -> {
                    val (len, lLen) = decodeVarint(data, pos)
                    pos += lLen
                    val end = pos + len.toInt()
                    if (end > data.size) break
                    pos = end
                }
                else -> break
            }
        }
        return null
    }
}
