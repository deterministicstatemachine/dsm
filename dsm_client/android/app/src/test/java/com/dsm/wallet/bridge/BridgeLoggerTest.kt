package com.dsm.wallet.bridge

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * Tests for [BridgeLogger] file I/O and log formatting.
 *
 * Uses Robolectric because appendLine calls SystemClock.elapsedRealtime()
 * and logBridgeCall calls android.util.Log in debug builds.
 *
 * Note: BridgeLogger is a singleton. Each test sets its own temp file via
 * setLogFile, but we cannot reset logFile to null through the public API.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BridgeLoggerTest {

    private lateinit var tempFile: File

    @Before
    fun setUp() {
        tempFile = File.createTempFile("bridge_log_test_", ".log")
        tempFile.deleteOnExit()
        BridgeLogger.setLogFile(tempFile)
    }

    @After
    fun tearDown() {
        tempFile.delete()
    }

    // ── readLogBytes ──────────────────────────────────────────────────────

    @Test
    fun readLogBytes_nonExistentFile_returnsEmpty() {
        val missing = File(tempFile.parent, "does_not_exist.log")
        BridgeLogger.setLogFile(missing)
        assertEquals(0, BridgeLogger.readLogBytes().size)
        BridgeLogger.setLogFile(tempFile)
    }

    @Test
    fun readLogBytes_emptyFile_returnsEmpty() {
        assertEquals(0, BridgeLogger.readLogBytes().size)
    }

    @Test
    fun readLogBytes_readsWrittenContent() {
        tempFile.writeText("hello\n")
        val bytes = BridgeLogger.readLogBytes()
        assertEquals("hello\n", String(bytes, Charsets.UTF_8))
    }

    @Test
    fun readLogBytes_maxBytesTruncation() {
        tempFile.writeBytes(ByteArray(200) { 0x41 })
        val bytes = BridgeLogger.readLogBytes(maxBytes = 50)
        assertEquals(50, bytes.size)
        assertTrue("Should read from end of file", bytes.all { it == 0x41.toByte() })
    }

    // ── logBridgeCall round-trip ──────────────────────────────────────────

    @Test
    fun logBridgeCall_writesMethodToFile() {
        BridgeLogger.logBridgeCall(
            method = "testMethod",
            payload = byteArrayOf(0x01, 0x02),
            response = byteArrayOf(0x03),
            error = null
        )
        val content = String(BridgeLogger.readLogBytes(), Charsets.UTF_8)
        assertTrue("Log should contain method name", content.contains("testMethod"))
        assertTrue("Log should contain BRIDGE prefix", content.contains("BRIDGE:"))
    }

    @Test
    fun logBridgeCall_shortPayload_notTruncated() {
        val payload = byteArrayOf(0x01, 0x02, 0x03)
        val b32 = BridgeEncoding.base32CrockfordEncode(payload)
        BridgeLogger.logBridgeCall("m", payload, null, null)
        val content = String(BridgeLogger.readLogBytes(), Charsets.UTF_8)
        assertTrue("Short payload b32 should appear in full", content.contains(b32))
    }

    @Test
    fun logBridgeCall_longPayload_truncated() {
        val payload = ByteArray(100) { it.toByte() }
        BridgeLogger.logBridgeCall("m", payload, null, null)
        val content = String(BridgeLogger.readLogBytes(), Charsets.UTF_8)
        assertTrue("Long payload should be truncated with ...", content.contains("..."))
    }

    @Test
    fun logBridgeCall_error_showsErrorMessage() {
        BridgeLogger.logBridgeCall(
            method = "failing",
            payload = ByteArray(0),
            response = null,
            error = RuntimeException("boom")
        )
        val content = String(BridgeLogger.readLogBytes(), Charsets.UTF_8)
        assertTrue("Error message should appear", content.contains("boom"))
    }

    // ── logDiagnosticsPayload ─────────────────────────────────────────────

    @Test
    fun logDiagnosticsPayload_writesToFile() {
        BridgeLogger.logDiagnosticsPayload(byteArrayOf(0x01, 0x02))
        val content = String(BridgeLogger.readLogBytes(), Charsets.UTF_8)
        assertTrue(content.contains("DIAGNOSTICS:"))
        assertTrue(content.contains("payload=2b"))
    }

    @Test
    fun logDiagnosticsPayload_longPayload_truncated() {
        val payload = ByteArray(100) { it.toByte() }
        BridgeLogger.logDiagnosticsPayload(payload)
        val content = String(BridgeLogger.readLogBytes(), Charsets.UTF_8)
        assertTrue(content.contains("..."))
    }
}
