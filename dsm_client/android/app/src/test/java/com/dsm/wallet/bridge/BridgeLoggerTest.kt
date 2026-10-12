package com.dsm.wallet.bridge

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
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

    // A bridge payload can be the mnemonic, and the log is a file on disk:
    // it names the payload's size and never a byte of it.
    @Test
    fun logBridgeCall_namesThePayloadSize_neverItsBytes() {
        val payload = byteArrayOf(0x01, 0x02, 0x03, 0x04, 0x05)
        BridgeLogger.logBridgeCall("m", payload, null, null)
        val content = String(BridgeLogger.readLogBytes(), Charsets.UTF_8)
        assertTrue("The size is logged", content.contains("payload=5b"))
        assertFalse(
            "No byte of the payload is logged",
            content.contains(BridgeEncoding.base32CrockfordEncode(payload))
        )
    }

    @Test
    fun logBridgeCall_longPayload_notEvenAPrefix() {
        val payload = ByteArray(100) { it.toByte() }
        BridgeLogger.logBridgeCall("m", payload, null, null)
        val content = String(BridgeLogger.readLogBytes(), Charsets.UTF_8)
        assertTrue("The size is logged", content.contains("payload=100b"))
        assertFalse(
            "Not even its first five bytes",
            content.contains(BridgeEncoding.base32CrockfordEncode(payload.copyOfRange(0, 5)))
        )
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
