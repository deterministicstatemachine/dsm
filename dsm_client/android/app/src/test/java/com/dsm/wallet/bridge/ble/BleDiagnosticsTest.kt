package com.dsm.wallet.bridge.ble

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleDiagnosticsTest {

    // ── recordEvent ───────────────────────────────────────────────────────

    @Test
    fun recordEvent_addsEventToLog() {
        val diag = BleDiagnostics()
        diag.recordEvent(BleDiagEvent(phase = "connect", device = "AA:BB"))

        val log = diag.getEventsLog()
        assertTrue(log.contains("connect"))
        assertTrue(log.contains("AA:BB"))
    }

    @Test
    fun recordEvent_assignsIncrementingSequenceNumbers() {
        val diag = BleDiagnostics()
        diag.recordEvent(BleDiagEvent(phase = "first"))
        diag.recordEvent(BleDiagEvent(phase = "second"))

        val lines = diag.getEventsLog().lines()
        assertEquals(2, lines.size)
        val ts1 = lines[0].substringBefore('|').toLong()
        val ts2 = lines[1].substringBefore('|').toLong()
        assertTrue("Second event ts ($ts2) should be > first ($ts1)", ts2 > ts1)
    }

    @Test
    fun recordEvent_disabledDoesNotRecord() {
        val diag = BleDiagnostics()
        diag.setDebugEnabled(false)
        diag.recordEvent(BleDiagEvent(phase = "invisible"))
        assertEquals("", diag.getEventsLog())
    }

    @Test
    fun recordEvent_capsAt1000() {
        val diag = BleDiagnostics()
        repeat(1100) { diag.recordEvent(BleDiagEvent(phase = "evt$it")) }
        assertEquals(1000, diag.getEventsLog().lines().size)
    }

    @Test
    fun recordEvent_reEnableAfterDisable() {
        val diag = BleDiagnostics()
        diag.setDebugEnabled(false)
        diag.recordEvent(BleDiagEvent(phase = "hidden"))
        diag.setDebugEnabled(true)
        diag.recordEvent(BleDiagEvent(phase = "visible"))

        val log = diag.getEventsLog()
        assertFalse(log.contains("hidden"))
        assertTrue(log.contains("visible"))
    }

    // ── recordError ───────────────────────────────────────────────────────

    @Test
    fun recordError_incrementsCountAndCreatesEvent() {
        val diag = BleDiagnostics()
        diag.recordError(BleErrorCategory.CONNECTION_FAILED, "scan", device = "XX:YY")

        val guidance = diag.getErrorGuidance()
        assertNotNull(guidance)
        assertEquals("CONNECTION_FAILED", guidance!!["category"])
        assertEquals(1, guidance["frequency"])

        val log = diag.getEventsLog()
        assertTrue(log.contains("CONNECTION_FAILED"))
    }

    @Test
    fun recordError_multipleCategories_dominantReturned() {
        val diag = BleDiagnostics()
        diag.recordError(BleErrorCategory.CONNECTION_FAILED, "scan")
        diag.recordError(BleErrorCategory.CONNECTION_FAILED, "scan")
        diag.recordError(BleErrorCategory.MTU_TOO_SMALL, "mtu")

        val guidance = diag.getErrorGuidance()!!
        assertEquals("CONNECTION_FAILED", guidance["category"])
        assertEquals(2, guidance["frequency"])
    }

    @Test
    fun recordError_guidanceContainsUserMessageAndSteps() {
        val diag = BleDiagnostics()
        diag.recordError(BleErrorCategory.BLUETOOTH_DISABLED, "init")

        val guidance = diag.getErrorGuidance()!!
        val message = guidance["message"] as String
        assertTrue(message.contains("Bluetooth"))
        @Suppress("UNCHECKED_CAST")
        val steps = guidance["troubleshooting"] as List<String>
        assertTrue(steps.isNotEmpty())
    }

    // ── getErrorGuidance ──────────────────────────────────────────────────

    @Test
    fun getErrorGuidance_noErrors_returnsNull() {
        assertNull(BleDiagnostics().getErrorGuidance())
    }

    // ── hasPersistentIssues ───────────────────────────────────────────────

    @Test
    fun hasPersistentIssues_belowThreshold() {
        val diag = BleDiagnostics()
        repeat(10) { diag.recordError(BleErrorCategory.CONNECTION_FAILED, "test") }
        assertFalse(diag.hasPersistentIssues())
    }

    @Test
    fun hasPersistentIssues_aboveThreshold() {
        val diag = BleDiagnostics()
        repeat(11) { diag.recordError(BleErrorCategory.CONNECTION_FAILED, "test") }
        assertTrue(diag.hasPersistentIssues())
    }

    @Test
    fun hasPersistentIssues_sumsAcrossCategories() {
        val diag = BleDiagnostics()
        repeat(6) { diag.recordError(BleErrorCategory.CONNECTION_FAILED, "a") }
        repeat(6) { diag.recordError(BleErrorCategory.MTU_TOO_SMALL, "b") }
        assertTrue(diag.hasPersistentIssues())
    }

    // ── clearEvents ───────────────────────────────────────────────────────

    @Test
    fun clearEvents_resetsAllState() {
        val diag = BleDiagnostics()
        diag.recordEvent(BleDiagEvent(phase = "evt"))
        diag.recordError(BleErrorCategory.UNKNOWN, "test")
        diag.clearEvents()

        assertEquals("", diag.getEventsLog())
        assertNull(diag.getErrorGuidance())
        assertFalse(diag.hasPersistentIssues())
    }

    // ── getEventsLog ──────────────────────────────────────────────────────

    @Test
    fun getEventsLog_pipeDelimitedFormat() {
        val diag = BleDiagnostics()
        diag.recordEvent(BleDiagEvent(phase = "scan", device = "DD:EE", status = 0))

        val log = diag.getEventsLog()
        val parts = log.split("|")
        assertTrue("Expected pipe-delimited fields, got: $log", parts.size >= 3)
        assertEquals("scan", parts[1])
        assertEquals("DD:EE", parts[2])
    }

    @Test
    fun getEventsLog_pipesInDeviceNameEscaped() {
        val diag = BleDiagnostics()
        diag.recordEvent(BleDiagEvent(phase = "scan", device = "AA|BB"))

        val log = diag.getEventsLog()
        assertFalse("Pipe in device name should be escaped", log.contains("AA|BB"))
        assertTrue(log.contains("AA/BB"))
    }
}
