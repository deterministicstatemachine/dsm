package com.dsm.wallet.bridge.ble

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class BleErrorCategoryTest {

    // ── Enum completeness ──────────────────────────────────────────────────

    @Test
    fun enumHasExpected14Values() {
        assertEquals(14, BleErrorCategory.entries.size)
    }

    @Test
    fun allExpectedEntriesExist() {
        val expected = setOf(
            "BLUETOOTH_DISABLED",
            "PERMISSION_DENIED",
            "HARDWARE_UNAVAILABLE",
            "MTU_TOO_SMALL",
            "MTU_NEGOTIATION_FAILED",
            "CONNECTION_FAILED",
            "SERVICE_DISCOVERY_FAILED",
            "CHARACTERISTIC_READ_FAILED",
            "CHARACTERISTIC_WRITE_FAILED",
            "CHARACTERISTIC_ERROR",
            "ADVERTISING_FAILED",
            "SCANNING_FAILED",
            "PROTOCOL_TIMEOUT",
            "UNKNOWN",
        )
        assertEquals(expected, BleErrorCategory.entries.map { it.name }.toSet())
    }

    @Test
    fun valueOfRoundTrips() {
        for (entry in BleErrorCategory.entries) {
            assertEquals(entry, BleErrorCategory.valueOf(entry.name))
        }
    }

    // ── getUserMessage() ───────────────────────────────────────────────────

    @Test
    fun everyEntryReturnsNonBlankUserMessage() {
        for (entry in BleErrorCategory.entries) {
            val msg = entry.getUserMessage()
            assertTrue("$entry has blank user message", msg.isNotBlank())
        }
    }

    @Test
    fun bluetoothDisabled_userMessageMentionsBluetooth() {
        assertTrue(
            BleErrorCategory.BLUETOOTH_DISABLED.getUserMessage().contains("Bluetooth", ignoreCase = true)
        )
    }

    @Test
    fun permissionDenied_userMessageMentionsPermission() {
        assertTrue(
            BleErrorCategory.PERMISSION_DENIED.getUserMessage().contains("permission", ignoreCase = true)
        )
    }

    @Test
    fun mtuTooSmall_userMessageMentionsAndroid8() {
        assertTrue(
            BleErrorCategory.MTU_TOO_SMALL.getUserMessage().contains("Android 8.0")
        )
    }

    @Test
    fun connectionFailed_userMessageMentionsDistance() {
        assertTrue(
            BleErrorCategory.CONNECTION_FAILED.getUserMessage().contains("10 meters")
        )
    }

    @Test
    fun unknown_userMessageSuggestsRestart() {
        assertTrue(
            BleErrorCategory.UNKNOWN.getUserMessage().contains("Restart", ignoreCase = true)
        )
    }

    @Test
    fun userMessages_areDistinctPerCategory() {
        val messages = BleErrorCategory.entries.map { it.getUserMessage() }
        assertEquals(messages.size, messages.toSet().size)
    }

    // ── getTroubleshootingSteps() ──────────────────────────────────────────

    @Test
    fun everyEntryReturnsNonEmptyTroubleshootingSteps() {
        for (entry in BleErrorCategory.entries) {
            val steps = entry.getTroubleshootingSteps()
            assertTrue("$entry returned empty troubleshooting steps", steps.isNotEmpty())
        }
    }

    @Test
    fun troubleshootingStepsContainNoBlankEntries() {
        for (entry in BleErrorCategory.entries) {
            for (step in entry.getTroubleshootingSteps()) {
                assertTrue("$entry has blank step", step.isNotBlank())
            }
        }
    }

    @Test
    fun bluetoothDisabled_stepsReferenceSettings() {
        val steps = BleErrorCategory.BLUETOOTH_DISABLED.getTroubleshootingSteps()
        assertTrue(steps.any { it.contains("Settings", ignoreCase = true) })
    }

    @Test
    fun permissionDenied_stepsReferencePermissions() {
        val steps = BleErrorCategory.PERMISSION_DENIED.getTroubleshootingSteps()
        assertTrue(steps.any { it.contains("Permission", ignoreCase = true) })
    }

    @Test
    fun connectionFailed_hasAtLeast3Steps() {
        assertTrue(BleErrorCategory.CONNECTION_FAILED.getTroubleshootingSteps().size >= 3)
    }

    @Test
    fun unknown_stepsSuggestContactSupport() {
        val steps = BleErrorCategory.UNKNOWN.getTroubleshootingSteps()
        assertTrue(steps.any { it.contains("support", ignoreCase = true) })
    }

    @Test
    fun scanningFailed_stepsMentionWiFi() {
        val steps = BleErrorCategory.SCANNING_FAILED.getTroubleshootingSteps()
        assertTrue(steps.any { it.contains("WiFi", ignoreCase = true) })
    }

    @Test
    fun advertisingFailed_stepsMentionOtherApps() {
        val steps = BleErrorCategory.ADVERTISING_FAILED.getTroubleshootingSteps()
        assertTrue(steps.any { it.contains("other apps", ignoreCase = true) })
    }

    // ── Specific step counts ───────────────────────────────────────────────

    @Test
    fun bluetoothDisabled_hasExactly3Steps() {
        assertEquals(3, BleErrorCategory.BLUETOOTH_DISABLED.getTroubleshootingSteps().size)
    }

    @Test
    fun connectionFailed_has4Steps() {
        assertEquals(4, BleErrorCategory.CONNECTION_FAILED.getTroubleshootingSteps().size)
    }

    @Test
    fun unknown_has4Steps() {
        assertEquals(4, BleErrorCategory.UNKNOWN.getTroubleshootingSteps().size)
    }

    // ── Cross-cutting consistency ──────────────────────────────────────────

    @Test
    fun readAndWriteFailed_haveIdenticalSteps() {
        assertEquals(
            BleErrorCategory.CHARACTERISTIC_READ_FAILED.getTroubleshootingSteps(),
            BleErrorCategory.CHARACTERISTIC_WRITE_FAILED.getTroubleshootingSteps()
        )
    }

    @Test
    fun everyUserMessageEndsWithPeriod() {
        for (entry in BleErrorCategory.entries) {
            val msg = entry.getUserMessage()
            assertTrue("$entry message doesn't end with '.': $msg", msg.endsWith("."))
        }
    }
}
