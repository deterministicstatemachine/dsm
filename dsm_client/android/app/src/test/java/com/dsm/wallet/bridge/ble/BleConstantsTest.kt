package com.dsm.wallet.bridge.ble

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4
import java.util.UUID

@RunWith(JUnit4::class)
class BleConstantsTest {

    // ── UUID validity ──────────────────────────────────────────────────────

    @Test
    fun serviceUuid_isNotNull() {
        assertTrue(BleConstants.DSM_SERVICE_UUID_V2 is UUID)
    }

    @Test
    fun characteristicUuids_areDistinct() {
        val uuids = listOf(
            BleConstants.TX_REQUEST_UUID,
            BleConstants.TX_RESPONSE_UUID,
            BleConstants.IDENTITY_UUID,
            BleConstants.PAIRING_UUID,
            BleConstants.PAIRING_ACK_UUID,
        )
        assertEquals(uuids.size, uuids.toSet().size)
    }

    @Test
    fun characteristicUuids_differFromServiceUuid() {
        val chars = listOf(
            BleConstants.TX_REQUEST_UUID,
            BleConstants.TX_RESPONSE_UUID,
            BleConstants.IDENTITY_UUID,
            BleConstants.PAIRING_UUID,
            BleConstants.PAIRING_ACK_UUID,
        )
        for (c in chars) {
            assertNotEquals(BleConstants.DSM_SERVICE_UUID_V2, c)
        }
    }

    @Test
    fun cccdUuid_isStandardBluetooth() {
        assertEquals(
            UUID.fromString("00002902-0000-1000-8000-00805f9b34fb"),
            BleConstants.CCCD_UUID
        )
    }

    @Test
    fun allUuids_shareBaseSuffix() {
        val suffix = "7c07-4f3f-9b32-7bf3ba6c2a01"
        val uuids = listOf(
            BleConstants.DSM_SERVICE_UUID_V2,
            BleConstants.TX_REQUEST_UUID,
            BleConstants.TX_RESPONSE_UUID,
            BleConstants.IDENTITY_UUID,
            BleConstants.PAIRING_UUID,
            BleConstants.PAIRING_ACK_UUID,
        )
        for (uuid in uuids) {
            assertTrue(
                "UUID $uuid doesn't end with DSM base suffix",
                uuid.toString().endsWith(suffix)
            )
        }
    }

    // ── Manufacturer data ──────────────────────────────────────────────────

    @Test
    fun manufacturerId_isExperimentalReserved() {
        assertEquals(0xFFFF, BleConstants.DSM_MANUFACTURER_ID)
    }

    @Test
    fun manufacturerMagic_isDSM01() {
        assertArrayEquals(
            byteArrayOf(0x44, 0x53, 0x4D, 0x01),
            BleConstants.DSM_MANUFACTURER_MAGIC
        )
    }

    @Test
    fun manufacturerMagic_startsWithDSM() {
        val magic = BleConstants.DSM_MANUFACTURER_MAGIC
        assertEquals('D'.code.toByte(), magic[0])
        assertEquals('S'.code.toByte(), magic[1])
        assertEquals('M'.code.toByte(), magic[2])
    }

    @Test
    fun manufacturerMagic_has4Bytes() {
        assertEquals(4, BleConstants.DSM_MANUFACTURER_MAGIC.size)
    }

    // ── MTU settings ───────────────────────────────────────────────────────

    @Test
    fun mtuSize_is517() {
        assertEquals(517, BleConstants.MTU_SIZE)
    }

    @Test
    fun identityMtuRequest_is512() {
        assertEquals(512, BleConstants.IDENTITY_MTU_REQUEST)
    }

    @Test
    fun minIdentityMtu_is67() {
        assertEquals(67, BleConstants.MIN_IDENTITY_MTU)
    }

    @Test
    fun mtuOrdering_minLessThanIdentityLessThanMax() {
        assertTrue(BleConstants.MIN_IDENTITY_MTU < BleConstants.IDENTITY_MTU_REQUEST)
        assertTrue(BleConstants.IDENTITY_MTU_REQUEST <= BleConstants.MTU_SIZE)
    }

    // ── Reconnection backoff ───────────────────────────────────────────────

    @Test
    fun reconnectInitialDelay_is1Second() {
        assertEquals(1_000L, BleConstants.RECONNECT_INITIAL_DELAY_MS)
    }

    @Test
    fun reconnectMaxDelay_is30Seconds() {
        assertEquals(30_000L, BleConstants.RECONNECT_MAX_DELAY_MS)
    }

    @Test
    fun reconnectMaxAttempts_is8() {
        assertEquals(8, BleConstants.RECONNECT_MAX_ATTEMPTS)
    }

    @Test
    fun reconnectBackoff_maxDelayGreaterThanInitial() {
        assertTrue(BleConstants.RECONNECT_MAX_DELAY_MS > BleConstants.RECONNECT_INITIAL_DELAY_MS)
    }

    // ── Scan duration ──────────────────────────────────────────────────────

    @Test
    fun scanLowLatencyDuration_is12Seconds() {
        assertEquals(12_000L, BleConstants.SCAN_LOW_LATENCY_DURATION_MS)
    }

    // ── GATT error retry ───────────────────────────────────────────────────

    @Test
    fun gattErrorStatus_is133() {
        assertEquals(133, BleConstants.GATT_ERROR_STATUS)
    }

    @Test
    fun gattRetryDelay_is300ms() {
        assertEquals(300L, BleConstants.GATT_RETRY_DELAY_MS)
    }

    @Test
    fun gattRetryMaxAttempts_is3() {
        assertEquals(3, BleConstants.GATT_RETRY_MAX_ATTEMPTS)
    }

    // ── Connection priority ────────────────────────────────────────────────

    @Test
    fun connectionPriorityResetDelay_is500ms() {
        assertEquals(500L, BleConstants.CONNECTION_PRIORITY_RESET_DELAY_MS)
    }

    // ── MTU fallback ───────────────────────────────────────────────────────

    @Test
    fun mtuFallbackDelay_is2Seconds() {
        assertEquals(2_000L, BleConstants.MTU_FALLBACK_DELAY_MS)
    }

    // ── Constant immutability ──────────────────────────────────────────────

    @Test
    fun allNumericConstants_arePositive() {
        assertTrue(BleConstants.MTU_SIZE > 0)
        assertTrue(BleConstants.IDENTITY_MTU_REQUEST > 0)
        assertTrue(BleConstants.MIN_IDENTITY_MTU > 0)
        assertTrue(BleConstants.RECONNECT_INITIAL_DELAY_MS > 0)
        assertTrue(BleConstants.RECONNECT_MAX_DELAY_MS > 0)
        assertTrue(BleConstants.RECONNECT_MAX_ATTEMPTS > 0)
        assertTrue(BleConstants.SCAN_LOW_LATENCY_DURATION_MS > 0)
        assertTrue(BleConstants.GATT_ERROR_STATUS > 0)
        assertTrue(BleConstants.GATT_RETRY_DELAY_MS > 0)
        assertTrue(BleConstants.GATT_RETRY_MAX_ATTEMPTS > 0)
        assertTrue(BleConstants.CONNECTION_PRIORITY_RESET_DELAY_MS > 0)
        assertTrue(BleConstants.MTU_FALLBACK_DELAY_MS > 0)
    }
}
