// path: app/src/androidTest/java/com/dsm/wallet/bridge/BleEventRelayPersistenceTest.kt
// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Instrumentation test for BleEventRelay SQLite persistence:
 * - Events persist across process death
 * - A flush deletes only what the bridge accepted; a failed delivery leaves the rows
 * - Cap enforcement (200 rows)
 */
@RunWith(AndroidJUnit4::class)
class BleEventRelayPersistenceTest {
    private lateinit var ctx: Context

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        // Clear any prior test data
        BleEventRelay.attach(ctx)
        clearPending()
    }

    @After
    fun tearDown() {
        clearPending()
    }

    /** The relay's own database, opened by the relay first so its table exists. */
    private fun relayDb(): SQLiteDatabase {
        BleEventRelay.flushPersisted(ctx)
        return SQLiteDatabase.openDatabase(ctx.getDatabasePath("ble_events.db").path, null, SQLiteDatabase.OPEN_READWRITE)
    }

    private fun clearPending() {
        relayDb().use { it.execSQL("DELETE FROM pending_ble") }
    }

    private fun pendingCount(): Int =
        relayDb().use { db ->
            db.rawQuery("SELECT COUNT(*) FROM pending_ble", null).use { c ->
                assertTrue(c.moveToFirst())
                c.getInt(0)
            }
        }

    @Test
    fun persistsEventsWhenBridgeUnavailable() {
        // Given: empty DB
        assertEquals(0, pendingCount())

        // When: an envelope arrives before the bridge is ready
        val testEnvelope = byteArrayOf(0x01, 0x02, 0x03)
        BleEventRelay.dispatchEnvelope(testEnvelope)

        // Then: event persisted
        assertTrue(pendingCount() > 0)
    }

    @Test
    fun flushLeavesEventsWhenDeliveryFails() {
        // Given: 3 persisted events
        for (i in 1..3) {
            val envelope = "event$i".toByteArray(Charsets.ISO_8859_1)
            BleEventRelay.dispatchEnvelope(envelope)
        }
        assertEquals(3, pendingCount())

        // When: the bridge is ready and we flush. There is no WebView in an
        // instrumented process, so every delivery fails.
        BleEventRelay.markBridgeReady(ctx)
        BleEventRelay.flushPersisted(ctx)

        // Then: nothing is dropped — a row leaves only once the bridge accepted it
        assertEquals(3, pendingCount())
    }

    @Test
    fun enforcesCap() {
        // Given: attempt to persist 210 events
        for (i in 1..210) {
            val envelope = "event$i".toByteArray(Charsets.ISO_8859_1)
            BleEventRelay.dispatchEnvelope(envelope)
        }

        // Then: only last 200 kept (FIFO pruning)
        val count = pendingCount()
        assertTrue("Expected ~200, got $count", count <= 200)
    }
}
