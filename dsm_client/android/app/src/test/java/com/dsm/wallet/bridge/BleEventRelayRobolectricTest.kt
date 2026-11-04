// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import android.content.Context
import android.database.sqlite.SQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.RobolectricTestRunner

/**
 * JVM unit tests for BleEventRelay using Robolectric so they run without a device.
 * The instrumentation tests hold the same behaviour on a device.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleEventRelayRobolectricTest {
    private lateinit var ctx: Context

    /**
     * The relay's own database, opened by the relay first so its table exists. The relay holds
     * the helper it first opened for the life of the process, and Robolectric gives each test its
     * own data directory, so what follows is one scenario in one test.
     */
    private fun relayDb(): SQLiteDatabase {
        BleEventRelay.flushPersisted(ctx)
        return SQLiteDatabase.openDatabase(ctx.getDatabasePath("ble_events.db").path, null, SQLiteDatabase.OPEN_READWRITE)
    }

    private fun pendingCount(): Int =
        relayDb().use { db ->
            db.rawQuery("SELECT COUNT(*) FROM pending_ble", null).use { c ->
                assertTrue(c.moveToFirst())
                c.getInt(0)
            }
        }

    /**
     * What the production entry does with an event the bridge cannot take: it is kept, a failed
     * delivery during a flush leaves it, and the table stays within its cap.
     */
    @Test
    fun theQueueKeepsWhatTheBridgeDidNotTakeWithinItsCap() {
        ctx = ApplicationProvider.getApplicationContext()
        BleEventRelay.attach(ctx)
        assertEquals(0, pendingCount())

        for (i in 1..3) {
            BleEventRelay.dispatchEnvelope("event$i".toByteArray(Charsets.ISO_8859_1))
        }
        assertEquals(3, pendingCount())

        // No WebView exists in this process, so every delivery fails; a failed delivery
        // leaves its row and the rows after it for the next flush instead of dropping them.
        BleEventRelay.markBridgeReady(ctx)
        BleEventRelay.flushPersisted(ctx)
        assertEquals(3, pendingCount())

        for (i in 1..210) {
            BleEventRelay.dispatchEnvelope("event$i".toByteArray(Charsets.ISO_8859_1))
        }
        val count = pendingCount()
        assertTrue("Expected <=200, got $count", count <= 200)
    }
}
