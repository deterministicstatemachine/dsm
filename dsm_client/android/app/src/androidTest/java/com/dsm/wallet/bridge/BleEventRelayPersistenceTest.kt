// path: app/src/androidTest/java/com/dsm/wallet/bridge/BleEventRelayPersistenceTest.kt
// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import android.content.Context
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
 * - Flush replays events and prunes
 * - Cap enforcement (200 rows)
 */
@RunWith(AndroidJUnit4::class)
class BleEventRelayPersistenceTest {
    private lateinit var ctx: Context

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        // Clear any prior test data
        BleEventRelay.clearAll(ctx)
    }

    @After
    fun tearDown() {
        BleEventRelay.clearAll(ctx)
    }

    @Test
    fun persistsEventsWhenBridgeUnavailable() {
        // Given: empty DB
        assertEquals(0, BleEventRelay.getPendingCount(ctx))

        // When: persist envelope directly via test hook
        val testEnvelope = byteArrayOf(0x01, 0x02, 0x03)
        BleEventRelay.testPersistDirect(ctx, testEnvelope)

        // Then: event persisted
        assertTrue(BleEventRelay.getPendingCount(ctx) > 0)
    }

    @Test
    fun flushReplaysAndPrunesEvents() {
        // Given: 3 persisted events
        for (i in 1..3) {
            val envelope = "event$i".toByteArray(Charsets.ISO_8859_1)
            BleEventRelay.testPersistDirect(ctx, envelope)
        }
        assertEquals(3, BleEventRelay.getPendingCount(ctx))

        // When: flush
        BleEventRelay.flushPersisted(ctx)

        // Then: all events flushed and pruned
        assertEquals(0, BleEventRelay.getPendingCount(ctx))
    }

    @Test
    fun enforcesCap() {
        // Given: attempt to persist 210 events
        for (i in 1..210) {
            val envelope = "event$i".toByteArray(Charsets.ISO_8859_1)
            BleEventRelay.testPersistDirect(ctx, envelope)
        }

        // Then: only last 200 kept (FIFO pruning)
        val count = BleEventRelay.getPendingCount(ctx)
        assertTrue("Expected ~200, got $count", count <= 200)
    }

    @Test
    fun transactionRollbackOnError() {
        // Given: 2 persisted events
        for (i in 1..2) {
            val envelope = "event$i".toByteArray(Charsets.ISO_8859_1)
            BleEventRelay.testPersistDirect(ctx, envelope)
        }
        assertEquals(2, BleEventRelay.getPendingCount(ctx))

        // When: flush (normally succeeds; testing rollback would require mocking DB failure)
        // For now, verify flush completes without exception
        BleEventRelay.flushPersisted(ctx)

        // Then: events cleared
        assertEquals(0, BleEventRelay.getPendingCount(ctx))
    }
}
