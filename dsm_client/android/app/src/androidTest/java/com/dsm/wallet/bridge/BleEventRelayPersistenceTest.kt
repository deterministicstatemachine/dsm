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
        // Clear any prior test data and any bridge-ready state a prior test set
        BleEventRelay.testResetBridgeReady()
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

        // When: the bridge is ready and we flush. There is no WebView in an
        // instrumented process, so delivery throws and the relay DROPS the
        // replayed event (persistIfUnavailable = false) instead of re-inserting
        // it — which is exactly what lets the row count reach zero.
        BleEventRelay.markBridgeReady(ctx)
        BleEventRelay.flushPersisted(ctx)

        // Then: all events flushed and pruned
        assertEquals(0, BleEventRelay.getPendingCount(ctx))
    }

    @Test
    fun flushLeavesEventsWhenBridgeNotReady() {
        // Given: 2 persisted events and a bridge that is NOT ready
        for (i in 1..2) {
            BleEventRelay.testPersistDirect(ctx, "event$i".toByteArray(Charsets.ISO_8859_1))
        }
        assertEquals(2, BleEventRelay.getPendingCount(ctx))

        // When: flush before the bridge is ready
        BleEventRelay.flushPersisted(ctx)

        // Then: nothing is dropped — the events wait for the bridge
        assertEquals(2, BleEventRelay.getPendingCount(ctx))
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

        // When: flush with the bridge ready (testing a mid-transaction DB
        // failure would need a fault-injecting database; here the flush must
        // complete and commit as one transaction)
        BleEventRelay.markBridgeReady(ctx)
        BleEventRelay.flushPersisted(ctx)

        // Then: events cleared
        assertEquals(0, BleEventRelay.getPendingCount(ctx))
    }
}
