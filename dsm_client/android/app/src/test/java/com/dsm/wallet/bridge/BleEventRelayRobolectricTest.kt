// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.annotation.Config
import org.robolectric.RobolectricTestRunner

/**
 * JVM unit tests for BleEventRelay using Robolectric so they run without a device.
 * Mirrors the instrumentation tests to validate persistence and flushing semantics.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleEventRelayRobolectricTest {
    private lateinit var ctx: Context

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
        BleEventRelay.clearAll(ctx)
    }

    @After
    fun tearDown() {
        BleEventRelay.clearAll(ctx)
    }

    @Test
    fun persistsEventsWhenBridgeUnavailable() {
        assertEquals(0, BleEventRelay.getPendingCount(ctx))
        val testEnvelope = byteArrayOf(0x01, 0x02, 0x03)
        // Persist directly via test hook to avoid depending on bridge reflection behavior
        BleEventRelay.testPersistDirect(ctx, testEnvelope)
        assertTrue(BleEventRelay.getPendingCount(ctx) > 0)
    }

    @Test
    fun flushReplaysAndPrunesEvents() {
        for (i in 1..3) {
            val env = "event$i".toByteArray(Charsets.ISO_8859_1)
            BleEventRelay.testPersistDirect(ctx, env)
        }
        assertEquals(3, BleEventRelay.getPendingCount(ctx))
        BleEventRelay.flushPersisted(ctx)
        assertEquals(0, BleEventRelay.getPendingCount(ctx))
    }

    @Test
    fun enforcesCap() {
        for (i in 1..210) {
            val env = "event$i".toByteArray(Charsets.ISO_8859_1)
            BleEventRelay.testPersistDirect(ctx, env)
        }
        val count = BleEventRelay.getPendingCount(ctx)
        assertTrue("Expected <=200, got $count", count <= 200)
    }
}
