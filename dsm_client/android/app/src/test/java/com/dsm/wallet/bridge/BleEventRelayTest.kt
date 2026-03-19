package com.dsm.wallet.bridge

import android.app.Application
import androidx.test.core.app.ApplicationProvider
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleEventRelayTest {
    @Test
    fun persistCountAndClear() {
        val ctx: Application = ApplicationProvider.getApplicationContext()
        // Clear any existing rows
        BleEventRelay.clearAll(ctx)
        assertEquals(0, BleEventRelay.getPendingCount(ctx))
        // Persist two fake envelopes
        BleEventRelay.testPersistDirect(ctx, byteArrayOf(1,2,3))
        BleEventRelay.testPersistDirect(ctx, byteArrayOf(4,5))
        assertEquals(2, BleEventRelay.getPendingCount(ctx))
        // Clear
        BleEventRelay.clearAll(ctx)
        assertEquals(0, BleEventRelay.getPendingCount(ctx))
    }
}
