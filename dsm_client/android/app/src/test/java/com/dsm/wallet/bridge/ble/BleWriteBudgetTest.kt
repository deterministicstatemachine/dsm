package com.dsm.wallet.bridge.ble

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleWriteBudgetTest {

    @Test
    fun tryConsume_succeedsUntilCreditsExhausted() {
        val budget = BleWriteBudget(maxCredits = 5, refillIntervalMs = 60_000L)
        repeat(5) {
            assertTrue("consume $it", budget.tryConsume())
        }
        assertFalse(budget.tryConsume())
    }

    @Test
    fun reset_restoresFullCredits() {
        val budget = BleWriteBudget(maxCredits = 3, refillIntervalMs = 60_000L)
        repeat(3) { budget.tryConsume() }
        assertFalse(budget.tryConsume())
        budget.reset()
        assertTrue(budget.tryConsume())
        assertTrue(budget.tryConsume())
        assertTrue(budget.tryConsume())
        assertFalse(budget.tryConsume())
    }

    @Test
    fun defaultConstructor_allowsTwentySequentialConsumes() {
        val budget = BleWriteBudget()
        repeat(20) {
            assertTrue(budget.tryConsume())
        }
        assertFalse(budget.tryConsume())
    }
}
