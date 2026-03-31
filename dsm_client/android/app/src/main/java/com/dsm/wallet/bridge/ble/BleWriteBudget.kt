package com.dsm.wallet.bridge.ble

import android.os.SystemClock

/**
 * Token-bucket rate limiter for BLE GATT notification writes.
 *
 * Each outgoing notification consumes one credit.  Credits refill at a rate
 * derived from the BLE connection interval (~7.5–15ms on modern stacks).
 * If credits are exhausted the caller should back-pressure (short delay)
 * rather than flooding the GATT write queue, which causes silent status-133
 * errors on Qualcomm/Samsung stacks.
 *
 * Ported from MeshCore's `RateLimiter.h` / `updateTxBudget` pattern.
 */
class BleWriteBudget(
    private val maxCredits: Int = 20,
    private val refillIntervalMs: Long = 15L,
) {
    private var credits: Int = maxCredits
    private var lastRefillTime: Long = SystemClock.elapsedRealtime()

    @Synchronized
    fun tryConsume(): Boolean {
        refill()
        if (credits <= 0) return false
        credits--
        return true
    }

    @Synchronized
    fun reset() {
        credits = maxCredits
        lastRefillTime = SystemClock.elapsedRealtime()
    }

    private fun refill() {
        val now = SystemClock.elapsedRealtime()
        val elapsed = now - lastRefillTime
        val earned = (elapsed / refillIntervalMs).toInt()
            .coerceAtMost(maxCredits - credits)
        if (earned > 0) {
            credits += earned
            lastRefillTime = now
        }
    }
}
