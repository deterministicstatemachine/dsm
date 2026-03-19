package com.dsm.wallet.bridge.ble

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Handles BLE diagnostics, error categorization, and user guidance.
 *
 * This component manages:
 * - Event logging and serialization
 * - Error categorization and user messaging
 * - Persistent issue detection
 * - Debug mode controls
 */
class BleDiagnostics {

    private val events = ConcurrentLinkedDeque<BleDiagEvent>()
    private val debugEnabled = AtomicBoolean(true)
    private val eventSequence = AtomicLong(0)

    // Error tracking for user guidance
    private val recentErrors = ConcurrentHashMap<BleErrorCategory, Int>()
    private val lastErrorTick = ConcurrentHashMap<BleErrorCategory, Long>()
    private val errorResetTicks = 30000L // 5 minutes

    fun recordEvent(event: BleDiagEvent) {
        if (!debugEnabled.get()) return

        val sequencedEvent = event.copy(ts = eventSequence.incrementAndGet())
        events.add(sequencedEvent)

        // Keep only recent events (cap at 1000)
        while (events.size > 1000) {
            events.removeFirst()
        }

        Log.d("BleDiagnostics", "Event: ${sequencedEvent.serialize()}")
    }

    fun recordError(category: BleErrorCategory, phase: String, device: String? = null, status: Int? = null) {
        val now = eventSequence.get() // Use deterministic counter instead of wall clock

        // Update error counts
        recentErrors.compute(category) { _, count -> (count ?: 0) + 1 }

        // Reset old errors
        val lastTick = lastErrorTick[category] ?: 0
        if (now - lastTick > errorResetTicks) {
            recentErrors[category] = 1
        }
        lastErrorTick[category] = now

        val event = BleDiagEvent(
            ts = eventSequence.incrementAndGet(),
            phase = phase,
            device = device,
            status = status,
            detail = category.name
        )
        events.add(event)

        Log.w("BleDiagnostics", "Error recorded: $category in phase $phase for device $device")
    }

    fun getErrorGuidance(): Map<String, Any>? {
        val dominantError = recentErrors.maxByOrNull { it.value }?.key ?: return null

        return mapOf<String, Any>(
            "category" to dominantError.name,
            "message" to dominantError.getUserMessage(),
            "troubleshooting" to dominantError.getTroubleshootingSteps(),
            "frequency" to (recentErrors[dominantError] ?: 0)
        )
    }

    fun hasPersistentIssues(): Boolean {
        return recentErrors.values.sum() > 10 // Arbitrary threshold
    }

    fun getEventsLog(): String {
        return events.joinToString("\n") { it.serialize() }
    }

    fun setDebugEnabled(enabled: Boolean) {
        debugEnabled.set(enabled)
    }

    fun clearEvents() {
        events.clear()
        recentErrors.clear()
        lastErrorTick.clear()
    }
}