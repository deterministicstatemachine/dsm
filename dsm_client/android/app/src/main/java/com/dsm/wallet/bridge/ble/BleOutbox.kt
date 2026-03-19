package com.dsm.wallet.bridge.ble

import android.content.Context
import com.dsm.wallet.bridge.BleOutboxItem
import com.dsm.wallet.bridge.BleOutboxRepository

/**
 * Manages persistent transaction queue with retry logic.
 *
 * This component handles:
 * - Enqueuing transactions for sending
 * - Tracking retry attempts
 * - Processing pending items
 * - Marking items as completed or failed
 */
class BleOutbox(
    context: Context,
    private val repository: BleOutboxRepository = BleOutboxRepository(context)
) {

    fun enqueueTransaction(deviceAddress: String, data: ByteArray): Long {
        return repository.enqueue(deviceAddress, data)
    }

    fun getPendingForDevice(deviceAddress: String): List<BleOutboxItem> {
        return repository.getPending().filter { it.address == deviceAddress }
    }

    fun markCompleted(itemId: Long) {
        repository.delete(itemId)
    }

    fun incrementAttempts(itemId: Long) {
        repository.incrementAttempts(itemId)
    }

    fun removeItem(itemId: Long) {
        repository.delete(itemId)
    }

    fun retryLastTransaction(deviceAddress: String): Boolean {
        val pending = getPendingForDevice(deviceAddress)
        val lastItem = pending.maxByOrNull { it.id }
        return if (lastItem != null && lastItem.attempts < 5) {
            repository.resetAttempts(lastItem.id)
            true
        } else {
            false
        }
    }
}