package com.dsm.wallet.bridge.ble

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import java.util.concurrent.ConcurrentHashMap

/**
 * Per-device serialized inbound chunk pipelines for the GATT server.
 *
 * GATT server write callbacks fire on a single shared Binder thread that must
 * return quickly, so each device's chunks are queued and one consumer per
 * device drains them FIFO off that thread. A device's queue is bounded by
 * [capacity]: a chunk past it is not taken (its frame does not complete, and
 * the peer's owed frame is sent again), so a writer cannot grow the queue
 * without limit. A device's pipeline ends when it disconnects ([close]) or the
 * server stops ([closeAll]); the chunks it queued are still processed.
 */
internal class InboundChunkPipelines(
    private val scope: CoroutineScope,
    private val capacity: Int,
    private val process: (deviceAddress: String, data: ByteArray) -> Unit,
) {
    private val pipelines = ConcurrentHashMap<String, Channel<ByteArray>>()

    /** Queue [data] written by [deviceAddress]. Whether its pipeline took it. */
    fun offer(deviceAddress: String, data: ByteArray): Boolean {
        val channel = pipelines.computeIfAbsent(deviceAddress) {
            Channel<ByteArray>(capacity).also { queued ->
                scope.launch {
                    for (chunk in queued) {
                        process(deviceAddress, chunk)
                    }
                }
            }
        }
        return channel.trySend(data).isSuccess
    }

    /** End [deviceAddress]'s pipeline: it takes nothing more. */
    fun close(deviceAddress: String) {
        pipelines.remove(deviceAddress)?.close()
    }

    /** End every device's pipeline. */
    fun closeAll() {
        pipelines.keys.toList().forEach(::close)
    }

    /** How many devices have a pipeline. */
    val size: Int
        get() = pipelines.size
}
