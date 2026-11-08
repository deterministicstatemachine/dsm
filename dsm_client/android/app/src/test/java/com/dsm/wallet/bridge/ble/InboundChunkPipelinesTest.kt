package com.dsm.wallet.bridge.ble

import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * SA-55. The GATT server queued each device's chunks on an unbounded channel
 * that was never removed when the device disconnected: a writer grew the
 * queue without limit, and every address that ever wrote kept a channel and a
 * consumer. Each device's queue is bounded now, and its pipeline ends when it
 * disconnects.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class InboundChunkPipelinesTest {

    private class Recorder {
        val processed = mutableListOf<Pair<String, Int>>()
    }

    /**
     * A device's queue takes at most its capacity while its consumer is
     * behind; what it took is processed in order.
     * MUTATION CONTROL: an unbounded queue takes the chunk past the bound and
     * turns this red.
     */
    @Test
    fun aDevicesQueueTakesNoMoreThanItsCapacity() {
        val scope = TestScope(StandardTestDispatcher())
        val recorder = Recorder()
        val pipelines = InboundChunkPipelines(scope, capacity = 3) { address, data ->
            recorder.processed += address to data.size
        }

        repeat(3) { assertTrue("chunk $it", pipelines.offer("A", ByteArray(it + 1))) }
        assertFalse("a chunk past the bound", pipelines.offer("A", ByteArray(9)))
        assertTrue("another device has its own queue", pipelines.offer("B", ByteArray(5)))

        scope.advanceUntilIdle()
        assertEquals(listOf("A" to 1, "A" to 2, "A" to 3, "B" to 5), recorder.processed)
        pipelines.closeAll()
        scope.advanceUntilIdle()
    }

    /**
     * A disconnected device's pipeline ends: it is removed, what it queued is
     * still processed, and a device that connects again gets a new one.
     * MUTATION CONTROL: keeping the pipeline on disconnect turns this red.
     */
    @Test
    fun aDisconnectedDevicesPipelineEnds() {
        val scope = TestScope(StandardTestDispatcher())
        val recorder = Recorder()
        val pipelines = InboundChunkPipelines(scope, capacity = 8) { address, data ->
            recorder.processed += address to data.size
        }

        assertTrue(pipelines.offer("A", ByteArray(2)))
        assertTrue(pipelines.offer("B", ByteArray(3)))
        assertEquals(2, pipelines.size)

        pipelines.close("A")
        assertEquals(1, pipelines.size)
        scope.advanceUntilIdle()
        assertEquals(listOf("A" to 2, "B" to 3), recorder.processed)

        assertTrue("a reconnected device", pipelines.offer("A", ByteArray(4)))
        assertEquals(2, pipelines.size)
        pipelines.closeAll()
        assertEquals(0, pipelines.size)
        scope.advanceUntilIdle()
        assertEquals(listOf("A" to 2, "B" to 3, "A" to 4), recorder.processed)
    }
}
