package com.dsm.wallet.bridge.ble

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.UUID

/**
 * The GATT operation queue against a stack that behaves like Android's: it
 * refuses to start an operation while another is outstanding ("prior command
 * is not finished"), and one outstanding operation ends only with its callback.
 */
class GattOperationQueueTest {

    private val pairing: UUID = BleConstants.PAIRING_UUID
    private val txRequest: UUID = BleConstants.TX_REQUEST_UUID

    /** Android's rule: one outstanding operation; a second start is refused. */
    private class FakeStack {
        var outstanding: FakeOp? = null
        val started = mutableListOf<String>()
        val refusedWhileBusy = mutableListOf<String>()
        var refuseNext = false

        fun start(op: FakeOp): Boolean {
            if (outstanding != null) {
                refusedWhileBusy += op.label
                return false
            }
            if (refuseNext) {
                refuseNext = false
                return false
            }
            outstanding = op
            started += op.label
            return true
        }
    }

    private class FakeOp(
        private val stack: FakeStack,
        override val key: GattOperationQueue.Key,
        override val label: String,
        private val isObsolete: () -> Boolean = { false },
    ) : GattOperationQueue.Op {
        val finished = mutableListOf<Boolean>()
        val abandoned = mutableListOf<String>()
        override fun start(): Boolean = stack.start(this)
        override fun finish(success: Boolean, value: ByteArray?) { finished += success }
        override fun abandon(reason: String) { abandoned += reason }
        override fun obsolete(): Boolean = isObsolete()
    }

    private fun write(uuid: UUID) = GattOperationQueue.Key(GattOperationQueue.Key.Type.WRITE, uuid)

    /** The stack's callback for its outstanding operation, delivered the way GattClientSession does. */
    private fun callback(queue: GattOperationQueue, stack: FakeStack, success: Boolean = true) {
        val outstanding = stack.outstanding ?: error("no operation outstanding")
        stack.outstanding = null
        val op = queue.completed(outstanding.key)
        assertSame("the callback completes the operation the queue has in flight", outstanding, op)
        op!!.finish(success, null)
        queue.pump()
    }

    @Test
    fun aPairingWriteFollowedByAMessageMeetsNoRefusal() {
        val stack = FakeStack()
        val queue = GattOperationQueue().apply { open() }
        val pairingWrite = FakeOp(stack, write(pairing), "pairing write")
        val chunks = (1..3).map { FakeOp(stack, write(txRequest), "chunk $it") }

        queue.enqueue(pairingWrite)
        queue.enqueueAll(chunks)
        repeat(4) { callback(queue, stack) }

        assertEquals(emptyList<String>(), stack.refusedWhileBusy)
        assertEquals(listOf("pairing write", "chunk 1", "chunk 2", "chunk 3"), stack.started)
        assertEquals(listOf(true), pairingWrite.finished)
        chunks.forEach { assertEquals(listOf(true), it.finished) }
        assertFalse(queue.busy)
    }

    @Test
    fun aStartTheStackRefusesIsReportedRefusedAndTheNextOperationStarts() {
        val stack = FakeStack()
        val queue = GattOperationQueue().apply { open() }
        val refused = FakeOp(stack, write(pairing), "refused")
        val next = FakeOp(stack, write(txRequest), "next")

        stack.refuseNext = true
        queue.enqueue(refused)
        queue.enqueue(next)

        assertEquals(listOf(GattOperationQueue.START_REFUSED), refused.abandoned)
        assertTrue(refused.finished.isEmpty())
        assertEquals(listOf("next"), stack.started)
    }

    @Test
    fun aCallbackForAnotherOperationLeavesTheSlotInFlight() {
        val stack = FakeStack()
        val queue = GattOperationQueue().apply { open() }
        val pairingWrite = FakeOp(stack, write(pairing), "pairing write")
        val chunk = FakeOp(stack, write(txRequest), "chunk")
        queue.enqueue(pairingWrite)
        queue.enqueue(chunk)

        assertNull(queue.completed(write(txRequest)))
        assertNull(queue.completed(GattOperationQueue.Key(GattOperationQueue.Key.Type.MTU, null)))
        queue.pump()

        assertEquals(listOf("pairing write"), stack.started)
        assertEquals(emptyList<String>(), stack.refusedWhileBusy)
    }

    @Test
    fun operationsWaitUntilTheLinkOpens() {
        val stack = FakeStack()
        val queue = GattOperationQueue()
        val op = FakeOp(stack, write(pairing), "early")

        queue.enqueue(op)
        assertTrue(stack.started.isEmpty())
        assertTrue(queue.busy)

        queue.open()
        assertEquals(listOf("early"), stack.started)
    }

    @Test
    fun theLinkEndingAbandonsEveryOperationAndRefusesLaterOnes() {
        val stack = FakeStack()
        val queue = GattOperationQueue().apply { open() }
        val inFlight = FakeOp(stack, write(pairing), "in flight")
        val waiting = FakeOp(stack, write(txRequest), "waiting")
        queue.enqueue(inFlight)
        queue.enqueue(waiting)

        queue.close("disconnected")
        val late = FakeOp(stack, write(txRequest), "late")
        queue.enqueue(late)

        assertEquals(listOf("disconnected"), inFlight.abandoned)
        assertEquals(listOf("disconnected"), waiting.abandoned)
        assertEquals(listOf("link_closed"), late.abandoned)
        assertEquals(listOf("in flight"), stack.started)
        assertFalse(queue.busy)
        // A callback arriving after the link ended completes nothing.
        assertNull(queue.completed(write(pairing)))
    }

    @Test
    fun anObsoleteOperationIsDroppedWithoutStarting() {
        val stack = FakeStack()
        val queue = GattOperationQueue().apply { open() }
        var messageFailed = false
        val first = FakeOp(stack, write(txRequest), "chunk 1")
        val second = FakeOp(stack, write(txRequest), "chunk 2") { messageFailed }
        queue.enqueueAll(listOf(first, second))

        messageFailed = true
        callback(queue, stack, success = false)

        assertEquals(listOf("chunk 1"), stack.started)
        assertTrue(second.finished.isEmpty() && second.abandoned.isEmpty())
        assertFalse(queue.busy)
    }

    @Test
    fun aNewerAckSupersedesTheWaitingOneButNotTheOneInFlight() {
        val stack = FakeStack()
        val queue = GattOperationQueue().apply { open() }
        val chunk1 = FakeOp(stack, write(txRequest), "chunk 1")
        val chunk2 = FakeOp(stack, write(txRequest), "chunk 2")
        queue.enqueueAll(listOf(chunk1, chunk2))
        val ack10 = FakeOp(stack, write(txRequest), "ack 10")
        val ack20 = FakeOp(stack, write(txRequest), "ack 20")

        queue.enqueueFirst(ack10) { it.label.startsWith("ack") }
        queue.enqueueFirst(ack20) { it.label.startsWith("ack") }
        repeat(3) { callback(queue, stack) }

        assertEquals(listOf("chunk 1", "ack 20", "chunk 2"), stack.started)
        assertTrue(ack10.finished.isEmpty())
        assertEquals(emptyList<String>(), stack.refusedWhileBusy)
    }
}
