// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge.ble

import java.util.UUID

/**
 * One GATT operation outstanding per connection — Android's rule for a GATT
 * client. Every write, descriptor write, read and MTU request on a link goes
 * through one queue.
 *
 * The in-flight slot is cleared only by that operation's own callback
 * ([completed] with its key) or by the link ending ([close]). A start the
 * stack refuses clears the slot at once and is reported to the operation's
 * owner as refused; nothing is reported as started that the stack did not
 * take.
 *
 * Operations enqueued before the link is [open] (service discovery complete)
 * wait; after [close] they are refused. A queue serves one link: a new
 * connection gets a new queue.
 */
internal class GattOperationQueue(private val onRefused: (Op, String) -> Unit = { _, _ -> }) {

    companion object {
        /** The reason [Op.abandon] receives when the stack refused the start. */
        const val START_REFUSED = "start_refused"
    }

    /** What completes an operation: its callback type and characteristic. */
    data class Key(val type: Type, val characteristic: UUID?) {
        enum class Type { WRITE, DESCRIPTOR_WRITE, READ, MTU }
    }

    interface Op {
        val key: Key
        val label: String

        /** Asks the stack to start the operation; false when the stack refused. */
        fun start(): Boolean

        /** The operation's callback arrived. */
        fun finish(success: Boolean, value: ByteArray?)

        /** The stack refused the start, or the link ended first. */
        fun abandon(reason: String)

        /** True when the operation no longer needs to run (its owner already failed). */
        fun obsolete(): Boolean = false
    }

    private val lock = Any()
    private val pending = ArrayDeque<Op>()
    private var inFlight: Op? = null
    private var isOpen = false
    private var isClosed = false

    /** True while an operation is in flight or waiting. */
    val busy: Boolean
        get() = synchronized(lock) { inFlight != null || pending.isNotEmpty() }

    fun enqueue(op: Op) = enqueueAll(listOf(op))

    /** Enqueue [batch] contiguously: nothing enqueued meanwhile lands between them. */
    fun enqueueAll(batch: List<Op>) {
        val refused = synchronized(lock) {
            if (isClosed) true else { pending.addAll(batch); false }
        }
        if (refused) {
            batch.forEach { it.abandon("link_closed") }
            return
        }
        pump()
    }

    /**
     * Put [op] ahead of every waiting operation (not ahead of the one in
     * flight). [replaces] names a waiting operation it supersedes, which is
     * dropped.
     */
    fun enqueueFirst(op: Op, replaces: (Op) -> Boolean = { false }) {
        val refused = synchronized(lock) {
            if (isClosed) {
                true
            } else {
                pending.removeAll(replaces)
                pending.addFirst(op)
                false
            }
        }
        if (refused) {
            op.abandon("link_closed")
            return
        }
        pump()
    }

    /** Service discovery completed: waiting operations may start. */
    fun open() {
        synchronized(lock) {
            if (isClosed) return
            isOpen = true
        }
        pump()
    }

    /**
     * The callback for [key] arrived: returns the in-flight operation and
     * clears the slot when it is the one [key] completes, else null (a
     * callback nobody here is waiting for, such as a peer-initiated MTU
     * exchange).
     */
    fun completed(key: Key): Op? = synchronized(lock) {
        val op = inFlight
        if (op != null && op.key == key) {
            inFlight = null
            op
        } else {
            null
        }
    }

    /** Start the next waiting operation if nothing is in flight. */
    fun pump() {
        while (true) {
            var next: Op? = null
            synchronized(lock) {
                if (inFlight != null || !isOpen || isClosed) return
                val head = pending.removeFirstOrNull() ?: return
                if (!head.obsolete()) {
                    inFlight = head
                    next = head
                }
            }
            val op = next ?: continue
            if (op.start()) return
            val wasInFlight = synchronized(lock) {
                if (inFlight === op) { inFlight = null; true } else false
            }
            if (wasInFlight) {
                onRefused(op, START_REFUSED)
                op.abandon(START_REFUSED)
            }
        }
    }

    /** The link ended: every operation, in flight or waiting, is abandoned. */
    fun close(reason: String) {
        val abandoned = synchronized(lock) {
            isClosed = true
            isOpen = false
            val all = listOfNotNull(inFlight) + pending
            inFlight = null
            pending.clear()
            all
        }
        abandoned.forEach { it.abandon(reason) }
    }
}
