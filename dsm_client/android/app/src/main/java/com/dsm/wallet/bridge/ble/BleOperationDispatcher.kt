package com.dsm.wallet.bridge.ble

import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Priority group for BLE operations.
 *
 * Operations are always drained highest-to-lowest:
 *   LIFECYCLE > PAIRING > TRANSFER
 *
 * LIFECYCLE: radio start/stop, GATT server lifecycle, connection state bookkeeping.
 * PAIRING  : identity exchange, pairing confirm writes, key handshakes.
 * TRANSFER : bilateral transaction data, outbox processing, chunked notifications.
 *
 * Keeping radio / connection ops in the highest-priority lane prevents outbox retry
 * floods from burying a pairing confirmation — the root cause of one-of-two-devices
 * "stuck pairing" failures.
 */
enum class BleOpLane { LIFECYCLE, PAIRING, TRANSFER }

/**
 * Three-lane priority dispatcher for BLE operations.
 *
 * A single supervisor coroutine serialises ALL BLE work so that radio state
 * mutations, pairing handshake steps, and bulk data transfers never race.
 *
 * Architecture:
 *   ┌────────────────────────────────────────────────────────────────────┐
 *   │  BleOperationDispatcher (single supervisor coroutine)              │
 *   │                                                                    │
 *   │  LIFECYCLE ch (cap=32) ──►─┐                                      │
 *   │  PAIRING   ch (cap=64) ──►─┤ priority drain ──► execute op        │
 *   │  TRANSFER  ch (cap=256)──►─┘                                      │
 *   └────────────────────────────────────────────────────────────────────┘
 *
 * After each completed operation the loop checks LIFECYCLE first with `tryReceive`,
 * then PAIRING, then blocks on a `select` across all three lanes so it never
 * busy-spins on an empty queue.
 *
 * `dispatch()` is non-blocking (trySend); callers that need the result use
 * `dispatchBlocking()` which waits up to 5 s via runBlocking + withTimeoutOrNull.
 * This matches the previous `runOperationBool` contract.
 *
 * Thread-safety: `dispatch` / `dispatchBlocking` may be called from any thread.
 * Channel state mutations are owned exclusively by the supervisor coroutine.
 */
class BleOperationDispatcher(private val scope: CoroutineScope) {

    private val lifecycleCh = Channel<suspend () -> Unit>(32)
    private val pairingCh   = Channel<suspend () -> Unit>(64)
    private val transferCh  = Channel<suspend () -> Unit>(256)

    init {
        scope.launch {
            while (true) {
                // Priority drain: LIFECYCLE > PAIRING > blocking select across all lanes.
                //
                // tryReceive() checks each high-priority lane without blocking, so a burst
                // of radio/connection events always finishes before outbox chunks are sent.
                val lifecycleOp = lifecycleCh.tryReceive().getOrNull()
                if (lifecycleOp != null) {
                    execute(lifecycleOp, BleOpLane.LIFECYCLE)
                    continue
                }

                val pairingOp = pairingCh.tryReceive().getOrNull()
                if (pairingOp != null) {
                    execute(pairingOp, BleOpLane.PAIRING)
                    continue
                }

                // Both high-priority lanes are empty; block until any lane has work.
                // select bias doesn't matter here: after each op we re-probe LIFECYCLE
                // and PAIRING at the top of the loop before falling through again.
                val (op, lane) = select {
                    lifecycleCh.onReceive { Pair(it, BleOpLane.LIFECYCLE) }
                    pairingCh.onReceive   { Pair(it, BleOpLane.PAIRING)   }
                    transferCh.onReceive  { Pair(it, BleOpLane.TRANSFER)  }
                }
                execute(op, lane)
            }
        }
    }

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Non-blocking enqueue. Drops the operation and logs a warning if the lane's
     * channel is full (should not happen with the chosen capacities under normal load).
     */
    fun dispatch(lane: BleOpLane, block: suspend () -> Unit) {
        val result = channelFor(lane).trySend(block)
        if (result.isFailure) {
            Log.w(TAG, "BLE op dropped: $lane lane full or closed")
        }
    }

    /**
     * Enqueue a Boolean-returning op and block the caller (up to 5 s) for the result.
     * Returns false if the channel is full, closed, or the op times out.
     *
     * This preserves the previous `runOperationBool` contract used in the public API
     * (startAdvertising, startScanning, etc.) which ultimately flows from JNI callers
     * that expect a synchronous Boolean return.
     */
    fun dispatchBlocking(lane: BleOpLane, block: suspend () -> Boolean): Boolean {
        val deferred = CompletableDeferred<Boolean>()
        val sent = channelFor(lane).trySend {
            try {
                deferred.complete(block())
            } catch (t: Throwable) {
                Log.e(TAG, "BLE blocking op failed in $lane lane", t)
                deferred.complete(false)
            }
        }.isSuccess

        if (!sent) {
            Log.w(TAG, "BLE blocking op dropped: $lane lane full or closed")
            return false
        }

        return runBlocking {
            withTimeoutOrNull(5_000L) { deferred.await() } ?: false
        }
    }

    /**
     * Close all lane channels. Supervisor coroutine will drain remaining items then exit.
     * Call once during BleCoordinator.cleanup().
     */
    fun shutdown() {
        lifecycleCh.close()
        pairingCh.close()
        transferCh.close()
    }

    // ── Internals ─────────────────────────────────────────────────────────────

    private suspend fun execute(op: suspend () -> Unit, lane: BleOpLane) {
        try {
            op()
        } catch (t: Throwable) {
            Log.e(TAG, "Uncaught exception in $lane BLE op", t)
        }
    }

    private fun channelFor(lane: BleOpLane): Channel<suspend () -> Unit> = when (lane) {
        BleOpLane.LIFECYCLE -> lifecycleCh
        BleOpLane.PAIRING   -> pairingCh
        BleOpLane.TRANSFER  -> transferCh
    }

    companion object {
        private const val TAG = "BleDispatcher"
    }
}
