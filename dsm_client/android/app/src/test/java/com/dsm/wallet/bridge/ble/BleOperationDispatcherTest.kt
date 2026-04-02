package com.dsm.wallet.bridge.ble

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineExceptionHandler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Tests for [BleOperationDispatcher] priority ordering and dispatching.
 *
 * Uses Robolectric to shadow android.util.Log (called in error/drop paths).
 * The dispatcher's supervisor coroutine runs on Dispatchers.Default so that
 * dispatchBlocking (which uses runBlocking internally) does not deadlock.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleOperationDispatcherTest {

    private lateinit var scope: CoroutineScope
    private lateinit var dispatcher: BleOperationDispatcher

    @Before
    fun setUp() {
        val handler = CoroutineExceptionHandler { _, _ -> }
        scope = CoroutineScope(Dispatchers.Default + SupervisorJob() + handler)
        dispatcher = BleOperationDispatcher(scope)
    }

    @After
    fun tearDown() {
        dispatcher.shutdown()
        scope.cancel()
    }

    // ── dispatch (fire-and-forget) ────────────────────────────────────────

    @Test
    fun dispatch_executesOp() {
        val latch = CountDownLatch(1)
        dispatcher.dispatch(BleOpLane.TRANSFER) { latch.countDown() }
        assertTrue("Op should execute within timeout", latch.await(5, TimeUnit.SECONDS))
    }

    @Test
    fun dispatch_allLanesExecute() {
        val latch = CountDownLatch(3)
        dispatcher.dispatch(BleOpLane.LIFECYCLE) { latch.countDown() }
        dispatcher.dispatch(BleOpLane.PAIRING) { latch.countDown() }
        dispatcher.dispatch(BleOpLane.TRANSFER) { latch.countDown() }
        assertTrue("All lanes should execute", latch.await(5, TimeUnit.SECONDS))
    }

    // ── dispatchBlocking ──────────────────────────────────────────────────

    @Test
    fun dispatchBlocking_returnsTrue() {
        assertTrue(dispatcher.dispatchBlocking(BleOpLane.LIFECYCLE) { true })
    }

    @Test
    fun dispatchBlocking_returnsFalse() {
        assertFalse(dispatcher.dispatchBlocking(BleOpLane.PAIRING) { false })
    }

    @Test
    fun dispatchBlocking_exceptionInOp_returnsFalse() {
        assertFalse(
            dispatcher.dispatchBlocking(BleOpLane.TRANSFER) { throw RuntimeException("boom") }
        )
    }

    // ── priority ordering ─────────────────────────────────────────────────

    @Test
    fun priority_lifecycleBeforePairingBeforeTransfer() {
        val order = Collections.synchronizedList(mutableListOf<String>())
        val gate = CompletableDeferred<Unit>()
        val gateStarted = CompletableDeferred<Unit>()
        val allDone = CountDownLatch(4)

        dispatcher.dispatch(BleOpLane.TRANSFER) {
            gateStarted.complete(Unit)
            gate.await()
            order.add("T0")
            allDone.countDown()
        }

        runBlocking { gateStarted.await() }

        dispatcher.dispatch(BleOpLane.TRANSFER) { order.add("T1"); allDone.countDown() }
        dispatcher.dispatch(BleOpLane.PAIRING) { order.add("P"); allDone.countDown() }
        dispatcher.dispatch(BleOpLane.LIFECYCLE) { order.add("L"); allDone.countDown() }

        gate.complete(Unit)
        assertTrue("Ops should complete in time", allDone.await(5, TimeUnit.SECONDS))
        assertEquals(
            "LIFECYCLE should drain before PAIRING, PAIRING before TRANSFER",
            listOf("T0", "L", "P", "T1"),
            order
        )
    }

    // ── shutdown ──────────────────────────────────────────────────────────

    @Test
    fun shutdown_rejectsFurtherOps() {
        dispatcher.shutdown()
        assertFalse(
            "dispatchBlocking after shutdown should return false",
            dispatcher.dispatchBlocking(BleOpLane.LIFECYCLE) { true }
        )
    }

    @Test
    fun dispatch_afterShutdown_doesNotThrow() {
        dispatcher.shutdown()
        dispatcher.dispatch(BleOpLane.TRANSFER) { /* no-op */ }
    }
}
