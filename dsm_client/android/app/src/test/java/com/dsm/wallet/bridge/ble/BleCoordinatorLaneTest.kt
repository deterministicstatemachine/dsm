package com.dsm.wallet.bridge.ble

import android.content.Context
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.inOrder
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.times
import org.mockito.kotlin.verify
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Everything that touches the scan runs on the dispatcher, in order: no op
 * waits on the dispatcher it runs on, the downshift never restarts a scan a
 * stop just ended, and a scan is restored only while Rust's pairing loop
 * requests one.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleCoordinatorLaneTest {

    private class RecordedEvents : BleRadioEvents {
        val events = CopyOnWriteArrayList<String>()
        override fun advertisingStarted() { events += "advertisingStarted" }
        override fun advertisingStopped() { events += "advertisingStopped" }
        override fun scanStarted() { events += "scanStarted" }
        override fun scanStopped() { events += "scanStopped" }
        override fun permissionDenied(operation: String) { events += "permissionDenied:$operation" }
    }

    private lateinit var advertiser: BleAdvertiser
    private lateinit var scanner: BleScanner
    private lateinit var gattServer: GattServerHost
    private lateinit var recorded: RecordedEvents
    private lateinit var coordinator: BleCoordinator
    @Volatile private var running = false

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        advertiser = mock()
        scanner = mock()
        gattServer = mock { onBlocking { ensureStarted() } doReturn true }
        running = false
        whenever(scanner.isScanning()).thenAnswer { running }
        whenever(scanner.startScanning(any())).thenAnswer { running = true; true }
        whenever(scanner.stopScanning()).thenAnswer { running = false; true }
        whenever(scanner.radioOff()).thenAnswer { val was = running; running = false; was }
        recorded = RecordedEvents()
        coordinator = BleCoordinator(
            context = context,
            permissionsGate = mock {
                on { hasAdvertisePermission() } doReturn true
                on { hasScanPermission() } doReturn true
            },
            advertiser = advertiser,
            gattServer = gattServer,
            scanner = scanner,
            outbox = mock(),
            diagnostics = BleDiagnostics(),
            radioEvents = recorded,
        )
    }

    /** A blocking lifecycle op: it runs after everything queued before it. */
    private fun barrier() {
        assertTrue(coordinator.ensureGattServerStarted())
    }

    /** Holds the lifecycle lane until [release] counts down. */
    private fun holdTheLane(release: CountDownLatch): Thread {
        val entered = CountDownLatch(1)
        whenever(advertiser.stopAdvertising()).thenAnswer {
            entered.countDown()
            release.await(10, TimeUnit.SECONDS)
            true
        }
        val holder = thread { coordinator.stopAdvertising() }
        assertTrue("the lane is held", entered.await(10, TimeUnit.SECONDS))
        return holder
    }

    private fun lowLatencyWindowPasses() {
        shadowOf(Looper.getMainLooper()).idleFor(BleConstants.SCAN_LOW_LATENCY_DURATION_MS, TimeUnit.MILLISECONDS)
    }

    private fun linkFailure(address: String) {
        coordinator.handleSessionEvent(
            BleSessionEvent.ErrorOccurred(address, BleErrorCategory.CONNECTION_FAILED, "connection_status_8", 8)
        )
    }

    // ── no op waits on its own dispatcher ──

    @Test
    fun a_delivered_pairing_confirm_leaves_the_scan_to_rust_and_holds_no_lane() {
        running = true
        val addr = "AA:BB:CC:DD:EE:01"
        coordinator.peers[addr] = PeerSession(addr).apply { pairingInProgress = true }

        coordinator.handleSessionEvent(BleSessionEvent.PairingConfirmWritten(addr))
        // A TRANSFER op drains after the PAIRING op. If the confirm op waited on its
        // own dispatcher, this blocking call would time out behind it and answer false.
        val sent = coordinator.sendTransactionRequest("AA:BB:CC:DD:EE:02", byteArrayOf(1))

        assertTrue("the confirm op held the dispatcher", sent)
        assertFalse(coordinator.peers[addr]!!.pairingInProgress)
        verify(scanner, never()).stopScanning()
        assertEquals(emptyList<String>(), recorded.events)
    }

    // ── the downshift runs on the lifecycle lane ──

    @Test
    fun the_downshift_waits_for_its_turn_on_the_lifecycle_lane() {
        assertTrue(coordinator.startScanning())
        val release = CountDownLatch(1)
        val holder = holdTheLane(release)
        var stopped = false
        val stopper: Thread
        try {
            lowLatencyWindowPasses()
            verify(scanner, never()).stopScanning()
            verify(scanner, never()).startScanning(false)
            stopper = thread { stopped = coordinator.stopScanning() }
        } finally {
            release.countDown()
        }
        holder.join(10_000)
        stopper.join(10_000)

        inOrder(scanner) {
            verify(scanner).startScanning(true)
            verify(scanner).stopScanning()
            verify(scanner).startScanning(false)
            verify(scanner).stopScanning()
        }
        assertTrue(stopped)
        assertFalse(running)
        assertEquals(listOf("scanStarted", "scanStopped"), recorded.events)
    }

    @Test
    fun bluetooth_off_before_the_downshift_reaches_the_lane_leaves_nothing_to_restart() {
        assertTrue(coordinator.startScanning())
        val release = CountDownLatch(1)
        val holder = holdTheLane(release)
        try {
            coordinator.onRadioOff()
            lowLatencyWindowPasses()
            verify(scanner, never()).startScanning(false)
        } finally {
            release.countDown()
        }
        holder.join(10_000)
        barrier()

        verify(scanner, never()).startScanning(false)
        verify(scanner, never()).stopScanning()
        assertFalse(running)
        assertEquals(listOf("scanStarted", "scanStopped"), recorded.events)
    }

    @Test
    fun after_the_low_latency_window_the_scan_is_restarted_balanced() {
        assertTrue(coordinator.startScanning())
        lowLatencyWindowPasses()
        barrier()

        inOrder(scanner) {
            verify(scanner).stopScanning()
            verify(scanner).startScanning(false)
        }
        assertTrue(running)
        assertEquals(listOf("scanStarted"), recorded.events)
    }

    // ── a scan is restored only while Rust requests one ──

    @Test
    fun a_link_failure_starts_no_scan_rust_did_not_request() {
        linkFailure("AA:BB:CC:DD:EE:10")
        barrier()

        verify(scanner, never()).startScanning(any())
        assertEquals(emptyList<String>(), recorded.events)
    }

    @Test
    fun a_requested_scan_the_stack_ended_is_resumed() {
        assertTrue(coordinator.startPairingScan())
        running = false
        coordinator.onScanFailed(2)
        linkFailure("AA:BB:CC:DD:EE:11")
        barrier()

        verify(scanner, times(2)).startScanning(any())
        assertEquals(listOf("scanStarted", "scanStopped", "scanStarted"), recorded.events)
    }

    @Test
    fun the_transfer_scan_is_not_a_pairing_request() {
        assertTrue(coordinator.startScanning())
        running = false
        coordinator.onScanFailed(2)
        linkFailure("AA:BB:CC:DD:EE:12")
        barrier()

        verify(scanner, times(1)).startScanning(any())
    }

    @Test
    fun a_scan_rust_withdrew_is_not_resumed() {
        assertTrue(coordinator.startPairingScan())
        running = false
        coordinator.onScanFailed(2)
        assertTrue(coordinator.stopPairingScan())
        linkFailure("AA:BB:CC:DD:EE:13")
        barrier()

        verify(scanner, times(1)).startScanning(any())
        assertEquals(listOf("scanStarted", "scanStopped"), recorded.events)
    }

    @Test
    fun rust_withdrawing_its_scan_ends_the_running_scan() {
        assertTrue(coordinator.startPairingScan())
        assertTrue(coordinator.stopPairingScan())

        verify(scanner).stopScanning()
        assertFalse(running)
        assertEquals(listOf("scanStarted", "scanStopped"), recorded.events)
    }

    @Test
    fun a_stop_of_no_scan_does_not_delay_the_next_start() {
        assertTrue(coordinator.stopScanning())
        assertTrue(coordinator.startScanning())

        verify(scanner, times(1)).startScanning(any())
    }
}
