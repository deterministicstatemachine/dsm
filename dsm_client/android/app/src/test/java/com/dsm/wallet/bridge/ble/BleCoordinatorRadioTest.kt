package com.dsm.wallet.bridge.ble

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.content.Context
import android.content.Intent
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.CopyOnWriteArrayList
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.atLeastOnce
import org.mockito.kotlin.doReturn
import org.mockito.kotlin.mock
import org.mockito.kotlin.never
import org.mockito.kotlin.verify
import org.mockito.kotlin.verifyBlocking
import org.mockito.kotlin.whenever
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * The coordinator reports only what the radio answered, and Bluetooth going off
 * clears what the radio ended so the next start really starts.
 *
 * The advertiser, scanner and GATT server stand in for the framework's answers;
 * the events are recorded where production relays them to Rust.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleCoordinatorRadioTest {

    private class RecordedEvents : BleRadioEvents {
        val events = CopyOnWriteArrayList<String>()
        override fun advertisingStarted() { events += "advertisingStarted" }
        override fun advertisingStopped() { events += "advertisingStopped" }
        override fun scanStarted() { events += "scanStarted" }
        override fun scanStopped() { events += "scanStopped" }
        override fun permissionDenied(operation: String) { events += "permissionDenied:$operation" }
    }

    private lateinit var context: Context
    private lateinit var advertiser: BleAdvertiser
    private lateinit var scanner: BleScanner
    private lateinit var gattServer: GattServerHost
    private lateinit var recorded: RecordedEvents
    private lateinit var coordinator: BleCoordinator

    @Before
    fun setUp() {
        context = ApplicationProvider.getApplicationContext()
        advertiser = mock()
        scanner = mock()
        gattServer = mock { onBlocking { ensureStarted() } doReturn true }
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

    private fun bluetoothStateReceivers(): Int =
        shadowOf(ApplicationProvider.getApplicationContext<android.app.Application>())
            .registeredReceivers
            .count { it.intentFilter.hasAction(BluetoothAdapter.ACTION_STATE_CHANGED) }

    @Test
    fun bluetooth_state_is_observed_once_by_the_coordinator() {
        val before = bluetoothStateReceivers()
        BleCoordinator(
            context = context,
            permissionsGate = BlePermissionsGate(context),
            advertiser = mock(),
            gattServer = mock(),
            scanner = mock(),
            outbox = mock(),
            diagnostics = BleDiagnostics(),
            radioEvents = recorded,
        )
        assertEquals(1, bluetoothStateReceivers() - before)
    }

    private fun advertiserCallback(): BleAdvertiser.Callback {
        val captor = argumentCaptor<BleAdvertiser.Callback>()
        verify(advertiser, atLeastOnce()).setCallback(captor.capture())
        return captor.lastValue
    }

    @Test
    fun an_advertising_start_the_advertiser_refuses_is_refused_and_reports_nothing() {
        whenever(advertiser.isAdvertising()).thenReturn(false)
        whenever(advertiser.startAdvertising()).thenReturn(false)

        assertFalse(coordinator.startAdvertising())
        assertEquals(emptyList<String>(), recorded.events)
    }

    @Test
    fun advertising_is_reported_started_only_when_the_stack_confirms_the_set() {
        whenever(advertiser.isAdvertising()).thenReturn(false)
        whenever(advertiser.startAdvertising()).thenReturn(true)

        assertTrue("a requested set is an accepted start", coordinator.startAdvertising())
        assertEquals("nothing is on the air until the stack says so", emptyList<String>(), recorded.events)

        advertiserCallback().onAdvertisingStarted()
        assertEquals(listOf("advertisingStarted"), recorded.events)

        advertiserCallback().onAdvertisingStopped()
        assertEquals(listOf("advertisingStarted", "advertisingStopped"), recorded.events)
    }

    @Test
    fun a_scan_the_scanner_refuses_is_refused_and_reports_nothing() {
        whenever(scanner.isScanning()).thenReturn(false)
        whenever(scanner.startScanning(any())).thenReturn(false)

        assertFalse(coordinator.startScanning())
        assertEquals(emptyList<String>(), recorded.events)
    }

    @Test
    fun a_scan_the_scanner_starts_is_reported_started_and_its_stop_reported_once() {
        var running = false
        whenever(scanner.isScanning()).thenAnswer { running }
        whenever(scanner.startScanning(any())).thenAnswer { running = true; true }
        whenever(scanner.stopScanning()).thenAnswer { running = false; true }

        assertTrue(coordinator.startScanning())
        assertEquals(listOf("scanStarted"), recorded.events)

        assertTrue(coordinator.stopScanning())
        assertTrue("stopping a stopped scan", coordinator.stopScanning())
        assertEquals(listOf("scanStarted", "scanStopped"), recorded.events)
    }

    @Test
    fun a_scan_the_stack_fails_after_starting_is_reported_stopped() {
        coordinator.onScanFailed(2)
        assertEquals(listOf("scanStopped"), recorded.events)
    }

    @Test
    fun bluetooth_going_off_clears_the_radio_state_and_the_next_start_starts_again() {
        var onAir = true
        var scanning = true
        whenever(advertiser.isAdvertising()).thenAnswer { onAir }
        whenever(advertiser.radioOff()).thenAnswer { val was = onAir; onAir = false; was }
        whenever(advertiser.startAdvertising()).thenReturn(true)
        whenever(scanner.isScanning()).thenAnswer { scanning }
        whenever(scanner.radioOff()).thenAnswer { val was = scanning; scanning = false; was }
        // A peer connected to our server and subscribed, and a peer we are connected to.
        val serverClient = PeerSession("11:22:33:44:55:66").apply {
            serverDevice = mock<BluetoothDevice>()
            subscribedCccds[BleConstants.TX_RESPONSE_UUID] = true
        }
        val clientSession = mock<GattClientSession>()
        val connected = PeerSession("77:88:99:AA:BB:CC").apply {
            gattClientSession = clientSession
            isConnected = true
        }
        coordinator.peers[serverClient.address] = serverClient
        coordinator.peers[connected.address] = connected

        context.sendBroadcast(
            Intent(BluetoothAdapter.ACTION_STATE_CHANGED)
                .putExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.STATE_OFF)
        )
        shadowOf(Looper.getMainLooper()).idle()

        // The clear runs on the lifecycle lane, so a start issued after it runs after it.
        assertTrue(coordinator.startAdvertising())
        verify(scanner).radioOff()
        verify(advertiser).radioOff()
        verify(gattServer).stop()
        verifyBlocking(gattServer) { ensureStarted() }
        verify(advertiser).startAdvertising()
        assertEquals(listOf("scanStopped", "advertisingStopped"), recorded.events)
        // No link outlives the radio: neither peer is left looking reachable.
        assertFalse(serverClient.isServerClient)
        assertFalse(serverClient.isSubscribedTo(BleConstants.TX_RESPONSE_UUID))
        assertFalse(connected.hasActiveClientSession)
        verify(clientSession).closeQuietly()
        assertTrue("peers with nothing left are dropped", coordinator.peers.isEmpty())
    }

    @Test
    fun without_bluetooth_going_off_a_set_on_the_air_is_not_requested_again() {
        whenever(advertiser.isAdvertising()).thenReturn(true)

        assertTrue(coordinator.startAdvertising())
        verify(advertiser, never()).startAdvertising()
        verify(advertiser, never()).radioOff()
    }
}
