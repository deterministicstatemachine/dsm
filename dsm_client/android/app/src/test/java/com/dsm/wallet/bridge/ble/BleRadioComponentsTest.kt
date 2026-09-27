package com.dsm.wallet.bridge.ble

import android.Manifest
import android.app.Application
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.bluetooth.le.AdvertisingSet
import android.bluetooth.le.AdvertisingSetCallback
import android.bluetooth.le.BluetoothLeAdvertiser
import android.content.Context
import androidx.test.core.app.ApplicationProvider
import java.util.concurrent.CopyOnWriteArrayList
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.mockito.kotlin.any
import org.mockito.kotlin.anyOrNull
import org.mockito.kotlin.argumentCaptor
import org.mockito.kotlin.doThrow
import org.mockito.kotlin.eq
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
 * The advertiser and scanner forget what Bluetooth going off ended, and report
 * the stack's word. Every advertising request is its own callback instance, so
 * the stack's answer about one request is never taken for another's, and a
 * withdrawn request is withdrawn. The framework's answers are simulated at the framework
 * boundary: a stand-in BluetoothLeAdvertiser whose callbacks the test delivers,
 * and Robolectric's scanner.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BleRadioComponentsTest {

    private lateinit var app: Application
    private lateinit var adapter: BluetoothAdapter

    @Before
    fun setUp() {
        app = ApplicationProvider.getApplicationContext()
        shadowOf(app).grantPermissions(
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_SCAN,
        )
        adapter = (app.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager).adapter
        shadowOf(adapter).setEnabled(true)
    }

    private class RecordedAdvertising : BleAdvertiser.Callback {
        val events = CopyOnWriteArrayList<String>()
        override fun onAdvertisingStarted() { events += "started" }
        override fun onAdvertisingStopped() { events += "stopped" }
        override fun onAdvertisingFailed(errorCode: Int) { events += "failed:$errorCode" }
    }

    private fun startedSetCallback(framework: BluetoothLeAdvertiser, requests: Int): AdvertisingSetCallback {
        val captor = argumentCaptor<AdvertisingSetCallback>()
        verify(framework, times(requests)).startAdvertisingSet(
            any(), any(), any(), anyOrNull(), anyOrNull(), captor.capture()
        )
        return captor.lastValue
    }

    @Test
    fun the_advertiser_reports_started_only_on_the_stacks_confirmation_and_a_refusal_as_failed() {
        val framework = mock<BluetoothLeAdvertiser>()
        shadowOf(adapter).setBluetoothLeAdvertiser(framework)
        val advertiser = BleAdvertiser(app)
        val recorded = RecordedAdvertising()
        advertiser.setCallback(recorded)

        assertTrue(advertiser.startAdvertising())
        assertFalse("requested is not on the air", advertiser.isAdvertising())
        assertEquals(emptyList<String>(), recorded.events)

        val confirmed = startedSetCallback(framework, 1)
        confirmed.onAdvertisingSetStarted(mock<AdvertisingSet>(), 0, AdvertisingSetCallback.ADVERTISE_SUCCESS)
        assertTrue(advertiser.isAdvertising())
        assertEquals(listOf("started"), recorded.events)

        assertTrue(advertiser.stopAdvertising())
        // The framework stops the set registered under the instance it is given.
        verify(framework).stopAdvertisingSet(confirmed)
        confirmed.onAdvertisingSetStopped(mock<AdvertisingSet>())
        assertFalse(advertiser.isAdvertising())
        assertEquals(listOf("started", "stopped"), recorded.events)

        assertTrue(advertiser.startAdvertising())
        startedSetCallback(framework, 2).onAdvertisingSetStarted(null, 0, AdvertisingSetCallback.ADVERTISE_FAILED_INTERNAL_ERROR)
        assertFalse(advertiser.isAdvertising())
        assertEquals(listOf("started", "stopped", "failed:${AdvertisingSetCallback.ADVERTISE_FAILED_INTERNAL_ERROR}"), recorded.events)
    }

    @Test
    fun a_stop_while_the_start_is_in_flight_withdraws_the_requested_set_from_the_stack() {
        val framework = mock<BluetoothLeAdvertiser>()
        shadowOf(adapter).setBluetoothLeAdvertiser(framework)
        val advertiser = BleAdvertiser(app)
        val recorded = RecordedAdvertising()
        advertiser.setCallback(recorded)

        assertTrue(advertiser.startAdvertising())
        val inFlight = startedSetCallback(framework, 1)
        assertTrue(advertiser.stopAdvertising())
        // The request is withdrawn under its own instance, or the set the stack
        // confirms later stays on the air with nothing tracking it.
        val order = inOrder(framework)
        order.verify(framework).startAdvertisingSet(any(), any(), any(), anyOrNull(), anyOrNull(), eq(inFlight))
        order.verify(framework).stopAdvertisingSet(inFlight)
        assertFalse(advertiser.isAdvertising())

        // The stack's late answers about the withdrawn request report nothing.
        inFlight.onAdvertisingSetStarted(mock<AdvertisingSet>(), 0, AdvertisingSetCallback.ADVERTISE_SUCCESS)
        inFlight.onAdvertisingSetStopped(mock<AdvertisingSet>())
        assertFalse(advertiser.isAdvertising())
        assertEquals(emptyList<String>(), recorded.events)

        assertTrue(advertiser.startAdvertising())
        startedSetCallback(framework, 2)
    }

    @Test
    fun the_stacks_answer_for_a_withdrawn_request_is_not_taken_for_the_next_request() {
        val framework = mock<BluetoothLeAdvertiser>()
        shadowOf(adapter).setBluetoothLeAdvertiser(framework)
        val advertiser = BleAdvertiser(app)
        val recorded = RecordedAdvertising()
        advertiser.setCallback(recorded)

        assertTrue(advertiser.startAdvertising())
        val withdrawn = startedSetCallback(framework, 1)
        assertTrue(advertiser.stopAdvertising())
        assertTrue(advertiser.startAdvertising())
        val next = startedSetCallback(framework, 2)
        assertNotSame("every request is its own callback instance", withdrawn, next)

        withdrawn.onAdvertisingSetStarted(mock<AdvertisingSet>(), 0, AdvertisingSetCallback.ADVERTISE_SUCCESS)
        withdrawn.onAdvertisingSetStopped(mock<AdvertisingSet>())
        assertFalse("the withdrawn set is not the next request's", advertiser.isAdvertising())
        assertEquals(emptyList<String>(), recorded.events)

        next.onAdvertisingSetStarted(null, 0, AdvertisingSetCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS)
        assertFalse(advertiser.isAdvertising())
        assertEquals(listOf("failed:${AdvertisingSetCallback.ADVERTISE_FAILED_TOO_MANY_ADVERTISERS}"), recorded.events)
    }

    @Test
    fun a_set_the_stack_confirms_for_a_request_no_longer_current_is_withdrawn() {
        val framework = mock<BluetoothLeAdvertiser>()
        shadowOf(adapter).setBluetoothLeAdvertiser(framework)
        val advertiser = BleAdvertiser(app)
        val recorded = RecordedAdvertising()
        advertiser.setCallback(recorded)

        assertTrue(advertiser.startAdvertising())
        val first = startedSetCallback(framework, 1)
        first.onAdvertisingSetStarted(null, 0, AdvertisingSetCallback.ADVERTISE_FAILED_INTERNAL_ERROR)
        verify(framework, never()).stopAdvertisingSet(any())

        // A set on the air that no current request wants is taken off and reported as nothing.
        first.onAdvertisingSetStarted(mock<AdvertisingSet>(), 0, AdvertisingSetCallback.ADVERTISE_SUCCESS)
        verify(framework).stopAdvertisingSet(first)
        assertFalse(advertiser.isAdvertising())
        assertEquals(listOf("failed:${AdvertisingSetCallback.ADVERTISE_FAILED_INTERNAL_ERROR}"), recorded.events)
    }

    @Test
    fun a_stop_the_stack_rejects_leaves_the_set_on_the_air() {
        val framework = mock<BluetoothLeAdvertiser>()
        shadowOf(adapter).setBluetoothLeAdvertiser(framework)
        val advertiser = BleAdvertiser(app)
        val recorded = RecordedAdvertising()
        advertiser.setCallback(recorded)

        assertTrue(advertiser.startAdvertising())
        val confirmed = startedSetCallback(framework, 1)
        confirmed.onAdvertisingSetStarted(mock<AdvertisingSet>(), 0, AdvertisingSetCallback.ADVERTISE_SUCCESS)
        doThrow(SecurityException("stop refused")).whenever(framework).stopAdvertisingSet(confirmed)

        assertFalse("the stop was not taken", advertiser.stopAdvertising())
        assertTrue("the stack's last word is that the set is on the air", advertiser.isAdvertising())
        assertEquals(listOf("started"), recorded.events)
    }

    @Test
    fun bluetooth_off_ends_the_advertising_set_and_the_next_start_requests_a_new_one() {
        val framework = mock<BluetoothLeAdvertiser>()
        shadowOf(adapter).setBluetoothLeAdvertiser(framework)
        val advertiser = BleAdvertiser(app)
        assertFalse("nothing was on the air", advertiser.radioOff())

        assertTrue(advertiser.startAdvertising())
        assertFalse("a set the stack never confirmed was not on the air", advertiser.radioOff())

        assertTrue(advertiser.startAdvertising())
        val confirmed = startedSetCallback(framework, 2)
        confirmed.onAdvertisingSetStarted(mock<AdvertisingSet>(), 0, AdvertisingSetCallback.ADVERTISE_SUCCESS)
        assertTrue(advertiser.isAdvertising())

        assertTrue("a confirmed set was on the air", advertiser.radioOff())
        assertFalse(advertiser.isAdvertising())
        // A late answer about the ended set changes nothing.
        confirmed.onAdvertisingSetStarted(mock<AdvertisingSet>(), 0, AdvertisingSetCallback.ADVERTISE_SUCCESS)
        assertFalse(advertiser.isAdvertising())

        assertTrue(advertiser.startAdvertising())
        startedSetCallback(framework, 3)
    }

    @Test
    fun bluetooth_off_during_a_stop_frees_the_advertiser_to_start_again() {
        val framework = mock<BluetoothLeAdvertiser>()
        shadowOf(adapter).setBluetoothLeAdvertiser(framework)
        val advertiser = BleAdvertiser(app)
        assertTrue(advertiser.startAdvertising())
        startedSetCallback(framework, 1).onAdvertisingSetStarted(mock<AdvertisingSet>(), 0, AdvertisingSetCallback.ADVERTISE_SUCCESS)
        assertTrue(advertiser.stopAdvertising())
        // Bluetooth goes off before the stack confirms the stop: without the reset the
        // advertiser waits for a callback that never comes and refuses every start.
        assertTrue("stopping from on the air counts as on the air", advertiser.radioOff())

        assertTrue(advertiser.startAdvertising())
        startedSetCallback(framework, 2)
    }

    @Test
    fun bluetooth_off_ends_the_scan_and_the_next_start_issues_a_new_one() {
        val scanner = BleScanner(app)
        val framework = shadowOf(adapter.bluetoothLeScanner)

        assertTrue(scanner.startScanning())
        assertTrue(scanner.isScanning())
        assertEquals(1, framework.scanCallbacks.size)

        assertTrue("a scan was running", scanner.radioOff())
        assertFalse(scanner.isScanning())
        assertFalse("nothing to clear twice", scanner.radioOff())

        assertTrue(scanner.startScanning())
        assertTrue(scanner.isScanning())
    }
}
