package com.dsm.wallet.bridge.ble

import android.annotation.SuppressLint
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference

/**
 * Handles Bluetooth LE advertising using the extended advertising API (API 26+).
 *
 * Uses [AdvertisingSetParameters] and [AdvertisingSetCallback].
 *
 * This component manages:
 * - Starting/stopping BLE advertising sets
 * - Advertising data and parameters
 * - Advertising set callbacks and error handling
 */
class BleAdvertiser(private val context: Context) {

    interface Callback {
        fun onAdvertisingFailed(errorCode: Int)
    }

    private var callback: Callback? = null

    fun setCallback(callback: Callback?) {
        this.callback = callback
    }

    // Current state: IDLE=0, REQUESTING_START=1, STARTED=2, REQUESTING_STOP=3
    private val state = AtomicReference<Int>(0)

    private val advertisingRequestId = AtomicInteger(0)
    private val currentAdvertisingSet = AtomicReference<AdvertisingSet?>(null)
    private var bluetoothLeAdvertiser: BluetoothLeAdvertiser? = null

    private var permissionsGate: BlePermissionsGate? = null

    private fun ensurePermissionsGate(): BlePermissionsGate {
        return permissionsGate ?: BlePermissionsGate(context).also {
            permissionsGate = it
        }
    }

    private val advertisingSetCallback = object : AdvertisingSetCallback() {
        override fun onAdvertisingSetStarted(
            advertisingSet: AdvertisingSet?,
            txPower: Int,
            status: Int
        ) {
            val currentId = advertisingRequestId.get()
            if (state.get() != 1) { // Not REQUESTING_START
                Log.w(TAG, "Stale start callback (id=$currentId, state=${state.get()}) ignored")
                return
            }

            if (status == AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                currentAdvertisingSet.set(advertisingSet)
                state.set(2) // STARTED
                Log.i(TAG, "Advertising set started (txPower=$txPower, id=$currentId)")
            } else {
                currentAdvertisingSet.set(null)
                state.set(0) // IDLE
                Log.e(TAG, "Advertising set failed to start, status=$status, id=$currentId")
                callback?.onAdvertisingFailed(status)
            }
        }

        override fun onAdvertisingSetStopped(advertisingSet: AdvertisingSet?) {
            val currentId = advertisingRequestId.get()
            if (state.get() != 3) { // Not REQUESTING_STOP
                Log.w(TAG, "Stale stop callback (id=$currentId, state=${state.get()}) ignored")
                return
            }

            currentAdvertisingSet.set(null)
            state.set(0) // IDLE
            Log.i(TAG, "Advertising set stopped (id=$currentId)")
        }

        override fun onAdvertisingDataSet(advertisingSet: AdvertisingSet?, status: Int) {
            if (status != AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                Log.e(TAG, "Failed to set advertising data, status=$status")
            }
        }

        override fun onScanResponseDataSet(advertisingSet: AdvertisingSet?, status: Int) {
            if (status != AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                Log.e(TAG, "Failed to set scan response data, status=$status")
            }
        }
    }

    @SuppressLint("MissingPermission")
    fun startAdvertising(): Boolean {
        val gate = ensurePermissionsGate()
        if (!gate.hasAdvertisePermission()) {
            Log.w(TAG, "Missing BLUETOOTH_ADVERTISE permission")
            return false
        }

        val adapter = gate.getBluetoothAdapter() ?: run {
            Log.w(TAG, "No Bluetooth adapter available")
            return false
        }

        if (!adapter.isEnabled) {
            Log.w(TAG, "Bluetooth adapter is disabled")
            return false
        }

        bluetoothLeAdvertiser = adapter.bluetoothLeAdvertiser ?: run {
            Log.w(TAG, "No BLE advertiser available")
            return false
        }

        val currentState = state.get()
        if (currentState == 2) { // Already STARTED
            Log.d(TAG, "Already advertising")
            return true
        }

        if (currentState == 1) { // REQUESTING_START - idempotent
            Log.d(TAG, "Start already in flight")
            return true
        }

        if (currentState == 3) { // REQUESTING_STOP - wait for it
            Log.d(TAG, "Start requested while stopping, will retry after stop")
            return false
        }

        // Transition IDLE -> REQUESTING_START
        if (!state.compareAndSet(0, 1)) {
            Log.w(TAG, "State transition failed (expected IDLE)")
            return false
        }

        val requestId = advertisingRequestId.incrementAndGet()

        // Defensive cleanup for any existing set
        try {
            bluetoothLeAdvertiser?.stopAdvertisingSet(advertisingSetCallback)
        } catch (_: Throwable) {
            // Ignore - may not exist
        }

        val parameters = AdvertisingSetParameters.Builder()
            .setLegacyMode(true)  // Connectable/scannable PDU required by current target devices
            .setConnectable(true)
            .setScannable(true)
            .setInterval(AdvertisingSetParameters.INTERVAL_LOW)
            .setTxPowerLevel(AdvertisingSetParameters.TX_POWER_HIGH)
            .build()

        val serviceUuid = ParcelUuid(BleConstants.DSM_SERVICE_UUID_V2)
        val advertiseData = AdvertiseData.Builder()
            .addServiceUuid(serviceUuid)
            .setIncludeDeviceName(false)
            .build()

        // Scan response carries manufacturer data for truncated advertisements.
        // Some Android devices truncate the advertising PDU and omit the 128-bit service UUID.
        // The scan response is sent on active scan and provides the secondary identifier.
        val scanResponseData = AdvertiseData.Builder()
            .addManufacturerData(BleConstants.DSM_MANUFACTURER_ID, BleConstants.DSM_MANUFACTURER_MAGIC)
            .setIncludeDeviceName(false)
            .build()

        return try {
            bluetoothLeAdvertiser?.startAdvertisingSet(
                parameters,
                advertiseData,
                scanResponseData,
                null,  // no periodic advertising parameters
                null,  // no periodic advertising data
                advertisingSetCallback
            )
            Log.i(TAG, "BLE advertising set requested (id=$requestId, with scan response)")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to start advertising set (id=$requestId)", t)
            state.set(0) // Back to IDLE on exception
            false
        }
    }

    @SuppressLint("MissingPermission")
    fun stopAdvertising(): Boolean {
        val currentState = state.get()
        if (currentState == 0) { // IDLE
            Log.d(TAG, "Not advertising")
            return true
        }

        if (currentState == 2) { // STARTED -> REQUESTING_STOP
            if (!state.compareAndSet(2, 3)) {
                Log.w(TAG, "Failed to transition STARTED -> REQUESTING_STOP")
                return false
            }
        } else if (currentState == 1) { // REQUESTING_START -> IDLE
            state.set(0)
            Log.d(TAG, "Stop requested while starting -> IDLE")
            return true
        } else { // Already REQUESTING_STOP
            Log.d(TAG, "Already stopping")
            return true
        }

        val bluetoothLeAdvertiserLocal = bluetoothLeAdvertiser
        if (bluetoothLeAdvertiserLocal == null) {
            Log.w(TAG, "No advertiser available for stop")
            state.set(0) // Treat as stopped
            return false
        }

        return try {
            bluetoothLeAdvertiserLocal.stopAdvertisingSet(advertisingSetCallback)
            Log.i(TAG, "BLE advertising stop requested")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to stop advertising", t)
            state.set(0) // Treat as stopped on error
            false
        }
    }

    fun isAdvertising(): Boolean = state.get() == 2

    companion object {
        private const val TAG = "BleAdvertiser"
    }
}