package com.dsm.wallet.bridge.ble

import android.annotation.SuppressLint
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Handles Bluetooth LE advertising using the extended advertising API (API 26+).
 *
 * Uses [AdvertisingSetParameters] and [AdvertisingSetCallback] — the modern API
 * that replaces the deprecated AdvertiseSettings/AdvertiseCallback path.
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

    private val advertising = AtomicBoolean(false)
    private val currentAdvertisingSet = AtomicReference<AdvertisingSet?>(null)
    private var bluetoothLeAdvertiser: BluetoothLeAdvertiser? = null

    private val advertisingSetCallback = object : AdvertisingSetCallback() {
        override fun onAdvertisingSetStarted(
            advertisingSet: AdvertisingSet?,
            txPower: Int,
            status: Int
        ) {
            if (status == AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                currentAdvertisingSet.set(advertisingSet)
                advertising.set(true)
                Log.i(TAG, "Advertising set started (txPower=$txPower)")
            } else {
                currentAdvertisingSet.set(null)
                advertising.set(false)
                Log.e(TAG, "Advertising set failed to start, status=$status")
                callback?.onAdvertisingFailed(status)
            }
        }

        override fun onAdvertisingSetStopped(advertisingSet: AdvertisingSet?) {
            currentAdvertisingSet.set(null)
            advertising.set(false)
            Log.i(TAG, "Advertising set stopped")
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
        if (advertising.get() || currentAdvertisingSet.get() != null) {
            Log.d(TAG, "Already advertising")
            return true
        }

        val permissionsGate = BlePermissionsGate(context)
        if (!permissionsGate.hasAdvertisePermission()) {
            Log.w(TAG, "Missing BLUETOOTH_ADVERTISE permission")
            return false
        }

        val adapter = permissionsGate.getBluetoothAdapter() ?: run {
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

        val parameters = AdvertisingSetParameters.Builder()
            .setLegacyMode(true)  // Legacy PDU for broadest device compatibility
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

        // Defensive cleanup: stop any existing advertising set to avoid
        // IllegalArgumentException("callback instance already associated").
        // Handles the race where startAdvertising() is called before the
        // previous onAdvertisingSetStopped callback has fired.
        try { bluetoothLeAdvertiser?.stopAdvertisingSet(advertisingSetCallback) } catch (_: Throwable) {}

        return try {
            bluetoothLeAdvertiser?.startAdvertisingSet(
                parameters,
                advertiseData,
                scanResponseData,
                null,  // no periodic advertising parameters
                null,  // no periodic advertising data
                advertisingSetCallback
            )
            Log.i(TAG, "BLE advertising set requested (with scan response)")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to start advertising set", t)
            false
        }
    }

    @SuppressLint("MissingPermission")
    fun stopAdvertising(): Boolean {
        if (!advertising.get()) {
            Log.d(TAG, "Not advertising")
            return true
        }

        return try {
            bluetoothLeAdvertiser?.stopAdvertisingSet(advertisingSetCallback)
            currentAdvertisingSet.set(null)
            advertising.set(false)
            Log.i(TAG, "BLE advertising stopped")
            true
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to stop advertising", t)
            false
        }
    }

    fun isAdvertising(): Boolean = advertising.get()

    companion object {
        private const val TAG = "BleAdvertiser"
    }
}
