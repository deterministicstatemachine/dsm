// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge.ble

import android.annotation.SuppressLint
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
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
 *
 * Every start issues its own [SetRequest]: the framework keys an advertising set
 * by its callback instance (a stop removes the set registered under the instance
 * it is given, and silently does nothing for an instance it does not hold), so
 * one callback per request is what lets a withdrawn request be withdrawn, and
 * keeps the stack's answer about one request from being taken for another's.
 *
 * Threading: start, stop and [radioOff] are serialized with each other on the
 * coordinator's lifecycle lane; the framework's callbacks arrive on the main
 * looper and interleave with them. Every transition is a compare-and-set on the
 * exact [Phase] instance that was read.
 */
class BleAdvertiser(private val context: Context) {

    /** The stack's answers about the advertising set, as they arrive. */
    interface Callback {
        /** The stack confirmed the set: it is on the air. */
        fun onAdvertisingStarted()
        /** The stack confirmed a requested stop: it is off the air. */
        fun onAdvertisingStopped()
        /** The stack refused the set it was asked to start. */
        fun onAdvertisingFailed(errorCode: Int)
    }

    private var callback: Callback? = null

    fun setCallback(callback: Callback?) {
        this.callback = callback
    }

    /** Where the current request stands with the stack. */
    private sealed class Phase {
        /** No set on the air and none requested. */
        object Idle : Phase()
        /** The stack was asked to start [request]'s set and has not answered. */
        class Requesting(val request: SetRequest) : Phase()
        /** The stack confirmed [request]'s set: it is on the air. */
        class Started(val request: SetRequest) : Phase()
        /** The stack was asked to stop [request]'s confirmed set and has not answered. */
        class Stopping(val request: SetRequest) : Phase()
    }

    private val phase = AtomicReference<Phase>(Phase.Idle)

    private var permissionsGate: BlePermissionsGate? = null

    private fun ensurePermissionsGate(): BlePermissionsGate {
        return permissionsGate ?: BlePermissionsGate(context).also {
            permissionsGate = it
        }
    }

    /**
     * One start request and the stack's answers about it. [framework] is the
     * advertiser the request was issued on; its set is stopped there, under this
     * instance.
     */
    private inner class SetRequest(val framework: BluetoothLeAdvertiser) : AdvertisingSetCallback() {

        @SuppressLint("MissingPermission")
        override fun onAdvertisingSetStarted(
            advertisingSet: AdvertisingSet?,
            txPower: Int,
            status: Int
        ) {
            val current = phase.get()
            val isCurrent = current is Phase.Requesting && current.request === this
            if (status == AdvertisingSetCallback.ADVERTISE_SUCCESS) {
                if (isCurrent && phase.compareAndSet(current, Phase.Started(this))) {
                    Log.i(TAG, "Advertising set started (txPower=$txPower)")
                    callback?.onAdvertisingStarted()
                    return
                }
                // The stack put a set on the air that no current request wants
                // (withdrawn, or ended with the radio): take it off, report nothing.
                Log.w(TAG, "Advertising set started for a request no longer current; withdrawing it")
                try {
                    framework.stopAdvertisingSet(this)
                } catch (t: Throwable) {
                    Log.e(TAG, "Failed to withdraw an advertising set no request wants", t)
                }
                return
            }
            if (isCurrent && phase.compareAndSet(current, Phase.Idle)) {
                Log.e(TAG, "Advertising set failed to start, status=$status")
                callback?.onAdvertisingFailed(status)
            } else {
                Log.w(TAG, "Stale advertising start failure (status=$status) for a request no longer current; ignored")
            }
        }

        override fun onAdvertisingSetStopped(advertisingSet: AdvertisingSet?) {
            val current = phase.get()
            if (current is Phase.Stopping && current.request === this &&
                phase.compareAndSet(current, Phase.Idle)
            ) {
                Log.i(TAG, "Advertising set stopped")
                callback?.onAdvertisingStopped()
            } else {
                Log.w(TAG, "Stale advertising stop for a request no longer current; ignored")
            }
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

        val framework = adapter.bluetoothLeAdvertiser ?: run {
            Log.w(TAG, "No BLE advertiser available")
            return false
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

        while (true) {
            when (val current = phase.get()) {
                is Phase.Started -> {
                    Log.d(TAG, "Already advertising")
                    return true
                }
                is Phase.Requesting -> {
                    Log.d(TAG, "Start already in flight")
                    return true
                }
                is Phase.Stopping -> {
                    Log.d(TAG, "Start requested while stopping; the stop must be confirmed first")
                    return false
                }
                Phase.Idle -> {
                    val request = SetRequest(framework)
                    val requesting = Phase.Requesting(request)
                    if (!phase.compareAndSet(current, requesting)) continue
                    return try {
                        framework.startAdvertisingSet(
                            parameters,
                            advertiseData,
                            scanResponseData,
                            null,  // no periodic advertising parameters
                            null,  // no periodic advertising data
                            request
                        )
                        Log.i(TAG, "BLE advertising set requested (with scan response)")
                        true
                    } catch (t: Throwable) {
                        Log.e(TAG, "Failed to request advertising set", t)
                        phase.compareAndSet(requesting, Phase.Idle)
                        false
                    }
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    fun stopAdvertising(): Boolean {
        while (true) {
            when (val current = phase.get()) {
                Phase.Idle -> {
                    Log.d(TAG, "Not advertising")
                    return true
                }
                is Phase.Stopping -> {
                    Log.d(TAG, "Already stopping")
                    return true
                }
                is Phase.Requesting -> {
                    // The confirmation may land between the read and the swap; then
                    // the set is on the air and is stopped as a started one.
                    if (!phase.compareAndSet(current, Phase.Idle)) continue
                    val request = current.request
                    // Nothing was reported started, so nothing is reported stopped.
                    // Withdraw the request from the stack under its own instance, or
                    // the set it confirms later stays on the air untracked.
                    return try {
                        request.framework.stopAdvertisingSet(request)
                        Log.i(TAG, "BLE advertising request withdrawn before the stack confirmed it")
                        true
                    } catch (t: Throwable) {
                        // The request is no longer current: if the stack confirms its
                        // set, the confirmation withdraws it.
                        Log.e(TAG, "Failed to withdraw the advertising request", t)
                        false
                    }
                }
                is Phase.Started -> {
                    val request = current.request
                    val stopping = Phase.Stopping(request)
                    if (!phase.compareAndSet(current, stopping)) continue
                    return try {
                        request.framework.stopAdvertisingSet(request)
                        Log.i(TAG, "BLE advertising stop requested")
                        true
                    } catch (t: Throwable) {
                        // The stack's last word is that the set is on the air.
                        Log.e(TAG, "Failed to stop advertising; the set stays on the air", t)
                        phase.compareAndSet(stopping, Phase.Started(request))
                        false
                    }
                }
            }
        }
    }

    fun isAdvertising(): Boolean = phase.get() is Phase.Started

    /**
     * Bluetooth is going off: the stack ends every advertising set with the radio,
     * and a callback for it may never come. Nothing is advertising and nothing is
     * in flight after this, so the next start requests a new set. Returns whether a
     * confirmed set was on the air (started, or stopping from started).
     */
    fun radioOff(): Boolean {
        val previous = phase.getAndSet(Phase.Idle)
        if (previous !== Phase.Idle) {
            Log.i(TAG, "Bluetooth off: advertising ${previous.javaClass.simpleName} cleared")
        }
        return previous is Phase.Started || previous is Phase.Stopping
    }

    companion object {
        private const val TAG = "BleAdvertiser"
    }
}
