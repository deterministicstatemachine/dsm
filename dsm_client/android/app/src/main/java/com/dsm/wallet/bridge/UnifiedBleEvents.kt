// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

internal object UnifiedBleEvents {

    fun onDeviceConnected(address: String) {
        // Dispatch BleEvent.device_connected envelope via binary path
        try {
            val envelope = UnifiedNativeApi.createBleConnectionEstablishedEnvelope(address, "")
            if (envelope.isNotEmpty()) BleEventRelay.dispatchEnvelope(envelope)
        } catch (t: Throwable) {
            android.util.Log.w("Unified", "createBleConnectionEstablishedEnvelope failed: ${t.message}")
        }
        android.util.Log.i("Unified", "onDeviceConnected: $address (bridged via binary path)")
    }

    fun onDeviceDisconnected(address: String) {
        // Dispatch BleEvent.device_disconnected envelope via binary path
        try {
            val envelope = UnifiedNativeApi.createBleConnectionLostEnvelope(address)
            if (envelope.isNotEmpty()) BleEventRelay.dispatchEnvelope(envelope)
        } catch (t: Throwable) {
            android.util.Log.w("Unified", "createBleConnectionLostEnvelope failed: ${t.message}")
        }
        android.util.Log.i("Unified", "onDeviceDisconnected: $address (bridged via binary path)")
    }

    /**
     * The link at [address] carries the appliance [deviceId]: its identity is
     * anchored there. Rust delivers what it owes that appliance.
     */
    fun onLinkUp(deviceId: ByteArray, address: String) {
        try {
            Unified.bleNotifyLink(deviceId, address, true)
        } catch (t: Throwable) {
            android.util.Log.e("Unified", "bleNotifyLink(up) failed", t)
        }
    }

    /** The link that carried the appliance [deviceId] ended. */
    fun onLinkDown(deviceId: ByteArray, address: String) {
        try {
            Unified.bleNotifyLink(deviceId, address, false)
        } catch (t: Throwable) {
            android.util.Log.e("Unified", "bleNotifyLink(down) failed", t)
        }
    }

    fun onScanStarted() {
        android.util.Log.i("Unified", "onScanStarted")
        try {
            val envelope = UnifiedNativeApi.createBleScanStartedEnvelope()
            if (envelope.isNotEmpty()) BleEventRelay.dispatchEnvelope(envelope)
        } catch (t: Throwable) {
            android.util.Log.w("Unified", "createBleScanStartedEnvelope failed: ${t.message}")
        }
    }

    fun onScanStopped() {
        android.util.Log.i("Unified", "onScanStopped")
        try {
            val envelope = UnifiedNativeApi.createBleScanStoppedEnvelope()
            if (envelope.isNotEmpty()) BleEventRelay.dispatchEnvelope(envelope)
        } catch (t: Throwable) {
            android.util.Log.w("Unified", "createBleScanStoppedEnvelope failed: ${t.message}")
        }
    }

    fun onDeviceFound(address: String, name: String, rssi: Int) {
        android.util.Log.i("Unified", "onDeviceFound: $address ($name) RSSI=$rssi")
        try {
            val envelope = UnifiedNativeApi.createBleDeviceFoundEnvelope(address, name, rssi)
            if (envelope.isNotEmpty()) BleEventRelay.dispatchEnvelope(envelope)
        } catch (t: Throwable) {
            android.util.Log.w("Unified", "createBleDeviceFoundEnvelope failed: ${t.message}")
        }
    }

    fun onAdvertisingStarted() {
        android.util.Log.i("Unified", "onAdvertisingStarted")
        try {
            val envelope = UnifiedNativeApi.createBleAdvertisingStartedEnvelope()
            if (envelope.isNotEmpty()) BleEventRelay.dispatchEnvelope(envelope)
        } catch (t: Throwable) {
            android.util.Log.w("Unified", "createBleAdvertisingStartedEnvelope failed: ${t.message}")
        }
    }

    fun onAdvertisingStopped() {
        android.util.Log.i("Unified", "onAdvertisingStopped")
        try {
            val envelope = UnifiedNativeApi.createBleAdvertisingStoppedEnvelope()
            if (envelope.isNotEmpty()) BleEventRelay.dispatchEnvelope(envelope)
        } catch (t: Throwable) {
            android.util.Log.w("Unified", "createBleAdvertisingStoppedEnvelope failed: ${t.message}")
        }
    }


    fun onConnectionFailed(address: String, reason: String) {
        try {
            val code = if (reason.contains(":")) {
                reason.substringAfterLast(":").toIntOrNull() ?: 1
            } else {
                1
            }

            Unified.createTransactionErrorEnvelope(address, code, reason)?.let {
                if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it)
            }
        } catch (t: Throwable) {
            android.util.Log.e("Unified", "Failed to dispatch connection failure envelope", t)
        }
    }
}
