package com.dsm.wallet.bridge

internal object UnifiedBleEvents {

    fun onDeviceConnected(address: String) {
        // Trigger automated reconciliation via bleNotifyConnectionState
        try {
            Unified.bleNotifyConnectionState(address, true)
        } catch (t: Throwable) {
            android.util.Log.e("Unified", "bleNotifyConnectionState(true) failed", t)
            Unified.createTransactionErrorEnvelope(address, 1, "bleNotifyConnectionState(true) failed: ${t.message}")
                ?.let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
        }
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
        try {
            Unified.bleNotifyConnectionState(address, false)
        } catch (t: Throwable) {
            android.util.Log.e("Unified", "bleNotifyConnectionState(false) failed", t)
            Unified.createTransactionErrorEnvelope(address, 1, "bleNotifyConnectionState(false) failed: ${t.message}")
                ?.let { if (it.isNotEmpty()) BleEventRelay.dispatchEnvelope(it) }
        }
        // Dispatch BleEvent.device_disconnected envelope via binary path
        try {
            val envelope = UnifiedNativeApi.createBleConnectionLostEnvelope(address)
            if (envelope.isNotEmpty()) BleEventRelay.dispatchEnvelope(envelope)
        } catch (t: Throwable) {
            android.util.Log.w("Unified", "createBleConnectionLostEnvelope failed: ${t.message}")
        }
        android.util.Log.i("Unified", "onDeviceDisconnected: $address (bridged via binary path)")
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
