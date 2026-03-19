package com.dsm.wallet.bridge

import android.util.Log
import com.dsm.wallet.bridge.ble.BleCoordinator

internal object BridgeBleHandler {

    fun requestBlePermissions() {
        try {
            val act = com.dsm.wallet.ui.MainActivity.getActiveInstance()
            if (act != null) {
                act.runOnUiThread {
                    try {
                        act.requestBlePermissionsFromUi()
                    } catch (_: Throwable) {
                        // ignore
                    }
                }
            }
        } catch (_: Throwable) {
            // ignore
        }
    }

    fun setBleIdentityForAdvertising(payload: ByteArray, logTag: String): ByteArray {
        if (payload.size != 64) {
            Log.e(logTag, "setBleIdentityForAdvertising: expected 64 bytes, got ${payload.size}")
            return ByteArray(0)
        }
        val genesisHash = payload.copyOfRange(0, 32)
        val deviceId = payload.copyOfRange(32, 64)

        try {
            val ctx = com.dsm.wallet.ui.MainActivity.getActiveInstance()?.baseContext
            if (ctx == null) {
                Log.w(logTag, "setBleIdentityForAdvertising: no active MainActivity")
                return ByteArray(0)
            }
            val bleService = BleCoordinator.getInstance(ctx)

            val gattReady = bleService.ensureGattServerStarted()
            if (!gattReady) {
                Log.w(logTag, "setBleIdentityForAdvertising: GATT server not ready (permissions not granted yet)")
                bleService.setIdentityValue(genesisHash, deviceId)
                return ByteArray(0)
            }

            bleService.setIdentityValue(genesisHash, deviceId)
            Log.i(logTag, "setBleIdentityForAdvertising: identity injected into BLE (genesis=${genesisHash.size}B, deviceId=${deviceId.size}B)")
        } catch (t: Throwable) {
            Log.w(logTag, "setBleIdentityForAdvertising failed", t)
        }
        return ByteArray(0)
    }
}
