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
        // Payload is protobuf-encoded BleIdentityCharValue from Rust's
        // encodeIdentityCharValue. Decode the proto fields.
        val genesisHash: ByteArray
        val deviceId: ByteArray
        try {
            val parsed = dsm.types.proto.BleIdentityCharValue.parseFrom(payload)
            genesisHash = parsed.genesisHash.toByteArray()
            deviceId = parsed.deviceId.toByteArray()
            if (genesisHash.size != 32 || deviceId.size != 32) {
                Log.e(logTag, "setBleIdentityForAdvertising: proto field sizes wrong genesis=${genesisHash.size} device=${deviceId.size}")
                return ByteArray(0)
            }
        } catch (e: Exception) {
            Log.e(logTag, "setBleIdentityForAdvertising: failed to decode ${payload.size} bytes: ${e.message}")
            return ByteArray(0)
        }

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
