// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import android.util.Log
import com.dsm.wallet.bridge.ble.BleConstants
import com.dsm.wallet.bridge.ble.BleCoordinator
import kotlinx.coroutines.runBlocking

internal object UnifiedBleBridge {

    private var bleCoordinator: BleCoordinator? = null
    /**
     * Write one message over our client link to [address]: TX_RESPONSE is
     * subscribed first, so the peer's answer can come back on this link.
     */
    private suspend fun sendOverClientLink(
        svc: BleCoordinator,
        address: String,
        chunks: Array<ByteArray>,
        failureCode: String,
    ): Boolean {
        if (!svc.ensureClientTxResponseSubscribed(address).await()) {
            Log.e("UnifiedBleBridge", "TX_RESPONSE not subscribed on the client link to $address; the message is not sent")
            UnifiedBleEvents.onConnectionFailed(address, "tx_response_subscription_failed")
            return false
        }
        Log.i("BleTransferTrace", "client link -> $address (chunks=${chunks.size})")
        val sent = svc.writeMessage(address, chunks)
        if (!sent) {
            Log.e("UnifiedBleBridge", "the message to $address was not written")
            UnifiedBleEvents.onConnectionFailed(address, failureCode)
        }
        return sent
    }

    private suspend fun sendOverServerLink(
        svc: BleCoordinator,
        address: String,
        chunks: Array<ByteArray>,
        failureCode: String,
    ): Boolean {
        Log.i("BleTransferTrace", "server notifications -> $address (chunks=${chunks.size})")
        val sent = svc.sendViaServerNotifications(address, chunks)
        if (!sent) UnifiedBleEvents.onConnectionFailed(address, failureCode)
        return sent
    }

    /**
     * Write [chunks], sealed by Rust, on exactly the link at [deviceAddress]
     * where this device is [role] (DSM Amendment A27: Rust chooses the link).
     * Nothing switches to another link: a link that is gone fails closed, and
     * Rust's frame stays owed.
     */
    fun dispatchRustFollowUp(
        deviceAddress: String,
        role: Int,
        chunks: Array<ByteArray>,
    ): Boolean {
        val svc = bleCoordinator ?: return false
        if (chunks.isEmpty()) {
            return true
        }
        return try {
            runBlocking {
                when (role) {
                    BleConstants.LINK_ROLE_CLIENT ->
                        svc.hasActiveClientSession(deviceAddress) &&
                            sendOverClientLink(svc, deviceAddress, chunks, "followup_client_send_failed")
                    BleConstants.LINK_ROLE_SERVER ->
                        svc.isGattServerClient(deviceAddress) &&
                            svc.isServerClientSubscribedToTxResponse(deviceAddress) &&
                            sendOverServerLink(svc, deviceAddress, chunks, "followup_server_notify_failed")
                    else -> {
                        Log.e("UnifiedBleBridge", "dispatchRustFollowUp: role $role names no link at $deviceAddress")
                        false
                    }
                }
            }
        } catch (t: Throwable) {
            Log.e("UnifiedBleBridge", "dispatchRustFollowUp failed for $deviceAddress", t)
            false
        }
    }

    // A link's handshake needs this device's identity and keys; advertising
    // without them would answer every Hello with nothing.
    private fun localIdentityAvailable(): Boolean = try {
        Unified.getDeviceIdBin().size == 32 && Unified.getGenesisHashBin().size == 32
    } catch (_: Throwable) {
        false
    }

    fun initBleCoordinator(
        context: android.content.Context,
        eventDispatcher: (eventName: String, detail: String) -> Unit
    ) {
        if (bleCoordinator == null) {
            bleCoordinator = BleCoordinator.getInstance(context)
            bleCoordinator?.setCallback(object : BleCoordinator.Callback {
                override fun onBlePermissionError(message: String) {
                    eventDispatcher("ble-permission-error", message)
                }
            })
        }
    }

    fun startBlePairingAdvertise(): Boolean {
        val svc = bleCoordinator ?: return false
        return try {
            if (!localIdentityAvailable()) {
                Log.w("UnifiedBleBridge", "startBlePairingAdvertise: refusing to advertise without local identity")
                return false
            }
            svc.startAdvertising()
        } catch (_: Throwable) { false }
    }

    fun startBlePairingScan(): Boolean {
        val svc = bleCoordinator ?: return false
        return try { svc.startScanning() } catch (_: Throwable) { false }
    }

    fun stopBlePairingScan(): Boolean {
        val svc = bleCoordinator ?: return false
        return try {
            svc.stopPairingScan()
        } catch (t: Throwable) {
            Log.w("UnifiedBleBridge", "stopBlePairingScan failed; answering whether the scanner is off", t)
            !svc.isScanning()
        }
    }


    /**
     * Rust asks for a link to the contact [deviceId], [addressHint] first: the
     * coordinator connects, and the link it opens names [deviceId] as its
     * handshake's target.
     */
    fun requestGattConnect(deviceId: ByteArray, addressHint: String) {
        val svc = bleCoordinator ?: return
        if (deviceId.size != 32) {
            Log.e("UnifiedBleBridge", "requestGattConnect: a device id of ${deviceId.size} bytes reaches nothing")
            return
        }
        svc.requestConnect(deviceId, addressHint)
    }

    fun getBleStats(deviceAddress: String): ByteArray {
        val svc = bleCoordinator ?: return ByteArray(0)
        return try { svc.getStatsString(deviceAddress).toByteArray(Charsets.UTF_8) } catch (_: Throwable) { ByteArray(0) }
    }

    fun getConnectedBluetoothDevices(): ByteArray {
        val svc = bleCoordinator ?: return ByteArray(0)
        return try {
            val connected = svc.getConnectedDeviceAddresses().sorted()
            // Binary format: [u32BE count][u32BE len1][addr1_utf8]...[u32BE lenN][addrN_utf8]
            val buf = java.io.ByteArrayOutputStream()
            val count = connected.size
            buf.write(byteArrayOf(
                (count shr 24).toByte(), (count shr 16).toByte(),
                (count shr 8).toByte(), count.toByte()
            ))
            for (addr in connected) {
                val addrBytes = addr.toByteArray(Charsets.UTF_8)
                val len = addrBytes.size
                buf.write(byteArrayOf(
                    (len shr 24).toByte(), (len shr 16).toByte(),
                    (len shr 8).toByte(), len.toByte()
                ))
                buf.write(addrBytes)
            }
            buf.toByteArray()
        } catch (_: Exception) {
            ByteArray(0)
        }
    }

    fun isBluetoothDeviceReady(deviceAddress: String): Boolean {
        val svc = bleCoordinator ?: return false
        return try { svc.isDeviceConnected(deviceAddress) } catch (_: Exception) { false }
    }

}
