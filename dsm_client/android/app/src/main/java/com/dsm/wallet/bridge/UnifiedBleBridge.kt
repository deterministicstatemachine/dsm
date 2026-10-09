// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import android.util.Log
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
     * Send a reply on the link at [deviceAddress] that the frame it answers
     * arrived on. Nothing reconnects for it: a reply whose link is gone is
     * answered again when the counterparty sends its frame again.
     * [useReliableWrite] prefers our client link to the peer's subscription to
     * our server when both exist.
     */
    fun dispatchRustFollowUp(
        deviceAddress: String,
        chunks: Array<ByteArray>,
        useReliableWrite: Boolean,
    ): Boolean {
        val svc = bleCoordinator ?: return false
        if (chunks.isEmpty()) {
            return true
        }
        return try {
            runBlocking {
                val client = svc.hasActiveClientSession(deviceAddress)
                val server = svc.isGattServerClient(deviceAddress) &&
                    svc.isServerClientSubscribedToTxResponse(deviceAddress)
                when {
                    client && (useReliableWrite || !server) ->
                        sendOverClientLink(svc, deviceAddress, chunks, "followup_client_send_failed")
                    server ->
                        sendOverServerLink(svc, deviceAddress, chunks, "followup_server_notify_failed")
                    else -> {
                        Log.w("UnifiedBleBridge", "dispatchRustFollowUp: the link at $deviceAddress is gone; the reply is not sent")
                        false
                    }
                }
            }
        } catch (t: Throwable) {
            Log.e("UnifiedBleBridge", "dispatchRustFollowUp failed for $deviceAddress", t)
            false
        }
    }

    // The GATT server reads the identity from Rust when a peer asks for it;
    // advertising without one would answer every identity read with a failure.
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
        return try { svc.stopScanning() } catch (_: Throwable) { false }
    }


    /**
     * Send one message to the appliance [deviceId]. Only a link whose identity
     * is anchored to it carries the message; with none, the coordinator
     * reaches for it — [addressHint] first. False is "not delivered now": the
     * SDK's frame stays owed and is delivered again when the appliance is
     * reached.
     */
    fun requestGattWriteChunks(deviceId: ByteArray, addressHint: String, chunks: Array<ByteArray>): Boolean {
        val svc = bleCoordinator ?: return false
        if (deviceId.size != 32) {
            Log.e("UnifiedBleBridge", "requestGattWriteChunks: a device id of ${deviceId.size} bytes routes nowhere")
            return false
        }
        val target = BridgeEncoding.base32CrockfordEncode(deviceId).take(8)
        return try {
            runBlocking {
                val route = svc.resolveRoute(deviceId, addressHint) ?: svc.reach(deviceId, addressHint)
                if (route == null) {
                    Log.i("UnifiedBleBridge", "requestGattWriteChunks: no route to $target; the frame stays owed")
                    return@runBlocking false
                }
                Log.i("UnifiedBleBridge", "requestGattWriteChunks: $target at ${route.address} (client link=${route.clientLink})")
                if (route.clientLink) {
                    sendOverClientLink(svc, route.address, chunks, "tx_chunk_send_failed")
                } else {
                    sendOverServerLink(svc, route.address, chunks, "server_notify_failed")
                }
            }
        } catch (t: Throwable) {
            Log.e("UnifiedBleBridge", "requestGattWriteChunks failed for $target", t)
            false
        }
    }

    fun deliverDeferredPairingAck(deviceAddress: String, ackBytes: ByteArray) {
        val svc = bleCoordinator ?: return
        svc.deliverDeferredPairingAck(deviceAddress, ackBytes)
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
