package com.dsm.wallet.bridge

import android.util.Log
import com.dsm.wallet.bridge.ble.BleCoordinator
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull

internal object UnifiedBleBridge {

    private var bleCoordinator: BleCoordinator? = null
    private const val TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS = 3
    private const val TX_RESPONSE_SUBSCRIBE_TIMEOUT_MS = 2500L

    private fun sendViaActiveClientSession(
        svc: BleCoordinator,
        deviceAddress: String,
        chunks: Array<ByteArray>,
        failureCode: String,
    ): Boolean {
        Log.i(
            "UnifiedBleBridge",
            "sendViaActiveClientSession: sending ${chunks.size} chunk(s) to $deviceAddress via existing GATT client session"
        )
        var sentCount = 0
        chunks.forEachIndexed { index, chunk ->
            val sent = svc.sendTransactionRequest(deviceAddress, chunk)
            if (sent) {
                sentCount += 1
            } else {
                Log.e(
                    "UnifiedBleBridge",
                    "sendViaActiveClientSession: failed chunk ${index + 1}/${chunks.size} to $deviceAddress"
                )
            }
        }
        if (sentCount != chunks.size) {
            UnifiedBleEvents.onConnectionFailed(deviceAddress, "$failureCode:$sentCount/${chunks.size}")
        }
        return sentCount == chunks.size
    }

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
            if (useReliableWrite) {
                requestGattWriteChunks(deviceAddress, chunks)
            } else if (svc.isGattServerClient(deviceAddress) && svc.isServerClientSubscribedToTxResponse(deviceAddress)) {
                Log.i(
                    "UnifiedBleBridge",
                    "dispatchRustFollowUp: routing ${chunks.size} chunk(s) via existing GATT server notification path to $deviceAddress"
                )
                runBlocking {
                    val ok = svc.sendViaServerNotifications(deviceAddress, chunks)
                    if (!ok) {
                        UnifiedBleEvents.onConnectionFailed(deviceAddress, "followup_server_notify_failed")
                    }
                    ok
                }
            } else if (svc.hasActiveClientSession(deviceAddress)) {
                sendViaActiveClientSession(
                    svc,
                    deviceAddress,
                    chunks,
                    "followup_client_send_partial",
                )
            } else {
                Log.w(
                    "UnifiedBleBridge",
                    "dispatchRustFollowUp: no existing route for non-reliable follow-up to $deviceAddress; refusing transport re-prime"
                )
                false
            }
        } catch (t: Throwable) {
            Log.e("UnifiedBleBridge", "dispatchRustFollowUp failed for $deviceAddress", t)
            false
        }
    }

    private fun publishLocalIdentityIfAvailable(svc: BleCoordinator): Boolean {
        try {
            val deviceIdBytes = try { Unified.getDeviceIdBin() } catch (_: Throwable) { byteArrayOf() }
            val genesisHashBytes = try { Unified.getGenesisHashBin() } catch (_: Throwable) { byteArrayOf() }
            if (deviceIdBytes.size == 32 && genesisHashBytes.size == 32) {
                svc.setIdentityValue(genesisHashBytes, deviceIdBytes)
                Log.i("UnifiedBleBridge", "publishLocalIdentityIfAvailable: local BLE identity published to GATT")
                return true
            } else {
                Log.w(
                    "UnifiedBleBridge",
                    "publishLocalIdentityIfAvailable: identity bytes unavailable (genesis=${genesisHashBytes.size}, device=${deviceIdBytes.size})"
                )
                return false
            }
        } catch (t: Throwable) {
            Log.w("UnifiedBleBridge", "publishLocalIdentityIfAvailable failed", t)
            return false
        }
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

    fun requestGattWrite(deviceAddress: String, transactionData: ByteArray): Boolean {
        val svc = bleCoordinator ?: return false
        return try { svc.sendTransactionRequest(deviceAddress, transactionData) } catch (_: Throwable) { false }
    }

    fun startBlePairingAdvertise(): Boolean {
        val svc = bleCoordinator ?: return false
        return try {
            if (!publishLocalIdentityIfAvailable(svc)) {
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

    fun stopBlePairingAdvertise(): Boolean {
        val svc = bleCoordinator ?: return false
        return try { svc.stopAdvertising() } catch (_: Throwable) { false }
    }

    fun requestGattWriteChunks(deviceAddress: String, chunks: Array<ByteArray>): Boolean {
        val svc = bleCoordinator ?: return false
        return try {
            // --- RPA resolution ---
            // Rust may pass a stale BLE address. Resolve via identity-anchored
            // registry (addressIndex → PeerIdentity → current address) or fall
            // back to any ready session in single-peer scenarios.
            val resolved = svc.resolveSession(deviceAddress)
            val effectiveAddr = resolved?.second ?: deviceAddress

            // Routing priority:
            // 1. If we have an active GATT client session (we connected to them), use regular writes.
            //    Both devices may have bidirectional GATT connections, so prefer the client path
            //    since the client subscribed to TX_RESPONSE on the remote server.
            // 2. Only fall back to server notifications if we DON'T have a client session but
            //    the target is connected as a client to our GATT server (reverse path).
            if (svc.hasActiveClientSession(effectiveAddr)) {
                Log.i("UnifiedBleBridge", "requestGattWriteChunks: routing ${chunks.size} chunks via GATT client writes to $effectiveAddr")
                // Ensure TX_RESPONSE is subscribed so we can receive the response
                // back from the peer via GATT server notifications.
                runBlocking {
                    try {
                        var subscribed = false
                        for (attempt in 1..TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) {
                            subscribed = withTimeoutOrNull(TX_RESPONSE_SUBSCRIBE_TIMEOUT_MS) {
                                svc.ensureClientTxResponseSubscribed(effectiveAddr).await()
                            } ?: false
                            if (subscribed) {
                                Log.i(
                                    "UnifiedBleBridge",
                                    "requestGattWriteChunks: TX_RESPONSE subscribed for $effectiveAddr (attempt $attempt/${TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS})"
                                )
                                break
                            }
                            Log.w(
                                "UnifiedBleBridge",
                                "requestGattWriteChunks: TX_RESPONSE subscription attempt $attempt/${TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS} failed for $effectiveAddr"
                            )
                            if (attempt < TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) {
                                delay(200L * attempt)
                            }
                        }

                        if (!subscribed) {
                            Log.e(
                                "UnifiedBleBridge",
                                "requestGattWriteChunks: TX_RESPONSE subscription failed after ${TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS} attempts for $effectiveAddr; aborting send"
                            )
                            UnifiedBleEvents.onConnectionFailed(effectiveAddr, "tx_response_subscription_failed")
                            return@runBlocking false
                        }

                        sendViaActiveClientSession(
                            svc,
                            effectiveAddr,
                            chunks,
                            "tx_chunk_send_partial",
                        )
                    } catch (t: Throwable) {
                        Log.w("UnifiedBleBridge", "requestGattWriteChunks: TX_RESPONSE subscription/send error for $effectiveAddr", t)
                        UnifiedBleEvents.onConnectionFailed(effectiveAddr, "tx_response_subscription_exception")
                        false
                    }
                }
            } else if (svc.isGattServerClient(effectiveAddr) && svc.isServerClientSubscribedToTxResponse(effectiveAddr)) {
                Log.i("UnifiedBleBridge", "requestGattWriteChunks: target is GATT server client AND subscribed — using server notifications immediately for $effectiveAddr")
                runBlocking {
                    val ok = svc.sendViaServerNotifications(effectiveAddr, chunks)
                    if (!ok) {
                        UnifiedBleEvents.onConnectionFailed(effectiveAddr, "server_notify_failed")
                    }
                    ok
                }
            } else {
                // No active session — on-demand connect.
                // connectToDevice handles: scan for RPA, connect, MTU negotiation.
                // resolveSession re-resolves after connect so we target the actual address.
                Log.i("UnifiedBleBridge", "requestGattWriteChunks: no route for $effectiveAddr — on-demand connect")
                svc.ensureGattServerStarted()
                publishLocalIdentityIfAvailable(svc)
                svc.startAdvertising()
                runBlocking {
                    try {
                        val connected = withTimeoutOrNull(15000L) {
                            svc.connectToDevice(effectiveAddr).await()
                        } ?: false

                        // Re-resolve: connectToDevice may have found the peer under a new RPA.
                        val currentAddr = svc.resolveSession(deviceAddress)?.second ?: effectiveAddr

                        if (!connected) {
                            // Check if peer connected to our server while we tried
                            if (svc.isGattServerClient(currentAddr) && svc.isServerClientSubscribedToTxResponse(currentAddr)) {
                                Log.i("UnifiedBleBridge", "requestGattWriteChunks: peer connected to our GATT server during wait — using server notifications for $currentAddr")
                                val ok = svc.sendViaServerNotifications(currentAddr, chunks)
                                if (!ok) UnifiedBleEvents.onConnectionFailed(currentAddr, "on_demand_server_notify_fallback_failed")
                                return@runBlocking ok
                            }
                            Log.e("UnifiedBleBridge", "requestGattWriteChunks: on-demand GATT connection failed for $currentAddr")
                            UnifiedBleEvents.onConnectionFailed(currentAddr, "on_demand_connect_failed")
                            return@runBlocking false
                        }

                        // Subscribe to TX_RESPONSE
                        var subscribed = false
                        for (attempt in 1..TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) {
                            subscribed = withTimeoutOrNull(TX_RESPONSE_SUBSCRIBE_TIMEOUT_MS) {
                                svc.ensureClientTxResponseSubscribed(currentAddr).await()
                            } ?: false
                            if (subscribed) break
                            if (attempt < TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) delay(200L * attempt)
                        }
                        if (!subscribed) {
                            Log.e("UnifiedBleBridge", "requestGattWriteChunks: TX_RESPONSE subscription failed for $currentAddr")
                            // Last resort: server notification path
                            if (svc.isGattServerClient(currentAddr) && svc.isServerClientSubscribedToTxResponse(currentAddr)) {
                                val ok = svc.sendViaServerNotifications(currentAddr, chunks)
                                if (!ok) UnifiedBleEvents.onConnectionFailed(currentAddr, "on_demand_server_notify_after_subscribe_failed")
                                return@runBlocking ok
                            }
                            UnifiedBleEvents.onConnectionFailed(currentAddr, "tx_response_subscription_failed")
                            return@runBlocking false
                        }

                        sendViaActiveClientSession(svc, currentAddr, chunks, "tx_chunk_send_partial")
                    } catch (t: Throwable) {
                        Log.e("UnifiedBleBridge", "requestGattWriteChunks: on-demand error", t)
                        UnifiedBleEvents.onConnectionFailed(effectiveAddr, "on_demand_connect_exception")
                        false
                    }
                }
            }
        } catch (_: Throwable) { false }
    }

    fun deliverDeferredPairingAck(deviceAddress: String, ackBytes: ByteArray) {
        val svc = bleCoordinator ?: return
        svc.deliverDeferredPairingAck(deviceAddress, ackBytes)
    }

    fun getBleStats(deviceAddress: String): ByteArray {
        val svc = bleCoordinator ?: return ByteArray(0)
        return try { svc.getStatsString(deviceAddress).toByteArray(Charsets.UTF_8) } catch (_: Throwable) { ByteArray(0) }
    }

    fun retryLastBleTransaction(deviceAddress: String): Boolean {
        val svc = bleCoordinator ?: return false
        return try { svc.retryLastTransaction(deviceAddress) } catch (_: Throwable) { false }
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
