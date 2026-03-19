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
            // Routing priority:
            // 1. If we have an active GATT client session (we connected to them), use regular writes.
            //    Both devices may have bidirectional GATT connections, so prefer the client path
            //    since the client subscribed to TX_RESPONSE on the remote server.
            // 2. Only fall back to server notifications if we DON'T have a client session but
            //    the target is connected as a client to our GATT server (reverse path).
            if (svc.hasActiveClientSession(deviceAddress)) {
                Log.i("UnifiedBleBridge", "requestGattWriteChunks: routing ${chunks.size} chunks via GATT client writes to $deviceAddress")
                // Ensure TX_RESPONSE is subscribed so we can receive the response
                // back from the peer via GATT server notifications.
                runBlocking {
                    try {
                        var subscribed = false
                        for (attempt in 1..TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) {
                            subscribed = withTimeoutOrNull(TX_RESPONSE_SUBSCRIBE_TIMEOUT_MS) {
                                svc.ensureClientTxResponseSubscribed(deviceAddress).await()
                            } ?: false
                            if (subscribed) {
                                Log.i(
                                    "UnifiedBleBridge",
                                    "requestGattWriteChunks: TX_RESPONSE subscribed for $deviceAddress (attempt $attempt/${TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS})"
                                )
                                break
                            }
                            Log.w(
                                "UnifiedBleBridge",
                                "requestGattWriteChunks: TX_RESPONSE subscription attempt $attempt/${TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS} failed for $deviceAddress"
                            )
                            if (attempt < TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) {
                                delay(200L * attempt)
                            }
                        }

                        if (!subscribed) {
                            Log.e(
                                "UnifiedBleBridge",
                                "requestGattWriteChunks: TX_RESPONSE subscription failed after ${TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS} attempts for $deviceAddress; aborting send"
                            )
                            UnifiedBleEvents.onConnectionFailed(deviceAddress, "tx_response_subscription_failed")
                            return@runBlocking false
                        }

                        Log.i("UnifiedBleBridge", "requestGattWriteChunks: sending ${chunks.size} chunks to $deviceAddress")
                        var sentCount = 0
                        chunks.forEachIndexed { index, chunk ->
                            val sent = svc.sendTransactionRequest(deviceAddress, chunk)
                            if (sent) {
                                sentCount += 1
                            } else {
                                Log.e(
                                    "UnifiedBleBridge",
                                    "requestGattWriteChunks: failed to send chunk ${index + 1}/${chunks.size} to $deviceAddress"
                                )
                            }
                        }
                        if (sentCount != chunks.size) {
                            UnifiedBleEvents.onConnectionFailed(
                                deviceAddress,
                                "tx_chunk_send_partial:$sentCount/${chunks.size}"
                            )
                        }
                        sentCount == chunks.size
                    } catch (t: Throwable) {
                        Log.w("UnifiedBleBridge", "requestGattWriteChunks: TX_RESPONSE subscription/send error for $deviceAddress", t)
                        UnifiedBleEvents.onConnectionFailed(deviceAddress, "tx_response_subscription_exception")
                        false
                    }
                }
            } else if (svc.isGattServerClient(deviceAddress)) {
                Log.i("UnifiedBleBridge", "requestGattWriteChunks: target is GATT server client — establishing reverse client connection for $deviceAddress")
                runBlocking {
                    try {
                        // Step 1: Establish lightweight GATT client connection (no re-pairing)
                        val connected = withTimeoutOrNull(8000L) {
                            svc.connectToDevice(deviceAddress).await()
                        } ?: false
                        if (!connected) {
                            // Fall back to server notifications if client connect fails
                            Log.w("UnifiedBleBridge", "requestGattWriteChunks: reverse client connect failed for $deviceAddress — falling back to server notifications")
                            val ok = svc.sendViaServerNotifications(deviceAddress, chunks)
                            Log.i("UnifiedBleBridge", "requestGattWriteChunks: server notification fallback result=$ok for $deviceAddress")
                            if (!ok) {
                                UnifiedBleEvents.onConnectionFailed(deviceAddress, "path2_connect_failed_notify_fallback_failed")
                            }
                            return@runBlocking ok
                        }

                        // Step 2: Ensure TX_RESPONSE is subscribed for receiving responses
                        var subscribed = false
                        for (attempt in 1..TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) {
                            subscribed = withTimeoutOrNull(TX_RESPONSE_SUBSCRIBE_TIMEOUT_MS) {
                                svc.ensureClientTxResponseSubscribed(deviceAddress).await()
                            } ?: false
                            if (subscribed) {
                                Log.i("UnifiedBleBridge", "requestGattWriteChunks: TX_RESPONSE subscribed for $deviceAddress (attempt $attempt)")
                                break
                            }
                            Log.w("UnifiedBleBridge", "requestGattWriteChunks: TX_RESPONSE subscription attempt $attempt/$TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS failed for $deviceAddress")
                            if (attempt < TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) {
                                delay(200L * attempt)
                            }
                        }
                        if (!subscribed) {
                            Log.e("UnifiedBleBridge", "requestGattWriteChunks: TX_RESPONSE subscription failed for $deviceAddress — falling back to server notifications")
                            val ok = svc.sendViaServerNotifications(deviceAddress, chunks)
                            if (!ok) {
                                UnifiedBleEvents.onConnectionFailed(deviceAddress, "path2_subscribe_failed_notify_fallback_failed")
                            }
                            return@runBlocking ok
                        }

                        // Step 3: Send via client writes (to peer's TX_REQUEST)
                        Log.i("UnifiedBleBridge", "requestGattWriteChunks: sending ${chunks.size} chunks via client writes to $deviceAddress")
                        var sentCount = 0
                        chunks.forEachIndexed { index, chunk ->
                            val sent = svc.sendTransactionRequest(deviceAddress, chunk)
                            if (sent) {
                                sentCount += 1
                            } else {
                                Log.e("UnifiedBleBridge", "requestGattWriteChunks: chunk ${index + 1}/${chunks.size} failed for $deviceAddress")
                            }
                        }
                        if (sentCount != chunks.size) {
                            UnifiedBleEvents.onConnectionFailed(deviceAddress, "tx_chunk_send_partial:$sentCount/${chunks.size}")
                        }
                        sentCount == chunks.size
                    } catch (t: Throwable) {
                        Log.e("UnifiedBleBridge", "requestGattWriteChunks: Path 2 error for $deviceAddress", t)
                        UnifiedBleEvents.onConnectionFailed(deviceAddress, "path2_connect_send_exception")
                        false
                    }
                }
            } else {
                // No active session — attempt on-demand GATT connection before sending.
                // connectToDevice() connects directly to a known BLE address without scanning,
                // so scan rate-limits do not apply.
                Log.i("UnifiedBleBridge", "requestGattWriteChunks: no route for $deviceAddress — attempting on-demand GATT connection")
                runBlocking {
                    try {
                        val connected = withTimeoutOrNull(8000L) {
                            svc.connectToDevice(deviceAddress).await()
                        } ?: false
                        if (!connected) {
                            Log.e("UnifiedBleBridge", "requestGattWriteChunks: on-demand GATT connection failed for $deviceAddress")
                            UnifiedBleEvents.onConnectionFailed(deviceAddress, "on_demand_connect_failed")
                            return@runBlocking false
                        }
                        // Subscribe to TX_RESPONSE
                        var subscribed = false
                        for (attempt in 1..TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) {
                            subscribed = withTimeoutOrNull(TX_RESPONSE_SUBSCRIBE_TIMEOUT_MS) {
                                svc.ensureClientTxResponseSubscribed(deviceAddress).await()
                            } ?: false
                            if (subscribed) break
                            if (attempt < TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) delay(200L * attempt)
                        }
                        // Send via client writes
                        Log.i("UnifiedBleBridge", "requestGattWriteChunks: on-demand connected, sending ${chunks.size} chunks to $deviceAddress (subscribed=$subscribed)")
                        var sentCount = 0
                        chunks.forEachIndexed { index, chunk ->
                            val sent = svc.sendTransactionRequest(deviceAddress, chunk)
                            if (sent) sentCount += 1
                            else Log.e("UnifiedBleBridge", "requestGattWriteChunks: chunk ${index + 1}/${chunks.size} failed for $deviceAddress")
                        }
                        if (sentCount != chunks.size) {
                            UnifiedBleEvents.onConnectionFailed(deviceAddress, "tx_chunk_send_partial:$sentCount/${chunks.size}")
                        }
                        sentCount == chunks.size
                    } catch (t: Throwable) {
                        Log.e("UnifiedBleBridge", "requestGattWriteChunks: on-demand error for $deviceAddress", t)
                        UnifiedBleEvents.onConnectionFailed(deviceAddress, "on_demand_connect_exception")
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

    /**
     * Ensure BLE transport infrastructure is primed for a bilateral transfer.
     * Starts GATT server, publishes identity, and starts advertising so the
     * peer device can discover and connect to us. Returns true if BLE is ready.
     *
     * Called by Rust before sending bilateral chunks to give the peer a chance
     * to re-establish a GATT connection if the previous session dropped.
     */
    fun ensureBleTransportReady(deviceAddress: String): Boolean {
        val svc = bleCoordinator ?: return false
        return try {
            svc.ensureGattServerStarted()
            publishLocalIdentityIfAvailable(svc)
            svc.startAdvertising()
            // If we already have a connection, we're ready
            if (svc.hasActiveClientSession(deviceAddress) || svc.isGattServerClient(deviceAddress)) {
                Log.i("UnifiedBleBridge", "ensureBleTransportReady: already connected to $deviceAddress")
                return true
            }
            // Give the peer a moment to discover our advertisement and connect
            Log.i("UnifiedBleBridge", "ensureBleTransportReady: advertising started for $deviceAddress, waiting for connection")
            runBlocking {
                // Wait up to 5s for the peer to connect to our GATT server
                val deadline = 5000L
                val start = android.os.SystemClock.elapsedRealtime()
                while (android.os.SystemClock.elapsedRealtime() - start < deadline) {
                    if (svc.hasActiveClientSession(deviceAddress) || svc.isGattServerClient(deviceAddress)) {
                        Log.i("UnifiedBleBridge", "ensureBleTransportReady: peer connected during wait for $deviceAddress")
                        return@runBlocking true
                    }
                    delay(200L)
                }
                Log.w("UnifiedBleBridge", "ensureBleTransportReady: peer did not connect within ${deadline}ms for $deviceAddress")
                false
            }
        } catch (_: Throwable) { false }
    }

}
