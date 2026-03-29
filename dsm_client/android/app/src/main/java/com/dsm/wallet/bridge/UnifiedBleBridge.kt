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

                        sendViaActiveClientSession(
                            svc,
                            deviceAddress,
                            chunks,
                            "tx_chunk_send_partial",
                        )
                    } catch (t: Throwable) {
                        Log.w("UnifiedBleBridge", "requestGattWriteChunks: TX_RESPONSE subscription/send error for $deviceAddress", t)
                        UnifiedBleEvents.onConnectionFailed(deviceAddress, "tx_response_subscription_exception")
                        false
                    }
                }
            } else if (svc.isGattServerClient(deviceAddress) && svc.isServerClientSubscribedToTxResponse(deviceAddress)) {
                Log.i("UnifiedBleBridge", "requestGattWriteChunks: target is GATT server client AND subscribed — using server notifications immediately for $deviceAddress")
                runBlocking {
                    val ok = svc.sendViaServerNotifications(deviceAddress, chunks)
                    if (!ok) {
                        UnifiedBleEvents.onConnectionFailed(deviceAddress, "server_notify_failed")
                    }
                    ok
                }
            } else {
                // No active session — ensure BLE infrastructure is up, then attempt on-demand connection.
                // Start GATT server + advertising so the peer can discover us while we also try to connect to them.
                Log.i("UnifiedBleBridge", "requestGattWriteChunks: no route for $deviceAddress — priming BLE and attempting on-demand connection")
                svc.ensureGattServerStarted()
                publishLocalIdentityIfAvailable(svc)
                svc.startAdvertising()
                runBlocking {
                    // Track effective BLE address — may change if Android rotated the peer's RPA
                    var effectiveAddress = deviceAddress
                    try {
                        // Attempt 1: direct on-demand GATT client connect (works if peer is connectable).
                        // connectToDevice now includes a 1.5s scan for RPA resolution + 12s poll,
                        // so allow 15s total.
                        var connected = withTimeoutOrNull(15000L) {
                            svc.connectToDevice(deviceAddress).await()
                        } ?: false
                        if (!connected) {
                            Log.w("UnifiedBleBridge", "requestGattWriteChunks: first connect attempt failed for $deviceAddress — checking reverse path")
                            // While we were trying to connect, the peer may have connected to our GATT server and subscribed.
                            if (svc.isGattServerClient(deviceAddress) && svc.isServerClientSubscribedToTxResponse(deviceAddress)) {
                                Log.i("UnifiedBleBridge", "requestGattWriteChunks: peer connected to our GATT server and subscribed during wait — using server notifications for $deviceAddress")
                                val ok = svc.sendViaServerNotifications(deviceAddress, chunks)
                                if (!ok) {
                                    UnifiedBleEvents.onConnectionFailed(deviceAddress, "on_demand_server_notify_fallback_failed")
                                }
                                return@runBlocking ok
                            }
                            // Attempt 2: start scanning to discover the peer under potentially new BLE address
                            // (Android rotates BLE addresses — the pairing-time address may be stale)
                            Log.i("UnifiedBleBridge", "requestGattWriteChunks: starting scan + retry connect for $deviceAddress")
                            svc.startScanning()
                            delay(3000L) // Allow 3s for scan results + peer discovery
                            svc.stopScanning()

                            // BLE address may have rotated since pairing. Check if a
                            // freshly-discovered peer created a session under a different
                            // address.  If so, use the new address for this send.
                            if (!svc.hasActiveClientSession(deviceAddress)
                                && !(svc.isGattServerClient(deviceAddress) && svc.isServerClientSubscribedToTxResponse(deviceAddress))
                            ) {
                                val freshAddr = svc.findAnyReadySessionAddress()
                                if (freshAddr != null && freshAddr != deviceAddress) {
                                    Log.i("UnifiedBleBridge", "requestGattWriteChunks: BLE address rotated $deviceAddress → $freshAddr")
                                    effectiveAddress = freshAddr
                                }
                            }

                            // Re-check with potentially updated address
                            if (svc.hasActiveClientSession(effectiveAddress)) {
                                connected = true
                            } else if (svc.isGattServerClient(effectiveAddress) && svc.isServerClientSubscribedToTxResponse(effectiveAddress)) {
                                val ok = svc.sendViaServerNotifications(effectiveAddress, chunks)
                                if (!ok) {
                                    UnifiedBleEvents.onConnectionFailed(effectiveAddress, "on_demand_scan_server_notify_failed")
                                }
                                return@runBlocking ok
                            } else {
                                connected = withTimeoutOrNull(15000L) {
                                    svc.connectToDevice(effectiveAddress).await()
                                } ?: false
                            }
                        }
                        if (!connected) {
                            Log.e("UnifiedBleBridge", "requestGattWriteChunks: on-demand GATT connection failed for $effectiveAddress")
                            UnifiedBleEvents.onConnectionFailed(effectiveAddress, "on_demand_connect_failed")
                            return@runBlocking false
                        }
                        // Subscribe to TX_RESPONSE
                        var subscribed = false
                        for (attempt in 1..TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) {
                            subscribed = withTimeoutOrNull(TX_RESPONSE_SUBSCRIBE_TIMEOUT_MS) {
                                svc.ensureClientTxResponseSubscribed(effectiveAddress).await()
                            } ?: false
                            if (subscribed) break
                            if (attempt < TX_RESPONSE_SUBSCRIBE_MAX_ATTEMPTS) delay(200L * attempt)
                        }
                        if (!subscribed) {
                            Log.e(
                                "UnifiedBleBridge",
                                "requestGattWriteChunks: on-demand TX_RESPONSE subscription failed for $effectiveAddress; aborting send"
                            )
                            if (svc.isGattServerClient(effectiveAddress) && svc.isServerClientSubscribedToTxResponse(effectiveAddress)) {
                                Log.i(
                                    "UnifiedBleBridge",
                                    "requestGattWriteChunks: falling back to server notifications after on-demand subscribe failure for $effectiveAddress"
                                )
                                val ok = svc.sendViaServerNotifications(effectiveAddress, chunks)
                                if (!ok) {
                                    UnifiedBleEvents.onConnectionFailed(effectiveAddress, "on_demand_server_notify_after_subscribe_failed")
                                }
                                return@runBlocking ok
                            }
                            UnifiedBleEvents.onConnectionFailed(effectiveAddress, "tx_response_subscription_failed")
                            return@runBlocking false
                        }
                        // Send via client writes
                        sendViaActiveClientSession(
                            svc,
                            effectiveAddress,
                            chunks,
                            "tx_chunk_send_partial",
                        )
                    } catch (t: Throwable) {
                        Log.e("UnifiedBleBridge", "requestGattWriteChunks: on-demand error for $effectiveAddress", t)
                        UnifiedBleEvents.onConnectionFailed(effectiveAddress, "on_demand_connect_exception")
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
