package com.dsm.wallet.bridge.ble

import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import kotlinx.coroutines.CompletableDeferred

/**
 * Represents a single GATT client session with a peer device.
 *
 * This component manages:
 * - GATT connection lifecycle
 * - Service discovery
 * - MTU negotiation
 * - Characteristic read/write operations
 * - Connection timeouts and error handling
 *
 * State changes are reported directly to the coordinator dispatcher so BLE transport
 * stays on one bounded scheduling path.
 */
@Suppress("OVERRIDE_DEPRECATION", "DEPRECATION")
class GattClientSession(
    private val context: Context,
    private val deviceAddress: String,
    private val diagnostics: BleDiagnostics,
    private val permissionsGate: BlePermissionsGate = BlePermissionsGate(context),
    private val eventSink: (BleSessionEvent) -> Unit,
) {

    companion object {
        /** Disconnect if GATT connection isn't established within 15 seconds. */
        private const val CONNECTION_TIMEOUT_MS = 15_000L
        /** Number of notification chunks to receive before sending ACK write-back. */
        private const val NOTIFICATION_ACK_WINDOW = 10
        // TRANSFER_IDLE_THRESHOLD_MS removed — transfer boundaries are now
        // detected via a 1-byte nonce prepended to the first chunk by the server.
    }

    private enum class TxRequestWriteKind {
        NONE,
        TRANSACTION,
        CHUNK_ACK,
    }

    private var bluetoothGatt: BluetoothGatt? = null
    private val timeoutHandler = Handler(Looper.getMainLooper())

    /**
     * Per-transfer notification counter.  Resets to 0 when the server's
     * transfer nonce changes (1 byte prepended to the first chunk of each
     * `sendChunkedNotifications` call).  No wall-clock idle-gap detection.
     */
    private var notificationChunkCount = 0
    private var currentTransferNonce: Byte = -1
    private val connectionTimeoutRunnable = Runnable {
        Log.w("GattClientSession", "GATT connection timeout (${CONNECTION_TIMEOUT_MS}ms) for $deviceAddress - disconnecting")
        emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CONNECTION_FAILED, "connection_timeout"))
        disconnect()
    }

    // Remove all local state variables - state is now managed exclusively by BleCoordinator
    private var requestCharacteristic: BluetoothGattCharacteristic? = null
    private var responseCharacteristic: BluetoothGattCharacteristic? = null
    private var identityCharacteristic: BluetoothGattCharacteristic? = null
    private var pairingCharacteristic: BluetoothGattCharacteristic? = null
    private var pairingAckCharacteristic: BluetoothGattCharacteristic? = null

    // Deferred MTU value: stored when MTU negotiation succeeds, emitted after
    // all CCCD descriptor writes complete (onDescriptorWrite) so that the
    // coordinator's identity read doesn't collide with a pending GATT op.
    private var pendingMtu: Int = 0
    // Track CCCD subscription chain: TX_RESPONSE → PAIRING_ACK → emit MTU
    private var txResponseSubscribed: Boolean = false
    // Deferred for re-subscription requests (outside the initial MTU chain)
    private var pendingTxResponseResubscribe: CompletableDeferred<Boolean>? = null
    // Transport-level chunk ACKs reuse TX_REQUEST writes but must not be reported as
    // application transaction write completions.
    private var pendingChunkAckWriteCount: Int? = null
    // Only one TX_REQUEST GATT write may be in flight at a time. Queue follow-on work
    // locally so transport ACKs and outbound payloads do not race at the Android stack.
    private var txRequestWriteKind: TxRequestWriteKind = TxRequestWriteKind.NONE
    private var queuedTransactionWrite: ByteArray? = null
    private var queuedChunkAckWriteCount: Int? = null
    // True while the scanner is waiting for its BlePairingConfirm write to be ACKed by the
    // BLE stack.
    private var awaitingConfirmWriteAck: Boolean = false
    // Whether the PAIRING_ACK CCCD subscription succeeded.
    private var pairingAckCccdSubscribed: Boolean = false
    // Service discovery retry: Samsung/Qualcomm BT stacks can return status 133 if
    // discoverServices() fires before link-layer negotiation settles. One retry with
    // a GATT cache refresh catches the transient error without masking real failures.
    private var serviceDiscoveryRetried: Boolean = false

    // Remove callback lambdas - operations are now fully asynchronous via events

    private fun emitEvent(event: BleSessionEvent) {
        try {
            eventSink(event)
        } catch (t: Throwable) {
            Log.e(
                "GattClientSession",
                "Failed to dispatch BLE session event for $deviceAddress: ${event::class.java.simpleName}",
                t
            )
        }
    }

    @Suppress("DEPRECATION")
    private fun startTxRequestWrite(data: ByteArray, kind: TxRequestWriteKind): Boolean {
        val char = requestCharacteristic
        if (char == null) {
            Log.w("GattClientSession", "startTxRequestWrite: TX_REQUEST not available for $deviceAddress")
            return false
        }

        char.setValue(data)
        return try {
            txRequestWriteKind = kind
            val sent = bluetoothGatt?.writeCharacteristic(char) == true
            if (!sent) {
                txRequestWriteKind = TxRequestWriteKind.NONE
            }
            sent
        } catch (e: SecurityException) {
            txRequestWriteKind = TxRequestWriteKind.NONE
            Log.e("GattClientSession", "Security exception writing TX_REQUEST for $deviceAddress", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
            false
        }
    }

    private fun drainQueuedTxRequestWrite() {
        if (txRequestWriteKind != TxRequestWriteKind.NONE) {
            return
        }

        val queuedAckCount = queuedChunkAckWriteCount
        if (queuedAckCount != null) {
            queuedChunkAckWriteCount = null
            pendingChunkAckWriteCount = queuedAckCount
            val ack = byteArrayOf(
                0xFF.toByte(),
                ((queuedAckCount shr 8) and 0xFF).toByte(),
                (queuedAckCount and 0xFF).toByte()
            )
            val sent = startTxRequestWrite(ack, TxRequestWriteKind.CHUNK_ACK)
            if (sent) {
                Log.d("GattClientSession", "Queued chunk ACK written: $queuedAckCount chunks confirmed to $deviceAddress")
            } else {
                pendingChunkAckWriteCount = null
                Log.w("GattClientSession", "drainQueuedTxRequestWrite: queued chunk ACK write failed for $deviceAddress (count=$queuedAckCount)")
            }
            return
        }

        val queuedTx = queuedTransactionWrite
        if (queuedTx != null) {
            queuedTransactionWrite = null
            val sent = startTxRequestWrite(queuedTx, TxRequestWriteKind.TRANSACTION)
            if (!sent) {
                emitEvent(BleSessionEvent.TransactionWriteCompleted(deviceAddress, false))
                emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write_queued", null))
            }
        }
    }

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt?, status: Int, newState: Int) {
            Log.d("GattClientSession", "Connection state change: $deviceAddress, status: $status, newState: $newState")

            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
                    // reset ack windows at new connection start so we don’t carry stale notification counters from previous transfers.
                    notificationChunkCount = 0

                    // Guard against platforms that deliver STATE_CONNECTED with a non-SUCCESS status
                    // (e.g. status 133 / GATT_ERROR on some OEMs). Proceeding to discoverServices()
                    // in this state causes silent failures — close and signal error instead.
                    if (status != BluetoothGatt.GATT_SUCCESS) {
                        Log.e("GattClientSession", "Connection error status=$status for $deviceAddress — closing GATT")
                        emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CONNECTION_FAILED, "connection_status_$status"))
                        cleanup()
                        return
                    }
                    diagnostics.recordEvent(BleDiagEvent(phase = "connected", device = deviceAddress))
                    // Emit connection event - BleCoordinator manages state
                    emitEvent(BleSessionEvent.Connected(deviceAddress))
                    // Dispatch discoverServices() onto the main thread after a 200ms delay.
                    // Calling it directly from the BluetoothGattCallback (BT thread) can
                    // trigger a rare deadlock in the Android BT stack on older API levels.
                    // The 200ms delay lets Samsung/Qualcomm BT stacks finish link-layer
                    // negotiation (supervision timeout, PHY, connection interval) before
                    // discovery starts, preventing transient status-133 failures.
                    serviceDiscoveryRetried = false
                    Handler(Looper.getMainLooper()).postDelayed({
                        try {
                            gatt?.discoverServices()
                        } catch (e: SecurityException) {
                            Log.e("GattClientSession", "Security exception discovering services for $deviceAddress", e)
                            BleCoordinator.getInstance(context).let { coordinator ->
                                coordinator.permissionsGate.recordPermissionFailure()
                                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                            }
                            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "service_discovery"))
                            cleanup()
                        }
                    }, 200L)
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
                    diagnostics.recordEvent(BleDiagEvent(phase = "disconnected", device = deviceAddress, status = status))
                    // Emit disconnection event - BleCoordinator manages state
                    emitEvent(BleSessionEvent.Disconnected(deviceAddress, status))
                    cleanup()
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt?, status: Int) {
            Log.d("GattClientSession", "Services discovered: $deviceAddress, status: $status")

            if (status == BluetoothGatt.GATT_SUCCESS) {
                val service = gatt?.getService(BleConstants.DSM_SERVICE_UUID_V2)
                if (service != null) {
                    requestCharacteristic = service.getCharacteristic(BleConstants.TX_REQUEST_UUID)
                    responseCharacteristic = service.getCharacteristic(BleConstants.TX_RESPONSE_UUID)
                    identityCharacteristic = service.getCharacteristic(BleConstants.IDENTITY_UUID)
                    pairingCharacteristic = service.getCharacteristic(BleConstants.PAIRING_UUID)
                    pairingAckCharacteristic = service.getCharacteristic(BleConstants.PAIRING_ACK_UUID)

                    // NOTE: Do NOT call subscribeToPairingAck() here.
                    // Android BLE only allows one GATT operation at a time; the CCCD
                    // descriptor write would conflict with the immediately following
                    // MTU request. Instead, we subscribe after MTU negotiation
                    // completes (onMtuChanged → subscribeToPairingAck → onDescriptorWrite → readIdentity).

                    // Emit service discovery success event
                    emitEvent(BleSessionEvent.ServiceDiscoveryCompleted(deviceAddress, true))
                    // Negotiate MTU
                    negotiateMtu()
                } else {
                    if (!serviceDiscoveryRetried) {
                        Log.w("GattClientSession", "DSM service UUID not found for $deviceAddress — retrying after cache refresh")
                        retryServiceDiscovery()
                    } else {
                        emitEvent(BleSessionEvent.ServiceDiscoveryCompleted(deviceAddress, false))
                        emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.SERVICE_DISCOVERY_FAILED, "service_discovery"))
                    }
                }
            } else {
                if (!serviceDiscoveryRetried) {
                    Log.w("GattClientSession", "Service discovery failed (status=$status) for $deviceAddress — retrying after cache refresh")
                    retryServiceDiscovery()
                } else {
                    emitEvent(BleSessionEvent.ServiceDiscoveryCompleted(deviceAddress, false))
                    emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.SERVICE_DISCOVERY_FAILED, "service_discovery", status))
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt?, mtu: Int, status: Int) {
            Log.d("GattClientSession", "MTU changed: $deviceAddress, mtu: $mtu, status: $status")

            if (status == BluetoothGatt.GATT_SUCCESS) {
                diagnostics.recordEvent(BleDiagEvent(phase = "mtu_negotiated", device = deviceAddress, bytes = mtu))

                // P1.1: Request HIGH connection priority for data transfer.
                // Transport-only optimization (rules.instructions.md §36).
                // Vendor docs confirm 10-25x notification throughput improvement.
                try {
                    gatt?.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
                    Log.i("GattClientSession", "Requested CONNECTION_PRIORITY_HIGH for $deviceAddress")
                } catch (e: SecurityException) {
                    Log.w("GattClientSession", "requestConnectionPriority failed: ${e.message}")
                }

                // Store MTU value so we can emit it after all CCCD writes complete.
                // Chain: TX_RESPONSE CCCD → onDescriptorWrite → PAIRING_ACK CCCD → onDescriptorWrite → emit MTU.
                // Android BLE only allows one GATT op at a time, so we serialize.
                pendingMtu = mtu
                txResponseSubscribed = false
                // Start the CCCD subscription chain with TX_RESPONSE
                if (!subscribeToTxResponse()) {
                    // TX_RESPONSE subscription failed — try PAIRING_ACK directly
                    txResponseSubscribed = true // skip TX_RESPONSE step in onDescriptorWrite
                    if (!subscribeToPairingAck()) {
                        // Both failed — emit MTU immediately
                        emitEvent(BleSessionEvent.MtuNegotiated(deviceAddress, mtu))
                    }
                }
            } else {
                emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.MTU_NEGOTIATION_FAILED, "mtu_negotiation", status))
            }
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt?, descriptor: android.bluetooth.BluetoothGattDescriptor?, status: Int) {
            val charUuid = descriptor?.characteristic?.uuid
            Log.d("GattClientSession", "Descriptor write: $deviceAddress, uuid: $charUuid, status: $status")
            if (charUuid == BleConstants.TX_RESPONSE_UUID) {
                txResponseSubscribed = (status == BluetoothGatt.GATT_SUCCESS)
                // Check if this was a re-subscription (not part of the initial MTU chain)
                val resubDeferred = pendingTxResponseResubscribe
                if (resubDeferred != null) {
                    pendingTxResponseResubscribe = null
                    Log.i("GattClientSession", "TX_RESPONSE re-subscription done (status=$status) for $deviceAddress")
                    resubDeferred.complete(txResponseSubscribed)
                } else {
                    // Initial subscription chain — continue to PAIRING_ACK
                    Log.i("GattClientSession", "TX_RESPONSE CCCD write done (status=$status) for $deviceAddress — subscribing to PAIRING_ACK next")
                    if (!subscribeToPairingAck()) {
                        // PAIRING_ACK subscription failed — emit MTU now
                        val mtu = pendingMtu
                        if (mtu > 0) {
                            pendingMtu = 0
                            emitEvent(BleSessionEvent.MtuNegotiated(deviceAddress, mtu))
                        }
                    }
                }
            } else if (charUuid == BleConstants.PAIRING_ACK_UUID) {
                pairingAckCccdSubscribed = (status == BluetoothGatt.GATT_SUCCESS)
                if (!pairingAckCccdSubscribed) {
                    Log.w("GattClientSession",
                        "PAIRING_ACK CCCD subscription failed for $deviceAddress (status=$status)")
                }
                // PAIRING_ACK CCCD write completed — all subscriptions done, emit MTU
                val mtu = pendingMtu
                if (mtu > 0) {
                    pendingMtu = 0
                    Log.i("GattClientSession", "PAIRING_ACK CCCD write done (status=$status) — emitting MtuNegotiated($mtu)")
                    emitEvent(BleSessionEvent.MtuNegotiated(deviceAddress, mtu))
                }
            }
        }

        @Suppress("DEPRECATION")
        override fun onCharacteristicRead(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?, status: Int) {
            when (characteristic?.uuid) {
                BleConstants.IDENTITY_UUID -> {
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        // Emit identity read completed event
                        emitEvent(BleSessionEvent.IdentityReadCompleted(deviceAddress, characteristic.value))
                    } else {
                        emitEvent(BleSessionEvent.IdentityReadCompleted(deviceAddress, null))
                        emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_READ_FAILED, "identity_read", status))
                    }
                }
            }
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?, status: Int) {
            val uuid = characteristic?.uuid
            Log.d("GattClientSession", "Characteristic write: $deviceAddress, uuid=$uuid, status=$status")
            when (uuid) {
                BleConstants.PAIRING_UUID -> {
                    if (awaitingConfirmWriteAck) {
                        // This is the scanner's BlePairingConfirm write-back (Phase 3).
                        // Do NOT wait for any additional ACK read-back — the round-trip is complete.
                        // Emit PairingConfirmWritten so BleCoordinator can lift the eviction guard.
                        awaitingConfirmWriteAck = false
                        if (status == BluetoothGatt.GATT_SUCCESS) {
                            Log.i("GattClientSession", "PAIRING_CONFIRM write ACKed by BLE stack for $deviceAddress")
                            emitEvent(BleSessionEvent.PairingConfirmWritten(deviceAddress))
                        } else {
                            Log.w("GattClientSession", "PAIRING_CONFIRM write failed for $deviceAddress: status=$status")
                            // Emit a plain error; BleCoordinator owns the fail-fast cleanup.
                            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "pairing_confirm_write", status))
                        }
                    } else {
                        if (status == BluetoothGatt.GATT_SUCCESS) {
                            if (!pairingAckCccdSubscribed) {
                                Log.w("GattClientSession", "Pairing identity write succeeded without PAIRING_ACK subscription for $deviceAddress")
                                emitEvent(
                                    BleSessionEvent.ErrorOccurred(
                                        deviceAddress,
                                        BleErrorCategory.CHARACTERISTIC_READ_FAILED,
                                        "pairing_ack_subscription_unavailable"
                                    )
                                )
                            } else {
                                Log.i("GattClientSession", "Pairing identity write successful for $deviceAddress — waiting for PAIRING_ACK indication")
                            }
                        } else {
                            Log.w("GattClientSession", "Pairing identity write failed for $deviceAddress: status=$status")
                            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "pairing_write", status))
                        }
                    }
                }
                BleConstants.TX_REQUEST_UUID -> {
                    val completedKind = txRequestWriteKind
                    txRequestWriteKind = TxRequestWriteKind.NONE
                    val ackCount = pendingChunkAckWriteCount
                    if (ackCount != null) {
                        pendingChunkAckWriteCount = null
                        if (status == BluetoothGatt.GATT_SUCCESS) {
                            Log.d("GattClientSession", "Transport chunk ACK write confirmed for $deviceAddress ($ackCount chunks)")
                        } else {
                            Log.w("GattClientSession", "Transport chunk ACK write failed for $deviceAddress (count=$ackCount, status=$status)")
                        }
                    } else if (completedKind == TxRequestWriteKind.TRANSACTION && status == BluetoothGatt.GATT_SUCCESS) {
                        emitEvent(BleSessionEvent.TransactionWriteCompleted(deviceAddress, true))
                    } else if (completedKind == TxRequestWriteKind.TRANSACTION) {
                        emitEvent(BleSessionEvent.TransactionWriteCompleted(deviceAddress, false))
                        emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write", status))
                    } else if (completedKind == TxRequestWriteKind.CHUNK_ACK) {
                        Log.w("GattClientSession", "TX_REQUEST write completed without pending chunk ACK count for $deviceAddress (status=$status)")
                    } else {
                        emitEvent(BleSessionEvent.TransactionWriteCompleted(deviceAddress, false))
                        emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write_unclassified", status))
                    }
                    drainQueuedTxRequestWrite()
                }
                else -> {
                    // Transaction write
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        emitEvent(BleSessionEvent.TransactionWriteCompleted(deviceAddress, true))
                    } else {
                        emitEvent(BleSessionEvent.TransactionWriteCompleted(deviceAddress, false))
                        emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write", status))
                    }
                }
            }
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?) {
            Log.d("GattClientSession", "Characteristic changed: $deviceAddress, uuid: ${characteristic?.uuid}")
            val data = characteristic?.value
            if (data == null || data.isEmpty()) return

            when (characteristic?.uuid) {
                BleConstants.PAIRING_ACK_UUID -> {
                    // Bilateral confirmation: the advertiser processed our identity and
                    // sent back a BlePairingAccept via INDICATE. Route through Rust.
                    Log.i("GattClientSession", "PAIRING_ACK indication received from $deviceAddress (${data.size} bytes)")
                    emitEvent(BleSessionEvent.PairingAckReceived(deviceAddress, data))
                }
                BleConstants.TX_RESPONSE_UUID -> {
                    // TX_RESPONSE notification — response data from the GATT server.
                    // Transfer nonce: the server prepends 1 byte to the first
                    // chunk of each sendChunkedNotifications call. If the nonce
                    // differs from the last one we saw, this is a new transfer —
                    // reset the ACK counter and strip the nonce byte.
                    var payload = data
                    if (data.isNotEmpty()) {
                        val nonce = data[0]
                        if (nonce != currentTransferNonce) {
                            if (notificationChunkCount > 0) {
                                Log.d("GattClientSession", "Transfer nonce changed for $deviceAddress (${(currentTransferNonce.toInt() and 0xFF)} -> ${(nonce.toInt() and 0xFF)}); resetting chunk counter from $notificationChunkCount")
                            }
                            currentTransferNonce = nonce
                            notificationChunkCount = 0
                            // Strip the nonce byte from the first chunk
                            payload = data.copyOfRange(1, data.size)
                        }
                    }

                    Log.d("GattClientSession", "TX_RESPONSE notification from $deviceAddress (${payload.size} bytes, nonce=${currentTransferNonce.toInt() and 0xFF})")
                    emitEvent(BleSessionEvent.ResponseReceived(deviceAddress, payload))

                    notificationChunkCount++
                    if (notificationChunkCount % 100 == 0) {
                        Log.d("GattClientSession", "BLE RX chunk #$notificationChunkCount for $deviceAddress")
                    }
                    if (notificationChunkCount % NOTIFICATION_ACK_WINDOW == 0) {
                        writeChunkAck(notificationChunkCount)
                    }
                }
                else -> {
                    // Unknown characteristic notification — emit as response
                    Log.d("GattClientSession", "Unknown characteristic notification from $deviceAddress (${data.size} bytes)")
                    emitEvent(BleSessionEvent.ResponseReceived(deviceAddress, data))
                }
            }
        }
    }

    fun disconnect() {
        try {
            bluetoothGatt?.disconnect()
        } catch (e: SecurityException) {
            Log.e("GattClientSession", "Security exception disconnecting from $deviceAddress", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
        }
        cleanup()
    }

    /**
     * Retry service discovery once after clearing the GATT cache.
     * Samsung/Qualcomm stacks often return status 133 on the first attempt if
     * discoverServices() fires before link-layer parameters settle. A single
     * retry with a cache refresh resolves the transient failure.
     */
    private fun retryServiceDiscovery() {
        serviceDiscoveryRetried = true
        refreshGattCache()
        Handler(Looper.getMainLooper()).postDelayed({
            try {
                bluetoothGatt?.discoverServices()
            } catch (e: SecurityException) {
                Log.e("GattClientSession", "Security exception retrying service discovery for $deviceAddress", e)
                emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "service_discovery_retry"))
                cleanup()
            }
        }, 300L)
    }

    /**
     * Attempt to refresh the Android GATT cache using the hidden BluetoothGatt.refresh() API.
     * Clears cached characteristic values that cause stale reads after GATT errors (status 133).
     */
    fun refreshGattCache(): Boolean {
        return try {
            val gatt = bluetoothGatt ?: return false
            val refreshMethod = gatt.javaClass.getMethod("refresh")
            val result = refreshMethod.invoke(gatt) as? Boolean ?: false
            Log.d("GattClientSession", "GATT cache refresh for $deviceAddress: $result")
            result
        } catch (e: Exception) {
            Log.w("GattClientSession", "GATT cache refresh not available for $deviceAddress", e)
            false
        }
    }

    /**
     * Close the GATT connection without emitting disconnect events.
     * Used when intentionally tearing down a session after a pairing-path failure,
     * so the Disconnected event doesn't race the coordinator cleanup.
     */
    fun closeQuietly() {
        timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
        try {
            bluetoothGatt?.close()
        } catch (e: SecurityException) {
            Log.e("GattClientSession", "Security exception closing GATT quietly for $deviceAddress", e)
        }
        bluetoothGatt = null
        requestCharacteristic = null
        responseCharacteristic = null
        identityCharacteristic = null
        pairingCharacteristic = null
        pairingAckCharacteristic = null
        txResponseSubscribed = false
        txRequestWriteKind = TxRequestWriteKind.NONE
        queuedTransactionWrite = null
        queuedChunkAckWriteCount = null
        pendingChunkAckWriteCount = null
        awaitingConfirmWriteAck = false
        pairingAckCccdSubscribed = false
        pendingTxResponseResubscribe?.cancel()
        pendingTxResponseResubscribe = null
    }

    /**
     * Subscribe to TX_RESPONSE notifications from the GATT server.
     * This enables the sender (GATT client) to receive chunked response data from the
     * receiver (GATT server), such as the accept envelope in bilateral transactions.
     *
     * @return true if the CCCD descriptor write was initiated (caller should wait for
     *         onDescriptorWrite before issuing the next GATT operation), false if
     *         subscription failed or was not possible (caller can proceed immediately).
     */
    @SuppressLint("MissingPermission")
    private fun subscribeToTxResponse(): Boolean {
        val char = responseCharacteristic
        if (char == null) {
            Log.w("GattClientSession", "subscribeToTxResponse: characteristic not found for $deviceAddress")
            return false
        }
        val gatt = bluetoothGatt
        if (gatt == null) {
            Log.w("GattClientSession", "subscribeToTxResponse: GATT not available for $deviceAddress")
            return false
        }
        // Enable local notification routing
        val registered = gatt.setCharacteristicNotification(char, true)
        if (!registered) {
            Log.w("GattClientSession", "subscribeToTxResponse: setCharacteristicNotification failed for $deviceAddress")
            return false
        }
        // Write to CCCD to enable server-side notifications (0x01 = NOTIFY)
        val cccd = char.getDescriptor(BleConstants.CCCD_UUID)
        if (cccd != null) {
            @Suppress("DEPRECATION")
            cccd.value = BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE
            try {
                gatt.writeDescriptor(cccd)
                Log.i("GattClientSession", "subscribeToTxResponse: CCCD written for $deviceAddress (notifications enabled)")
                return true
            } catch (e: SecurityException) {
                Log.e("GattClientSession", "subscribeToTxResponse: security exception writing CCCD for $deviceAddress", e)
                return false
            }
        } else {
            Log.w("GattClientSession", "subscribeToTxResponse: CCCD not found on TX_RESPONSE for $deviceAddress")
            return false
        }
    }

    /**
     * Subscribe to PAIRING_ACK indications from the advertiser.
     * The advertiser sends a BlePairingAccept envelope as an INDICATE after processing
     * the scanner's identity write — this is the bilateral confirmation gate.
     *
     * @return true if the CCCD descriptor write was initiated (caller should wait for
     *         onDescriptorWrite before issuing the next GATT operation), false if
     *         subscription failed or was not possible (caller can proceed immediately).
     */
    @SuppressLint("MissingPermission")
    private fun subscribeToPairingAck(): Boolean {
        val char = pairingAckCharacteristic
        if (char == null) {
            Log.w("GattClientSession", "subscribeToPairingAck: characteristic not found for $deviceAddress")
            return false
        }
        val gatt = bluetoothGatt
        if (gatt == null) {
            Log.w("GattClientSession", "subscribeToPairingAck: GATT not available for $deviceAddress")
            return false
        }
        // Enable local notification routing
        val registered = gatt.setCharacteristicNotification(char, true)
        if (!registered) {
            Log.w("GattClientSession", "subscribeToPairingAck: setCharacteristicNotification failed for $deviceAddress")
            return false
        }
        // Write to CCCD to enable server-side indications (0x02 = INDICATE)
        val cccd = char.getDescriptor(BleConstants.CCCD_UUID)
        if (cccd != null) {
            @Suppress("DEPRECATION")
            cccd.value = BluetoothGattDescriptor.ENABLE_INDICATION_VALUE
            try {
                gatt.writeDescriptor(cccd)
                Log.i("GattClientSession", "subscribeToPairingAck: CCCD written for $deviceAddress (indications enabled)")
                return true
            } catch (e: SecurityException) {
                Log.e("GattClientSession", "subscribeToPairingAck: security exception writing CCCD for $deviceAddress", e)
                return false
            }
        } else {
            Log.w("GattClientSession", "subscribeToPairingAck: CCCD not found on PAIRING_ACK for $deviceAddress")
            return false
        }
    }

    /**
     * Initiate connection to the device.
     * Connection state is communicated via events to BleCoordinator.
     */
    @SuppressLint("MissingPermission")
    fun connect(): Boolean {
        if (!permissionsGate.hasConnectPermission()) {
            diagnostics.recordError(BleErrorCategory.PERMISSION_DENIED, "connect")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "connect"))
            return false
        }

        val adapter = permissionsGate.getBluetoothAdapter() ?: run {
            diagnostics.recordError(BleErrorCategory.HARDWARE_UNAVAILABLE, "connect")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.HARDWARE_UNAVAILABLE, "connect"))
            return false
        }

        try {
            val device = adapter.getRemoteDevice(deviceAddress)
            bluetoothGatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
            timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
            timeoutHandler.postDelayed(connectionTimeoutRunnable, CONNECTION_TIMEOUT_MS)
            diagnostics.recordEvent(BleDiagEvent(phase = "connecting", device = deviceAddress))
            return true
        } catch (t: Throwable) {
            Log.e("GattClientSession", "Failed to connect to $deviceAddress", t)
            diagnostics.recordError(BleErrorCategory.CONNECTION_FAILED, "connect")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CONNECTION_FAILED, "connect"))
            return false
        }
    }

    /**
     * Initiate identity read operation.
     * Result is communicated via IdentityReadCompleted event.
     */
    fun readIdentity(): Boolean {
        val char = identityCharacteristic
        if (char == null) {
            diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "identity_read_no_char")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_READ_FAILED, "identity_read_no_char"))
            return false
        }

        try {
            return bluetoothGatt?.readCharacteristic(char) == true
        } catch (e: SecurityException) {
            Log.e("GattClientSession", "Security exception reading characteristic for $deviceAddress", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
            diagnostics.recordError(BleErrorCategory.PERMISSION_DENIED, "characteristic_read")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "characteristic_read"))
            return false
        }
    }

    /**
     * Send transaction data.
     * Result is communicated via TransactionWriteCompleted event.
     */
    fun sendTransaction(data: ByteArray): Boolean {
        if (requestCharacteristic == null) {
            diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write_no_char")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write_no_char"))
            return false
        }

        if (txRequestWriteKind != TxRequestWriteKind.NONE) {
            if (queuedTransactionWrite != null) {
                Log.w("GattClientSession", "sendTransaction: TX_REQUEST busy and queued slot already occupied for $deviceAddress")
                return false
            }
            queuedTransactionWrite = data.copyOf()
            Log.d("GattClientSession", "sendTransaction: deferred TX_REQUEST write for $deviceAddress (${data.size} bytes)")
            return true
        }

        val sent = startTxRequestWrite(data, TxRequestWriteKind.TRANSACTION)
        if (!sent) {
            diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write_start_failed"))
        }
        return sent
    }

    /**
     * Write a transport-level chunk ACK back to the server's TX_REQUEST characteristic.
     * Frame format: [0xFF][chunk_count_hi][chunk_count_lo]
     * This tells the server how many notification chunks the client has received,
     * allowing it to pace delivery and detect drops.
     */
    private fun writeChunkAck(chunkCount: Int) {
        if (requestCharacteristic == null) {
            Log.w("GattClientSession", "writeChunkAck: TX_REQUEST not available for $deviceAddress")
            return
        }

        if (txRequestWriteKind != TxRequestWriteKind.NONE) {
            queuedChunkAckWriteCount = chunkCount
            Log.d("GattClientSession", "writeChunkAck: deferred ACK for $deviceAddress until current TX_REQUEST write completes (count=$chunkCount)")
            return
        }

        // 5-byte ACK frame: [0xFF][b3][b2][b1][b0] — 32-bit chunk count.
        val ack = byteArrayOf(
            0xFF.toByte(),
            ((chunkCount shr 24) and 0xFF).toByte(),
            ((chunkCount shr 16) and 0xFF).toByte(),
            ((chunkCount shr 8) and 0xFF).toByte(),
            (chunkCount and 0xFF).toByte()
        )
        pendingChunkAckWriteCount = chunkCount
        val sent = startTxRequestWrite(ack, TxRequestWriteKind.CHUNK_ACK)
        if (sent) {
            Log.d("GattClientSession", "Chunk ACK written: $chunkCount chunks confirmed to $deviceAddress")
        } else {
            pendingChunkAckWriteCount = null
            Log.w("GattClientSession", "writeChunkAck: write failed for $deviceAddress (count=$chunkCount)")
        }
    }

    /**
     * Reset the notification chunk counter and idle-gap timestamp.
     * Called on connection reset; per-transfer resets are handled
     * automatically by idle-gap detection in onCharacteristicChanged.
     */
    fun resetNotificationCounter() {
        notificationChunkCount = 0
        currentTransferNonce = -1
    }

    /**
     * Ensure TX_RESPONSE notifications are subscribed before sending transaction data.
     * If already subscribed, returns an immediately completed deferred.
     * If not subscribed, initiates the CCCD write and returns a deferred that completes
     * when the descriptor write callback fires.
     *
     * This is critical for receiving bilateral transaction responses: the receiver sends
     * the accept envelope back via GATT server notifications on TX_RESPONSE, so the
     * sender (GATT client) must be subscribed to receive them.
     */
    fun ensureTxResponseSubscribed(): CompletableDeferred<Boolean> {
        if (txResponseSubscribed) {
            return CompletableDeferred(true)
        }
        Log.i("GattClientSession", "ensureTxResponseSubscribed: re-subscribing for $deviceAddress")
        val deferred = CompletableDeferred<Boolean>()
        pendingTxResponseResubscribe = deferred
        if (!subscribeToTxResponse()) {
            pendingTxResponseResubscribe = null
            deferred.complete(false)
        }
        return deferred
    }

    /**
    * Write the Phase-3 BlePairingConfirm envelope to the advertiser's PAIRING characteristic.
    * Sets [awaitingConfirmWriteAck] so that [onCharacteristicWrite] emits
    * [BleSessionEvent.PairingConfirmWritten] instead of treating the confirm as a
    * Phase-1 identity write.
     */
    fun writePairingConfirm(data: ByteArray): Boolean {
        val char = pairingCharacteristic
        if (char == null) {
            Log.w("GattClientSession", "writePairingConfirm: pairing characteristic not found for $deviceAddress")
            return false
        }
        @Suppress("DEPRECATION")
        char.setValue(data)
        return try {
            awaitingConfirmWriteAck = true
            val result = bluetoothGatt?.writeCharacteristic(char) == true
            if (!result) awaitingConfirmWriteAck = false // write didn't even start; clear flag
            Log.d("GattClientSession", "writePairingConfirm: wrote ${data.size} bytes to $deviceAddress, result=$result")
            result
        } catch (e: SecurityException) {
            awaitingConfirmWriteAck = false
            Log.e("GattClientSession", "Security exception writing pairing confirm for $deviceAddress", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
            false
        }
    }

    /**
     * Write identity/pairing data to the peer's PAIRING characteristic.
     * Used by the scanner to send its own identity back to the advertiser.
     */
    fun writePairingData(data: ByteArray): Boolean {
        val char = pairingCharacteristic
        if (char == null) {
            Log.w("GattClientSession", "writePairingData: pairing characteristic not found for $deviceAddress")
            return false
        }

        @Suppress("DEPRECATION")
        char.setValue(data)

        try {
            val result = bluetoothGatt?.writeCharacteristic(char) == true
            Log.d("GattClientSession", "writePairingData: wrote ${data.size} bytes to $deviceAddress, result=$result")
            return result
        } catch (e: SecurityException) {
            Log.e("GattClientSession", "Security exception writing pairing data for $deviceAddress", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
            return false
        }
    }

    @SuppressLint("MissingPermission")
    private fun negotiateMtu() {
        val requestedMtu = BleConstants.IDENTITY_MTU_REQUEST
        if (bluetoothGatt?.requestMtu(requestedMtu) != true) {
            Log.w("GattClientSession", "MTU request failed, using default")
            emitEvent(BleSessionEvent.MtuNegotiated(deviceAddress, 23))
        }
    }

    private fun cleanup() {
        timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
        // P1.1: Reset connection priority to balanced on cleanup to save battery.
        try {
            bluetoothGatt?.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_BALANCED)
        } catch (_: SecurityException) { /* best-effort */ }
        try {
            bluetoothGatt?.close()
        } catch (e: SecurityException) {
            Log.e("GattClientSession", "Security exception closing GATT for $deviceAddress", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
        }
        bluetoothGatt = null
        requestCharacteristic = null
        responseCharacteristic = null
        identityCharacteristic = null
        pairingCharacteristic = null
        pairingAckCharacteristic = null
        pendingMtu = 0
        txResponseSubscribed = false
        txRequestWriteKind = TxRequestWriteKind.NONE
        queuedTransactionWrite = null
        queuedChunkAckWriteCount = null
        pendingChunkAckWriteCount = null
        awaitingConfirmWriteAck = false
        pairingAckCccdSubscribed = false
        notificationChunkCount = 0
        pendingTxResponseResubscribe?.cancel()
        pendingTxResponseResubscribe = null
    }
}
