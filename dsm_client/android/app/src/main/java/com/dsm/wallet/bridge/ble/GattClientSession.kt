package com.dsm.wallet.bridge.ble

import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow

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
 * State changes are communicated via a shared flow instead of direct atomic variable access
 * to eliminate split-brain concurrency issues with BleCoordinator.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
@Suppress("OVERRIDE_DEPRECATION", "DEPRECATION")
class GattClientSession(
    private val context: Context,
    private val deviceAddress: String,
    private val diagnostics: BleDiagnostics,
    private val permissionsGate: BlePermissionsGate = BlePermissionsGate(context)
) {

    // Shared flow for state changes - BleCoordinator collects from this
    private val _events = MutableSharedFlow<BleSessionEvent>(
        replay = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    val events: SharedFlow<BleSessionEvent> = _events.asSharedFlow()

    companion object {
        /** Disconnect if GATT connection isn't established within 15 seconds. */
        private const val CONNECTION_TIMEOUT_MS = 15_000L
    }

    private var bluetoothGatt: BluetoothGatt? = null
    private val timeoutHandler = Handler(Looper.getMainLooper())
    private val connectionTimeoutRunnable = Runnable {
        Log.w("GattClientSession", "GATT connection timeout (${CONNECTION_TIMEOUT_MS}ms) for $deviceAddress - disconnecting")
        _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CONNECTION_FAILED, "connection_timeout"))
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
    // True while the scanner is waiting for its BlePairingConfirm write to be ACKed by the
    // BLE stack. Prevents the stale-session eviction from disconnecting before the confirm
    // reaches the advertiser (the bilateral handshake completion gate).
    private var awaitingConfirmWriteAck: Boolean = false
    // Whether the PAIRING_ACK CCCD subscription succeeded. Pairing now relies on that
    // indication path directly instead of layering delayed read-back retries on top.
    private var pairingAckCccdSubscribed: Boolean = false
    // Service discovery retry: Samsung/Qualcomm BT stacks can return status 133 if
    // discoverServices() fires before link-layer negotiation settles. One retry with
    // a GATT cache refresh catches the transient error without masking real failures.
    private var serviceDiscoveryRetried: Boolean = false

    // Remove callback lambdas - operations are now fully asynchronous via events

    private val gattCallback = object : BluetoothGattCallback() {
        override fun onConnectionStateChange(gatt: BluetoothGatt?, status: Int, newState: Int) {
            Log.d("GattClientSession", "Connection state change: $deviceAddress, status: $status, newState: $newState")

            when (newState) {
                BluetoothProfile.STATE_CONNECTED -> {
                    timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
                    // Guard against platforms that deliver STATE_CONNECTED with a non-SUCCESS status
                    // (e.g. status 133 / GATT_ERROR on some OEMs). Proceeding to discoverServices()
                    // in this state causes silent failures — close and signal error instead.
                    if (status != BluetoothGatt.GATT_SUCCESS) {
                        Log.e("GattClientSession", "Connection error status=$status for $deviceAddress — closing GATT")
                        _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CONNECTION_FAILED, "connection_status_$status"))
                        cleanup()
                        return
                    }
                    diagnostics.recordEvent(BleDiagEvent(phase = "connected", device = deviceAddress))
                    // Emit connection event - BleCoordinator manages state
                    _events.tryEmit(BleSessionEvent.Connected(deviceAddress))
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
                            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "service_discovery"))
                            cleanup()
                        }
                    }, 200L)
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
                    diagnostics.recordEvent(BleDiagEvent(phase = "disconnected", device = deviceAddress, status = status))
                    // Emit disconnection event - BleCoordinator manages state
                    _events.tryEmit(BleSessionEvent.Disconnected(deviceAddress, status))
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
                    _events.tryEmit(BleSessionEvent.ServiceDiscoveryCompleted(deviceAddress, true))
                    // Negotiate MTU
                    negotiateMtu()
                } else {
                    if (!serviceDiscoveryRetried) {
                        Log.w("GattClientSession", "DSM service UUID not found for $deviceAddress — retrying after cache refresh")
                        retryServiceDiscovery()
                    } else {
                        _events.tryEmit(BleSessionEvent.ServiceDiscoveryCompleted(deviceAddress, false))
                        _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.SERVICE_DISCOVERY_FAILED, "service_discovery"))
                    }
                }
            } else {
                if (!serviceDiscoveryRetried) {
                    Log.w("GattClientSession", "Service discovery failed (status=$status) for $deviceAddress — retrying after cache refresh")
                    retryServiceDiscovery()
                } else {
                    _events.tryEmit(BleSessionEvent.ServiceDiscoveryCompleted(deviceAddress, false))
                    _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.SERVICE_DISCOVERY_FAILED, "service_discovery", status))
                }
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt?, mtu: Int, status: Int) {
            Log.d("GattClientSession", "MTU changed: $deviceAddress, mtu: $mtu, status: $status")

            if (status == BluetoothGatt.GATT_SUCCESS) {
                diagnostics.recordEvent(BleDiagEvent(phase = "mtu_negotiated", device = deviceAddress, bytes = mtu))
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
                        _events.tryEmit(BleSessionEvent.MtuNegotiated(deviceAddress, mtu))
                    }
                }
            } else {
                _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.MTU_NEGOTIATION_FAILED, "mtu_negotiation", status))
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
                            _events.tryEmit(BleSessionEvent.MtuNegotiated(deviceAddress, mtu))
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
                    _events.tryEmit(BleSessionEvent.MtuNegotiated(deviceAddress, mtu))
                }
            }
        }

        @Suppress("DEPRECATION")
        override fun onCharacteristicRead(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?, status: Int) {
            when (characteristic?.uuid) {
                BleConstants.IDENTITY_UUID -> {
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        // Emit identity read completed event
                        _events.tryEmit(BleSessionEvent.IdentityReadCompleted(deviceAddress, characteristic.value))
                    } else {
                        _events.tryEmit(BleSessionEvent.IdentityReadCompleted(deviceAddress, null))
                        _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_READ_FAILED, "identity_read", status))
                    }
                }
                BleConstants.PAIRING_UUID -> {
                    if (status == BluetoothGatt.GATT_SUCCESS && characteristic.value != null && characteristic.value.isNotEmpty()) {
                        Log.i("GattClientSession", "PAIRING read-back from $deviceAddress: ${characteristic.value.size} bytes (ACK response)")
                        _events.tryEmit(BleSessionEvent.PairingAckReceived(deviceAddress, characteristic.value))
                    } else {
                        Log.w("GattClientSession", "PAIRING read-back empty for $deviceAddress (status=$status)")
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
                            _events.tryEmit(BleSessionEvent.PairingConfirmWritten(deviceAddress))
                        } else {
                            Log.w("GattClientSession", "PAIRING_CONFIRM write failed for $deviceAddress: status=$status")
                            // Emit a plain error; BleCoordinator owns the fail-fast cleanup.
                            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "pairing_confirm_write", status))
                        }
                    } else {
                        if (status == BluetoothGatt.GATT_SUCCESS) {
                            // Phase 2 identity write delivered to the advertiser.
                            // Immediately read back PAIRING_UUID — this is the primary, reliable path
                            // to retrieve the advertiser's BlePairingAccept without depending on
                            // the INDICATE subscription being fully established.
                            // If a PAIRING_ACK indication also arrives, Rust handles idempotency.
                            Log.i("GattClientSession", "Pairing identity write successful for $deviceAddress — reading back PAIRING_UUID for ACK")
                            val readOk = readPairingAck()
                            if (!readOk) {
                                if (pairingAckCccdSubscribed) {
                                    Log.w("GattClientSession", "PAIRING read-back initiation failed for $deviceAddress — falling back to PAIRING_ACK indication only")
                                } else {
                                    Log.w("GattClientSession", "PAIRING read-back failed and PAIRING_ACK indication unavailable for $deviceAddress — pairing may stall")
                                    _events.tryEmit(
                                        BleSessionEvent.ErrorOccurred(
                                            deviceAddress,
                                            BleErrorCategory.CHARACTERISTIC_READ_FAILED,
                                            "pairing_ack_readback_and_indication_both_unavailable"
                                        )
                                    )
                                }
                            }
                        } else {
                            Log.w("GattClientSession", "Pairing identity write failed for $deviceAddress: status=$status")
                            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "pairing_write", status))
                        }
                    }
                }
                else -> {
                    // Transaction write
                    if (status == BluetoothGatt.GATT_SUCCESS) {
                        _events.tryEmit(BleSessionEvent.TransactionWriteCompleted(deviceAddress, true))
                    } else {
                        _events.tryEmit(BleSessionEvent.TransactionWriteCompleted(deviceAddress, false))
                        _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write", status))
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
                    _events.tryEmit(BleSessionEvent.PairingAckReceived(deviceAddress, data))
                }
                BleConstants.TX_RESPONSE_UUID -> {
                    // TX_RESPONSE notification — this is response data from the GATT server.
                    // Could be a BLE chunk (needs reassembly) or a complete envelope.
                    // Emit the event for BleCoordinator to handle (it routes through
                    // processBleChunk or processEnvelopeV3 as appropriate).
                    Log.d("GattClientSession", "TX_RESPONSE notification from $deviceAddress (${data.size} bytes)")
                    _events.tryEmit(BleSessionEvent.ResponseReceived(deviceAddress, data))
                }
                else -> {
                    // Unknown characteristic notification — emit as response
                    Log.d("GattClientSession", "Unknown characteristic notification from $deviceAddress (${data.size} bytes)")
                    _events.tryEmit(BleSessionEvent.ResponseReceived(deviceAddress, data))
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
                _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "service_discovery_retry"))
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
            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "connect"))
            return false
        }

        val adapter = permissionsGate.getBluetoothAdapter() ?: run {
            diagnostics.recordError(BleErrorCategory.HARDWARE_UNAVAILABLE, "connect")
            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.HARDWARE_UNAVAILABLE, "connect"))
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
            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CONNECTION_FAILED, "connect"))
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
            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_READ_FAILED, "identity_read_no_char"))
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
            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "characteristic_read"))
            return false
        }
    }

    /**
     * Send transaction data.
     * Result is communicated via TransactionWriteCompleted event.
     */
    fun sendTransaction(data: ByteArray): Boolean {
        val char = requestCharacteristic
        if (char == null) {
            diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write_no_char")
            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write_no_char"))
            return false
        }

        @Suppress("DEPRECATION")
        char.setValue(data)

        try {
            return bluetoothGatt?.writeCharacteristic(char) == true
        } catch (e: SecurityException) {
            Log.e("GattClientSession", "Security exception writing characteristic for $deviceAddress", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
            diagnostics.recordError(BleErrorCategory.PERMISSION_DENIED, "characteristic_write")
            _events.tryEmit(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "characteristic_write"))
            return false
        }
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
     * Sets [awaitingConfirmWriteAck] so that [onCharacteristicWrite] emits [BleSessionEvent.PairingConfirmWritten]
     * instead of spuriously treating the confirm as a Phase-1 identity write. The confirm-sent flag in BleCoordinator
     * lifts the stale-session eviction guard only after this callback fires, ensuring the advertiser
     * receives the confirm before the GATT connection can be torn down.
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
     * Read the PAIRING characteristic from the peer to retrieve the advertiser's
     * BlePairingAccept response (Phase 2 read-back).
     *
     * This is the primary ACK retrieval path — more reliable than waiting for a
     * PAIRING_ACK indication which may be dropped or delayed. Both paths are active
     * simultaneously (belt-and-suspenders); Rust handles idempotency if both fire.
     *
     * Result is communicated via [BleSessionEvent.PairingAckReceived].
     */
    fun readPairingAck(): Boolean {
        val char = pairingCharacteristic
        if (char == null) {
            Log.w("GattClientSession", "readPairingAck: PAIRING characteristic not found for $deviceAddress")
            diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "pairing_ack_read_no_char")
            return false
        }
        return try {
            val result = bluetoothGatt?.readCharacteristic(char) == true
            Log.d("GattClientSession", "readPairingAck: initiated read for $deviceAddress, result=$result")
            result
        } catch (e: SecurityException) {
            Log.e("GattClientSession", "Security exception reading PAIRING characteristic for $deviceAddress", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
            diagnostics.recordError(BleErrorCategory.PERMISSION_DENIED, "pairing_ack_read")
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
            _events.tryEmit(BleSessionEvent.MtuNegotiated(deviceAddress, 23))
        }
    }

    private fun cleanup() {
        timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
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
        awaitingConfirmWriteAck = false
        pairingAckCccdSubscribed = false
        pendingTxResponseResubscribe?.cancel()
        pendingTxResponseResubscribe = null
    }
}
