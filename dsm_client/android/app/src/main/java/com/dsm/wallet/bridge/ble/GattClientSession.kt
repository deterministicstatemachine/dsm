// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge.ble

import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.Context
import android.os.Build
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
 * Every GATT operation on the link — MTU request, the CCCD write, message
 * chunks (the link handshake's and its sealed records) and chunk ACKs — goes
 * through one [GattOperationQueue], so exactly one is outstanding at a time
 * and each start the stack refuses is reported as refused.
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
        /** How many times a refused start of service discovery is tried, and how far apart. */
        private const val SERVICE_DISCOVERY_START_ATTEMPTS = 6
        private const val SERVICE_DISCOVERY_RETRY_MS = 500L
    }

    private var bluetoothGatt: BluetoothGatt? = null
    private val timeoutHandler = Handler(Looper.getMainLooper())

    /** The link's GATT operations; a new connection gets a new queue. */
    @Volatile private var ops = newQueue()

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

    private var requestCharacteristic: BluetoothGattCharacteristic? = null
    private var responseCharacteristic: BluetoothGattCharacteristic? = null

    // The TX_RESPONSE subscription starts once per connection, from the first MTU
    // the link reports; MtuNegotiated is emitted when it ends.
    @Volatile private var subscriptionChainStarted: Boolean = false
    @Volatile private var txResponseSubscribed: Boolean = false
    @Volatile private var txResponseResubscribe: CompletableDeferred<Boolean>? = null
    // Service discovery retry: Samsung/Qualcomm BT stacks can return status 133 if
    // discoverServices() fires before link-layer negotiation settles. One retry with
    // a GATT cache refresh catches the transient error without masking real failures.
    private var serviceDiscoveryRetried: Boolean = false

    // ── GATT error 133 retry ──
    // Status 133 is transient on most OEMs: close GATT, wait, retry fresh.
    private var connectionRetryCount: Int = 0

    /** True while a GATT operation is in flight or waiting on this link. */
    val hasPendingOperations: Boolean
        get() = ops.busy

    private fun newQueue() = GattOperationQueue { op, reason ->
        Log.w("GattClientSession", "GATT ${op.label} for $deviceAddress not started: $reason")
    }

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

    private fun reportPermissionFailure(e: SecurityException, operation: String) {
        Log.e("GattClientSession", "Security exception during $operation for $deviceAddress", e)
        BleCoordinator.getInstance(context).let { coordinator ->
            coordinator.permissionsGate.recordPermissionFailure()
            coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
        }
    }

    // ── GATT operations ───────────────────────────────────────────────────

    private fun writeKey(uuid: java.util.UUID) =
        GattOperationQueue.Key(GattOperationQueue.Key.Type.WRITE, uuid)

    /** Asks the stack to write [value]; true only when the stack took the write. */
    @SuppressLint("MissingPermission")
    private fun startCharacteristicWrite(
        characteristic: BluetoothGattCharacteristic?,
        value: ByteArray,
        writeType: Int,
        operation: String,
    ): Boolean {
        val gatt = bluetoothGatt ?: return false
        val char = characteristic ?: return false
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                gatt.writeCharacteristic(char, value, writeType) == BluetoothStatusCodes.SUCCESS
            } else {
                char.writeType = writeType
                char.value = value
                gatt.writeCharacteristic(char)
            }
        } catch (e: SecurityException) {
            reportPermissionFailure(e, operation)
            false
        }
    }

    /**
     * Enable notifications (or indications) on [uuid]: the local routing, then
     * the peer's CCCD. [onDone] receives whether the CCCD write succeeded, or
     * false when the stack refused it. A link that ends first reports nothing:
     * the Disconnected event covers it.
     */
    private inner class CccdWrite(
        private val uuid: java.util.UUID,
        private val enableValue: ByteArray,
        private val onDone: (Boolean) -> Unit,
        private val onLinkEnded: () -> Unit = {},
    ) : GattOperationQueue.Op {
        override val key = GattOperationQueue.Key(GattOperationQueue.Key.Type.DESCRIPTOR_WRITE, uuid)
        override val label = "CCCD write ($uuid)"

        @SuppressLint("MissingPermission")
        override fun start(): Boolean {
            val gatt = bluetoothGatt ?: return false
            val char = when (uuid) {
                BleConstants.TX_RESPONSE_UUID -> responseCharacteristic
                else -> null
            } ?: return false
            val cccd = char.getDescriptor(BleConstants.CCCD_UUID) ?: return false
            return try {
                if (!gatt.setCharacteristicNotification(char, true)) return false
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    gatt.writeDescriptor(cccd, enableValue) == BluetoothStatusCodes.SUCCESS
                } else {
                    cccd.value = enableValue
                    gatt.writeDescriptor(cccd)
                }
            } catch (e: SecurityException) {
                reportPermissionFailure(e, label)
                false
            }
        }

        override fun finish(success: Boolean, value: ByteArray?) = onDone(success)

        override fun abandon(reason: String) {
            if (reason == GattOperationQueue.START_REFUSED) onDone(false) else onLinkEnded()
        }
    }

    private inner class MtuRequest(private val mtu: Int) : GattOperationQueue.Op {
        override val key = GattOperationQueue.Key(GattOperationQueue.Key.Type.MTU, null)
        override val label = "MTU request ($mtu)"

        @SuppressLint("MissingPermission")
        override fun start(): Boolean = try {
            bluetoothGatt?.requestMtu(mtu) == true
        } catch (e: SecurityException) {
            reportPermissionFailure(e, label)
            false
        }

        // The MTU is taken from onMtuChanged itself, requested or not.
        override fun finish(success: Boolean, value: ByteArray?) = Unit

        override fun abandon(reason: String) {
            if (reason != GattOperationQueue.START_REFUSED) return
            // An MTU the link already reported (a peer-initiated or automatic
            // exchange) has started the CCCD chain. Otherwise the link's MTU is
            // unknown, and a chunk cannot be sized to it: the link does not
            // become a route.
            if (subscriptionChainStarted) return
            Log.w("GattClientSession", "requestMtu($mtu) refused for $deviceAddress and no MTU reported — the link's MTU is unknown")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.MTU_NEGOTIATION_FAILED, "mtu_request_refused"))
        }
    }

    /** One message's chunks, written in order; [done] is true only when the stack took every chunk. */
    private class OutboundMessage(val chunks: Array<ByteArray>) {
        val done = CompletableDeferred<Boolean>()
    }

    private inner class ChunkWrite(
        private val message: OutboundMessage,
        private val index: Int,
    ) : GattOperationQueue.Op {
        override val key = writeKey(BleConstants.TX_REQUEST_UUID)
        override val label = "chunk ${index + 1}/${message.chunks.size}"

        // A message whose earlier chunk failed sends nothing more.
        override fun obsolete(): Boolean = message.done.isCompleted

        override fun start(): Boolean = startCharacteristicWrite(
            requestCharacteristic,
            message.chunks[index],
            BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE,
            label,
        )

        override fun finish(success: Boolean, value: ByteArray?) {
            if (!success) {
                failed("stack reported a failed write")
            } else if (index == message.chunks.lastIndex) {
                message.done.complete(true)
            }
        }

        override fun abandon(reason: String) = failed(reason)

        private fun failed(reason: String) {
            if (message.done.complete(false)) {
                Log.w("GattClientSession", "Message to $deviceAddress failed at $label: $reason")
                diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "tx_write")
            }
        }
    }

    /**
     * Transport-level chunk ACK back to the server's TX_REQUEST characteristic:
     * [0xFF][b3][b2][b1][b0], the 32-bit count of notification chunks received,
     * so the server can pace delivery. Queued ahead of waiting message chunks;
     * a newer count supersedes a waiting one.
     */
    private inner class ChunkAckWrite(val count: Int) : GattOperationQueue.Op {
        override val key = writeKey(BleConstants.TX_REQUEST_UUID)
        override val label = "chunk ACK ($count)"

        override fun start(): Boolean = startCharacteristicWrite(
            requestCharacteristic,
            byteArrayOf(
                0xFF.toByte(),
                ((count shr 24) and 0xFF).toByte(),
                ((count shr 16) and 0xFF).toByte(),
                ((count shr 8) and 0xFF).toByte(),
                (count and 0xFF).toByte()
            ),
            BluetoothGattCharacteristic.WRITE_TYPE_NO_RESPONSE,
            label,
        )

        override fun finish(success: Boolean, value: ByteArray?) {
            if (success) {
                Log.d("GattClientSession", "Transport chunk ACK write confirmed for $deviceAddress ($count chunks)")
            } else {
                Log.w("GattClientSession", "Transport chunk ACK write failed for $deviceAddress (count=$count)")
            }
        }

        override fun abandon(reason: String) {
            Log.w("GattClientSession", "Transport chunk ACK for $deviceAddress not written (count=$count): $reason")
        }
    }

    /**
     * The TX_RESPONSE subscription, then MtuNegotiated: the link is ready for
     * its handshake. A subscription the stack refused or failed leaves it
     * unsubscribed; the link's first message subscribes again.
     */
    @SuppressLint("MissingPermission")
    private fun startSubscriptionChain(mtu: Int) {
        if (subscriptionChainStarted) return
        subscriptionChainStarted = true
        // Transport-only optimization (rules.instructions.md §36): HIGH
        // connection priority for data transfer.
        try {
            bluetoothGatt?.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_HIGH)
        } catch (e: SecurityException) {
            Log.w("GattClientSession", "requestConnectionPriority failed: ${e.message}")
        }
        ops.enqueue(
            CccdWrite(BleConstants.TX_RESPONSE_UUID, BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE, { ok ->
                txResponseSubscribed = ok
                Log.i("GattClientSession", "TX_RESPONSE CCCD for $deviceAddress: subscribed=$ok — emitting MtuNegotiated($mtu)")
                emitEvent(BleSessionEvent.MtuNegotiated(deviceAddress, mtu))
            })
        )
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
                        // Status 133 is transient on most OEMs. Close GATT, wait, retry fresh
                        // with exponential backoff before giving up.
                        if (status == BleConstants.GATT_ERROR_STATUS && connectionRetryCount < BleConstants.GATT_RETRY_MAX_ATTEMPTS) {
                            connectionRetryCount++
                            val delay = (BleConstants.GATT_RETRY_DELAY_MS * Math.pow(1.5, (connectionRetryCount - 1).toDouble())).toLong()
                            Log.w("GattClientSession", "Status 133 retry #$connectionRetryCount for $deviceAddress — retrying in ${delay}ms")
                            cleanup("connection_status_133_retry", resetRetries = false)
                            timeoutHandler.postDelayed({ connect() }, delay)
                            return
                        }
                        emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CONNECTION_FAILED, "connection_status_$status"))
                        cleanup("connection_status_$status")
                        return
                    }
                    connectionRetryCount = 0
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
                    Handler(Looper.getMainLooper()).postDelayed({ startServiceDiscovery(gatt, 1) }, 200L)
                }
                BluetoothProfile.STATE_DISCONNECTED -> {
                    timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
                    diagnostics.recordEvent(BleDiagEvent(phase = "disconnected", device = deviceAddress, status = status))
                    // Status 133 on disconnect is also transient on some OEMs — retry
                    // if we haven't exhausted retries (e.g., Samsung Tab A9).
                    if (status == BleConstants.GATT_ERROR_STATUS && connectionRetryCount < BleConstants.GATT_RETRY_MAX_ATTEMPTS) {
                        connectionRetryCount++
                        val delay = (BleConstants.GATT_RETRY_DELAY_MS * Math.pow(1.5, (connectionRetryCount - 1).toDouble())).toLong()
                        Log.w("GattClientSession", "Status 133 on disconnect retry #$connectionRetryCount for $deviceAddress — retrying in ${delay}ms")
                        cleanup("disconnect_status_133_retry", resetRetries = false)
                        timeoutHandler.postDelayed({ connect() }, delay)
                        return
                    }
                    // Emit disconnection event - BleCoordinator manages state
                    emitEvent(BleSessionEvent.Disconnected(deviceAddress, status))
                    cleanup("disconnected")
                }
            }
        }

        override fun onServicesDiscovered(gatt: BluetoothGatt?, status: Int) {
            Log.d("GattClientSession", "Services discovered: $deviceAddress, status: $status")

            val service = if (status == BluetoothGatt.GATT_SUCCESS) gatt?.getService(BleConstants.DSM_SERVICE_UUID) else null
            if (service != null) {
                requestCharacteristic = service.getCharacteristic(BleConstants.TX_REQUEST_UUID)
                responseCharacteristic = service.getCharacteristic(BleConstants.TX_RESPONSE_UUID)

                emitEvent(BleSessionEvent.ServiceDiscoveryCompleted(deviceAddress, true))
                // The link's operations may start; the MTU request is the first.
                ops.open()
                ops.enqueue(MtuRequest(BleConstants.LINK_MTU_REQUEST))
            } else if (!serviceDiscoveryRetried) {
                Log.w("GattClientSession", "Service discovery for $deviceAddress found no DSM service (status=$status) — retrying after cache refresh")
                retryServiceDiscovery()
            } else {
                emitEvent(BleSessionEvent.ServiceDiscoveryCompleted(deviceAddress, false))
                emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.SERVICE_DISCOVERY_FAILED, "service_discovery", status))
            }
        }

        override fun onMtuChanged(gatt: BluetoothGatt?, mtu: Int, status: Int) {
            Log.d("GattClientSession", "MTU changed: $deviceAddress, mtu: $mtu, status: $status")
            ops.completed(GattOperationQueue.Key(GattOperationQueue.Key.Type.MTU, null))
                ?.finish(status == BluetoothGatt.GATT_SUCCESS, null)

            if (status == BluetoothGatt.GATT_SUCCESS) {
                diagnostics.recordEvent(BleDiagEvent(phase = "mtu_negotiated", device = deviceAddress, bytes = mtu))
                startSubscriptionChain(mtu)
            } else {
                emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.MTU_NEGOTIATION_FAILED, "mtu_negotiation", status))
            }
            ops.pump()
        }

        override fun onDescriptorWrite(gatt: BluetoothGatt?, descriptor: BluetoothGattDescriptor?, status: Int) {
            val charUuid = descriptor?.characteristic?.uuid
            Log.d("GattClientSession", "Descriptor write: $deviceAddress, uuid: $charUuid, status: $status")
            val op = ops.completed(GattOperationQueue.Key(GattOperationQueue.Key.Type.DESCRIPTOR_WRITE, charUuid))
            if (op == null) {
                Log.w("GattClientSession", "Descriptor write callback for $charUuid on $deviceAddress with no such operation in flight")
            } else {
                op.finish(status == BluetoothGatt.GATT_SUCCESS, null)
            }
            ops.pump()
        }

        override fun onCharacteristicRead(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?, status: Int) {
            val uuid = characteristic?.uuid
            val op = ops.completed(GattOperationQueue.Key(GattOperationQueue.Key.Type.READ, uuid))
            if (op == null) {
                Log.w("GattClientSession", "Read callback for $uuid on $deviceAddress with no such operation in flight")
            } else {
                op.finish(status == BluetoothGatt.GATT_SUCCESS, characteristic?.value)
            }
            ops.pump()
        }

        override fun onCharacteristicWrite(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?, status: Int) {
            val uuid = characteristic?.uuid
            Log.d("GattClientSession", "Characteristic write: $deviceAddress, uuid=$uuid, status=$status")
            val op = ops.completed(writeKey(uuid ?: return))
            if (op == null) {
                Log.w("GattClientSession", "Write callback for $uuid on $deviceAddress with no such operation in flight")
            } else {
                op.finish(status == BluetoothGatt.GATT_SUCCESS, null)
            }
            ops.pump()
        }

        override fun onCharacteristicChanged(gatt: BluetoothGatt?, characteristic: BluetoothGattCharacteristic?) {
            Log.d("GattClientSession", "Characteristic changed: $deviceAddress, uuid: ${characteristic?.uuid}")
            val data = characteristic?.value
            if (data == null || data.isEmpty()) return

            when (characteristic?.uuid) {
                BleConstants.TX_RESPONSE_UUID -> {
                    // TX_RESPONSE notification — response data from the GATT server.
                    // Transfer nonce: the server prepends [0xFF, nonce] to the
                    // FIRST chunk of each sendChunkedNotifications call.
                    // 0xFF is an invalid protobuf tag so it can't appear as
                    // the first byte of a real BleChunk payload.
                    // When detected: strip the 2-byte header, reset the ACK
                    // counter so per-transfer flow control stays synchronized.
                    val payload: ByteArray
                    if (data.size > 2 && data[0] == 0xFF.toByte()) {
                        // First chunk of a new transfer — extract nonce, strip header
                        val nonce = data[1]
                        if (nonce != currentTransferNonce || notificationChunkCount > 0) {
                            Log.d("GattClientSession", "Transfer nonce for $deviceAddress: ${(nonce.toInt() and 0xFF)} (prev=${(currentTransferNonce.toInt() and 0xFF)}, reset counter from $notificationChunkCount)")
                        }
                        currentTransferNonce = nonce
                        notificationChunkCount = 0
                        payload = data.copyOfRange(2, data.size)
                    } else {
                        // Continuation chunk — raw payload
                        payload = data
                    }

                    Log.d("GattClientSession", "TX_RESPONSE notification from $deviceAddress (${payload.size} bytes, nonce=${currentTransferNonce.toInt() and 0xFF})")
                    emitEvent(BleSessionEvent.ResponseReceived(deviceAddress, payload))

                    notificationChunkCount++
                    if (notificationChunkCount % 100 == 0) {
                        Log.d("GattClientSession", "BLE RX chunk #$notificationChunkCount for $deviceAddress")
                    }
                    if (notificationChunkCount % NOTIFICATION_ACK_WINDOW == 0) {
                        val count = notificationChunkCount
                        ops.enqueueFirst(ChunkAckWrite(count)) { it is ChunkAckWrite }
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

    /**
     * Start service discovery on a link just connected. The stack refuses to start it while
     * another operation on the link is in flight (both phones connect to each other at once,
     * each as client and server): a refusal is tried again, and a link that never starts its
     * discovery is closed and reported, not left idle until the radio drops it.
     */
    @SuppressLint("MissingPermission")
    private fun startServiceDiscovery(gatt: BluetoothGatt?, attempt: Int) {
        if (gatt == null || gatt !== bluetoothGatt) return
        val started = try {
            gatt.discoverServices()
        } catch (e: SecurityException) {
            reportPermissionFailure(e, "service discovery")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.PERMISSION_DENIED, "service_discovery"))
            cleanup("service_discovery_permission")
            return
        }
        if (started) return
        if (attempt < SERVICE_DISCOVERY_START_ATTEMPTS) {
            Log.w("GattClientSession", "Service discovery for $deviceAddress not started (attempt $attempt); trying again")
            Handler(Looper.getMainLooper()).postDelayed({ startServiceDiscovery(gatt, attempt + 1) }, SERVICE_DISCOVERY_RETRY_MS)
        } else {
            Log.e("GattClientSession", "Service discovery for $deviceAddress not started after $attempt attempts — closing the link")
            emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.SERVICE_DISCOVERY_FAILED, "service_discovery_not_started"))
            disconnect()
        }
    }

    fun disconnect() {
        try {
            bluetoothGatt?.disconnect()
        } catch (e: SecurityException) {
            reportPermissionFailure(e, "disconnect")
        }
        cleanup("disconnect")
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
                cleanup("service_discovery_retry_permission")
            }
        }, 300L)
    }

    /**
     * Attempt to refresh the Android GATT cache using the hidden BluetoothGatt.refresh() API.
     * Clears cached characteristic values that cause stale reads after GATT errors (status 133).
     */
    private fun refreshGattCache(): Boolean {
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
        try {
            bluetoothGatt?.disconnect()
        } catch (e: SecurityException) {
            Log.e("GattClientSession", "Security exception closing GATT quietly for $deviceAddress", e)
        }
        cleanup("closed")
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

        // Close any stale GATT client to prevent leaking Android's ~32-object limit.
        // A leaked GATT client permanently degrades BLE until the app process is killed.
        bluetoothGatt?.let { stale ->
            try { stale.close() } catch (_: Throwable) {}
        }
        bluetoothGatt = null
        ops.close("reconnecting")
        ops = newQueue()

        try {
            val device = adapter.getRemoteDevice(deviceAddress)
            // Some OEMs (Samsung, Xiaomi) require connectGatt() on the main Looper.
            // If we're already on main, call directly; otherwise dispatch and wait.
            if (Looper.myLooper() == Looper.getMainLooper()) {
                bluetoothGatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
            } else {
                val latch = java.util.concurrent.CountDownLatch(1)
                Handler(Looper.getMainLooper()).post {
                    bluetoothGatt = device.connectGatt(context, false, gattCallback, BluetoothDevice.TRANSPORT_LE)
                    latch.countDown()
                }
                if (!latch.await(3, java.util.concurrent.TimeUnit.SECONDS)) {
                    Log.e("GattClientSession", "connectGatt main-thread dispatch timed out for $deviceAddress")
                    diagnostics.recordError(BleErrorCategory.CONNECTION_FAILED, "connect_main_thread_timeout")
                    emitEvent(BleSessionEvent.ErrorOccurred(deviceAddress, BleErrorCategory.CONNECTION_FAILED, "connect_main_thread_timeout"))
                    return false
                }
            }
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
     * Write one message's chunks to the peer's TX_REQUEST characteristic, in
     * order and contiguous. Completes true only when the stack took every
     * chunk; false when any chunk was refused or failed, or the link ended
     * first — the chunks after a failed one are not written.
     */
    fun sendMessage(chunks: Array<ByteArray>): CompletableDeferred<Boolean> {
        val message = OutboundMessage(chunks)
        if (chunks.isEmpty()) {
            message.done.complete(false)
            return message.done
        }
        ops.enqueueAll(chunks.indices.map { index -> ChunkWrite(message, index) })
        return message.done
    }

    /**
     * Ensure TX_RESPONSE notifications are subscribed before sending transaction data.
     * If already subscribed, returns an immediately completed deferred; otherwise
     * queues the CCCD write and completes with its outcome (false when the stack
     * refused it or the link ended).
     *
     * This is critical for receiving bilateral transaction responses: the receiver sends
     * the accept envelope back via GATT server notifications on TX_RESPONSE, so the
     * sender (GATT client) must be subscribed to receive them.
     */
    fun ensureTxResponseSubscribed(): CompletableDeferred<Boolean> {
        if (txResponseSubscribed) {
            return CompletableDeferred(true)
        }
        txResponseResubscribe?.let { return it }
        Log.i("GattClientSession", "ensureTxResponseSubscribed: re-subscribing for $deviceAddress")
        val deferred = CompletableDeferred<Boolean>()
        txResponseResubscribe = deferred
        ops.enqueue(
            CccdWrite(
                BleConstants.TX_RESPONSE_UUID,
                BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE,
                onDone = { ok ->
                    txResponseSubscribed = ok
                    txResponseResubscribe = null
                    Log.i("GattClientSession", "TX_RESPONSE re-subscription for $deviceAddress: subscribed=$ok")
                    deferred.complete(ok)
                },
                onLinkEnded = {
                    txResponseResubscribe = null
                    deferred.complete(false)
                },
            )
        )
        return deferred
    }

    private fun cleanup(reason: String, resetRetries: Boolean = true) {
        timeoutHandler.removeCallbacks(connectionTimeoutRunnable)
        // P1.1: Reset connection priority to balanced on cleanup to save battery.
        try {
            bluetoothGatt?.requestConnectionPriority(BluetoothGatt.CONNECTION_PRIORITY_BALANCED)
        } catch (_: Throwable) { /* best-effort */ }
        // Null the field BEFORE calling close() so that re-entrant paths (e.g.,
        // an onConnectionStateChange firing during close()) do not double-close.
        // Widened catch to Throwable: Samsung throws DeadObjectException, not SecurityException.
        val gatt = bluetoothGatt
        bluetoothGatt = null
        try {
            gatt?.close()
        } catch (t: Throwable) {
            Log.e("GattClientSession", "Exception closing GATT for $deviceAddress", t)
            if (t is SecurityException) reportPermissionFailure(t, "close")
        }
        requestCharacteristic = null
        responseCharacteristic = null
        subscriptionChainStarted = false
        txResponseSubscribed = false
        notificationChunkCount = 0
        if (resetRetries) connectionRetryCount = 0
        // Every operation in flight or waiting ends with the link.
        ops.close(reason)
    }
}
