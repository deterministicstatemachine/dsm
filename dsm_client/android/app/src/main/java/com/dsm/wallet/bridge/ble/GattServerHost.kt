// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge.ble

import android.annotation.SuppressLint
import android.bluetooth.*
import android.content.Context
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.withLock
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Hosts the GATT server for peripheral role operations.
 *
 * This component manages:
 * - GATT server lifecycle (open/close)
 * - Service and characteristic registration
 * - Write buffer handling for incoming requests
 *
 * The server holds no identity characteristic and no pairing characteristics:
 * a link's peer is learned only by the link handshake Rust runs on it (DSM
 * Amendment A27), whose every byte, like every later byte, travels on
 * TX_REQUEST and TX_RESPONSE.
 */
class GattServerHost(private val context: Context) {

    internal var peerLookup: ((String) -> PeerSession)? = null
    internal var peerEntries: (() -> Collection<PeerSession>)? = null

    private val txResponseScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /**
     * Per-device serialized inbound chunk pipeline.
     *
     * GATT server write callbacks fire on a single shared Binder thread that
     * MUST return quickly so the OS BLE stack can ACK the next ATT write.
     * Calling `processIncomingBleData` (JNI → Rust reassembly + frame
     * decode) directly on that thread blocks for ~30 ms per chunk; on a
     * 200-chunk confirm envelope the OS receive buffer overruns long
     * before the GATT thread drains and chunks 11+ are silently dropped.
     *
     * Decouple by enqueueing the raw bytes onto a bounded per-device
     * channel; a single dedicated consumer coroutine drains it FIFO and
     * does the synchronous Rust call off the GATT thread. Per-device
     * channels preserve reassembly ordering without serializing across
     * unrelated peers. A device's pipeline ends when it disconnects.
     */
    private val inboundChunks = InboundChunkPipelines(
        txResponseScope,
        INBOUND_CHUNK_QUEUE_CAPACITY,
    ) { deviceAddress, data -> processCompletedTxDataInline(deviceAddress, data) }

    private val gattServer = AtomicReference<BluetoothGattServer?>(null)
    private val servicesReady = AtomicBoolean(false)
    private val serviceRegistrationInProgress = AtomicBoolean(false)
    @Volatile private var serviceReadyDeferred: CompletableDeferred<Boolean>? = null

    // Write buffers for handling chunked writes
    private val pendingTxWriteBuffers = ConcurrentHashMap<String, ByteArray>()

    private fun peer(address: String): PeerSession =
        peerLookup?.invoke(address) ?: PeerSession(address)

    companion object {
        /** Marker byte for transport-level chunk ACK frames (client → server). */
        const val CHUNK_ACK_MARKER: Byte = 0xFF.toByte()
        /** Number of notification chunks to send before pausing for an ACK. */
        const val NOTIFICATION_WINDOW_SIZE = 10

        // Whole-transfer retry on window-ACK timeout (transport-level; see sendChunkedNotifications).
        const val TRANSFER_MAX_ATTEMPTS = 3
        const val TRANSFER_RETRY_DELAY_MS = 500L
        /** Timeout waiting for client ACK write-back per window. */
        const val ACK_TIMEOUT_MS = 5000L
        /** Granularity for draining stale ACKs while still honoring ACK_TIMEOUT_MS overall. */
        private const val ACK_WAIT_SLICE_MS = 250L
        /** Maximum allowed write buffer size (64KB). Rejects oversized prepared writes to prevent OOM. */
        private const val MAX_WRITE_BUFFER_SIZE = 65536
        /** Android GATT max attribute value size for notifications/indications. */
        private const val MAX_GATT_ATTRIBUTE_VALUE_BYTES = 512
        /**
         * Chunks one device may have queued for processing: a whole bearer
         * confirm (a few hundred chunks) arriving faster than it is processed
         * fits, with room.
         */
        private const val INBOUND_CHUNK_QUEUE_CAPACITY = 1024
    }

    // GATT server callback
    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            val deviceAddress = device?.address ?: "unknown"
            val connected = newState == BluetoothProfile.STATE_CONNECTED
            Log.d("GattServerHost", "Connection state change: $deviceAddress, status: $status, newState: $newState, connected: $connected")
            if (connected && device != null && deviceAddress != "unknown") {
                peer(deviceAddress).serverDevice = device
                Log.i("GattServerHost", "GATT server client connected: $deviceAddress")
                // The server answers the client's Hello; it writes nothing first.
                try {
                    com.dsm.wallet.bridge.Unified.bleLinkOpened(deviceAddress, BleConstants.LINK_ROLE_SERVER, ByteArray(0))
                } catch (t: Throwable) {
                    Log.e("GattServerHost", "The link from $deviceAddress was not opened; disconnecting", t)
                    disconnectClient(deviceAddress)
                }
            } else if (!connected && deviceAddress != "unknown") {
                val peer = peer(deviceAddress)
                peer.clearServerState()
                pendingTxWriteBuffers.remove(deviceAddress)
                inboundChunks.close(deviceAddress)
                Log.i("GattServerHost", "GATT server client disconnected: $deviceAddress")
                try {
                    com.dsm.wallet.bridge.Unified.bleLinkClosed(deviceAddress, BleConstants.LINK_ROLE_SERVER)
                } catch (t: Throwable) {
                    Log.e("GattServerHost", "Closing the link from $deviceAddress failed", t)
                }
            }
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            // Only the registration in flight is answered here. After stop() (or
            // Bluetooth off) forgot it, a late answer belongs to a closed server and
            // must not mark the next server's service as registered.
            if (!serviceRegistrationInProgress.compareAndSet(true, false)) {
                Log.w("GattServerHost", "onServiceAdded for no registration in flight (status=$status) ignored")
                return
            }
            val success = status == BluetoothGatt.GATT_SUCCESS
            if (success) {
                servicesReady.set(true)
                Log.i("GattServerHost", "GATT service registered via onServiceAdded callback")
            } else {
                servicesReady.set(false)
                Log.e("GattServerHost", "GATT service registration failed in onServiceAdded: status=$status")
            }
            serviceReadyDeferred?.complete(success)
        }

        override fun onNotificationSent(device: BluetoothDevice?, status: Int) {
            val deviceAddress = device?.address ?: return
            val success = status == BluetoothGatt.GATT_SUCCESS
            Log.d("GattServerHost", "Notification sent to $deviceAddress: status=$status, success=$success")
            val p = peer(deviceAddress)
            p.notificationCompletion?.complete(success)
            p.notificationCompletion = null
        }

        override fun onCharacteristicReadRequest(
            device: BluetoothDevice?,
            requestId: Int,
            offset: Int,
            characteristic: BluetoothGattCharacteristic?
        ) {
            val deviceAddress = device?.address ?: return
            Log.d("GattServerHost", "Read request: $deviceAddress, char: ${characteristic?.uuid}")

            when (characteristic?.uuid) {
                else -> {
                    try {
                        gattServer.get()?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                    } catch (e: SecurityException) {
                        Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                        BleCoordinator.getInstance(context).let { coordinator ->
                            coordinator.permissionsGate.recordPermissionFailure()
                            coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                        }
                    }
                }
            }
        }

        override fun onCharacteristicWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            characteristic: BluetoothGattCharacteristic?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            val deviceAddress = device?.address ?: return
            Log.d("GattServerHost", "Write request: $deviceAddress, char: ${characteristic?.uuid}, offset: $offset")

            when (characteristic?.uuid) {
                BleConstants.TX_REQUEST_UUID -> {
                    handleTxWrite(device, requestId, preparedWrite, responseNeeded, offset, value)
                }
                else -> {
                    try {
                        gattServer.get()?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                    } catch (e: SecurityException) {
                        Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                        BleCoordinator.getInstance(context).let { coordinator ->
                            coordinator.permissionsGate.recordPermissionFailure()
                            coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                        }
                    }
                }
            }
        }

        override fun onDescriptorWriteRequest(
            device: BluetoothDevice?,
            requestId: Int,
            descriptor: BluetoothGattDescriptor?,
            preparedWrite: Boolean,
            responseNeeded: Boolean,
            offset: Int,
            value: ByteArray?
        ) {
            val deviceAddress = device?.address ?: return
            val characteristicUuid = descriptor?.characteristic?.uuid
            Log.d("GattServerHost", "Descriptor write: $deviceAddress, desc: ${descriptor?.uuid}, char: $characteristicUuid")

            // Handle CCCD (Client Characteristic Configuration Descriptor) writes
            if (descriptor?.uuid == BleConstants.CCCD_UUID) {
                val enabled = isCccdEnableValue(value)
                val disabled = isCccdDisableValue(value)

                if (characteristicUuid != null) {
                    val peerCccds = peer(deviceAddress).subscribedCccds
                    when {
                        enabled -> {
                            peerCccds[characteristicUuid] = true
                            Log.i(
                                "GattServerHost",
                                "CCCD enabled for $deviceAddress on $characteristicUuid (value=${cccdValueLabel(value)})"
                            )
                        }
                        disabled -> {
                            peerCccds[characteristicUuid] = false
                            Log.i("GattServerHost", "CCCD disabled for $deviceAddress on $characteristicUuid")
                        }
                        else -> {
                            peerCccds[characteristicUuid] = false
                            Log.w(
                                "GattServerHost",
                                "CCCD unknown value for $deviceAddress on $characteristicUuid: ${cccdValueLabel(value)}"
                            )
                        }
                    }
                }

                try {
                    gattServer.get()?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                } catch (e: SecurityException) {
                    Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                    BleCoordinator.getInstance(context).let { coordinator ->
                        coordinator.permissionsGate.recordPermissionFailure()
                        coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                    }
                }
            } else {
                try {
                    gattServer.get()?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                } catch (e: SecurityException) {
                    Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                    BleCoordinator.getInstance(context).let { coordinator ->
                        coordinator.permissionsGate.recordPermissionFailure()
                        coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                    }
                }
            }
        }

        override fun onExecuteWrite(device: BluetoothDevice?, requestId: Int, execute: Boolean) {
            val deviceAddress = device?.address ?: return
            Log.d("GattServerHost", "Execute write: $deviceAddress, execute: $execute")

            if (execute) {
                // Execute prepared writes - process buffered data
                val txBuffer = pendingTxWriteBuffers.remove(deviceAddress)

                if (txBuffer != null && txBuffer.isNotEmpty()) {
                    Log.i("GattServerHost", "Executing prepared TX write: ${txBuffer.size} bytes for $deviceAddress")
                    processCompletedTxData(deviceAddress, txBuffer)
                }
            } else {
                // Cancel prepared writes - clear buffers
                Log.i("GattServerHost", "Cancelling prepared writes for $deviceAddress")
                pendingTxWriteBuffers.remove(deviceAddress)
            }

            try {
                gattServer.get()?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
            } catch (e: SecurityException) {
                Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                BleCoordinator.getInstance(context).let { coordinator ->
                    coordinator.permissionsGate.recordPermissionFailure()
                    coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                }
            }
        }
    }

    suspend fun ensureStarted(): Boolean {
        if (!BleCoordinator.getInstance(context).permissionsGate.hasConnectPermission()) {
            Log.w("GattServerHost", "Missing BLUETOOTH_CONNECT permission")
            return false
        }

        if (gattServer.get() == null) {
            openGattServer()
        }

        val server = gattServer.get() ?: return false

        // Already registered — return immediately
        if (servicesReady.get()) return true

        // Registration in progress from another caller — await the existing deferred
        if (serviceRegistrationInProgress.get()) {
            val deferred = serviceReadyDeferred
            return if (deferred != null) {
                withTimeoutOrNull(5000L) { deferred.await() } ?: false
            } else false
        }

        // Start registration and await the onServiceAdded callback
        setupGattService(server)
        val deferred = serviceReadyDeferred
        return if (deferred != null) {
            withTimeoutOrNull(5000L) { deferred.await() } ?: false
        } else false
    }

    fun isReady(): Boolean = gattServer.get() != null && servicesReady.get()

    /**
     * Close the server and forget its registration, so the next [ensureStarted]
     * opens a new server and registers the service again. Also what Bluetooth going
     * off requires: the stack drops the server registration with the radio.
     */
    fun stop() {
        try {
            gattServer.get()?.close()
        } catch (t: Throwable) {
            Log.e("GattServerHost", "Exception closing GATT server", t)
        }
        gattServer.set(null)
        servicesReady.set(false)
        serviceRegistrationInProgress.set(false)
        serviceReadyDeferred?.complete(false)
        serviceReadyDeferred = null
        pendingTxWriteBuffers.clear()
        inboundChunks.closeAll()
        Log.i("GattServerHost", "GATT server stopped")
    }

    /**
     * Check if the given address is a device connected to our GATT server.
     * These are devices that initiated a GATT client connection to us (we are their server).
     */
    fun isServerClient(address: String): Boolean = peerLookup?.invoke(address)?.isServerClient ?: false

    /**
     * Check if a device address is subscribed to the TX_RESPONSE characteristic on our GATT server.
     * Required to know if we can send them server notifications.
     */
    fun isServerClientSubscribedToTxResponse(address: String): Boolean {
        return isCccdEnabled(address, BleConstants.TX_RESPONSE_UUID)
    }

    /** Find any connected server client that is subscribed to TX_RESPONSE. */
    fun findSubscribedServerClient(): String? {
        return peerEntries?.invoke()?.firstOrNull { peer ->
            peer.isServerClient && peer.isSubscribedTo(BleConstants.TX_RESPONSE_UUID)
        }?.address
    }

    /**
     * Send chunked data as GATT server notifications on the TX_RESPONSE characteristic.
     * Each chunk is sent as a separate notification, waiting for onNotificationSent
     * before proceeding to the next chunk.
     *
     * This is used when the receiver (GATT server) needs to send data back to the
     * sender (GATT client) — e.g., the accept envelope in a bilateral transaction.
     * The sender is already connected as a GATT client, so we can push data via notifications.
     */
    @SuppressLint("MissingPermission")
    /**
     * Send notification chunks to a GATT client using windowed flow control.
     *
     * Sends [NOTIFICATION_WINDOW_SIZE] chunks, then waits for the client to write
     * back a transport-level ACK confirming receipt before continuing. This prevents
     * silent notification drops caused by BLE buffer overflow on the remote device.
     *
     * The client ACKs by writing [0xFF][hi][lo] to TX_REQUEST, where hi:lo is the
     * number of chunks received so far. The server detects this in [handleTxWrite].
     */
    suspend fun sendChunkedNotifications(deviceAddress: String, chunks: Array<ByteArray>): Boolean {
        val server = gattServer.get()
        if (server == null) {
            Log.w("GattServerHost", "sendChunkedNotifications: GATT server not available")
            return false
        }
        val service = server.getService(BleConstants.DSM_SERVICE_UUID)
        if (service == null) {
            Log.w("GattServerHost", "sendChunkedNotifications: DSM service not found")
            return false
        }
        val txResponseChar = service.getCharacteristic(BleConstants.TX_RESPONSE_UUID)
        if (txResponseChar == null) {
            Log.w("GattServerHost", "sendChunkedNotifications: TX_RESPONSE characteristic not found")
            return false
        }
        val peer = peer(deviceAddress)
        val device = peer.serverDevice
        if (device == null) {
            Log.w("GattServerHost", "sendChunkedNotifications: device $deviceAddress not connected as server client")
            return false
        }
        if (!peer.isSubscribedTo(BleConstants.TX_RESPONSE_UUID)) {
            Log.e(
                "GattServerHost",
                "sendChunkedNotifications: TX_RESPONSE CCCD not enabled for $deviceAddress; refusing ${chunks.size} chunks"
            )
            return false
        }

        return peer.notificationSendLock.withLock {
            // Whole-transfer retry: BLE notification streams die routinely mid-flight (observed
            // live: ACK timeout at chunk 150/295 killed a settled transfer's commit ack, leaving
            // the sender undebited). Each attempt bumps the transfer nonce, which resets the
            // client's per-transfer ACK counter, and the Rust reassembly layer dedupes
            // re-received chunks by index — so a full resend is safe and self-consistent.
            attempts@ for (attempt in 1..TRANSFER_MAX_ATTEMPTS) {
            // Increment transfer nonce so the client resets its ACK counter.
            // This eliminates reliance on idle-gap detection for transfer boundary.
            peer.serverTransferNonce = ((peer.serverTransferNonce.toInt() + 1) and 0xFF).toByte()
            val nonce = peer.serverTransferNonce

            Log.i("GattServerHost", "sendChunkedNotifications: sending ${chunks.size} chunks to $deviceAddress (window=$NOTIFICATION_WINDOW_SIZE, nonce=${nonce.toInt() and 0xFF})")
            // ACK flow only needs the latest observed count while a send window waits.
            // Keep the channel bounded so a noisy peer cannot accumulate unbounded ACK state.
            val ackChannel = Channel<Int>(Channel.CONFLATED)
            peer.chunkAckChannel = ackChannel
            var windowTimedOut = false

            try {
                // Prepend [0xFF, nonce] to the first chunk so the client can
                // detect transfer boundaries. 0xFF is an invalid protobuf tag
                // so it won't be confused with real BleChunk payload bytes.
                val framedChunks = chunks.mapIndexed { i, c ->
                    if (i == 0) byteArrayOf(0xFF.toByte(), nonce) + c else c
                }.toTypedArray()

                for ((index, chunk) in framedChunks.withIndex()) {
                    val deferred = CompletableDeferred<Boolean>()
                    peer.notificationCompletion = deferred

                    try {
                        val sent: Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                            server.notifyCharacteristicChanged(device, txResponseChar, false, chunk) == BluetoothStatusCodes.SUCCESS
                        } else {
                            @Suppress("DEPRECATION") txResponseChar.setValue(chunk)
                            @Suppress("DEPRECATION") server.notifyCharacteristicChanged(device, txResponseChar, false)
                        }
                        if (!sent) {
                            // BLE notification buffer may be momentarily full. Wait 50ms
                            // and retry once before giving up — matches Android BLE best
                            // practice for transient buffer-full conditions.
                            Log.w("GattServerHost", "sendChunkedNotifications: buffer-full for chunk $index/${chunks.size} — retry in 50ms")
                            kotlinx.coroutines.delay(50)
                            val retrySent: Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                server.notifyCharacteristicChanged(device, txResponseChar, false, chunk) == BluetoothStatusCodes.SUCCESS
                            } else {
                                @Suppress("DEPRECATION") txResponseChar.setValue(chunk)
                                @Suppress("DEPRECATION") server.notifyCharacteristicChanged(device, txResponseChar, false)
                            }
                            if (!retrySent) {
                                Log.e("GattServerHost", "sendChunkedNotifications: notifyCharacteristicChanged failed after retry for chunk $index/${chunks.size}")
                                peer.notificationCompletion = null
                                return@withLock false
                            }
                        }

                        // P1.2: Wait for onNotificationSent with retry on timeout.
                        // Android BLE can silently drop notifications if link layer is congested.
                        // Retry up to 2 times with exponential backoff before continuing.
                        var notifSuccess: Boolean? = withTimeoutOrNull(5000) { deferred.await() }
                        peer.notificationCompletion = null
                        if (notifSuccess == null) {
                            // Retry loop: 50ms, then 200ms backoff
                            val retryDelays = longArrayOf(50, 200)
                            for ((retryIdx, retryDelay) in retryDelays.withIndex()) {
                                Log.w("GattServerHost", "sendChunkedNotifications: onNotificationSent timeout for chunk $index/${chunks.size}; retry ${retryIdx + 1}")
                                kotlinx.coroutines.delay(retryDelay)
                                val retryDeferred = CompletableDeferred<Boolean>()
                                peer.notificationCompletion = retryDeferred
                                val retrySent: Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                                    server.notifyCharacteristicChanged(device, txResponseChar, false, chunk) == BluetoothStatusCodes.SUCCESS
                                } else {
                                    @Suppress("DEPRECATION") txResponseChar.setValue(chunk)
                                    @Suppress("DEPRECATION") server.notifyCharacteristicChanged(device, txResponseChar, false)
                                }
                                if (!retrySent) {
                                    peer.notificationCompletion = null
                                    continue
                                }
                                notifSuccess = withTimeoutOrNull(5000) { retryDeferred.await() }
                                peer.notificationCompletion = null
                                if (notifSuccess != null) break
                            }
                            if (notifSuccess == null) {
                                Log.w("GattServerHost", "sendChunkedNotifications: onNotificationSent exhausted retries for chunk $index/${chunks.size}; continuing")
                            }
                        } else if (notifSuccess == false) {
                            Log.w("GattServerHost", "sendChunkedNotifications: onNotificationSent reported failure for chunk $index/${chunks.size}; continuing")
                        }

                        // Adaptive inter-chunk pacing via token bucket.
                        // Replaces static delay(10) with back-pressure that
                        // adapts to the actual BLE connection interval.
                        if (index < framedChunks.size - 1) {
                            val budget = peer.writeBudget
                            var backoff = 0
                            while (!budget.tryConsume()) {
                                kotlinx.coroutines.delay(2)
                                backoff++
                                if (backoff > 50) break // safety cap: 100ms max wait
                            }
                        }

                        // Windowed flow control: after every WINDOW_SIZE chunks, wait for client ACK.
                        // The client only emits an ACK on exact window boundaries, not on a final partial window.
                        val chunkNum = index + 1
                        Log.i("BleTransferTrace", "Send chunk $chunkNum/${chunks.size} to $deviceAddress")
                        Log.i("BleTransferTrace", "Send chunk $chunkNum/${chunks.size} to $deviceAddress")
                        val isWindowBoundary = chunkNum % NOTIFICATION_WINDOW_SIZE == 0
                        val isLastChunk = chunkNum == framedChunks.size
                        if (isWindowBoundary) {
                            Log.d("GattServerHost", "sendChunkedNotifications: waiting for ACK after chunk $chunkNum/${chunks.size}")

                            var ackCount: Int? = null
                            repeat((ACK_TIMEOUT_MS / ACK_WAIT_SLICE_MS).toInt()) {
                                if (ackCount != null) return@repeat

                                val candidate = withTimeoutOrNull(ACK_WAIT_SLICE_MS) { ackChannel.receive() } ?: return@repeat
                                // Client resets its counter per-transfer (idle-gap
                                // detection), so ACKs are 1-indexed within each
                                // sendChunkedNotifications call. No offset needed.
                                if (candidate >= chunkNum) {
                                    ackCount = candidate
                                    return@repeat
                                }

                                Log.w(
                                    "GattServerHost",
                                    "sendChunkedNotifications: stale ACK $candidate while waiting for $chunkNum/${chunks.size}; continuing to wait"
                                )
                            }

                            if (ackCount == null) {
                                Log.e(
                                    "GattServerHost",
                                    "sendChunkedNotifications: ACK timeout at chunk $chunkNum/${chunks.size} (attempt $attempt/$TRANSFER_MAX_ATTEMPTS)"
                                )
                                windowTimedOut = true
                                break
                            }

                            Log.d("GattServerHost", "sendChunkedNotifications: ACK confirmed $ackCount/$chunkNum")
                        } else if (isLastChunk) {
                            Log.d(
                                "GattServerHost",
                                "sendChunkedNotifications: final partial window completed at $chunkNum/${chunks.size}; no explicit ACK expected"
                            )
                        }
                    } catch (e: SecurityException) {
                        Log.e("GattServerHost", "sendChunkedNotifications: security exception at chunk $index", e)
                        peer.notificationCompletion = null
                        return@withLock false
                    }
                }

                if (!windowTimedOut) {
                    Log.i(
                        "GattServerHost",
                        "sendChunkedNotifications: all ${chunks.size} chunks sent and ACK'd by $deviceAddress (attempt $attempt)"
                    )
                    return@withLock true
                }
            } finally {
                peer.chunkAckChannel = null
                ackChannel.close()
            }
            // Window ACK timed out: pause briefly for the link to recover, then retry the
            // whole transfer under a fresh nonce.
            if (attempt < TRANSFER_MAX_ATTEMPTS) {
                kotlinx.coroutines.delay(TRANSFER_RETRY_DELAY_MS)
            }
            }
            Log.e(
                "GattServerHost",
                "sendChunkedNotifications: transfer to $deviceAddress failed after $TRANSFER_MAX_ATTEMPTS attempts"
            )
            false
        }
    }

    private fun openGattServer() {
        if (!BleCoordinator.getInstance(context).permissionsGate.hasConnectPermission()) {
            Log.e("GattServerHost", "Cannot open GATT server: missing BLUETOOTH_CONNECT permission")
            return
        }

        val manager = context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager ?: run {
            Log.e("GattServerHost", "Cannot open GATT server: BluetoothManager not available")
            return
        }

        try {
            val server = manager.openGattServer(context, gattServerCallback)
            gattServer.set(server)
            Log.i("GattServerHost", "GATT server opened successfully")
        } catch (e: SecurityException) {
            Log.e("GattServerHost", "Security exception opening GATT server", e)
        } catch (e: Throwable) {
            Log.e("GattServerHost", "Exception opening GATT server", e)
        }
    }

    @SuppressLint("MissingPermission")
    private fun setupGattService(server: BluetoothGattServer) {
        servicesReady.set(false)
        serviceRegistrationInProgress.set(true)
        serviceReadyDeferred = CompletableDeferred()

        Log.i("GattServerHost", "Setting up GATT service")

        val service = BluetoothGattService(
            BleConstants.DSM_SERVICE_UUID,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        // TX Request characteristic (write-only)
        val txRequestChar = BluetoothGattCharacteristic(
            BleConstants.TX_REQUEST_UUID,
            BluetoothGattCharacteristic.PROPERTY_WRITE or BluetoothGattCharacteristic.PROPERTY_WRITE_NO_RESPONSE,
            BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        service.addCharacteristic(txRequestChar)

        // TX Response characteristic (notify)
        val txResponseChar = BluetoothGattCharacteristic(
            BleConstants.TX_RESPONSE_UUID,
            BluetoothGattCharacteristic.PROPERTY_NOTIFY,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        val cccd = BluetoothGattDescriptor(
            BleConstants.CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        txResponseChar.addDescriptor(cccd)
        service.addCharacteristic(txResponseChar)

        try {
            val success = server.addService(service)
            if (success) {
                // servicesReady is set in onServiceAdded callback — addService() is
                // asynchronous on API 21+. The boolean return only confirms the request
                // was accepted by the API, NOT that the service is registered.
                Log.i("GattServerHost", "GATT addService() accepted — awaiting onServiceAdded")
            } else {
                serviceRegistrationInProgress.set(false)
                Log.e("GattServerHost", "addService() returned false — service not queued")
            }
        } catch (t: Throwable) {
            serviceRegistrationInProgress.set(false)
            Log.e("GattServerHost", "Exception adding GATT service", t)
        }
    }

    private fun handleTxWrite(
        device: BluetoothDevice,
        requestId: Int,
        preparedWrite: Boolean,
        responseNeeded: Boolean,
        offset: Int,
        value: ByteArray?
    ) {
        val deviceAddress = device.address

        var writeStatus = BluetoothGatt.GATT_SUCCESS
        if (preparedWrite) {
            // Buffer prepared write data
            val merged = mergeWriteBuffer(pendingTxWriteBuffers[deviceAddress], offset, value ?: ByteArray(0))
            if (merged != null) {
                pendingTxWriteBuffers[deviceAddress] = merged
                Log.d("GattServerHost", "TX prepared write buffered: ${merged.size} bytes for $deviceAddress")
            } else {
                // Buffer exceeded max size — reject
                pendingTxWriteBuffers.remove(deviceAddress)
                writeStatus = BluetoothGatt.GATT_FAILURE
            }
        } else {
            // Immediate write — MUST send the write response BEFORE processing data.
            // ACK writes are just regular TX_REQUEST writes from the client's perspective;
            // if we process them first and start waiting/sending more notifications before
            // the ATT write response is returned, some Android stacks serialize the next
            // GATT operation behind that response and the stream stalls.
            val data = value ?: ByteArray(0)

            if (responseNeeded) {
                try {
                    gattServer.get()?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                } catch (e: SecurityException) {
                    Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                    BleCoordinator.getInstance(context).let { coordinator ->
                        coordinator.permissionsGate.recordPermissionFailure()
                        coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                    }
                    return
                }
            }

            // Check for transport-level chunk ACK: [0xFF][b3][b2][b1][b0].
            if (data.size == 5 && data[0] == CHUNK_ACK_MARKER) {
                val ackCount =
                    ((data[1].toInt() and 0xFF) shl 24) or
                    ((data[2].toInt() and 0xFF) shl 16) or
                    ((data[3].toInt() and 0xFF) shl 8) or
                    (data[4].toInt() and 0xFF)
                Log.i("GattServerHost", "Chunk ACK received from $deviceAddress: $ackCount chunks confirmed")
                peer(deviceAddress).chunkAckChannel?.trySend(ackCount)
            } else {
                // Regular immediate write — process as transaction data
                Log.d("GattServerHost", "TX immediate write: ${data.size} bytes from $deviceAddress")
                processCompletedTxData(deviceAddress, data)
            }

            return
        }

        if (responseNeeded) {
            try {
                gattServer.get()?.sendResponse(device, requestId, writeStatus, 0, null)
            } catch (e: SecurityException) {
                Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                BleCoordinator.getInstance(context).let { coordinator ->
                    coordinator.permissionsGate.recordPermissionFailure()
                    coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                }
            }
        }
    }

    private fun processCompletedTxData(deviceAddress: String, data: ByteArray) {
        // Hand off to the per-device serialized inbound pipeline so the
        // GATT server callback thread returns immediately. Without this
        // hand-off the Rust JNI call (~30 ms per chunk) blocks the BLE
        // stack's ATT-callback dispatcher and chunks 11+ of a long
        // confirm envelope get silently dropped on the receiver side.
        if (!inboundChunks.offer(deviceAddress, data)) {
            Log.w(
                "GattServerHost",
                "Inbound chunk queue for $deviceAddress is full; ${data.size} bytes not taken (its frame is sent again)"
            )
        }
    }

    private fun processCompletedTxDataInline(deviceAddress: String, data: ByteArray) {
        Log.d("GattServerHost", "Processing completed TX data: ${data.size} bytes from $deviceAddress")
        try {
            // All routing — chunk reassembly, frame-type detection, and bilateral
            // follow-up chunking — is performed in Rust via processIncomingBleData.
            // Kotlin MUST NOT inspect frame byte values or branch on protocol content.
            val responseProto = com.dsm.wallet.bridge.Unified.processIncomingBleData(
                deviceAddress,
                BleConstants.LINK_ROLE_SERVER,
                data,
            )
            // Bytes Rust refused (a handshake that failed, a record that does not
            // open) end the link: its next connection runs the handshake again.
            if (com.dsm.wallet.bridge.Unified.isErrorEnvelope(responseProto) != 0) {
                Log.w("GattServerHost", "The link from $deviceAddress refused its bytes; disconnecting")
                disconnectClient(deviceAddress)
                return
            }
            // Extract response fields via JNI helpers (no proto codegen in Kotlin).
            val chunks = com.dsm.wallet.bridge.Unified.bleDataResponseExtractChunks(responseProto)

            // What Rust answers goes back on this link, on a coroutine:
            // dispatchRustBleFollowUp blocks until the link takes it, which would
            // stall the BLE stack's callback thread.
            if (chunks.isNotEmpty()) {
                val addr = deviceAddress
                txResponseScope.launch {
                    try {
                        val queued = com.dsm.wallet.bridge.Unified.dispatchRustBleFollowUp(
                            addr,
                            BleConstants.LINK_ROLE_SERVER,
                            chunks,
                        )
                        Log.i("GattServerHost", "Answer queued=$queued, chunks=${chunks.size} for $addr")
                    } catch (e: Throwable) {
                        Log.e("GattServerHost", "The answer to $addr was not sent", e)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("GattServerHost", "Failed to process transaction payload from $deviceAddress", e)
        }
    }

    private fun isCccdEnabled(deviceAddress: String, characteristicUuid: java.util.UUID): Boolean {
        return peer(deviceAddress).subscribedCccds[characteristicUuid] == true
    }

    private fun isCccdEnableValue(value: ByteArray?): Boolean {
        if (value == null) return false
        return value.contentEquals(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE) ||
            value.contentEquals(BluetoothGattDescriptor.ENABLE_INDICATION_VALUE)
    }

    private fun isCccdDisableValue(value: ByteArray?): Boolean {
        if (value == null) return false
        return value.contentEquals(BluetoothGattDescriptor.DISABLE_NOTIFICATION_VALUE)
    }

    private fun cccdValueLabel(value: ByteArray?): String {
        if (value == null || value.isEmpty()) return "<empty>"
        return value.joinToString(separator = " ") { b -> "%02X".format(b) }
    }

    private fun mergeWriteBuffer(existing: ByteArray?, offset: Int, value: ByteArray): ByteArray? {
        val end = offset + value.size
        if (end > MAX_WRITE_BUFFER_SIZE) {
            Log.w("GattServerHost", "Write buffer exceeded max size ($end > $MAX_WRITE_BUFFER_SIZE), rejecting")
            return null
        }
        val buf = if (existing == null || end > existing.size) {
            val newSize = maxOf(end, existing?.size ?: 0)
            val arr = ByteArray(newSize)
            if (existing != null) System.arraycopy(existing, 0, arr, 0, existing.size)
            arr
        } else existing
        System.arraycopy(value, 0, buf, offset, value.size)
        return buf
    }
    @android.annotation.SuppressLint("MissingPermission")
    fun disconnectClient(deviceAddress: String) {
        val p = peerLookup?.invoke(deviceAddress)
        p?.serverDevice?.let { device ->
            try {
                android.util.Log.i("GattServerHost", "Forcibly disconnecting server client $deviceAddress")
                gattServer.get()?.cancelConnection(device)
            } catch (e: SecurityException) {
                android.util.Log.e("GattServerHost", "Security exception disconnecting", e)
            }
        }
    }
}
