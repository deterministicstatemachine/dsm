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
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.UUID

/**
 * Hosts the GATT server for peripheral role operations.
 *
 * This component manages:
 * - GATT server lifecycle (open/close)
 * - Service and characteristic registration
 * - Identity value management
 * - Write buffer handling for incoming requests
 */
class GattServerHost(private val context: Context) {

    /**
     * Callback for notifying the coordinator when pairing completes on the advertiser side.
     */
    interface PairingCompleteCallback {
        fun onAdvertiserPairingComplete(deviceAddress: String)
    }

    var pairingCompleteCallback: PairingCompleteCallback? = null

    private val txResponseScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val gattServer = AtomicReference<BluetoothGattServer?>(null)
    private val servicesReady = AtomicBoolean(false)
    private val serviceRegistrationInProgress = AtomicBoolean(false)
    @Volatile private var serviceReadyDeferred: CompletableDeferred<Boolean>? = null
    @Volatile private var identityValue: ByteArray? = null

    // Write buffers for handling chunked writes
    private val pendingTxWriteBuffers = ConcurrentHashMap<String, ByteArray>()
    private val pendingPairingWriteBuffers = ConcurrentHashMap<String, ByteArray>()

    // Track devices connected to our GATT server (they are GATT clients of ours)
    private val connectedServerClients = ConcurrentHashMap<String, BluetoothDevice>()
    // Per-device CCCD enablement state: deviceAddress -> characteristicUuid -> enabled
    private val cccdEnabledByDevice = ConcurrentHashMap<String, ConcurrentHashMap<UUID, Boolean>>()
    // Completion handlers for chunked notification flow control
    private val notificationCompletions = ConcurrentHashMap<String, CompletableDeferred<Boolean>>()

    // GATT server callback
    private val gattServerCallback = object : BluetoothGattServerCallback() {
        override fun onConnectionStateChange(device: BluetoothDevice?, status: Int, newState: Int) {
            val deviceAddress = device?.address ?: "unknown"
            val connected = newState == BluetoothProfile.STATE_CONNECTED
            Log.d("GattServerHost", "Connection state change: $deviceAddress, status: $status, newState: $newState, connected: $connected")
            if (connected && device != null && deviceAddress != "unknown") {
                connectedServerClients[deviceAddress] = device
                Log.i("GattServerHost", "GATT server client connected: $deviceAddress (${connectedServerClients.size} total)")
            } else if (!connected && deviceAddress != "unknown") {
                connectedServerClients.remove(deviceAddress)
                cccdEnabledByDevice.remove(deviceAddress)
                pendingTxWriteBuffers.remove(deviceAddress)
                pendingPairingWriteBuffers.remove(deviceAddress)
                // Cancel any pending notification completions
                notificationCompletions.remove(deviceAddress)?.cancel()
                Log.i("GattServerHost", "GATT server client disconnected: $deviceAddress (${connectedServerClients.size} remaining)")
            }
        }

        override fun onServiceAdded(status: Int, service: BluetoothGattService?) {
            serviceRegistrationInProgress.set(false)
            val success = status == BluetoothGatt.GATT_SUCCESS
            if (success) {
                servicesReady.set(true)
                updateIdentityCharacteristic()
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
            notificationCompletions[deviceAddress]?.complete(success)
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
                BleConstants.IDENTITY_UUID -> {
                    handleIdentityRead(device, requestId, offset)
                }
                BleConstants.PAIRING_UUID -> {
                    handlePairingRead(device, requestId, offset)
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
                BleConstants.PAIRING_UUID -> {
                    handlePairingWrite(device, requestId, preparedWrite, responseNeeded, offset, value)
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
                    val perDevice = cccdEnabledByDevice.getOrPut(deviceAddress) { ConcurrentHashMap() }
                    when {
                        enabled -> {
                            perDevice[characteristicUuid] = true
                            Log.i(
                                "GattServerHost",
                                "CCCD enabled for $deviceAddress on $characteristicUuid (value=${cccdValueLabel(value)})"
                            )
                        }
                        disabled -> {
                            perDevice[characteristicUuid] = false
                            Log.i("GattServerHost", "CCCD disabled for $deviceAddress on $characteristicUuid")
                        }
                        else -> {
                            perDevice[characteristicUuid] = false
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
                val pairingBuffer = pendingPairingWriteBuffers.remove(deviceAddress)

                if (txBuffer != null && txBuffer.isNotEmpty()) {
                    Log.i("GattServerHost", "Executing prepared TX write: ${txBuffer.size} bytes for $deviceAddress")
                    processCompletedTxData(deviceAddress, txBuffer)
                }

                if (pairingBuffer != null && pairingBuffer.isNotEmpty()) {
                    Log.i("GattServerHost", "Executing prepared pairing write: ${pairingBuffer.size} bytes for $deviceAddress")
                    processCompletedPairingData(deviceAddress, pairingBuffer)
                }
            } else {
                // Cancel prepared writes - clear buffers
                Log.i("GattServerHost", "Cancelling prepared writes for $deviceAddress")
                pendingTxWriteBuffers.remove(deviceAddress)
                pendingPairingWriteBuffers.remove(deviceAddress)
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
        val permissionsGate = BlePermissionsGate(context)
        if (!permissionsGate.hasConnectPermission()) {
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

    /** Non-suspend version: triggers service setup if needed but does not await the callback. */
    fun ensureStartedNonBlocking() {
        val permissionsGate = BlePermissionsGate(context)
        if (!permissionsGate.hasConnectPermission()) return
        if (gattServer.get() == null) openGattServer()
        val server = gattServer.get() ?: return
        if (!servicesReady.get() && !serviceRegistrationInProgress.get()) {
            setupGattService(server)
        }
    }

    fun stop() {
        try {
            gattServer.get()?.close()
        } catch (e: SecurityException) {
            Log.e("GattServerHost", "Security exception closing GATT server", e)
        }
        gattServer.set(null)
        servicesReady.set(false)
        connectedServerClients.clear()
        cccdEnabledByDevice.clear()
        notificationCompletions.values.forEach { it.cancel() }
        notificationCompletions.clear()
        Log.i("GattServerHost", "GATT server stopped")
    }

    fun getIdentityValue(): ByteArray? = identityValue?.clone()

    fun setIdentityValue(genesisHash: ByteArray, deviceId: ByteArray) {
        if (genesisHash.size != 32 || deviceId.size != 32) {
            Log.w("GattServerHost", "Invalid identity value lengths")
            return
        }

        // Encode identity as protobuf BleIdentityCharValue via Rust.
        // Kotlin MUST NOT concatenate raw bytes — Rust is the canonical encoder.
        val encoded = com.dsm.wallet.bridge.Unified.encodeIdentityCharValue(genesisHash, deviceId)
        if (encoded.isEmpty()) {
            Log.e("GattServerHost", "encodeIdentityCharValue returned empty — identity not set")
            return
        }
        identityValue = encoded
        Log.i("GattServerHost", "Identity value set (proto-encoded, ${identityValue?.size} bytes)")

        // Trigger GATT server setup if needed (non-blocking — doesn't await callback)
        ensureStartedNonBlocking()
        updateIdentityCharacteristic()
    }

    /**
     * Check if the given address is a device connected to our GATT server.
     * These are devices that initiated a GATT client connection to us (we are their server).
     */
    fun isServerClient(address: String): Boolean = connectedServerClients.containsKey(address)

    /**
     * Check if a device address is subscribed to the TX_RESPONSE characteristic on our GATT server.
     * Required to know if we can send them server notifications.
     */
    fun isServerClientSubscribedToTxResponse(address: String): Boolean {
        return isCccdEnabled(address, BleConstants.TX_RESPONSE_UUID)
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
    suspend fun sendChunkedNotifications(deviceAddress: String, chunks: Array<ByteArray>): Boolean {
        val server = gattServer.get()
        if (server == null) {
            Log.w("GattServerHost", "sendChunkedNotifications: GATT server not available")
            return false
        }
        val service = server.getService(BleConstants.DSM_SERVICE_UUID_V2)
        if (service == null) {
            Log.w("GattServerHost", "sendChunkedNotifications: DSM service not found")
            return false
        }
        val txResponseChar = service.getCharacteristic(BleConstants.TX_RESPONSE_UUID)
        if (txResponseChar == null) {
            Log.w("GattServerHost", "sendChunkedNotifications: TX_RESPONSE characteristic not found")
            return false
        }
        val device = connectedServerClients[deviceAddress]
        if (device == null) {
            Log.w("GattServerHost", "sendChunkedNotifications: device $deviceAddress not connected as server client")
            return false
        }
        if (!isCccdEnabled(deviceAddress, BleConstants.TX_RESPONSE_UUID)) {
            Log.e(
                "GattServerHost",
                "sendChunkedNotifications: TX_RESPONSE CCCD not enabled for $deviceAddress; refusing ${chunks.size} chunks"
            )
            return false
        }

        Log.i("GattServerHost", "sendChunkedNotifications: sending ${chunks.size} chunks to $deviceAddress")
        for ((index, chunk) in chunks.withIndex()) {
            val deferred = CompletableDeferred<Boolean>()
            notificationCompletions[deviceAddress] = deferred

            try {
                val sent: Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    server.notifyCharacteristicChanged(device, txResponseChar, false, chunk) == BluetoothStatusCodes.SUCCESS
                } else {
                    @Suppress("DEPRECATION") txResponseChar.setValue(chunk)
                    @Suppress("DEPRECATION") server.notifyCharacteristicChanged(device, txResponseChar, false)
                }
                if (!sent) {
                    Log.e("GattServerHost", "sendChunkedNotifications: notifyCharacteristicChanged failed for chunk $index/${chunks.size}")
                    notificationCompletions.remove(deviceAddress)
                    return false
                }

                // Wait for onNotificationSent callback (5s timeout per chunk)
                val success = withTimeoutOrNull(5000) { deferred.await() } ?: false
                notificationCompletions.remove(deviceAddress)
                if (!success) {
                    Log.e("GattServerHost", "sendChunkedNotifications: notification delivery failed/timed out for chunk $index/${chunks.size}")
                    return false
                }
                Log.d("GattServerHost", "sendChunkedNotifications: chunk ${index + 1}/${chunks.size} delivered (${chunk.size} bytes)")

                // Add inter-chunk pacing delay to prevent remote-side BLE buffer overflow.
                // onNotificationSent only confirms local BLE stack acceptance, NOT remote receipt.
                // Without pacing, 168+ chunks can overwhelm the remote's notification buffer,
                // causing ~15% silent drops (e.g. 27/168 chunks lost).
                // Batch strategy: small delay every chunk, slightly longer every 20 chunks.
                if (index < chunks.size - 1) {
                    if ((index + 1) % 20 == 0) {
                        kotlinx.coroutines.delay(15)  // Longer pause every 20 chunks
                    } else {
                        kotlinx.coroutines.delay(3)   // Brief 3ms pause per chunk
                    }
                }
            } catch (e: SecurityException) {
                Log.e("GattServerHost", "sendChunkedNotifications: security exception at chunk $index", e)
                notificationCompletions.remove(deviceAddress)
                return false
            }
        }

        Log.i("GattServerHost", "sendChunkedNotifications: all ${chunks.size} chunks sent to $deviceAddress")
        return true
    }

    private fun openGattServer() {
        val permissionsGate = BlePermissionsGate(context)
        if (!permissionsGate.hasConnectPermission()) {
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
            BleConstants.DSM_SERVICE_UUID_V2,
            BluetoothGattService.SERVICE_TYPE_PRIMARY
        )

        // Identity characteristic (read-only)
        val identityChar = BluetoothGattCharacteristic(
            BleConstants.IDENTITY_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        service.addCharacteristic(identityChar)

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

        // Pairing characteristic (read/write)
        val pairingChar = BluetoothGattCharacteristic(
            BleConstants.PAIRING_UUID,
            BluetoothGattCharacteristic.PROPERTY_READ or BluetoothGattCharacteristic.PROPERTY_WRITE,
            BluetoothGattCharacteristic.PERMISSION_READ or BluetoothGattCharacteristic.PERMISSION_WRITE
        )
        service.addCharacteristic(pairingChar)

        // Pairing ACK characteristic (indicate)
        val pairingAckChar = BluetoothGattCharacteristic(
            BleConstants.PAIRING_ACK_UUID,
            BluetoothGattCharacteristic.PROPERTY_INDICATE,
            BluetoothGattCharacteristic.PERMISSION_READ
        )
        val pairingAckCccd = BluetoothGattDescriptor(
            BleConstants.CCCD_UUID,
            BluetoothGattDescriptor.PERMISSION_READ or BluetoothGattDescriptor.PERMISSION_WRITE
        )
        pairingAckChar.addDescriptor(pairingAckCccd)
        service.addCharacteristic(pairingAckChar)

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

    private fun updateIdentityCharacteristic() {
        val server = gattServer.get() ?: return
        val service = server.getService(BleConstants.DSM_SERVICE_UUID_V2) ?: return
        val identityChar = service.getCharacteristic(BleConstants.IDENTITY_UUID) ?: return

        identityValue?.let { value ->
            @Suppress("DEPRECATION")
            identityChar.setValue(value)
            Log.d("GattServerHost", "Identity characteristic updated")
        }
    }

    private fun handleIdentityRead(device: BluetoothDevice, requestId: Int, offset: Int) {
        val value = identityValue
        // Null identity (identity not yet published) and out-of-range offset are distinct
        // error conditions requiring different GATT status codes so the client can distinguish them.
        if (value == null) {
            Log.w("GattServerHost", "Identity read for ${device.address}: identity not yet set")
            try {
                gattServer.get()?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
            } catch (e: SecurityException) {
                Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                BleCoordinator.getInstance(context).let { coordinator ->
                    coordinator.permissionsGate.recordPermissionFailure()
                    coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                }
            }
            return
        }
        if (offset >= value.size) {
            Log.w(
                "GattServerHost",
                "Identity read invalid offset for ${device.address}: offset=$offset size=${value.size}"
            )
            try {
                gattServer.get()?.sendResponse(device, requestId, BluetoothGatt.GATT_INVALID_OFFSET, 0, null)
            } catch (e: SecurityException) {
                Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                BleCoordinator.getInstance(context).let { coordinator ->
                    coordinator.permissionsGate.recordPermissionFailure()
                    coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                }
            }
            return
        }

        val chunk = if (offset + BleConstants.MTU_SIZE > value.size) {
            value.copyOfRange(offset, value.size)
        } else {
            value.copyOfRange(offset, offset + BleConstants.MTU_SIZE)
        }

        try {
            gattServer.get()?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, chunk)
        } catch (e: SecurityException) {
            Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
        }
    }

    private fun handlePairingRead(device: BluetoothDevice, requestId: Int, offset: Int) {
        val server = gattServer.get()
        val service = server?.getService(BleConstants.DSM_SERVICE_UUID_V2)
        val pairingChar = service?.getCharacteristic(BleConstants.PAIRING_UUID)
        @Suppress("DEPRECATION")
        val value = pairingChar?.value

        if (value == null || value.isEmpty()) {
            // ACK not yet stored (Rust still processing) — return empty success
            // so the scanner retries rather than treating it as a hard GATT error.
            Log.d("GattServerHost", "Pairing read for ${device.address}: ACK not yet available")
            try {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, ByteArray(0))
            } catch (e: SecurityException) {
                Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                BleCoordinator.getInstance(context).let { coordinator ->
                    coordinator.permissionsGate.recordPermissionFailure()
                    coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                }
            }
            return
        }
        if (offset >= value.size) {
            Log.w("GattServerHost", "Pairing read invalid offset for ${device.address}: offset=$offset size=${value.size}")
            try {
                server?.sendResponse(device, requestId, BluetoothGatt.GATT_INVALID_OFFSET, 0, null)
            } catch (e: SecurityException) {
                Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
                BleCoordinator.getInstance(context).let { coordinator ->
                    coordinator.permissionsGate.recordPermissionFailure()
                    coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
                }
            }
            return
        }

        val chunk = if (offset + BleConstants.MTU_SIZE > value.size) {
            value.copyOfRange(offset, value.size)
        } else {
            value.copyOfRange(offset, offset + BleConstants.MTU_SIZE)
        }

        Log.i("GattServerHost", "Pairing read for ${device.address}: returning ${chunk.size} bytes (offset=$offset)")
        try {
            server?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, offset, chunk)
        } catch (e: SecurityException) {
            Log.e("GattServerHost", "Security exception sending response to ${device.address}", e)
            BleCoordinator.getInstance(context).let { coordinator ->
                coordinator.permissionsGate.recordPermissionFailure()
                coordinator.callback?.onBlePermissionError("Bluetooth connection permission required")
            }
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
            // Immediate write - process directly
            val data = value ?: ByteArray(0)
            Log.d("GattServerHost", "TX immediate write: ${data.size} bytes from $deviceAddress")
            processCompletedTxData(deviceAddress, data)
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

    private fun handlePairingWrite(
        device: BluetoothDevice,
        requestId: Int,
        preparedWrite: Boolean,
        responseNeeded: Boolean,
        offset: Int,
        value: ByteArray?
    ) {
        val deviceAddress = device.address

        if (preparedWrite) {
            // Buffer prepared write data
            var writeStatus = BluetoothGatt.GATT_SUCCESS
            val merged = mergeWriteBuffer(pendingPairingWriteBuffers[deviceAddress], offset, value ?: ByteArray(0))
            if (merged != null) {
                pendingPairingWriteBuffers[deviceAddress] = merged
                Log.d("GattServerHost", "Pairing prepared write buffered: ${merged.size} bytes for $deviceAddress")
            } else {
                // Buffer exceeded max size — reject
                pendingPairingWriteBuffers.remove(deviceAddress)
                writeStatus = BluetoothGatt.GATT_FAILURE
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
        } else {
            // Immediate write — MUST send the write response BEFORE processing data.
            // processCompletedPairingData may send a PAIRING_ACK indication via
            // notifyCharacteristicChanged; if the write response hasn't been sent yet,
            // the client's BLE stack will be waiting for it and the indication will be
            // silently dropped or cause a GATT protocol error.
            val data = value ?: ByteArray(0)
            Log.d("GattServerHost", "Pairing immediate write: ${data.size} bytes from $deviceAddress")
            if (responseNeeded) {
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
            // Now safe to process — write response already sent
            processCompletedPairingData(deviceAddress, data)
        }
    }

    private fun processCompletedTxData(deviceAddress: String, data: ByteArray) {
        Log.d("GattServerHost", "Processing completed TX data: ${data.size} bytes from $deviceAddress")
        try {
            // All routing — chunk reassembly, frame-type detection, and bilateral
            // follow-up chunking — is performed in Rust via processIncomingBleData.
            // Kotlin MUST NOT inspect frame byte values or branch on protocol content.
            val responseProto = com.dsm.wallet.bridge.Unified.processIncomingBleData(deviceAddress, data)
            Log.d("GattServerHost", "Transaction payload processed from $deviceAddress via processIncomingBleData")

            // Extract response fields via JNI helpers (no proto codegen in Kotlin).
            val chunks = com.dsm.wallet.bridge.Unified.bleDataResponseExtractChunks(responseProto)
            val flags = com.dsm.wallet.bridge.Unified.bleDataResponseGetFlags(responseProto)
            val pairingComplete = (flags and 1) != 0
            val useReliableWrite = (flags and 2) != 0

            // If Rust produced bilateral follow-up chunks, send them on a coroutine to
            // avoid blocking the GATT server callback thread. requestGattWriteChunks uses
            // runBlocking internally, which would stall the BLE stack's callback thread.
            if (chunks.isNotEmpty()) {
                val addr = deviceAddress
                txResponseScope.launch {
                    try {
                        val queued = com.dsm.wallet.bridge.Unified.requestGattWriteChunks(addr, chunks)
                        Log.i("GattServerHost", "Follow-up queued=$queued, chunks=${chunks.size}, reliableWrite=$useReliableWrite for $addr")
                        if (pairingComplete && queued) {
                            try {
                                val n = com.dsm.wallet.bridge.Unified.markAnyBilateralConfirmDelivered()
                                Log.i("GattServerHost", "markAnyBilateralConfirmDelivered: $n session(s) committed after confirm to $addr")
                            } catch (t: Throwable) {
                                Log.w("GattServerHost", "markAnyBilateralConfirmDelivered failed for $addr: ${t.message}")
                            }
                        }
                    } catch (e: Throwable) {
                        Log.e("GattServerHost", "Follow-up chunking/routing failed for $addr", e)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e("GattServerHost", "Failed to process transaction payload from $deviceAddress", e)
        }
    }

    private fun sendTxResponse(
        deviceAddress: String,
        responseBytes: ByteArray,
        preferBleChunkFraming: Boolean = false,
    ): Boolean {
        if (preferBleChunkFraming) {
            val frameType = try {
                com.dsm.wallet.bridge.Unified.detectEnvelopeFrameType(responseBytes)
            } catch (e: Throwable) {
                Log.e("GattServerHost", "Failed to detect frame type for TX_RESPONSE (${responseBytes.size} bytes)", e)
                return false
            }

            if (frameType > 0) {
                val chunks = try {
                    com.dsm.wallet.bridge.Unified.chunkEnvelopeForBle(responseBytes, frameType)
                } catch (e: Throwable) {
                    Log.e(
                        "GattServerHost",
                        "Failed to chunk TX_RESPONSE for BLE framing (${responseBytes.size} bytes, frameType=$frameType)",
                        e
                    )
                    return false
                }

                if (chunks.isNotEmpty()) {
                    Log.i(
                        "GattServerHost",
                        "Queueing TX_RESPONSE via BLE chunk notifications: ${responseBytes.size} bytes -> ${chunks.size} chunks for $deviceAddress"
                    )
                    txResponseScope.launch {
                        val ok = sendChunkedNotifications(deviceAddress, chunks)
                        if (!ok) {
                            Log.e(
                                "GattServerHost",
                                "Chunked TX_RESPONSE delivery failed for $deviceAddress (${responseBytes.size} bytes, ${chunks.size} chunks)"
                            )
                        }
                    }
                    return true
                }

                Log.e(
                    "GattServerHost",
                    "TX_RESPONSE chunking produced 0 chunks (${responseBytes.size} bytes, frameType=$frameType)"
                )
                return false
            }

            Log.w(
                "GattServerHost",
                "TX_RESPONSE frame type unknown for ${responseBytes.size} bytes; falling back to direct notify"
            )
        }

        // Android enforces a strict max characteristic value length (typically 512 bytes).
        // Large envelopes (e.g. bilateral prepare/commit responses) must be chunked.
        if (responseBytes.size > MAX_GATT_ATTRIBUTE_VALUE_BYTES) {
            val frameType = try {
                com.dsm.wallet.bridge.Unified.detectEnvelopeFrameType(responseBytes)
            } catch (e: Throwable) {
                Log.e("GattServerHost", "Failed to detect frame type for oversized TX_RESPONSE (${responseBytes.size} bytes)", e)
                return false
            }

            if (frameType <= 0) {
                Log.e("GattServerHost", "Cannot chunk oversized TX_RESPONSE (${responseBytes.size} bytes): unknown frame type=$frameType")
                return false
            }

            val chunks = try {
                com.dsm.wallet.bridge.Unified.chunkEnvelopeForBle(responseBytes, frameType)
            } catch (e: Throwable) {
                Log.e("GattServerHost", "Failed to chunk oversized TX_RESPONSE (${responseBytes.size} bytes), frameType=$frameType", e)
                return false
            }

            if (chunks.isEmpty()) {
                Log.e("GattServerHost", "Chunking produced 0 chunks for oversized TX_RESPONSE (${responseBytes.size} bytes)")
                return false
            }

            Log.i(
                "GattServerHost",
                "Queueing oversized TX_RESPONSE via chunked notifications: ${responseBytes.size} bytes -> ${chunks.size} chunks for $deviceAddress"
            )
            txResponseScope.launch {
                val ok = sendChunkedNotifications(deviceAddress, chunks)
                if (!ok) {
                    Log.e(
                        "GattServerHost",
                        "Chunked TX_RESPONSE delivery failed for $deviceAddress (${responseBytes.size} bytes, ${chunks.size} chunks)"
                    )
                }
            }
            return true
        }

        return sendTxResponseNotification(deviceAddress, responseBytes)
    }

    @SuppressLint("MissingPermission")
    private fun sendTxResponseNotification(deviceAddress: String, responseBytes: ByteArray): Boolean {
        val server = gattServer.get() ?: return false
        val service = server.getService(BleConstants.DSM_SERVICE_UUID_V2) ?: return false
        val txResponseChar = service.getCharacteristic(BleConstants.TX_RESPONSE_UUID) ?: return false

        if (!isCccdEnabled(deviceAddress, BleConstants.TX_RESPONSE_UUID)) {
            Log.e(
                "GattServerHost",
                "TX_RESPONSE notify blocked for $deviceAddress: CCCD not enabled (${responseBytes.size} bytes)"
            )
            return false
        }

        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)
            ?.adapter ?: return false
        val device = adapter.getRemoteDevice(deviceAddress) ?: return false

        try {
            val sent: Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                server.notifyCharacteristicChanged(device, txResponseChar, false, responseBytes) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION") txResponseChar.setValue(responseBytes)
                @Suppress("DEPRECATION") server.notifyCharacteristicChanged(device, txResponseChar, false)
            }
            Log.i("GattServerHost", "TX_RESPONSE notify sent to $deviceAddress: success=$sent (${responseBytes.size} bytes)")
            return sent
        } catch (e: IllegalArgumentException) {
            Log.e(
                "GattServerHost",
                "TX_RESPONSE notify rejected for $deviceAddress (${responseBytes.size} bytes): ${e.message}"
            )
            return false
        } catch (e: SecurityException) {
            Log.e("GattServerHost", "Security exception sending TX_RESPONSE to $deviceAddress", e)
            return false
        }
    }

    private fun processCompletedPairingData(deviceAddress: String, data: ByteArray) {
        Log.d("GattServerHost", "Processing completed pairing data: ${data.size} bytes from $deviceAddress")
        try {
            // Query Rust for pairing state BEFORE processing so we can detect transitions.
            val wasPaired = try {
                com.dsm.wallet.bridge.Unified.isBleAddressPaired(deviceAddress)
            } catch (_: Throwable) { false }

            if (data.isNotEmpty() && com.dsm.wallet.bridge.Unified.requiresBleAck(data)) {
                // Framed envelope — route through typed JNI with the GATT sender
                // address so Rust can update the correct BLE address.
                val response = com.dsm.wallet.bridge.Unified.processBleIdentityEnvelope(data, deviceAddress)
                Log.d("GattServerHost", "BLE identity envelope processed from $deviceAddress: ${response.size} bytes")

                if (response.isNotEmpty()) {
                    // Non-empty = BlePairingAccept (identity propose was processed).
                    // Store ACK bytes as the PAIRING characteristic's readable value.
                    storePairingAckValue(response)
                    // Also send as INDICATE (belt-and-suspenders).
                    sendPairingAckIndication(deviceAddress, response)
                }
            } else {
                // Other pairing data — forward to generic envelope handler
                val response = com.dsm.wallet.bridge.Unified.processEnvelopeV3(data)
                Log.d("GattServerHost", "Pairing envelope processed from $deviceAddress: ${response.size} bytes")
            }

            // Query Rust for pairing state AFTER processing. If it transitioned
            // false→true, pairing is complete on the advertiser side.
            val isPairedNow = try {
                com.dsm.wallet.bridge.Unified.isBleAddressPaired(deviceAddress)
            } catch (_: Throwable) { false }

            if (!wasPaired && isPairedNow) {
                Log.i("GattServerHost", "Pairing confirm processed for $deviceAddress — pairing complete on advertiser side")
                pairingCompleteCallback?.onAdvertiserPairingComplete(deviceAddress)
            }
        } catch (e: Exception) {
            Log.e("GattServerHost", "Failed to process pairing data from $deviceAddress", e)
        }
    }

    /**
     * Store the BlePairingAccept bytes as the PAIRING characteristic's readable value.
     * The scanner reads this after its identity write completes (request-response pattern).
     */
    @SuppressLint("MissingPermission")
    private fun storePairingAckValue(ackBytes: ByteArray) {
        val server = gattServer.get() ?: return
        val service = server.getService(BleConstants.DSM_SERVICE_UUID_V2) ?: return
        val pairingChar = service.getCharacteristic(BleConstants.PAIRING_UUID) ?: return
        @Suppress("DEPRECATION")
        pairingChar.setValue(ackBytes)
        Log.i("GattServerHost", "PAIRING characteristic value set to ACK (${ackBytes.size} bytes) — scanner can read it")
    }

    /**
     * Send a BlePairingAccept envelope as an INDICATE on the PAIRING_ACK characteristic.
     * The scanner subscribes to this characteristic and waits for the indication before
     * marking pairing complete — this ensures bilateral confirmation.
     */
    @SuppressLint("MissingPermission")
    private fun sendPairingAckIndication(deviceAddress: String, ackBytes: ByteArray) {
        val server = gattServer.get()
        if (server == null) {
            Log.w("GattServerHost", "Cannot send PAIRING_ACK: GATT server not available")
            return
        }
        val service = server.getService(BleConstants.DSM_SERVICE_UUID_V2)
        if (service == null) {
            Log.w("GattServerHost", "Cannot send PAIRING_ACK: DSM service not found")
            return
        }
        val ackChar = service.getCharacteristic(BleConstants.PAIRING_ACK_UUID)
        if (ackChar == null) {
            Log.w("GattServerHost", "Cannot send PAIRING_ACK: characteristic not found")
            return
        }

        val adapter = (context.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager)
            ?.adapter
        if (adapter == null) {
            Log.w("GattServerHost", "Cannot send PAIRING_ACK: no Bluetooth adapter")
            return
        }
        val device = adapter.getRemoteDevice(deviceAddress)
        if (device == null) {
            Log.w("GattServerHost", "Cannot send PAIRING_ACK: device not found for $deviceAddress")
            return
        }

        try {
            // confirm = true → INDICATE (requires client acknowledgement), not NOTIFY
            val sent: Boolean = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                server.notifyCharacteristicChanged(device, ackChar, true, ackBytes) == BluetoothStatusCodes.SUCCESS
            } else {
                @Suppress("DEPRECATION") ackChar.setValue(ackBytes)
                @Suppress("DEPRECATION") server.notifyCharacteristicChanged(device, ackChar, true)
            }
            Log.i("GattServerHost", "PAIRING_ACK indication sent to $deviceAddress: success=$sent (${ackBytes.size} bytes)")
        } catch (e: SecurityException) {
            Log.e("GattServerHost", "Security exception sending PAIRING_ACK to $deviceAddress", e)
        }
    }

    private fun isCccdEnabled(deviceAddress: String, characteristicUuid: UUID): Boolean {
        return cccdEnabledByDevice[deviceAddress]?.get(characteristicUuid) == true
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

    /**
     * Deliver a deferred BlePairingAccept envelope from Rust's async retry.
     * Called when the contact was not in SQLite at the time of identity write,
     * but was found by the background polling task. Reuses the same ACK delivery
     * path as the synchronous processBleIdentityEnvelope return value.
     *
     * Pairing completion is now detected by querying Rust's authoritative state
     * via isBleAddressPaired (before/after pattern in processCompletedPairingData).
     */
    fun deliverDeferredAck(deviceAddress: String, ackBytes: ByteArray) {
        Log.i("GattServerHost", "deliverDeferredAck: ${ackBytes.size} bytes for $deviceAddress")
        storePairingAckValue(ackBytes)
        sendPairingAckIndication(deviceAddress, ackBytes)
    }

    companion object {
        /** Maximum allowed write buffer size (64KB). Rejects oversized prepared writes to prevent OOM. */
        private const val MAX_WRITE_BUFFER_SIZE = 65536
        /** Android GATT max attribute value size for notifications/indications. */
        private const val MAX_GATT_ATTRIBUTE_VALUE_BYTES = 512
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
}