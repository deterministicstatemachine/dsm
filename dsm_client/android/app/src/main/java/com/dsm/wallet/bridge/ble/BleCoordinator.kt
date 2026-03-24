package com.dsm.wallet.bridge.ble

import android.bluetooth.BluetoothDevice
import android.content.Context
import android.util.Log
import com.dsm.wallet.bridge.BleOutboxRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
// Removed unused mutex imports; coordinator uses an actor (Channel) to serialize operations.

/**
 * Public BLE Coordinator façade.
 *
 * This is the single entry point for all BLE operations. It owns the actor pattern
 * for serializing BLE operations and coordinates between internal components.
 *
 * Wall-clock and elapsed-time checks are allowed here for BLE transport control
 * such as scan throttling, connect readiness, retry pacing, and actor safety
 * timeouts. They are operational only and never change protobuf contents,
 * commitment bytes, or DSM protocol acceptance.
 *
 * No BLE implementation details leak through this API.
 */
class BleCoordinator private constructor(private val context: Context) : BleScanner.Callback {

    interface Callback {
        fun onBlePermissionError(message: String)
    }

    internal var callback: Callback? = null

    private val bleScope = CoroutineScope(SupervisorJob())
    private val operationChannel = Channel<suspend () -> Unit>(Channel.UNLIMITED)
    // Note: Operation serialization is handled via `operationChannel` and `runOperation`.

    // Rate limit protection: Android allows max 5 scan start/stop within 30s window.
    // This is transport-runtime pacing only, not protocol state.
    private val scanStartTimestamps = mutableListOf<Long>()
    private val SCAN_RATE_LIMIT_WINDOW_MS = 30_000L  // 30 seconds
    private val MAX_SCANS_PER_WINDOW = 5
    private var lastScanStopTimestamp = 0L
    private val MIN_SCAN_GAP_MS = 6_000L  // 6 seconds between scan operations

    // Session state management - BleCoordinator is now the single source of truth
    private val sessionStates = mutableMapOf<String, BleSessionState>()

    // Internal components
    internal var permissionsGate = BlePermissionsGate(context)
    private var scanner = BleScanner(context)
    private var advertiser = BleAdvertiser(context)
    private var gattServer = GattServerHost(context)
    private var outbox = BleOutbox(context, BleOutboxRepository(context))
    private var diagnostics = BleDiagnostics()
    // PairingMachine deleted — pairing state is Rust-authoritative via PairingOrchestrator.
    // Use Unified.isBleAddressPaired(address) to query pairing status.

    // Single-flight guards to avoid redundant GATT/advertising work when multiple
    // components request the same operation at once.
    private var gattStartInFlight = false
    private var advertiseInFlight = false

    // Session management - one per peer device
    private val activeSessions = mutableMapOf<String, GattClientSession>()

    // BLE addresses that completed pairing in this session — skip on rediscovery
    // to prevent the reconnect → re-pair → disconnect loop that causes "stuck scanning".
    private val pairedBleAddresses = mutableSetOf<String>()

    // Addresses for which connectGatt() has been issued but the session has not yet
    // emitted Connected/Disconnected/Error. Pairing should not race a second connectGatt()
    // into the same peer while the first one is still unresolved.
    private val pendingConnectionAddresses = mutableSetOf<String>()

    // PAIRING_CONFIRM payloads that failed to write (connection dropped mid-handshake).
    // Keyed by BLE address; retried on the next successful reconnect before any other work.
    private val pendingPairingConfirms = mutableMapOf<String, ByteArray>()

    init {
        // Start the operation processor
        bleScope.launch {
            for (operation in operationChannel) {
                operation()
            }
        }

        // Wire scanner callback so discovered devices trigger GATT connections
        scanner.setCallback(this)

        // Wire GATT server callback so advertiser-side pairing completion stops advertising
        gattServer.pairingCompleteCallback = object : GattServerHost.PairingCompleteCallback {
            override fun onAdvertiserPairingComplete(deviceAddress: String) {
                notifyAdvertiserPairingComplete(deviceAddress)
            }
        }

        // Initialize components
        permissionsGate.initialize()
    }

    // Secondary constructor for tests allowing dependency injection
    internal constructor(
        context: Context,
        permissionsGate: BlePermissionsGate,
        advertiser: BleAdvertiser,
        gattServer: GattServerHost,
        scanner: BleScanner = BleScanner(context),
        outbox: BleOutbox = BleOutbox(context, BleOutboxRepository(context)),
        diagnostics: BleDiagnostics = BleDiagnostics()
    ) : this(context) {
        this.permissionsGate = permissionsGate
        this.advertiser = advertiser
        this.gattServer = gattServer
        this.scanner = scanner
        this.outbox = outbox
        this.diagnostics = diagnostics
        // Re-wire scanner callback after replacing the scanner instance
        this.scanner.setCallback(this)
    }

    companion object {
        private var instance: BleCoordinator? = null

        fun getInstance(context: Context): BleCoordinator {
            return instance ?: synchronized(this) {
                instance ?: BleCoordinator(context.applicationContext).also { 
                    instance = it
                    // Initialize JNI bridge
                    com.dsm.wallet.bridge.Unified.initBleCoordinator(context.applicationContext)
                }
            }
        }
    }

    // ===== PUBLIC API =====

    fun setCallback(callback: Callback?) {
        this.callback = callback
    }

    /**
     * Send a transaction request to a peer device.
     */
    fun sendTransactionRequest(deviceAddress: String, transactionData: ByteArray): Boolean {
        return runOperationBool {
            outbox.enqueueTransaction(deviceAddress, transactionData)
            processOutboxForDevice(deviceAddress)
            true // Successfully enqueued and processed
        }
    }

    /**
     * Start advertising this device for pairing/discovery.
     */
    fun startAdvertising(): Boolean {
        return runOperationBool {
            if (!permissionsGate.hasAdvertisePermission()) {
                diagnostics.recordError(BleErrorCategory.PERMISSION_DENIED, "advertising")
                permissionsGate.recordPermissionFailure()
                com.dsm.wallet.bridge.UnifiedNativeApi.createBlePermissionDeniedEnvelope("advertise").let { if (it.isNotEmpty()) com.dsm.wallet.bridge.BleEventRelay.dispatchEnvelope(it) }
                return@runOperationBool false
            }

            // If already advertising or a start is in-flight, avoid redundant calls.
            if (advertiser.isAdvertising() || advertiseInFlight) {
                return@runOperationBool true
            }

            advertiseInFlight = true
            try {
                // Ensure GATT server is started exactly once across concurrent callers.
                var gattReady = false
                if (!gattStartInFlight) {
                    gattStartInFlight = true
                    try {
                        gattReady = gattServer.ensureStarted()
                    } finally {
                        gattStartInFlight = false
                    }
                } else {
                    gattReady = gattServer.isReady()
                }
                if (!gattReady) {
                    Log.w("BleCoordinator", "startAdvertising aborted: GATT server not ready")
                    return@runOperationBool false
                }
                advertiser.startAdvertising()
                com.dsm.wallet.bridge.Unified.onAdvertisingStarted()
                true
            } finally {
                advertiseInFlight = false
            }
        }
    }

    /**
     * Stop advertising.
     */
    fun stopAdvertising(): Boolean {
        return runOperationBool {
            advertiser.stopAdvertising()
            com.dsm.wallet.bridge.Unified.onAdvertisingStopped()
            true // Always succeeds
        }
    }

    /**
     * Start scanning for peer devices.
     */
    fun startScanning(): Boolean {
        return runOperationBool {
            if (!permissionsGate.hasScanPermission()) {
                diagnostics.recordError(BleErrorCategory.PERMISSION_DENIED, "scanning")
                permissionsGate.recordPermissionFailure()
                com.dsm.wallet.bridge.UnifiedNativeApi.createBlePermissionDeniedEnvelope("scan").let { if (it.isNotEmpty()) com.dsm.wallet.bridge.BleEventRelay.dispatchEnvelope(it) }
                return@runOperationBool false
            }

            // If already scanning, leave it alone
            if (scanner.isScanning()) {
                return@runOperationBool true
            }

            // Rate limit check: enforce minimum gap since last stop
            val now = System.currentTimeMillis()
            val timeSinceLastStop = now - lastScanStopTimestamp
            if (lastScanStopTimestamp > 0 && timeSinceLastStop < MIN_SCAN_GAP_MS) {
                Log.w("BleCoordinator", "Scan throttled: ${timeSinceLastStop}ms since last stop (min ${MIN_SCAN_GAP_MS}ms)")
                return@runOperationBool false
            }

            // Rate limit check: enforce 5-per-30-second window
            scanStartTimestamps.removeAll { now - it > SCAN_RATE_LIMIT_WINDOW_MS }
            if (scanStartTimestamps.size >= MAX_SCANS_PER_WINDOW) {
                val oldestInWindow = scanStartTimestamps.minOrNull() ?: now
                val waitTimeMs = SCAN_RATE_LIMIT_WINDOW_MS - (now - oldestInWindow)
                Log.w("BleCoordinator", "Scan rate limited: ${scanStartTimestamps.size} scans in last ${SCAN_RATE_LIMIT_WINDOW_MS}ms, wait ${waitTimeMs}ms")
                diagnostics.recordError(BleErrorCategory.HARDWARE_UNAVAILABLE, "scan_rate_limited")
                return@runOperationBool false
            }

            // Selective eviction: only disconnect truly stale sessions.
            // Preserve sessions mid-handshake (connected + discovering/negotiating/transacting)
            // and sessions awaiting bilateral pairing confirmation (PAIRING_ACK).
            if (activeSessions.isNotEmpty()) {
                val staleAddresses = mutableListOf<String>()
                for ((addr, _) in activeSessions) {
                    val state = sessionStates[addr]
                    val isConnecting = pendingConnectionAddresses.contains(addr)
                    val isActive = state != null && (
                        isConnecting ||
                        state.identityExchangeInProgress ||
                        state.pairingInProgress ||
                        state.currentTransaction != null ||
                        (state.isConnected && !state.serviceDiscoveryCompleted) ||
                        (state.isConnected && state.negotiatedMtu == 23)
                    )
                    if (!isActive) {
                        staleAddresses.add(addr)
                    }
                }
                if (staleAddresses.isNotEmpty()) {
                    Log.i("BleCoordinator", "Evicting ${staleAddresses.size} stale session(s), keeping ${activeSessions.size - staleAddresses.size} active")
                    for (addr in staleAddresses) {
                        val session = activeSessions.remove(addr)
                        if (!gattServer.isServerClient(addr)) {
                            session?.disconnect()
                        }
                        sessionStates.remove(addr)
                        pendingConnectionAddresses.remove(addr)
                    }
                }
            }

            // Record timestamp BEFORE starting
            scanStartTimestamps.add(now)

            scanner.startScanning()
            com.dsm.wallet.bridge.Unified.onScanStarted()
            true
        }
    }

    /**
     * Stop scanning.
     */
    fun stopScanning(): Boolean {
        return runOperationBool {
            lastScanStopTimestamp = System.currentTimeMillis()
            scanner.stopScanning()
            com.dsm.wallet.bridge.Unified.onScanStopped()
            true // Always succeeds
        }
    }

    fun isScanning(): Boolean = scanner.isScanning()

    fun isAdvertising(): Boolean = advertiser.isAdvertising()

    /**
     * Set the current session mode.
     */
    fun setSessionMode(mode: BleSessionMode) {
        runOperation {
            scanner.setSessionMode(mode)
            // Update session mode logic here if needed for other components
        }
    }

    /**
     * Read peer identity information.
     */
    fun readPeerIdentity(deviceAddress: String): Boolean {
        return runOperationBool {
            val session = getOrCreateSession(deviceAddress)
            session.readIdentity()
            // For now, just start the operation - result will be handled asynchronously
            true
        }
    }

    /**
     * Set local identity value for GATT server.
     */
    fun setIdentityValue(genesisHash: ByteArray, deviceId: ByteArray) {
        runOperation {
            gattServer.setIdentityValue(genesisHash, deviceId)
        }
    }

    /**
     * Ensure GATT server is started.
     */
    fun ensureGattServerStarted(): Boolean {
        return runOperationBool {
            // Deduplicate concurrent ensure calls; if one is in flight, consider it handled.
            if (gattStartInFlight) {
                return@runOperationBool true
            }
            gattStartInFlight = true
            try {
                gattServer.ensureStarted()
            } finally {
                gattStartInFlight = false
            }
        }
    }

    /**
     * Get diagnostic information about BLE errors.
     */
    fun getBleErrorGuidance(): Map<String, Any>? {
        return diagnostics.getErrorGuidance()
    }

    /**
     * Check if there are persistent BLE issues.
     */
    fun hasPersistentBleIssues(): Boolean {
        return diagnostics.hasPersistentIssues()
    }

    /**
     * Get BLE events log for debugging.
     */
    fun getBleEventsLog(): String {
        return diagnostics.getEventsLog()
    }

    /**
     * Enable/disable BLE debug logging.
     */
    fun setBleDebugEnabled(enabled: Boolean) {
        diagnostics.setDebugEnabled(enabled)
    }

    /**
     * Get connection statistics for a device.
     */
    fun getStatsString(deviceAddress: String): String {
        val state = sessionStates[deviceAddress]
        return if (state != null) {
            "Session[$deviceAddress]: connected=${state.isConnected}, mtu=${state.negotiatedMtu}, services=${state.serviceDiscoveryCompleted}"
        } else {
            "No active session state for $deviceAddress"
        }
    }

    /**
     * Retry the last transaction for a device.
     */
    fun retryLastTransaction(deviceAddress: String): Boolean {
        return runOperationBool {
            outbox.retryLastTransaction(deviceAddress)
            processOutboxForDevice(deviceAddress)
            true // Successfully retried and processed
        }
    }

    /**
     * Get list of connected device addresses.
     */
    fun getConnectedDeviceAddresses(): List<String> {
        return sessionStates.filter { it.value.isConnected }.keys.toList()
    }

    /**
     * Check if a specific device is connected.
     */
    fun isDeviceConnected(deviceAddress: String): Boolean {
        return sessionStates[deviceAddress]?.isConnected == true
    }

    /**
     * Mark a device as paired. No-op — pairing state is Rust-authoritative
     * (persisted via finalizeScannerPairing / handle_pairing_confirm).
     */
    fun markDeviceAsPaired(deviceId: String) {
        Log.d("BleCoordinator", "markDeviceAsPaired($deviceId) — no-op, Rust is authoritative")
    }

    /**
     * Get list of paired device IDs. Returns empty — use Rust queries instead.
     */
    fun getPairedDeviceIds(): List<String> {
        return emptyList()
    }

    /**
     * Check if a device is paired. Delegates to Rust's SQLite-authoritative store.
     */
    fun isDevicePaired(deviceId: String): Boolean {
        return try {
            com.dsm.wallet.bridge.Unified.isBleAddressPaired(deviceId)
        } catch (_: Throwable) {
            false
        }
    }

    /**
     * Called by GattServerHost when the advertiser side processes a PairingConfirm
     * (Rust returns empty after the confirm envelope). Keep advertising active so
     * already-paired peers can reconnect later for offline bilateral transfers.
     *
     * Does NOT add to pairedBleAddresses — the bilateral protocol requires this
     * device's scanner to still connect to the peer (Direction 2: send our identity
     * to them). Only the scanner-side PairingConfirmWritten event marks the address
     * as fully bilaterally paired and prevents further rediscovery.
     */
    fun notifyAdvertiserPairingComplete(bleAddress: String) {
        runOperation {
            // Clear session state after pairing so the bilateral send uses a fresh
            // on-demand connection instead of the pairing session. The active session
            // (activeSessions) is kept alive; connectToDevice() will clean it up if
            // needed when the send is initiated.
            sessionStates.remove(bleAddress)
            pendingConnectionAddresses.remove(bleAddress)
            Log.i("BleCoordinator", "Advertiser pairing complete for $bleAddress — keeping advertising active for reconnects")
        }
    }

    /**
     * Clean up resources.
     */
    fun cleanup() {
        runOperation {
            scanner.stopScanning()
            advertiser.stopAdvertising()
            gattServer.stop()
            activeSessions.values.forEach { session -> session.disconnect() }
            activeSessions.clear()
            sessionStates.clear()
            pendingConnectionAddresses.clear()
            pairedBleAddresses.clear()
            permissionsGate.cleanup()
        }
    }

    // ===== BleScanner.Callback =====

    override fun onDeviceDiscovered(device: BluetoothDevice, rssi: Int) {
        val address = device.address
        // Skip devices that already completed pairing — prevents the
        // rediscovery → reconnect → re-pair → disconnect → stuck-scanning loop.
        if (pairedBleAddresses.contains(address)) {
            Log.d("BleCoordinator", "Skipping already-paired device $address")
            return
        }
        if (pendingConnectionAddresses.contains(address)) {
            Log.d("BleCoordinator", "Skipping $address — GATT connection already in flight")
            return
        }
        if (activeSessions.containsKey(address)) {
            return
        }
        Log.i("BleCoordinator", "Discovered DSM peer: $address (rssi=$rssi) — initiating GATT connection")
        com.dsm.wallet.bridge.Unified.onDeviceFound(address, device.name ?: "", rssi)
        runOperation {
            if (pendingConnectionAddresses.contains(address) || activeSessions.containsKey(address)) {
                return@runOperation
            }
            // Stop the active scan before connectGatt(). Android BLE guidance and
            // field experience both point to scan/connect overlap as a reliability hit,
            // especially on Samsung/Qualcomm stacks where callbacks can stall.
            if (scanner.isScanning()) {
                scanner.stopScanning()
                com.dsm.wallet.bridge.Unified.onScanStopped()
            }
            val session = getOrCreateSession(address)
            pendingConnectionAddresses.add(address)
            val connected = session.connect()
            if (connected) {
                Log.i("BleCoordinator", "GATT connection initiated to $address")
            } else {
                Log.w("BleCoordinator", "Failed to initiate GATT connection to $address")
                activeSessions.remove(address)
                pendingConnectionAddresses.remove(address)
                com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed(address, "GATT connection initiation failed")
                resumePairingScan(address, "connect_init_failed")
            }
        }
    }

    override fun onScanFailed(errorCode: Int) {
        Log.e("BleCoordinator", "BLE scan failed: errorCode=$errorCode")
        diagnostics.recordError(BleErrorCategory.HARDWARE_UNAVAILABLE, "scan_failed_code_$errorCode")
        com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed("", "scan_failed_code_$errorCode")
    }

    private fun runOperation(block: suspend () -> Unit) {
        if (operationChannel.trySend {
                try {
                    block()
                } catch (t: Throwable) {
                    Log.e("BleCoordinator", "BLE operation failed", t)
                }
            }.isFailure
        ) {
            Log.w("BleCoordinator", "BLE operation dropped: channel unavailable")
        }
    }

    private fun runOperationBool(block: suspend () -> Boolean): Boolean {
        val deferred = CompletableDeferred<Boolean>()
        val sent = operationChannel.trySend {
            try {
                deferred.complete(block())
            } catch (t: Throwable) {
                Log.e("BleCoordinator", "BLE operation failed", t)
                deferred.complete(false)
            }
        }.isSuccess
        if (!sent) {
            Log.w("BleCoordinator", "BLE operation dropped: channel unavailable")
            return false
        }
        // Block the caller until the actor processes this operation and produces the
        // real Boolean result. The actor runs on Dispatchers.Default (SupervisorJob),
        // so this will not deadlock even when the caller is the main thread. The 5 s
        // timeout is an operational safety net against actor stalls, not a protocol
        // deadline.
        return runBlocking {
            withTimeoutOrNull(5_000L) { deferred.await() } ?: false
        }
    }

    private fun resumePairingScan(deviceAddress: String, reason: String) {
        if (pairedBleAddresses.contains(deviceAddress)) {
            return
        }

        // Already scanning - no action needed
        if (scanner.isScanning()) {
            return
        }

        // Rate limit check before attempting resume. This gates Android BLE radio
        // behavior only and must not be interpreted as protocol timing.
        val now = System.currentTimeMillis()
        val timeSinceLastStop = now - lastScanStopTimestamp
        if (lastScanStopTimestamp > 0 && timeSinceLastStop < MIN_SCAN_GAP_MS) {
            Log.d("BleCoordinator", "Resume scan throttled for $deviceAddress: ${timeSinceLastStop}ms since last stop")
            return
        }

        scanStartTimestamps.removeAll { now - it > SCAN_RATE_LIMIT_WINDOW_MS }
        if (scanStartTimestamps.size >= MAX_SCANS_PER_WINDOW) {
            Log.w("BleCoordinator", "Resume scan rate limited for $deviceAddress: ${scanStartTimestamps.size} scans in window")
            return
        }

        scanStartTimestamps.add(now)
        val started = scanner.startScanning()
        Log.i("BleCoordinator", "Pairing scan resume for $deviceAddress: reason=$reason started=$started")
        if (started) {
            com.dsm.wallet.bridge.Unified.onScanStarted()
        }
    }

    private fun handleSessionEvent(event: BleSessionEvent) {
        // Serialize all state mutations and follow-up actions through the coordinator's actor.
        // This avoids races between event handling and public API calls that also mutate state.
        bleScope.launch {
            operationChannel.send {
                val state = sessionStates.getOrPut(event.deviceAddress) { BleSessionState(event.deviceAddress) }

                when (event) {
                    is BleSessionEvent.Connected -> {
                        pendingConnectionAddresses.remove(event.deviceAddress)
                        state.isConnected = true
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_connected", device = event.deviceAddress))
                        // IMPORTANT:
                        // Do NOT stop advertising on connect.
                        // We previously stopped advertising to preserve battery and prevent
                        // extra connections, but that breaks the "second sender" case:
                        // after the first device connects, the other device may need to
                        // initiate its own GATT client connection back (role swap /
                        // bidirectional sends). If the peripheral stops advertising, that
                        // reverse connection never forms, and the recipient sees nothing.
                        com.dsm.wallet.bridge.Unified.onDeviceConnected(event.deviceAddress)
                    }
                    is BleSessionEvent.Disconnected -> {
                        pendingConnectionAddresses.remove(event.deviceAddress)
                        state.isConnected = false
                        state.serviceDiscoveryCompleted = false
                        state.currentTransaction = null // Clear any pending transaction
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_disconnected", device = event.deviceAddress, status = event.status))
                        // Remove stale session so future scans can reconnect to this peer
                        activeSessions.remove(event.deviceAddress)
                        sessionStates.remove(event.deviceAddress)
                        com.dsm.wallet.bridge.Unified.onDeviceDisconnected(event.deviceAddress)
                        resumePairingScan(event.deviceAddress, "disconnected")
                    }
                    is BleSessionEvent.MtuNegotiated -> {
                        state.negotiatedMtu = event.mtu
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_mtu_negotiated", device = event.deviceAddress, bytes = event.mtu))
                        // Query Rust for pairing status — skip identity read if already paired (bilateral reconnect)
                        val alreadyPaired = try { com.dsm.wallet.bridge.Unified.isBleAddressPaired(event.deviceAddress) } catch (_: Throwable) { false }
                        if (alreadyPaired) {
                            // Check if we have a PAIRING_CONFIRM that failed to deliver last
                            // time (connection dropped between PAIRING_ACK and confirm write).
                            // If so, retry the write before doing anything else.
                            val pendingConfirm = pendingPairingConfirms.remove(event.deviceAddress)
                            if (pendingConfirm != null) {
                                val session = activeSessions[event.deviceAddress]
                                if (session != null) {
                                    Log.i("BleCoordinator", "MTU negotiated (${event.mtu}) for ${event.deviceAddress} — retrying pending PAIRING_CONFIRM (${pendingConfirm.size}B)")
                                    state.pairingInProgress = true
                                    val writeOk = session.writePairingConfirm(pendingConfirm)
                                    Log.i("BleCoordinator", "PAIRING_CONFIRM retry for ${event.deviceAddress}: success=$writeOk")
                                    if (!writeOk) {
                                        // Still failing — put it back and scan again
                                        pendingPairingConfirms[event.deviceAddress] = pendingConfirm
                                        state.pairingInProgress = false
                                        diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "coordinator_pairing_confirm_retry_failed")
                                        activeSessions.remove(event.deviceAddress)?.closeQuietly()
                                        sessionStates.remove(event.deviceAddress)
                                        pendingConnectionAddresses.remove(event.deviceAddress)
                                        resumePairingScan(event.deviceAddress, "pairing_confirm_retry_failed")
                                    }
                                } else {
                                    // No session yet — put back so the next MTU cycle retries
                                    pendingPairingConfirms[event.deviceAddress] = pendingConfirm
                                    Log.w("BleCoordinator", "PAIRING_CONFIRM retry: no session for ${event.deviceAddress}; will retry on next connect")
                                }
                            } else {
                                // Normal bilateral reconnect — nothing pending.
                                Log.i("BleCoordinator", "MTU negotiated (${event.mtu}) for ${event.deviceAddress} — skipping identity read (already paired per Rust)")
                            }
                        } else {
                            // Set identity exchange guard BEFORE reading — prevents
                            // startScanning() eviction during the identity read/write phase.
                            state.identityExchangeInProgress = true
                            val session = activeSessions[event.deviceAddress]
                            if (session != null) {
                                Log.i("BleCoordinator", "MTU negotiated (${event.mtu}) for ${event.deviceAddress} — reading peer identity")
                                session.readIdentity()
                            } else {
                                state.identityExchangeInProgress = false
                            }
                        }
                        // Drain any pending outbox items now that the connection is ready
                        operationChannel.send { processNextOutboxItem(event.deviceAddress) }
                    }
                    is BleSessionEvent.ServiceDiscoveryCompleted -> {
                        state.serviceDiscoveryCompleted = event.success
                        if (!event.success) {
                            diagnostics.recordError(BleErrorCategory.SERVICE_DISCOVERY_FAILED, "coordinator_service_discovery")
                        } else {
                            // Drain any pending outbox items now that services are discovered
                            operationChannel.send { processNextOutboxItem(event.deviceAddress) }
                        }
                    }
                    is BleSessionEvent.IdentityReadCompleted -> {
                        // Identity exchange phase complete (read result received).
                        // Clear the guard — PairingAckReceived will set pairingInProgress.
                        state.identityExchangeInProgress = false
                        if (event.data != null && event.data.isNotEmpty()) {
                            Log.i("BleCoordinator", "Peer identity read from ${event.deviceAddress}: ${event.data.size} bytes")
                            diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_identity_read_ok", device = event.deviceAddress, bytes = event.data.size))

                            // Send raw proto bytes to Rust — Kotlin MUST NOT parse or split identity data.
                            // Rust decodes BleIdentityCharValue, dispatches events, and returns
                            // the write-back envelope for the peer's PAIRING characteristic.
                            try {
                                val resultBytes = com.dsm.wallet.bridge.Unified.processGattIdentityRead(
                                    event.deviceAddress, event.data
                                )

                                // Extract fields via JNI helpers — Kotlin has no proto codegen.
                                // Rust decodes the BleGattIdentityReadResult and returns individual fields.
                                val success = com.dsm.wallet.bridge.Unified.identityReadResultGetSuccess(resultBytes)

                                if (success) {
                                    Log.i("BleCoordinator", "processGattIdentityRead succeeded for ${event.deviceAddress}")

                                    val writeBackEnvelope = com.dsm.wallet.bridge.Unified.identityReadResultExtractWriteBack(resultBytes)
                                        .takeIf { it.isNotEmpty() }
                                    if (writeBackEnvelope != null) {
                                        val session = activeSessions[event.deviceAddress]
                                        if (session != null) {
                                            val writeOk = session.writePairingData(writeBackEnvelope)
                                            Log.i("BleCoordinator", "Identity write-back to ${event.deviceAddress}: success=$writeOk (${writeBackEnvelope.size}B)")
                                            if (!writeOk) {
                                                diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "coordinator_identity_writeback_failed")
                                                activeSessions.remove(event.deviceAddress)?.closeQuietly()
                                                sessionStates.remove(event.deviceAddress)
                                                pendingConnectionAddresses.remove(event.deviceAddress)
                                                com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed(event.deviceAddress, "identity_writeback_failed")
                                                resumePairingScan(event.deviceAddress, "identity_writeback_failed")
                                            }
                                        } else {
                                            Log.w("BleCoordinator", "Identity write-back: no active session for ${event.deviceAddress}")
                                            resumePairingScan(event.deviceAddress, "identity_writeback_no_session")
                                        }
                                    } else {
                                        Log.w("BleCoordinator", "Identity write-back: no envelope returned (local identity may not be set)")
                                    }
                                } else {
                                    Log.w("BleCoordinator", "processGattIdentityRead failed for ${event.deviceAddress}")
                                    diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "coordinator_identity_rust_decode_failed")
                                }
                            } catch (t: Throwable) {
                                Log.w("BleCoordinator", "processGattIdentityRead exception for ${event.deviceAddress}", t)
                                diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "coordinator_identity_exception")
                            }
                        } else {
                            diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "coordinator_identity_read")
                            Log.e("BleCoordinator", "Identity read failed for ${event.deviceAddress} — failing fast")
                            activeSessions.remove(event.deviceAddress)?.closeQuietly()
                            sessionStates.remove(event.deviceAddress)
                            pendingConnectionAddresses.remove(event.deviceAddress)
                            com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed(
                                event.deviceAddress,
                                "identity_read_failed"
                            )
                            resumePairingScan(event.deviceAddress, "identity_read_failed")
                        }
                    }
                    is BleSessionEvent.TransactionWriteCompleted -> {
                        val currentTx = state.currentTransaction
                        if (currentTx != null) {
                            if (event.success) {
                                val expectsProtocolAck =
                                    currentTx.payload.isNotEmpty() && com.dsm.wallet.bridge.Unified.requiresBleAck(currentTx.payload)
                                if (expectsProtocolAck) {
                                    diagnostics.recordEvent(
                                        BleDiagEvent(
                                            phase = "coordinator_tx_write_ok_waiting_response",
                                            device = event.deviceAddress
                                        )
                                    )
                                    // Keep currentTransaction set; completion occurs on ResponseReceived.
                                    return@send
                                }

                                outbox.markCompleted(currentTx.id)
                                diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_tx_completed", device = event.deviceAddress))
                            } else {
                                outbox.incrementAttempts(currentTx.id)
                                diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "coordinator_tx_write")
                            }
                            state.currentTransaction = null
                            // Process next transaction in outbox (serialized)
                            operationChannel.send { processNextOutboxItem(event.deviceAddress) }
                        }
                    }
                    is BleSessionEvent.ResponseReceived -> {
                        // All routing — chunk vs envelope dispatch, frame-type detection, and
                        // bilateral follow-up chunking — is performed by Rust via processIncomingBleData.
                        // Kotlin MUST NOT inspect data[0] or branch on protocol frame type codes.
                        try {
                            val responseProto = com.dsm.wallet.bridge.Unified.processIncomingBleData(event.deviceAddress, event.data)
                            val chunks = com.dsm.wallet.bridge.Unified.bleDataResponseExtractChunks(responseProto)
                            val flags = com.dsm.wallet.bridge.Unified.bleDataResponseGetFlags(responseProto)
                            val confirmCommitmentHash = com.dsm.wallet.bridge.Unified.bleDataResponseExtractConfirmCommitmentHash(responseProto)
                            val pairingComplete = (flags and 1) != 0
                            val useReliableWrite = (flags and 2) != 0
                            Log.d("BleCoordinator", "Response processed from ${event.deviceAddress}: chunks=${chunks.size}, flags=$flags")

                            // If Rust produced follow-up chunks, send them outside the actor
                            // to avoid self-deadlock (requestGattWriteChunks uses runBlocking).
                            if (chunks.isNotEmpty()) {
                                val addr = event.deviceAddress
                                bleScope.launch {
                                    val queued = com.dsm.wallet.bridge.Unified.dispatchRustBleFollowUp(addr, chunks, useReliableWrite)
                                    Log.i("BleCoordinator", "Queued follow-up to $addr: chunks=${chunks.size}, queued=$queued reliableWrite=$useReliableWrite")
                                    if (!queued) {
                                        diagnostics.recordError(
                                            BleErrorCategory.CHARACTERISTIC_WRITE_FAILED,
                                            "coordinator_followup_queue_failed"
                                        )
                                    }
                                    if (pairingComplete && queued) {
                                        try {
                                            if (confirmCommitmentHash.size == 32) {
                                                val ok = com.dsm.wallet.bridge.Unified.markBilateralConfirmDelivered(confirmCommitmentHash)
                                                Log.i("BleCoordinator", "markBilateralConfirmDelivered: ok=$ok after confirm to $addr")
                                            } else {
                                                Log.w("BleCoordinator", "Missing confirm commitment hash after confirm to $addr; refusing broad ConfirmPending sweep")
                                            }
                                        } catch (t: Throwable) {
                                            Log.w("BleCoordinator", "markBilateralConfirmDelivered failed for $addr: ${t.message}")
                                        }
                                    }
                                }
                            }

                            val currentTx = state.currentTransaction
                            if (currentTx != null) {
                                val expectsProtocolAck =
                                    currentTx.payload.isNotEmpty() && com.dsm.wallet.bridge.Unified.requiresBleAck(currentTx.payload)
                                if (expectsProtocolAck) {
                                    outbox.markCompleted(currentTx.id)
                                    state.currentTransaction = null
                                    diagnostics.recordEvent(
                                        BleDiagEvent(
                                            phase = "coordinator_tx_completed_on_response",
                                            device = event.deviceAddress
                                        )
                                    )
                                    operationChannel.send { processNextOutboxItem(event.deviceAddress) }
                                }
                            }
                        } catch (e: Exception) {
                            Log.e("BleCoordinator", "Failed to process response from ${event.deviceAddress}", e)
                            diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "coordinator_response_processing")
                        }
                    }
                    is BleSessionEvent.PairingAckReceived -> {
                        // Bilateral confirmation: the advertiser processed our identity.
                        // This can arrive via two paths (belt-and-suspenders):
                        //   1. PAIRING_ACK INDICATE (onCharacteristicChanged)
                        //   2. PAIRING characteristic read-back (onCharacteristicRead)
                        // Process only the first one; skip duplicates.
                        // Pairing ACK received — Rust handles idempotency internally.
                        state.pairingInProgress = true
                        Log.i("BleCoordinator", "PAIRING_ACK received from ${event.deviceAddress} (${event.data.size} bytes)")
                        try {
                            val response = com.dsm.wallet.bridge.Unified.processBleIdentityEnvelope(event.data, event.deviceAddress)
                            Log.i("BleCoordinator", "PAIRING_ACK processed through Rust for ${event.deviceAddress}: ${response.size} bytes")

                            // Phase 3 of atomic pairing: Rust returns a BlePairingConfirm
                            // envelope if the ACK was valid. Write it back to the advertiser’s
                            // PAIRING characteristic so the advertiser can persist its side.
                            if (response.isNotEmpty()) {
                                val session = activeSessions[event.deviceAddress]
                                if (session != null) {
                                    val writeOk = session.writePairingConfirm(response)
                                    Log.i("BleCoordinator", "PAIRING_CONFIRM write-back to ${event.deviceAddress}: success=$writeOk (${response.size}B)")
                                    if (!writeOk) {
                                        // Stash payload — will be retried the moment we
                                        // successfully reconnect and negotiate MTU again.
                                        pendingPairingConfirms[event.deviceAddress] = response
                                        diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "coordinator_pairing_confirm_writeback_failed")
                                        state.pairingInProgress = false
                                        activeSessions.remove(event.deviceAddress)?.closeQuietly()
                                        sessionStates.remove(event.deviceAddress)
                                        pendingConnectionAddresses.remove(event.deviceAddress)
                                        com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed(event.deviceAddress, "pairing_confirm_writeback_failed")
                                        resumePairingScan(event.deviceAddress, "pairing_confirm_writeback_failed")
                                    }
                                } else {
                                    Log.w("BleCoordinator", "PAIRING_CONFIRM: no active session for ${event.deviceAddress}")
                                    state.pairingInProgress = false
                                    resumePairingScan(event.deviceAddress, "pairing_confirm_no_session")
                                }
                            } else {
                                // Empty response — Rust had nothing to send (duplicate or error)
                                state.pairingInProgress = false
                            }
                        } catch (e: Exception) {
                            Log.e("BleCoordinator", "Failed to process PAIRING_ACK from ${event.deviceAddress}", e)
                            state.pairingInProgress = false
                        }
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_pairing_ack", device = event.deviceAddress))
                    }
                    is BleSessionEvent.PairingConfirmWritten -> {
                        // The BLE stack has delivered our BlePairingConfirm write to the advertiser.
                        // Pairing is complete — eviction guard can be lifted.
                        state.pairingInProgress = false
                        Log.i("BleCoordinator", "PAIRING_CONFIRM BLE-stack ACK for ${event.deviceAddress} — eviction guard lifted")
                        // Atomic pairing Phase 3b: finalize scanner session now that confirm
                        // was delivered. Persists ble_address to SQLite and marks Complete.
                        try {
                            val ok = com.dsm.wallet.bridge.Unified.finalizeScannerPairing(event.deviceAddress)
                            Log.i("BleCoordinator", "finalizeScannerPairing(${event.deviceAddress}): ok=$ok")
                        } catch (t: Throwable) {
                            Log.w("BleCoordinator", "finalizeScannerPairing(${event.deviceAddress}) threw: ${t.message}")
                        }
                        // Pairing complete on scanner side — stop scanning to prevent the
                        // rediscovery → reconnect → re-pair loop that causes "stuck scanning".
                        pairedBleAddresses.add(event.deviceAddress)
                        scanner.stopScanning()
                        // Clear session state after pairing so the bilateral send uses a fresh
                        // on-demand connection instead of the pairing session. The active session
                        // (activeSessions) is kept alive; connectToDevice() will clean it up if
                        // needed when the send is initiated.
                        sessionStates.remove(event.deviceAddress)
                        pendingConnectionAddresses.remove(event.deviceAddress)
                        Log.i("BleCoordinator", "Pairing complete for ${event.deviceAddress} (session kept active for bilateral transfers)")
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_pairing_confirm_sent", device = event.deviceAddress))
                    }
                    is BleSessionEvent.ErrorOccurred -> {
                        if (event.status == 133) {
                            Log.w("BleCoordinator", "GATT 133 observed. Scheduling delay recovery...")
                            kotlinx.coroutines.GlobalScope.launch {
                                kotlinx.coroutines.delay(1500)
                                getOrCreateSession(event.deviceAddress).connect()
                            }
                        }

                        if (event.status == 133) {
                            Log.w("BleCoordinator", "GATT 133 observed. Scheduling delay recovery...")
                            kotlinx.coroutines.GlobalScope.launch {
                                kotlinx.coroutines.delay(1500)
                                getOrCreateSession(event.deviceAddress).connect()
                            }
                        }

                        pendingConnectionAddresses.remove(event.deviceAddress)
                        state.lastError = event
                        // Clear current transaction on error and try to process next item
                        val currentTx = state.currentTransaction
                        if (currentTx != null) {
                            outbox.incrementAttempts(currentTx.id)
                            state.currentTransaction = null
                            // Try to process next item after error (serialized)
                            operationChannel.send { processNextOutboxItem(event.deviceAddress) }
                        }
                        diagnostics.recordError(event.category, event.details, event.deviceAddress, event.status)
                        
                        val alreadyPaired = try { com.dsm.wallet.bridge.Unified.isBleAddressPaired(event.deviceAddress) } catch (_: Throwable) { false }
                        if (!pairedBleAddresses.contains(event.deviceAddress) && !alreadyPaired) {
                            activeSessions.remove(event.deviceAddress)?.closeQuietly()
                            sessionStates.remove(event.deviceAddress)
                            resumePairingScan(event.deviceAddress, event.details)
                        } else {
                            Log.w("BleCoordinator", "ErrorOccurred for ${event.deviceAddress} (${event.category}), but device is already paired. Not closing session aggressively.")
                        }
                    }
                }
            }
        }
    }

    /**
     * Check if we have an active GATT client session to this device (we connected to them).
     * If true, we should use regular GATT writes to send data.
     */
    fun hasActiveClientSession(address: String): Boolean {
        val hasSession = activeSessions.containsKey(address)
        val isConn = sessionStates[address]?.isConnected == true
        if (!hasSession || !isConn) {
            Log.w("BleCoordinator", "hasActiveClientSession($address): hasSession=$hasSession, isConnected=$isConn, " +
                "activeSessions.keys=${activeSessions.keys}, sessionStates.keys=${sessionStates.keys.map { "$it=${sessionStates[it]?.isConnected}" }}")
        }
        return hasSession && isConn
    }

    private fun dropClientSession(address: String, reason: String) {
        val removed = activeSessions.remove(address)
        sessionStates.remove(address)
        pendingConnectionAddresses.remove(address)
        
        // If the peer is connected to our GATT server, do not forcefully close the client
        // session object right away, as it can cause Android to tear down the entire
        // underlying ACL link and break the server notifications.
        if (gattServer.isServerClient(address)) {
            Log.w(
                "BleCoordinator",
                "dropClientSession($address): reason=$reason removedSession=${removed != null} (avoiding closeQuietly because peer is GATT server client)"
            )
            // Just disconnect so we don't leak it indefinitely, but don't close until we know
            // the server notifications are done, or let system GC handle the stale Gatt.
            // Actually, even disconnect() might drop the link. Let's just do nothing to the 
            // physical Gatt layer since the server relies on the shared BLE radio link.
        } else {
            removed?.closeQuietly()
            Log.w(
                "BleCoordinator",
                "dropClientSession($address): reason=$reason removedSession=${removed != null}"
            )
        }
    }

    /**
     * Establish an on-demand GATT client connection to a device.
     * Used when bilateral send needs to subscribe to TX_RESPONSE on the
     * peer's server but no client session exists (torn down after pairing).
     */
    fun connectToDevice(address: String): kotlinx.coroutines.CompletableDeferred<Boolean> {
        val deferred = kotlinx.coroutines.CompletableDeferred<Boolean>()
        if (hasActiveClientSession(address)) {
            deferred.complete(true)
            return deferred
        }
        runOperation {
            if (hasActiveClientSession(address)) {
                deferred.complete(true)
                return@runOperation
            }
            // Clean up stale session
            if (activeSessions.containsKey(address)) {
                dropClientSession(address, "pre_connect_stale_session")
            }
            // Ensure GATT server is running
            if (!gattStartInFlight) {
                gattStartInFlight = true
                try { gattServer.ensureStarted() } finally { gattStartInFlight = false }
            }
            val session = getOrCreateSession(address)
            pendingConnectionAddresses.add(address)
            // Bilateral reconnect — identity read skip is determined by Rust pairing status
            val connected = session.connect()
            if (!connected) {
                dropClientSession(address, "connect_init_failed")
                deferred.complete(false)
                return@runOperation
            }
            // Poll for MTU negotiation completion (connection ready). The elapsed-time
            // window is transport readiness control only and does not affect protocol
            // semantics.
            bleScope.launch {
                val startTime = android.os.SystemClock.elapsedRealtime()
                while (android.os.SystemClock.elapsedRealtime() - startTime < 6000L) {
                    val state = sessionStates[address]
                    if (state != null && state.isConnected && state.negotiatedMtu > 23 && state.serviceDiscoveryCompleted) {
                        pendingConnectionAddresses.remove(address)
                        deferred.complete(true)
                        return@launch
                    }
                    if (state == null || (!state.isConnected && !activeSessions.containsKey(address))) {
                        runOperation {
                            dropClientSession(address, "connect_aborted_before_ready")
                        }
                        deferred.complete(false)
                        return@launch
                    }
                    kotlinx.coroutines.delay(100)
                }
                runOperation {
                    dropClientSession(address, "connect_ready_timeout")
                }
                deferred.complete(false)
            }
        }
        return deferred
    }

    /**
     * Ensure the GATT client session's TX_RESPONSE CCCD subscription is active.
     * Returns a deferred that resolves to true when subscribed, false on failure.
     * If there is no active client session, returns an immediately-completed false.
     */
    fun ensureClientTxResponseSubscribed(address: String): kotlinx.coroutines.CompletableDeferred<Boolean> {
        val session = activeSessions[address]
        if (session == null || sessionStates[address]?.isConnected != true) {
            return kotlinx.coroutines.CompletableDeferred(false)
        }
        return session.ensureTxResponseSubscribed()
    }

    /**
     * Deliver a deferred BlePairingAccept ACK from Rust's async retry task.
     * Called via JNI when the contact was not in SQLite at identity-write time
     * but was found by the background polling task.
     */
    fun deliverDeferredPairingAck(deviceAddress: String, ackBytes: ByteArray) {
        Log.i("BleCoordinator", "deliverDeferredPairingAck: ${ackBytes.size} bytes for $deviceAddress")
        runOperation {
            gattServer.deliverDeferredAck(deviceAddress, ackBytes)
        }
    }

    /**
     * Check if a device address belongs to a device connected to our GATT server.
     * These are devices that initiated a GATT client connection to us (we are their server).
     * Used to route outgoing data through server notifications instead of client writes.
     */
    fun isGattServerClient(address: String): Boolean = gattServer.isServerClient(address)

    /**
     * Check if a device address is subscribed to our TX_RESPONSE notifications.
     */
    fun isServerClientSubscribedToTxResponse(address: String): Boolean = 
        gattServer.isServerClientSubscribedToTxResponse(address)

    /**
     * Send data chunks via GATT server notifications to a connected server client.
     * Used when the receiver (GATT server) needs to send response data back to the
     * sender (GATT client) who is connected to our server.
     */
    suspend fun sendViaServerNotifications(address: String, chunks: Array<ByteArray>): Boolean {
        Log.i("BleCoordinator", "sendViaServerNotifications: routing ${chunks.size} chunks to $address via GATT server")
        return gattServer.sendChunkedNotifications(address, chunks)
    }

    private suspend fun processOutboxForDevice(deviceAddress: String) {
        val state = sessionStates[deviceAddress]

        // If already processing a transaction, wait for it to complete
        if (state?.currentTransaction != null) {
            return
        }

        // Only process outbox via GATT client path when we have an active client connection.
        // If not connected as a GATT client, we cannot send via this path.
        // (Server notification path is handled separately via sendViaServerNotifications)
        if (state?.isConnected != true) {
            return
        }

        processNextOutboxItem(deviceAddress)
    }

    private suspend fun processNextOutboxItem(deviceAddress: String) {
        val state = sessionStates[deviceAddress]
        if (state?.isConnected != true || state.currentTransaction != null) {
            return
        }

        val pendingItems = outbox.getPendingForDevice(deviceAddress)
        val nextItem = pendingItems.firstOrNull()
        if (nextItem == null) {
            return // No more items to process
        }

        if (nextItem.attempts >= 5) {
            outbox.removeItem(nextItem.id)
            // Try next item
            processNextOutboxItem(deviceAddress)
            return
        }

        val session = getOrCreateSession(deviceAddress)
        val started = session.sendTransaction(nextItem.payload)
        if (started) {
            state.currentTransaction = nextItem
        } else {
            // Failed to start transaction, increment attempts
            outbox.incrementAttempts(nextItem.id)
            // Try next item
            processNextOutboxItem(deviceAddress)
        }
    }

    private fun getOrCreateSession(deviceAddress: String): GattClientSession {
        return activeSessions.getOrPut(deviceAddress) {
            val newSession = GattClientSession(context, deviceAddress, diagnostics, permissionsGate)
            // Start collecting events from this session
            bleScope.launch {
                newSession.events.collect { event ->
                    handleSessionEvent(event)
                }
            }
            // Initialize session state
            sessionStates.getOrPut(deviceAddress) { BleSessionState(deviceAddress) }
            newSession
        }
    }

}
