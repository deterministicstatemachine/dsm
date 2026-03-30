package com.dsm.wallet.bridge.ble

import android.bluetooth.BluetoothDevice
import android.content.Context
import android.util.Log
import com.dsm.wallet.bridge.BleOutboxRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Public BLE Coordinator facade.
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
    private val operationDispatcher = BleOperationDispatcher(bleScope)

    // Rate limit protection: Android allows max 5 scan start/stop within 30s window.
    // This is transport-runtime pacing only, not protocol state.
    private val scanStartTimestamps = mutableListOf<Long>()
    private val SCAN_RATE_LIMIT_WINDOW_MS = 30_000L  // 30 seconds
    private val MAX_SCANS_PER_WINDOW = 5
    private var lastScanStopTimestamp = 0L
    private val MIN_SCAN_GAP_MS = 6_000L  // 6 seconds between scan operations

    // Unified per-peer state. Replaces sessionStates, activeSessions,
    // pendingConnectionAddresses, and pendingPairingConfirms.
    internal val peers = java.util.concurrent.ConcurrentHashMap<String, PeerSession>()

    // Reverse index: BLE MAC address → PeerIdentity. Updated on every
    // identity observation (pairing + reconnect). Enables O(1) resolution
    // of stale addresses to the peer's current address.
    internal val addressIndex = java.util.concurrent.ConcurrentHashMap<String, PeerIdentity>()

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

    init {
        // Wire scanner callback so discovered devices trigger GATT connections
        scanner.setCallback(this)

        // Wire GATT server callback so advertiser-side pairing completion stops advertising
        gattServer.pairingCompleteCallback = object : GattServerHost.PairingCompleteCallback {
            override fun onAdvertiserPairingComplete(deviceAddress: String) {
                notifyAdvertiserPairingComplete(deviceAddress)
            }
        }

        // Wire peer lookup so GattServerHost delegates per-device state to PeerSession
        gattServer.peerLookup = { address -> peers.getOrPut(address) { PeerSession(address) } }
        gattServer.peerEntries = { peers.values }

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
        // Re-wire peer lookup after replacing the gattServer instance
        this.gattServer.peerLookup = { address -> peers.getOrPut(address) { PeerSession(address) } }
        this.gattServer.peerEntries = { peers.values }
    }

    companion object {
        /** Max time to wait for GATT connection readiness (connect + discover + MTU). */
        private const val CONNECT_READY_TIMEOUT_MS = 12_000L
        private const val MAX_PENDING_PAIRING_CONFIRMS = 8

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
        return runOperationBool(BleOpLane.TRANSFER) {
            outbox.enqueueTransaction(deviceAddress, transactionData)
            processOutboxForDevice(deviceAddress)
            true // Successfully enqueued and processed
        }
    }

    /**
     * Start advertising this device for pairing/discovery.
     */
    fun startAdvertising(): Boolean {
        return runOperationBool(BleOpLane.LIFECYCLE) {
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
        return runOperationBool(BleOpLane.LIFECYCLE) {
            advertiser.stopAdvertising()
            com.dsm.wallet.bridge.Unified.onAdvertisingStopped()
            true // Always succeeds
        }
    }

    /**
     * Start scanning for peer devices.
     */
    fun startScanning(): Boolean {
        return runOperationBool(BleOpLane.LIFECYCLE) {
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
            if (peers.values.any { it.gattClientSession != null }) {
                val staleAddresses = mutableListOf<String>()
                for ((addr, peer) in peers) {
                    if (peer.gattClientSession == null) continue
                    val isActive = (
                        peer.connectionPending ||
                        peer.identityExchangeInProgress ||
                        peer.pairingInProgress ||
                        peer.currentTransaction != null ||
                        (peer.isConnected && !peer.serviceDiscoveryCompleted) ||
                        (peer.isConnected && peer.negotiatedMtu == 23)
                    )
                    if (!isActive) {
                        staleAddresses.add(addr)
                    }
                }
                if (staleAddresses.isNotEmpty()) {
                    val activeCount = peers.values.count { it.gattClientSession != null } - staleAddresses.size
                    Log.i("BleCoordinator", "Evicting ${staleAddresses.size} stale session(s), keeping $activeCount active")
                    for (addr in staleAddresses) {
                        val peer = peers[addr] ?: continue
                        if (!gattServer.isServerClient(addr)) {
                            peer.gattClientSession?.disconnect()
                        }
                        peer.clearClientState()
                        if (peer.isEmpty) peers.remove(addr)
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
        return runOperationBool(BleOpLane.LIFECYCLE) {
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
        runOperation(BleOpLane.LIFECYCLE) {
            scanner.setSessionMode(mode)
            // Update session mode logic here if needed for other components
        }
    }

    /**
     * Read peer identity information.
     */
    fun readPeerIdentity(deviceAddress: String): Boolean {
        return runOperationBool(BleOpLane.PAIRING) {
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
        runOperation(BleOpLane.LIFECYCLE) {
            gattServer.setIdentityValue(genesisHash, deviceId)
        }
    }

    /**
     * Ensure BLE is ready to receive bilateral transfers: GATT server running
     * and advertising active. Called by the frontend wallet screen lifecycle
     * via the protobuf bridge (device.ble.advertise.start). Also called
     * internally by connectToDevice as a safety net.
     */
    fun ensureBleReady(): Boolean {
        return runOperationBool(BleOpLane.LIFECYCLE) {
            if (!gattServer.isReady()) {
                if (!gattStartInFlight) {
                    gattStartInFlight = true
                    try { gattServer.ensureStarted() } finally { gattStartInFlight = false }
                }
            }
            if (!advertiser.isAdvertising()) {
                try { advertiser.startAdvertising() } catch (_: Throwable) { /* best-effort */ }
            }
            gattServer.isReady()
        }
    }

    /**
     * Ensure GATT server is started.
     */
    fun ensureGattServerStarted(): Boolean {
        return runOperationBool(BleOpLane.LIFECYCLE) {
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
        val peer = peers[deviceAddress]
        return if (peer != null) {
            "Session[$deviceAddress]: connected=${peer.isConnected}, mtu=${peer.negotiatedMtu}, services=${peer.serviceDiscoveryCompleted}"
        } else {
            "No active session state for $deviceAddress"
        }
    }

    /**
     * Retry the last transaction for a device.
     */
    fun retryLastTransaction(deviceAddress: String): Boolean {
        return runOperationBool(BleOpLane.TRANSFER) {
            outbox.retryLastTransaction(deviceAddress)
            processOutboxForDevice(deviceAddress)
            true // Successfully retried and processed
        }
    }

    /**
     * Get list of connected device addresses.
     */
    fun getConnectedDeviceAddresses(): List<String> {
        return peers.filter { it.value.isConnected }.keys.toList()
    }

    /**
     * Check if a specific device is connected.
     */
    fun isDeviceConnected(deviceAddress: String): Boolean {
        return peers[deviceAddress]?.isConnected == true
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
     * Called by GattServerHost when the advertiser side processes a PairingConfirm.
     * Keep advertising active so already-paired peers can reconnect later for
     * offline bilateral transfers.
     */
    fun notifyAdvertiserPairingComplete(bleAddress: String) {
        runOperation(BleOpLane.PAIRING) {
            // Mark the session as disconnected but keep the entry so on-demand
            // reconnect does not lose track of the device entirely. connectToDevice()
            // will clean up and re-establish the GATT connection as needed.
            peers[bleAddress]?.let { peer ->
                peer.isConnected = false
                peer.serviceDiscoveryCompleted = false
            }
            peers[bleAddress]?.let { p -> p.connectResult?.complete(false); p.connectResult = null }
            Log.i("BleCoordinator", "Advertiser pairing complete for $bleAddress — marked disconnected, keeping advertising active for reconnects")
        }
    }

    /**
     * Clean up resources.
     */
    fun cleanup() {
        runOperation(BleOpLane.LIFECYCLE) {
            scanner.stopScanning()
            advertiser.stopAdvertising()
            gattServer.stop()
            peers.values.forEach { it.gattClientSession?.disconnect() }
            peers.clear()
            permissionsGate.cleanup()
        }
    }

    // ===== BleScanner.Callback =====

    override fun onDeviceDiscovered(device: BluetoothDevice, rssi: Int) {
        val address = device.address
        if (peers[address]?.connectionPending == true) {
            Log.d("BleCoordinator", "Skipping $address — GATT connection already in flight")
            return
        }
        if (peers[address]?.gattClientSession != null) {
            return
        }
        Log.i("BleCoordinator", "Discovered DSM peer: $address (rssi=$rssi) — initiating GATT connection")
        com.dsm.wallet.bridge.Unified.onDeviceFound(address, device.name ?: "", rssi)
        runOperation(BleOpLane.LIFECYCLE) {
            if (peers[address]?.connectionPending == true || peers[address]?.gattClientSession != null) {
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
            // Mark connection in-flight via a sentinel deferred so connectionPending returns true.
            // This prevents double-connectGatt from scan overlap. The deferred is completed
            // by handleSessionEvent (MtuNegotiated/Disconnected/Error).
            peers[address]!!.connectResult = peers[address]!!.connectResult ?: kotlinx.coroutines.CompletableDeferred()
            val connected = session.connect()
            if (connected) {
                Log.i("BleCoordinator", "GATT connection initiated to $address")
            } else {
                Log.w("BleCoordinator", "Failed to initiate GATT connection to $address")
                peers[address]?.clearClientState()
                if (peers[address]?.isEmpty == true) peers.remove(address)
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

    private fun runOperation(
        lane: BleOpLane = BleOpLane.LIFECYCLE,
        block: suspend () -> Unit,
    ) {
        operationDispatcher.dispatch(lane, block)
    }

    @androidx.annotation.WorkerThread
    private fun runOperationBool(
        lane: BleOpLane = BleOpLane.LIFECYCLE,
        block: suspend () -> Boolean,
    ): Boolean {
        return operationDispatcher.dispatchBlocking(lane, block)
    }

    private fun storePendingPairingConfirm(deviceAddress: String, payload: ByteArray) {
        if (peers[deviceAddress]?.pendingPairingConfirm == null &&
            peers.values.count { it.pendingPairingConfirm != null } >= MAX_PENDING_PAIRING_CONFIRMS
        ) {
            val evicted = peers.entries.firstOrNull { it.value.pendingPairingConfirm != null }?.key
            if (evicted != null) {
                peers[evicted]?.pendingPairingConfirm = null
                Log.w("BleCoordinator", "Evicted oldest pending PAIRING_CONFIRM for $evicted to keep BLE retry state bounded")
            }
        }
        peers.getOrPut(deviceAddress) { PeerSession(deviceAddress) }.pendingPairingConfirm = payload.copyOf()
    }

    private fun resumePairingScan(deviceAddress: String, reason: String) {
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
        val lane = when (event) {
            is BleSessionEvent.TransactionWriteCompleted,
            is BleSessionEvent.ResponseReceived -> BleOpLane.TRANSFER
            is BleSessionEvent.IdentityReadCompleted,
            is BleSessionEvent.MtuNegotiated,
            is BleSessionEvent.PairingAckReceived,
            is BleSessionEvent.PairingConfirmWritten -> BleOpLane.PAIRING
            else -> BleOpLane.LIFECYCLE
        }

        // Serialize all state mutations and follow-up actions through the bounded
        // dispatcher so transport stays on one scheduling path.
        runOperation(lane) {
                val peer = peers.getOrPut(event.deviceAddress) { PeerSession(event.deviceAddress) }

                when (event) {
                    is BleSessionEvent.Connected -> {
                        // Don't complete connectResult yet — wait for MtuNegotiated.
                        peer.isConnected = true
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
                        // connectResult deferred is completed by clearClientState() below.
                        peer.isConnected = false
                        peer.serviceDiscoveryCompleted = false
                        peer.currentTransaction = null // Clear any pending transaction
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_disconnected", device = event.deviceAddress, status = event.status))
                        // Remove stale session so future scans can reconnect to this peer
                        peer.clearClientState()
                        if (peer.isEmpty) peers.remove(event.deviceAddress)
                        com.dsm.wallet.bridge.Unified.onDeviceDisconnected(event.deviceAddress)
                        resumePairingScan(event.deviceAddress, "disconnected")
                    }
                    is BleSessionEvent.MtuNegotiated -> {
                        peer.negotiatedMtu = event.mtu
                        // Complete the on-demand connect deferred if one is pending.
                        // This replaces the 100ms polling loop that used to check
                        // sessionStates from outside the dispatcher.
                        peer.connectResult?.let { result ->
                            peer.connectResult = null
                            result.complete(true)
                        }
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_mtu_negotiated", device = event.deviceAddress, bytes = event.mtu))
                        // Query Rust for pairing status — skip identity read if already paired (bilateral reconnect)
                        val alreadyPaired = try { com.dsm.wallet.bridge.Unified.isBleAddressPaired(event.deviceAddress) } catch (_: Throwable) { false }
                        if (alreadyPaired) {
                            // Check if we have a PAIRING_CONFIRM that failed to deliver last
                            // time (connection dropped between PAIRING_ACK and confirm write).
                            // If so, retry the write before doing anything else.
                            val pendingConfirm = peer.pendingPairingConfirm
                            peer.pendingPairingConfirm = null
                            if (pendingConfirm != null) {
                                val session = peer.gattClientSession
                                if (session != null) {
                                    Log.i("BleCoordinator", "MTU negotiated (${event.mtu}) for ${event.deviceAddress} — retrying pending PAIRING_CONFIRM (${pendingConfirm.size}B)")
                                    peer.pairingInProgress = true
                                    val writeOk = session.writePairingConfirm(pendingConfirm)
                                    Log.i("BleCoordinator", "PAIRING_CONFIRM retry for ${event.deviceAddress}: success=$writeOk")
                                    if (!writeOk) {
                                        // Still failing — put it back and scan again
                                        storePendingPairingConfirm(event.deviceAddress, pendingConfirm)
                                        peer.pairingInProgress = false
                                        diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "coordinator_pairing_confirm_retry_failed")
                                        peer.clearClientState()
                                        if (peer.isEmpty) peers.remove(event.deviceAddress)
                                        resumePairingScan(event.deviceAddress, "pairing_confirm_retry_failed")
                                    }
                                } else {
                                    // No session yet — put back so the next MTU cycle retries
                                    storePendingPairingConfirm(event.deviceAddress, pendingConfirm)
                                    Log.w("BleCoordinator", "PAIRING_CONFIRM retry: no session for ${event.deviceAddress}; will retry on next connect")
                                }
                            } else {
                                // Normal bilateral reconnect — nothing pending.
                                Log.i("BleCoordinator", "MTU negotiated (${event.mtu}) for ${event.deviceAddress} — skipping identity read (already paired per Rust)")
                            }
                        } else {
                            // Set identity exchange guard BEFORE reading — prevents
                            // startScanning() eviction during the identity read/write phase.
                            peer.identityExchangeInProgress = true
                            val session = peer.gattClientSession
                            if (session != null) {
                                Log.i("BleCoordinator", "MTU negotiated (${event.mtu}) for ${event.deviceAddress} — reading peer identity")
                                session.readIdentity()
                            } else {
                                peer.identityExchangeInProgress = false
                            }
                        }
                        // Drain any pending outbox items now that the connection is ready
                        runOperation(BleOpLane.TRANSFER) { processNextOutboxItem(event.deviceAddress) }
                    }
                    is BleSessionEvent.ServiceDiscoveryCompleted -> {
                        peer.serviceDiscoveryCompleted = event.success
                        if (!event.success) {
                            diagnostics.recordError(BleErrorCategory.SERVICE_DISCOVERY_FAILED, "coordinator_service_discovery")
                        } else {
                            // Drain any pending outbox items now that services are discovered
                            runOperation(BleOpLane.TRANSFER) { processNextOutboxItem(event.deviceAddress) }
                        }
                    }
                    is BleSessionEvent.IdentityReadCompleted -> {
                        // Identity exchange phase complete (read result received).
                        // Clear the guard — PairingAckReceived will set pairingInProgress.
                        peer.identityExchangeInProgress = false
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

                                    // Anchor the peer's identity for RPA-proof addressing.
                                    // Extract deviceId + genesisHash from the Rust-decoded result
                                    // proto. Kotlin does not parse protobuf — all decoding is Rust-side.
                                    val peerDeviceId = com.dsm.wallet.bridge.Unified.identityReadResultExtractPeerDeviceId(resultBytes)
                                    val peerGenesisHash = com.dsm.wallet.bridge.Unified.identityReadResultExtractPeerGenesisHash(resultBytes)
                                    if (peerDeviceId.size == 32 && peerGenesisHash.size == 32) {
                                        anchorIdentity(event.deviceAddress, PeerIdentity(peerDeviceId, peerGenesisHash))
                                    }

                                    val writeBackEnvelope = com.dsm.wallet.bridge.Unified.identityReadResultExtractWriteBack(resultBytes)
                                        .takeIf { it.isNotEmpty() }
                                    if (writeBackEnvelope != null) {
                                        val session = peer.gattClientSession
                                        if (session != null) {
                                            val writeOk = session.writePairingData(writeBackEnvelope)
                                            Log.i("BleCoordinator", "Identity write-back to ${event.deviceAddress}: success=$writeOk (${writeBackEnvelope.size}B)")
                                            if (!writeOk) {
                                                diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "coordinator_identity_writeback_failed")
                                                peer.clearClientState()
                                                if (peer.isEmpty) peers.remove(event.deviceAddress)
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
                            peer.clearClientState()
                            if (peer.isEmpty) peers.remove(event.deviceAddress)
                            com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed(
                                event.deviceAddress,
                                "identity_read_failed"
                            )
                            resumePairingScan(event.deviceAddress, "identity_read_failed")
                        }
                    }
                    is BleSessionEvent.TransactionWriteCompleted -> {
                        val currentTx = peer.currentTransaction
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
                                } else {
                                    outbox.markCompleted(currentTx.id)
                                    diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_tx_completed", device = event.deviceAddress))
                                }
                            } else {
                                outbox.incrementAttempts(currentTx.id)
                                diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "coordinator_tx_write")
                            }
                            val expectsProtocolAck =
                                event.success && currentTx.payload.isNotEmpty() &&
                                    com.dsm.wallet.bridge.Unified.requiresBleAck(currentTx.payload)
                            if (!expectsProtocolAck) {
                                peer.currentTransaction = null
                                // Process next transaction in outbox (serialized)
                                runOperation(BleOpLane.TRANSFER) { processNextOutboxItem(event.deviceAddress) }
                            }
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

                            val currentTx = peer.currentTransaction
                            if (currentTx != null) {
                                val expectsProtocolAck =
                                    currentTx.payload.isNotEmpty() && com.dsm.wallet.bridge.Unified.requiresBleAck(currentTx.payload)
                                if (expectsProtocolAck) {
                                    outbox.markCompleted(currentTx.id)
                                    peer.currentTransaction = null
                                    diagnostics.recordEvent(
                                        BleDiagEvent(
                                            phase = "coordinator_tx_completed_on_response",
                                            device = event.deviceAddress
                                        )
                                    )
                                    runOperation(BleOpLane.TRANSFER) { processNextOutboxItem(event.deviceAddress) }
                                }
                            }
                        } catch (e: Exception) {
                            Log.e("BleCoordinator", "Failed to process response from ${event.deviceAddress}", e)
                            diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "coordinator_response_processing")
                        }
                    }
                    is BleSessionEvent.PairingAckReceived -> {
                        // Bilateral confirmation: the advertiser processed our identity
                        // and sent the PAIRING_ACK indication.
                        peer.pairingInProgress = true
                        Log.i("BleCoordinator", "PAIRING_ACK received from ${event.deviceAddress} (${event.data.size} bytes)")
                        try {
                            val response = com.dsm.wallet.bridge.Unified.processBleIdentityEnvelope(event.data, event.deviceAddress)
                            Log.i("BleCoordinator", "PAIRING_ACK processed through Rust for ${event.deviceAddress}: ${response.size} bytes")

                            // Phase 3 of atomic pairing: Rust returns a BlePairingConfirm
                            // envelope if the ACK was valid. Write it back to the advertiser's
                            // PAIRING characteristic so the advertiser can persist its side.
                            if (response.isNotEmpty()) {
                                val session = peer.gattClientSession
                                if (session != null) {
                                    val writeOk = session.writePairingConfirm(response)
                                    Log.i("BleCoordinator", "PAIRING_CONFIRM write-back to ${event.deviceAddress}: success=$writeOk (${response.size}B)")
                                    if (!writeOk) {
                                        // Stash payload — will be retried the moment we
                                        // successfully reconnect and negotiate MTU again.
                                        storePendingPairingConfirm(event.deviceAddress, response)
                                        diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_WRITE_FAILED, "coordinator_pairing_confirm_writeback_failed")
                                        peer.pairingInProgress = false
                                        peer.clearClientState()
                                        if (peer.isEmpty) peers.remove(event.deviceAddress)
                                        com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed(event.deviceAddress, "pairing_confirm_writeback_failed")
                                        resumePairingScan(event.deviceAddress, "pairing_confirm_writeback_failed")
                                    }
                                } else {
                                    Log.w("BleCoordinator", "PAIRING_CONFIRM: no active session for ${event.deviceAddress}")
                                    peer.pairingInProgress = false
                                    resumePairingScan(event.deviceAddress, "pairing_confirm_no_session")
                                }
                            } else {
                                // Empty response — Rust had nothing to send (duplicate or error)
                                peer.pairingInProgress = false
                            }
                        } catch (e: Exception) {
                            Log.e("BleCoordinator", "Failed to process PAIRING_ACK from ${event.deviceAddress}", e)
                            peer.pairingInProgress = false
                        }
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_pairing_ack", device = event.deviceAddress))
                    }
                    is BleSessionEvent.PairingConfirmWritten -> {
                        // The BLE stack has delivered our BlePairingConfirm write to the advertiser.
                        // Pairing is complete — eviction guard can be lifted.
                        peer.pairingInProgress = false
                        Log.i("BleCoordinator", "PAIRING_CONFIRM BLE-stack ACK for ${event.deviceAddress} — eviction guard lifted")
                        // Atomic pairing Phase 3b: finalize scanner session now that confirm
                        // was delivered. Persists ble_address to SQLite and marks Complete.
                        try {
                            val ok = com.dsm.wallet.bridge.Unified.finalizeScannerPairing(event.deviceAddress)
                            Log.i("BleCoordinator", "finalizeScannerPairing(${event.deviceAddress}): ok=$ok")
                        } catch (t: Throwable) {
                            Log.w("BleCoordinator", "finalizeScannerPairing(${event.deviceAddress}) threw: ${t.message}")
                        }
                        // Pairing complete on scanner side — stop scanning so the next
                        // transport action starts from a clean reconnect path.
                        scanner.stopScanning()
                        // Keep peer consistent so hasActiveClientSession() returns true
                        // while the GATT link is still live.
                        peer.connectResult?.let { r -> peer.connectResult = null; r.complete(true) }
                        Log.i("BleCoordinator", "Pairing complete for ${event.deviceAddress} (session + state kept for bilateral transfers)")
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_pairing_confirm_sent", device = event.deviceAddress))
                    }
                    is BleSessionEvent.ErrorOccurred -> {
                        if (event.status == 133) {
                            Log.w("BleCoordinator", "GATT 133 observed. Scheduling delay recovery...")
                            bleScope.launch {
                                kotlinx.coroutines.delay(1500)
                                getOrCreateSession(event.deviceAddress).connect()
                            }
                        }

                        // connectResult deferred is completed by clearClientState() below.
                        peer.lastError = event
                        // Clear current transaction on error and try to process next item
                        val currentTx = peer.currentTransaction
                        if (currentTx != null) {
                            outbox.incrementAttempts(currentTx.id)
                            peer.currentTransaction = null
                            // Try to process next item after error (serialized)
                            runOperation(BleOpLane.TRANSFER) { processNextOutboxItem(event.deviceAddress) }
                        }
                        diagnostics.recordError(event.category, event.details, event.deviceAddress, event.status)

                        val alreadyPaired = try { com.dsm.wallet.bridge.Unified.isBleAddressPaired(event.deviceAddress) } catch (_: Throwable) { false }
                        if (!alreadyPaired) {
                            peer.clearClientState()
                            if (peer.isEmpty) peers.remove(event.deviceAddress)
                            resumePairingScan(event.deviceAddress, event.details)
                        } else {
                            // Already-paired device hit a write failure — the GATT session
                            // is stale (likely BLE MAC rotated since last transfer).  Close
                            // the dead session so the next bilateral transfer gets a fresh
                            // GATT connection to whatever address the peer is now advertising.
                            Log.w("BleCoordinator", "ErrorOccurred for ${event.deviceAddress} (${event.category}), paired device — closing stale session for fresh reconnect")
                            peer.clearClientState()
                            if (peer.isEmpty) peers.remove(event.deviceAddress)
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
        val result = peers[address]?.hasActiveClientSession ?: false
        if (!result) {
            Log.w("BleCoordinator", "hasActiveClientSession($address): false, " +
                "peers.keys=${peers.keys.map { "$it: client=${peers[it]?.gattClientSession != null}, connected=${peers[it]?.isConnected}" }}")
        }
        return result
    }

    private fun dropClientSession(address: String, reason: String) {
        val peer = peers[address]
        val removed = peer?.gattClientSession

        // If the peer is connected to our GATT server, do not forcefully close the client
        // session object right away, as it can cause Android to tear down the entire
        // underlying ACL link and break the server notifications.
        if (gattServer.isServerClient(address)) {
            Log.w(
                "BleCoordinator",
                "dropClientSession($address): reason=$reason removedSession=${removed != null} (avoiding closeQuietly because peer is GATT server client)"
            )
            // Just clear the client fields without closing the underlying GATT —
            // the server relies on the shared BLE radio link.
            peer?.let {
                it.gattClientSession = null
                it.isConnected = false
                it.negotiatedMtu = 23
                it.serviceDiscoveryCompleted = false
                it.lastError = null
                it.currentTransaction = null
                it.identityExchangeInProgress = false
                it.pairingInProgress = false
                it.connectResult?.complete(false)
                it.connectResult = null
                it.pendingPairingConfirm = null
            }
        } else {
            peer?.clearClientState()
            Log.w(
                "BleCoordinator",
                "dropClientSession($address): reason=$reason removedSession=${removed != null}"
            )
        }
        if (peers[address]?.isEmpty == true) peers.remove(address)
    }

    /**
     * Find any active client session or subscribed server-client address.
     * Used by UnifiedBleBridge when the original BLE address has rotated —
     * a scan may have discovered the same DSM peer under a new address.
     */
    private fun findAnyReadySessionAddress(): String? {
        // Prefer an active GATT client session (we can write to them)
        for ((addr, peer) in peers) {
            if (peer.isConnected && peer.negotiatedMtu > 23) {
                return addr
            }
        }
        // Fall back to a GATT server client that's subscribed to TX_RESPONSE
        return peers.entries.firstOrNull {
            it.value.isServerClient && it.value.isSubscribedTo(BleConstants.TX_RESPONSE_UUID)
        }?.key
    }

    /**
     * Resolve a BLE address (potentially stale) to the current PeerSession.
     *
     * Resolution order:
     * 1. Direct peers[address] lookup (address is current)
     * 2. addressIndex[address] → PeerIdentity → find peer with matching identity
     * 3. findAnyReadySessionAddress() fallback (single-peer scenario)
     *
     * Returns the PeerSession and its current address, or null if unknown.
     */
    fun resolveSession(address: String): Pair<PeerSession, String>? {
        // 1. Direct hit — but only if the peer is actually reachable
        peers[address]?.let { peer ->
            if (peer.hasActiveClientSession || peer.isServerClient) {
                return peer to address
            }
            // Entry exists but is a dead shell — fall through to identity lookup
        }

        // 2. Identity-indexed lookup — address is stale but identity is known
        addressIndex[address]?.let { identity ->
            for ((addr, peer) in peers) {
                if (peer.identity == identity && (peer.hasActiveClientSession || peer.isServerClient)) {
                    Log.i("BleCoordinator", "resolveSession: stale $address → identity → current $addr")
                    return peer to addr
                }
            }
        }

        // 3. Fallback — any ready session (single-peer scenario)
        findAnyReadySessionAddress()?.let { freshAddr ->
            if (freshAddr != address) {
                Log.i("BleCoordinator", "resolveSession: fallback $address → $freshAddr")
            }
            peers[freshAddr]?.let { return it to freshAddr }
        }

        return null
    }

    /**
     * Anchor a peer's identity after successful GATT identity read.
     * Updates the addressIndex so future RPA rotations can be resolved.
     */
    fun anchorIdentity(address: String, identity: PeerIdentity) {
        val peer = peers[address] ?: return
        peer.identity = identity
        addressIndex[address] = identity
        Log.i("BleCoordinator", "anchorIdentity: $address → ${identity.key.take(16)}...")
    }

    /**
     * Update a peer's BLE address after RPA rotation detected during scan.
     * Migrates the PeerSession from the old address key to the new one.
     */
    fun updatePeerAddress(identity: PeerIdentity, newAddress: String) {
        // Find the old entry
        val oldEntry = peers.entries.firstOrNull { it.value.identity == identity }
        if (oldEntry == null || oldEntry.key == newAddress) return

        val oldAddr = oldEntry.key
        val session = oldEntry.value

        // Migrate: remove old key, insert under new key
        peers.remove(oldAddr)
        peers[newAddress] = session
        addressIndex.remove(oldAddr)
        addressIndex[newAddress] = identity
        Log.i("BleCoordinator", "updatePeerAddress: ${identity.key.take(16)}... migrated $oldAddr → $newAddress")
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
        // If a connect is already in flight for this peer, piggy-back on it.
        peers[address]?.connectResult?.let { existing ->
            bleScope.launch { deferred.complete(existing.await()) }
            return deferred
        }
        runOperation(BleOpLane.LIFECYCLE) {
            if (hasActiveClientSession(address)) {
                deferred.complete(true)
                return@runOperation
            }
            // Clean up stale client session if one exists under this address
            if (peers[address]?.gattClientSession != null) {
                dropClientSession(address, "pre_connect_stale_session")
            }

            // ── Step 1: Start advertising so the receiver can find US ──
            // The reverse path (receiver connects to our GATT server) is the
            // most reliable route. Prime it before scanning.
            if (!gattStartInFlight) {
                gattStartInFlight = true
                try { gattServer.ensureStarted() } finally { gattStartInFlight = false }
            }
            if (!advertiser.isAdvertising()) {
                try {
                    advertiser.startAdvertising()
                    Log.i("BleCoordinator", "connectToDevice($address): started advertising for reverse path")
                } catch (_: Throwable) { /* best-effort */ }
            }

            // ── Step 2: Scan the full budget, checking for reverse connection ──
            // Scan up to 10s. Every second, check if:
            //   a) We discovered the peer under a fresh address → connect to it
            //   b) The peer connected to our GATT server → use server notifications
            Log.i("BleCoordinator", "connectToDevice($address): scanning up to ${CONNECT_READY_TIMEOUT_MS}ms for peer discovery or reverse connection")
            scanner.startScanning()
            val scanStartTime = android.os.SystemClock.elapsedRealtime()
            var resolvedAddress: String? = null

            while (android.os.SystemClock.elapsedRealtime() - scanStartTime < CONNECT_READY_TIMEOUT_MS) {
                kotlinx.coroutines.delay(1000)

                // Check identity-based resolution first
                val resolved = resolveSession(address)
                if (resolved != null) {
                    val (peer, addr) = resolved
                    if (peer.hasActiveClientSession) {
                        Log.i("BleCoordinator", "connectToDevice: peer found with active client session at $addr")
                        resolvedAddress = addr
                        break
                    }
                    if (peer.isServerClient && peer.isSubscribedTo(BleConstants.TX_RESPONSE_UUID)) {
                        Log.i("BleCoordinator", "connectToDevice: peer connected to our GATT server at $addr — using server path")
                        resolvedAddress = addr
                        break
                    }
                }

                // Check for any server client that appeared during scan
                for ((addr, peer) in peers) {
                    if (peer.isServerClient && peer.isSubscribedTo(BleConstants.TX_RESPONSE_UUID)) {
                        Log.i("BleCoordinator", "connectToDevice: reverse connection detected from $addr during scan")
                        resolvedAddress = addr
                        break
                    }
                }
                if (resolvedAddress != null) break

                // Check if scan discovered any new DSM peer (onDeviceDiscovered may
                // have created a session and initiated connectGatt already)
                for ((addr, peer) in peers) {
                    if (addr != address && peer.gattClientSession != null && peer.isConnected) {
                        Log.i("BleCoordinator", "connectToDevice: scan discovered connected peer at $addr")
                        resolvedAddress = addr
                        break
                    }
                }
                if (resolvedAddress != null) break
            }

            scanner.stopScanning()

            if (resolvedAddress != null) {
                deferred.complete(true)
                return@runOperation
            }

            // ── Step 3: No peer found during full scan window ──
            // Do NOT try connectGatt to the stale address — it's a guaranteed
            // 10-second timeout to a dead address. Fail fast.
            Log.w("BleCoordinator", "connectToDevice($address): no peer discovered after ${CONNECT_READY_TIMEOUT_MS}ms scan — failing (stale address, not attempting dead connectGatt)")
            deferred.complete(false)
        }
        return deferred
    }

    /**
     * Ensure the GATT client session's TX_RESPONSE CCCD subscription is active.
     * Returns a deferred that resolves to true when subscribed, false on failure.
     * If there is no active client session, returns an immediately-completed false.
     */
    fun ensureClientTxResponseSubscribed(address: String): kotlinx.coroutines.CompletableDeferred<Boolean> {
        val session = peers[address]?.gattClientSession
        if (session == null || peers[address]?.isConnected != true) {
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
        runOperation(BleOpLane.PAIRING) {
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
        val peer = peers[deviceAddress]

        // If already processing a transaction, wait for it to complete
        if (peer?.currentTransaction != null) {
            return
        }

        // Only process outbox via GATT client path when we have an active client connection.
        // If not connected as a GATT client, we cannot send via this path.
        // (Server notification path is handled separately via sendViaServerNotifications)
        if (peer?.isConnected != true) {
            return
        }

        processNextOutboxItem(deviceAddress)
    }

    private suspend fun processNextOutboxItem(deviceAddress: String) {
        val peer = peers[deviceAddress]
        if (peer?.isConnected != true || peer.currentTransaction != null) {
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
            peer.currentTransaction = nextItem
        } else {
            // Failed to start transaction, increment attempts
            outbox.incrementAttempts(nextItem.id)
            // Try next item
            processNextOutboxItem(deviceAddress)
        }
    }

    private fun getOrCreateSession(deviceAddress: String): GattClientSession {
        val peer = peers.getOrPut(deviceAddress) { PeerSession(deviceAddress) }
        return peer.gattClientSession ?: GattClientSession(
            context,
            deviceAddress,
            diagnostics,
            permissionsGate,
            ::handleSessionEvent,
        ).also { peer.gattClientSession = it }
    }

}
