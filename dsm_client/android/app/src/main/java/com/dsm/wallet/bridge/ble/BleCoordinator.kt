// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge.ble

import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.util.Log
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.withLock

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
    private val scanStartTimestamps = java.util.concurrent.CopyOnWriteArrayList<Long>()
    private val SCAN_RATE_LIMIT_WINDOW_MS = 30_000L  // 30 seconds
    private val MAX_SCANS_PER_WINDOW = 5
    @Volatile private var lastScanStopTimestamp = 0L
    private val MIN_SCAN_GAP_MS = 6_000L  // 6 seconds between scan operations

    // ── Scan downshift ──
    // LOW_LATENCY (100% duty) drains battery fast. After 12s, auto-downshift
    // to BALANCED (~33% duty) for sustained discovery without battery damage.
    private val scanDownshiftHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private val scanDownshiftRunnable = Runnable {
        if (scanner.isScanning()) {
            Log.i("BleCoordinator", "Scan downshift: LOW_LATENCY → BALANCED after ${BleConstants.SCAN_LOW_LATENCY_DURATION_MS}ms")
            scanner.stopScanning()
            if (!scanner.startScanning(lowLatency = false)) {
                Log.w("BleCoordinator", "Scan downshift: the balanced scan was refused; scanning ended")
                radioEvents.scanStopped()
            }
        }
    }

    // ── Reconnection backoff ──
    private val reconnectHandler = android.os.Handler(android.os.Looper.getMainLooper())

    // Unified per-peer state.
    internal val peers = java.util.concurrent.ConcurrentHashMap<String, PeerSession>()

    // Internal components
    internal var permissionsGate = BlePermissionsGate(context)
    private var scanner = BleScanner(context)
    private var advertiser = BleAdvertiser(context)
    private var gattServer = GattServerHost(context)
    private var diagnostics = BleDiagnostics()
    private var radioEvents: BleRadioEvents = UnifiedRadioEvents

    // The advertiser's word, relayed: started and stopped are reported when the
    // stack confirms them, never when they are only requested.
    private val advertiserCallback = object : BleAdvertiser.Callback {
        override fun onAdvertisingStarted() = radioEvents.advertisingStarted()
        override fun onAdvertisingStopped() = radioEvents.advertisingStopped()
        override fun onAdvertisingFailed(errorCode: Int) {
            Log.e("BleCoordinator", "The stack refused the advertising set: errorCode=$errorCode")
            diagnostics.recordError(BleErrorCategory.HARDWARE_UNAVAILABLE, "advertise_failed_code_$errorCode")
        }
    }

    // Bluetooth going off ends every advertising set, scan and GATT server
    // registration with the radio. Registered for the life of the process (the
    // coordinator is a process singleton), so the state is cleared whether or not
    // the BLE service is running when it happens.
    private val adapterStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            when (intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)) {
                BluetoothAdapter.STATE_TURNING_OFF, BluetoothAdapter.STATE_OFF -> onRadioOff()
            }
        }
    }
    // PairingMachine deleted — pairing state is Rust-authoritative via PairingOrchestrator:
    // Rust decides from the identity read on a link, by device id, whether it pairs.


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

        advertiser.setCallback(advertiserCallback)

        // Initialize components
        permissionsGate.initialize()
        registerAdapterStateReceiver()
    }

    // Secondary constructor for tests allowing dependency injection
    internal constructor(
        context: Context,
        permissionsGate: BlePermissionsGate,
        advertiser: BleAdvertiser,
        gattServer: GattServerHost,
        scanner: BleScanner = BleScanner(context),
        diagnostics: BleDiagnostics = BleDiagnostics(),
        radioEvents: BleRadioEvents = UnifiedRadioEvents,
    ) : this(context) {
        this.permissionsGate = permissionsGate
        this.advertiser = advertiser
        this.gattServer = gattServer
        this.scanner = scanner
        this.diagnostics = diagnostics
        this.radioEvents = radioEvents
        // Re-wire scanner and advertiser callbacks after replacing the instances
        this.scanner.setCallback(this)
        this.advertiser.setCallback(advertiserCallback)
        // Re-wire peer lookup after replacing the gattServer instance
        this.gattServer.peerLookup = { address -> peers.getOrPut(address) { PeerSession(address) } }
        this.gattServer.peerEntries = { peers.values }
    }

    companion object {
        /** How long one reach looks for its appliance: connect, discovery, MTU, identity. */
        private const val REACH_BUDGET_MS = 20_000L
        /** How often a reach looks for a route that came up by another path. */
        private const val REACH_POLL_MS = 500L

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
     * Write one message's chunks over our client link to [address], in order.
     * True only when the stack took every chunk; false when there is no client
     * link, a chunk was refused or failed, or the link ended first. Not run on
     * the dispatcher: the link's write callbacks complete it.
     */
    suspend fun writeMessage(address: String, chunks: Array<ByteArray>): Boolean {
        val peer = peers[address] ?: return false
        val session = peer.gattClientSession ?: return false
        if (!peer.isConnected) return false
        return session.sendMessage(chunks).await()
    }

    /**
     * Start advertising this appliance for pairing/discovery.
     *
     * True when an advertising set is on the air or requested from the stack;
     * false when the advertiser refused. The started event is reported when the
     * stack confirms the set, through the advertiser's callback.
     */
    fun startAdvertising(): Boolean {
        return runOperationBool(BleOpLane.LIFECYCLE) {
            if (!permissionsGate.hasAdvertisePermission()) {
                diagnostics.recordError(BleErrorCategory.PERMISSION_DENIED, "advertising")
                permissionsGate.recordPermissionFailure()
                radioEvents.permissionDenied("advertise")
                return@runOperationBool false
            }

            if (advertiser.isAdvertising()) {
                return@runOperationBool true
            }

            val gattReady = gattServer.ensureStarted()
            if (!gattReady) {
                Log.w("BleCoordinator", "startAdvertising aborted: GATT server not ready")
                return@runOperationBool false
            }
            val requested = advertiser.startAdvertising()
            if (!requested) Log.w("BleCoordinator", "startAdvertising: the advertiser refused")
            requested
        }
    }

    /**
     * Stop advertising. The advertiser's answer; the stopped event is reported
     * when the stack confirms the stop, through the advertiser's callback.
     */
    fun stopAdvertising(): Boolean {
        return runOperationBool(BleOpLane.LIFECYCLE) {
            advertiser.stopAdvertising()
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
                radioEvents.permissionDenied("scan")
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
                        peer.clientRouteReady ||
                        peer.connectionPending ||
                        peer.identityExchangeInProgress ||
                        peer.pairingInProgress ||
                        peer.gattClientSession?.hasPendingOperations == true ||
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
                        clearClient(peer)
                        if (peer.isEmpty) peers.remove(addr)
                    }
                }
            }

            // Record the attempt BEFORE starting: the platform's limit counts attempts
            scanStartTimestamps.add(now)

            if (!scanner.startScanning()) {
                Log.w("BleCoordinator", "startScanning: the scanner refused")
                return@runOperationBool false
            }
            // Schedule downshift from LOW_LATENCY → BALANCED after 12s
            scanDownshiftHandler.removeCallbacks(scanDownshiftRunnable)
            scanDownshiftHandler.postDelayed(scanDownshiftRunnable, BleConstants.SCAN_LOW_LATENCY_DURATION_MS)
            radioEvents.scanStarted()
            true
        }
    }

    /**
     * Stop scanning. The scanner's answer; the stopped event is reported only
     * for a scan that was running and stopped.
     */
    fun stopScanning(): Boolean {
        return runOperationBool(BleOpLane.LIFECYCLE) {
            lastScanStopTimestamp = System.currentTimeMillis()
            scanDownshiftHandler.removeCallbacks(scanDownshiftRunnable)
            val wasScanning = scanner.isScanning()
            val stopped = scanner.stopScanning()
            if (wasScanning && stopped) radioEvents.scanStopped()
            stopped
        }
    }

    /**
     * Bluetooth is going off: clear what the radio ended with it, so the next
     * start (the STATE_ON refresh) opens a new GATT server and requests new
     * advertising and scans instead of trusting state from before. Runs on the
     * lifecycle lane, in order with every start and stop.
     */
    internal fun onRadioOff() {
        runOperation(BleOpLane.LIFECYCLE) {
            scanDownshiftHandler.removeCallbacks(scanDownshiftRunnable)
            val wasScanning = scanner.radioOff()
            val wasAdvertising = advertiser.radioOff()
            gattServer.stop()
            // Every link ended with the radio. The server that would have reported
            // its clients' disconnects is closed, so no disconnect will clear them:
            // clear each peer's links here, keeping what outlives a link.
            var links = 0
            for ((address, peer) in peers) {
                if (peer.gattClientSession != null || peer.isServerClient || peer.connectionPending) links++
                clearClient(peer)
                peer.clearServerState()
                if (peer.isEmpty) peers.remove(address)
            }
            Log.i("BleCoordinator", "Bluetooth off: radio state cleared (scanning=$wasScanning advertising=$wasAdvertising links=$links)")
            if (wasScanning) radioEvents.scanStopped()
            if (wasAdvertising) radioEvents.advertisingStopped()
        }
    }

    private fun registerAdapterStateReceiver() {
        val appContext = context.applicationContext
        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                appContext.registerReceiver(adapterStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                appContext.registerReceiver(adapterStateReceiver, filter)
            }
        } catch (t: Throwable) {
            Log.e("BleCoordinator", "Bluetooth state receiver not registered: ${t.message}")
        }
    }

    fun isScanning(): Boolean = scanner.isScanning()

    fun isAdvertising(): Boolean = advertiser.isAdvertising()

    /**
     * Ensure GATT server is started.
     */
    fun ensureGattServerStarted(): Boolean {
        return runOperationBool(BleOpLane.LIFECYCLE) {
            gattServer.ensureStarted()
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
     * Called by GattServerHost when the advertiser side processes a PairingConfirm.
     * Keep advertising active so already-paired peers can reconnect later for
     * offline bilateral transfers.
     */
    fun notifyAdvertiserPairingComplete(bleAddress: String) {
        runOperation(BleOpLane.PAIRING) {
            // Mark the session as disconnected but keep the entry; a reach for the
            // appliance re-establishes a link to it when a message needs one.
            peers[bleAddress]?.let { peer ->
                peer.isConnected = false
                peer.serviceDiscoveryCompleted = false
                peer.identityExchangeInProgress = false
                peer.pairingInProgress = false
            }
            peers[bleAddress]?.let { p -> p.connectResult?.complete(false); p.connectResult = null }
            Log.i("BleCoordinator", "Advertiser pairing complete for $bleAddress — marked disconnected, keeping advertising active for reconnects")
        }
    }

    /**
     * Close all GATT client sessions so the next transfer creates fresh
     * connections. Called on app resume to prevent stale RPA addresses
     * from causing write failures after a background/foreground cycle.
     */
    fun closeStaleGattSessions() {
        runOperation(BleOpLane.LIFECYCLE) {
            var closed = 0
            peers.values.forEach { peer ->
                if (peer.gattClientSession != null) {
                    clearClient(peer)
                    closed++
                }
            }
            if (closed > 0) {
                Log.i("BleCoordinator", "closeStaleGattSessions: closed $closed session(s) for fresh RPA resolution")
            }
        }
    }

    /**
     * Clean up resources.
     */
    fun cleanup() {
        runOperation(BleOpLane.LIFECYCLE) {
            if (scanner.isScanning() && scanner.stopScanning()) radioEvents.scanStopped()
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
        // A reach connects only for its appliance, one candidate at a time,
        // and keeps scanning past every other one.
        activeReach?.let { reach ->
            if (address !in reach.excluded && reach.seen.add(address)) {
                runOperation(BleOpLane.LIFECYCLE) { tryCandidate(reach, address) }
            }
            return
        }
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
            if (scanner.isScanning() && scanner.stopScanning()) {
                radioEvents.scanStopped()
            }
            val session = getOrCreateSession(address)
            // Mark connection in-flight via a sentinel deferred so connectionPending returns true.
            // This prevents double-connectGatt from scan overlap. The deferred is completed
            // when the identity read anchors the link, or by clearClientState.
            peers[address]!!.connectResult = peers[address]!!.connectResult ?: kotlinx.coroutines.CompletableDeferred()
            val connected = session.connect()
            if (connected) {
                Log.i("BleCoordinator", "GATT connection initiated to $address")
            } else {
                Log.w("BleCoordinator", "Failed to initiate GATT connection to $address")
                peers[address]?.let { clearClient(it) }
                if (peers[address]?.isEmpty == true) peers.remove(address)
                com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed(address, "GATT connection initiation failed")
                resumePairingScan(address, "connect_init_failed")
            }
        }
    }

    override fun onScanFailed(errorCode: Int) {
        Log.e("BleCoordinator", "BLE scan failed: errorCode=$errorCode")
        diagnostics.recordError(BleErrorCategory.HARDWARE_UNAVAILABLE, "scan_failed_code_$errorCode")
        radioEvents.scanStopped()
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
            radioEvents.scanStarted()
        }
    }

    private fun handleSessionEvent(event: BleSessionEvent) {
        val lane = when (event) {
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
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_disconnected", device = event.deviceAddress, status = event.status))
                        activeReach?.takeIf { it.isCandidate(event.deviceAddress) }
                            ?.let { rejectCandidate(it, event.deviceAddress, "disconnected") }
                        // Remove stale session so future scans can reconnect to this peer
                        clearClient(peer)
                        if (peer.isEmpty) peers.remove(event.deviceAddress)
                        com.dsm.wallet.bridge.Unified.onDeviceDisconnected(event.deviceAddress)
                        // Exponential backoff on reconnection to prevent battery drain
                        // and Android scan-rate-limit violations from rapid reconnect loops.
                        if (peer.reconnectAttemptCount < BleConstants.RECONNECT_MAX_ATTEMPTS) {
                            val delay = minOf(
                                BleConstants.RECONNECT_INITIAL_DELAY_MS * (1L shl peer.reconnectAttemptCount),
                                BleConstants.RECONNECT_MAX_DELAY_MS
                            )
                            peer.reconnectAttemptCount++
                            Log.i("BleCoordinator", "Reconnect backoff #${peer.reconnectAttemptCount} for ${event.deviceAddress} — resuming scan in ${delay}ms")
                            val addr = event.deviceAddress
                            reconnectHandler.postDelayed({ resumePairingScan(addr, "disconnected_backoff") }, delay)
                        } else {
                            Log.w("BleCoordinator", "Reconnect limit reached for ${event.deviceAddress} — waiting for user-initiated scan")
                        }
                    }
                    is BleSessionEvent.MtuNegotiated -> {
                        peer.negotiatedMtu = event.mtu
                        // Successful connection — reset backoff counter.
                        peer.reconnectAttemptCount = 0
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_mtu_negotiated", device = event.deviceAddress, bytes = event.mtu))
                        // The CCCD chain is done. The link becomes a route once the
                        // identity read on it is anchored; Rust decides from that
                        // identity, by the contact's device id, whether it re-anchors a
                        // paired contact or starts pairing. The guard keeps
                        // startScanning() eviction off the link meanwhile.
                        val session = peer.gattClientSession
                        if (session != null) {
                            peer.identityExchangeInProgress = true
                            Log.i("BleCoordinator", "MTU negotiated (${event.mtu}) for ${event.deviceAddress} — reading peer identity")
                            session.readIdentity()
                        }
                    }
                    is BleSessionEvent.ServiceDiscoveryCompleted -> {
                        peer.serviceDiscoveryCompleted = event.success
                        if (!event.success) {
                            diagnostics.recordError(BleErrorCategory.SERVICE_DISCOVERY_FAILED, "coordinator_service_discovery")
                        }
                    }
                    is BleSessionEvent.IdentityReadCompleted -> {
                        // Identity exchange phase complete (read result received).
                        // Clear the guard — PairingAckReceived will set pairingInProgress.
                        peer.identityExchangeInProgress = false
                        // A reach's candidate is identified against the appliance the
                        // reach is for; any other link is not a reach.
                        val reach = activeReach?.takeIf { it.isCandidate(event.deviceAddress) }
                        val expected = takeExpectedIdentity(event.deviceAddress)
                        // A finished reach's candidate: not a reach now, but still not anyone else's link.
                        val abandoned = reach == null && expected.isNotEmpty()
                        if (event.data != null && event.data.isNotEmpty()) {
                            Log.i("BleCoordinator", "Peer identity read from ${event.deviceAddress}: ${event.data.size} bytes")
                            diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_identity_read_ok", device = event.deviceAddress, bytes = event.data.size))

                            // Send raw proto bytes to Rust — Kotlin MUST NOT parse or split identity data.
                            try {
                                val resultBytes = com.dsm.wallet.bridge.Unified.processGattIdentityRead(
                                    event.deviceAddress,
                                    event.data,
                                    expected,
                                )
                                // Extract fields via JNI helpers — Kotlin has no proto codegen.
                                val success = com.dsm.wallet.bridge.Unified.identityReadResultGetSuccess(resultBytes)
                                val peerDeviceId = com.dsm.wallet.bridge.Unified.identityReadResultExtractPeerDeviceId(resultBytes)
                                val peerGenesisHash = com.dsm.wallet.bridge.Unified.identityReadResultExtractPeerGenesisHash(resultBytes)

                                if (success && peerDeviceId?.size == 32 && peerGenesisHash?.size == 32) {
                                    Log.i("BleCoordinator", "processGattIdentityRead succeeded for ${event.deviceAddress}")
                                    anchorIdentity(event.deviceAddress, PeerIdentity(peerDeviceId, peerGenesisHash))
                                    // The link is a route now: CCCD chain done, identity read on it.
                                    peer.clientRouteReady = true
                                    peer.connectResult?.let { result ->
                                        peer.connectResult = null
                                        result.complete(true)
                                    }
                                    val address = event.deviceAddress
                                    if (reach != null) {
                                        // The reach's caller sends what it reached for.
                                        reach.candidates.remove(address)
                                        reach.found.complete(BleRoute(address, clientLink = true))
                                    } else {
                                        // Rust delivers whatever it owes the appliance on this link.
                                        bleScope.launch { com.dsm.wallet.bridge.UnifiedBleEvents.onLinkUp(peerDeviceId, address) }
                                    }

                                    val writeBackEnvelope = com.dsm.wallet.bridge.Unified.identityReadResultExtractWriteBack(resultBytes)
                                        ?.takeIf { it.isNotEmpty() }
                                    if (writeBackEnvelope != null) {
                                        val session = peer.gattClientSession
                                        if (session != null) {
                                            // A failed write-back is reported as ErrorOccurred(pairing_write).
                                            session.writePairingData(writeBackEnvelope)
                                            Log.i("BleCoordinator", "Identity write-back to ${event.deviceAddress} queued (${writeBackEnvelope.size}B)")
                                        } else {
                                            Log.w("BleCoordinator", "Identity write-back: no active session for ${event.deviceAddress}")
                                            resumePairingScan(event.deviceAddress, "identity_writeback_no_session")
                                        }
                                    }
                                } else if (reach != null) {
                                    rejectCandidate(reach, event.deviceAddress, "not_the_addressed_appliance")
                                } else if (abandoned) {
                                    Log.i("BleCoordinator", "${event.deviceAddress}: a finished reach's candidate, not its appliance — closed")
                                    clearClient(peer)
                                    if (peer.isEmpty) peers.remove(event.deviceAddress)
                                } else {
                                    Log.w("BleCoordinator", "processGattIdentityRead failed for ${event.deviceAddress}")
                                    diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "coordinator_identity_rust_decode_failed")
                                }
                            } catch (t: Throwable) {
                                Log.w("BleCoordinator", "processGattIdentityRead exception for ${event.deviceAddress}", t)
                                diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "coordinator_identity_exception")
                                reach?.let { rejectCandidate(it, event.deviceAddress, "identity_exception") }
                            }
                        } else {
                            diagnostics.recordError(BleErrorCategory.CHARACTERISTIC_READ_FAILED, "coordinator_identity_read")
                            Log.e("BleCoordinator", "Identity read failed for ${event.deviceAddress} — failing fast")
                            if (reach != null) {
                                rejectCandidate(reach, event.deviceAddress, "identity_read_failed")
                            } else {
                                clearClient(peer)
                                if (peer.isEmpty) peers.remove(event.deviceAddress)
                                com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed(
                                    event.deviceAddress,
                                    "identity_read_failed"
                                )
                                resumePairingScan(event.deviceAddress, "identity_read_failed")
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
                            val useReliableWrite = com.dsm.wallet.bridge.Unified.bleDataResponseUsesReliableWrite(responseProto)
                            Log.i("BleTransferTrace", "Response received from ${event.deviceAddress}|chunks=${chunks.size}|reliableWrite=$useReliableWrite")
                            Log.d("BleCoordinator", "Response processed from ${event.deviceAddress}: chunks=${chunks.size}, reliableWrite=$useReliableWrite")

                            // If Rust produced follow-up chunks, send them on the link they answer,
                            // outside the actor: dispatchRustBleFollowUp blocks until the link takes them.
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
                        var confirmQueued = false
                        try {
                            val response = com.dsm.wallet.bridge.Unified.processBleIdentityEnvelope(event.data, event.deviceAddress)
                            Log.i("BleCoordinator", "PAIRING_ACK processed through Rust for ${event.deviceAddress}: ${response.size} bytes")

                            // Phase 3 of atomic pairing: Rust returns a BlePairingConfirm
                            // envelope if the ACK was valid. Write it back to the advertiser's
                            // PAIRING characteristic so the advertiser can persist its side.
                            if (response.isNotEmpty()) {
                                val session = peer.gattClientSession
                                if (session != null) {
                                    // Reported as PairingConfirmWritten when the stack acknowledges
                                    // it, as ErrorOccurred(pairing_confirm_write) when it fails.
                                    session.writePairingConfirm(response)
                                    confirmQueued = true
                                    Log.i("BleCoordinator", "PAIRING_CONFIRM write-back to ${event.deviceAddress} queued (${response.size}B)")
                                } else {
                                    Log.w("BleCoordinator", "PAIRING_CONFIRM: no active session for ${event.deviceAddress}")
                                    resumePairingScan(event.deviceAddress, "pairing_confirm_no_session")
                                }
                            }
                        } catch (e: Exception) {
                            Log.e("BleCoordinator", "Failed to process PAIRING_ACK from ${event.deviceAddress}", e)
                        } finally {
                            if (!confirmQueued) {
                                peer.pairingInProgress = false
                            }
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
                        this@BleCoordinator.stopScanning()
                        // Keep peer consistent so hasActiveClientSession() returns true
                        // while the GATT link is still live.
                        peer.connectResult?.let { r -> peer.connectResult = null; r.complete(true) }
                        Log.i("BleCoordinator", "Pairing complete for ${event.deviceAddress} (session + state kept for bilateral transfers)")
                        diagnostics.recordEvent(BleDiagEvent(phase = "coordinator_pairing_confirm_sent", device = event.deviceAddress))
                    }
                    is BleSessionEvent.ErrorOccurred -> {
                        // A reach's candidate is not reconnected by this recovery: the
                        // reach excludes it and connects its next candidate.
                        val reach = activeReach
                        val candidateOfReach = reach?.isCandidate(event.deviceAddress) == true
                        if (event.status == 133 && !candidateOfReach) {
                            Log.w("BleCoordinator", "GATT 133 observed. Scheduling delay recovery...")
                            bleScope.launch {
                                kotlinx.coroutines.delay(1500)
                                runOperation(BleOpLane.LIFECYCLE) {
                                    val currentPeer = peers[event.deviceAddress]
                                    val excluded = activeReach?.excluded?.contains(event.deviceAddress) == true
                                    if (!excluded && currentPeer != null && currentPeer.gattClientSession == null && !currentPeer.connectionPending) {
                                        getOrCreateSession(event.deviceAddress).connect()
                                    }
                                }
                            }
                        }

                        // The link failed at its connection, discovery, MTU, identity or
                        // pairing step, so the session is unusable. A message write that
                        // fails is not reported here: it fails that message alone.
                        // connectResult deferred is completed by clearClientState() below.
                        peer.lastError = event
                        diagnostics.recordError(event.category, event.details, event.deviceAddress, event.status)
                        if (event.details == "pairing_write" || event.details == "pairing_confirm_write") {
                            com.dsm.wallet.bridge.UnifiedBleEvents.onConnectionFailed(event.deviceAddress, event.details)
                        }

                        Log.w("BleCoordinator", "ErrorOccurred for ${event.deviceAddress} (${event.category}/${event.details}) — closing the session")
                        if (candidateOfReach) {
                            rejectCandidate(reach!!, event.deviceAddress, event.details)
                        }
                        // A link never identified resumes the pairing scan; an identified
                        // appliance is reached again by the SDK while frames are owed.
                        val identified = peer.identity != null
                        clearClient(peer)
                        if (peer.isEmpty) peers.remove(event.deviceAddress)
                        if (!identified && reach == null) {
                            resumePairingScan(event.deviceAddress, event.details)
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

    /**
     * Close our client link to [peer], reporting link-down for the appliance it
     * carried when it was a route: that appliance's delivered frames are
     * undelivered again, and the SDK reaches for it.
     */
    private fun clearClient(peer: PeerSession) {
        val carried = peer.identity?.takeIf { peer.clientRouteReady }
        peer.clearClientState()
        if (carried != null) {
            val address = peer.address
            bleScope.launch { com.dsm.wallet.bridge.UnifiedBleEvents.onLinkDown(carried.deviceId, address) }
        }
    }

    /** Where a message goes: our client link to [address], or the peer's link to our server there. */
    data class BleRoute(val address: String, val clientLink: Boolean)

    /**
     * Where a message to the appliance [deviceId] goes now, or null: "no route",
     * a liveness state — the frame stays owed.
     * 1. Our client link anchored to it: the identity read on that link named
     *    it, after the CCCD chain completed.
     * 2. Its link to our server, anchored to it and subscribed to TX_RESPONSE.
     * 3. A link to our server at [hint] — the address the SDK names for it —
     *    subscribed and anchored to no other appliance.
     * No other link is a substitute for the one addressed.
     */
    fun resolveRoute(deviceId: ByteArray, hint: String): BleRoute? {
        val anchored = peers.entries.filter { it.value.identity?.deviceId?.contentEquals(deviceId) == true }
        anchored.firstOrNull { it.value.clientRouteReady && it.value.hasActiveClientSession }
            ?.let { return BleRoute(it.key, clientLink = true) }
        anchored.firstOrNull { it.value.isServerClient && it.value.isSubscribedTo(BleConstants.TX_RESPONSE_UUID) }
            ?.let { return BleRoute(it.key, clientLink = false) }
        if (hint.isNotEmpty()) {
            peers[hint]?.let { peer ->
                if (peer.identity == null && peer.isServerClient && peer.isSubscribedTo(BleConstants.TX_RESPONSE_UUID)) {
                    return BleRoute(hint, clientLink = false)
                }
            }
        }
        return null
    }

    /**
     * Anchor a peer's identity after a successful GATT identity read: the link
     * at [address] carries that appliance.
     */
    fun anchorIdentity(address: String, identity: PeerIdentity) {
        val peer = peers[address] ?: return
        peer.identity = identity
        Log.i("BleCoordinator", "anchorIdentity: $address → ${com.dsm.wallet.bridge.BridgeEncoding.base32CrockfordEncode(identity.deviceId).take(8)}")
    }

    /** One reach: connecting for the appliance [deviceId], [hint] first, past every other appliance. */
    private class Reach(val deviceId: ByteArray, val hint: String) {
        val target: String = com.dsm.wallet.bridge.BridgeEncoding.base32CrockfordEncode(deviceId).take(8)
        /** Addresses whose identity read named another appliance, or whose link failed. */
        val excluded: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()
        /** Addresses discovered during the reach, each dispatched once. */
        val seen: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()
        /** Discovered while another candidate was connecting; tried in turn. */
        val waiting = java.util.concurrent.ConcurrentLinkedDeque<String>()
        /**
         * The addresses being connected and identified now: the hint, and at
         * most one discovered address beside it — a stale hint waits out its
         * connect timeout without holding back the scan.
         */
        val candidates: MutableSet<String> = java.util.concurrent.ConcurrentHashMap.newKeySet()
        @Volatile var startedScan: Boolean = false
        val found = CompletableDeferred<BleRoute>()

        fun isCandidate(address: String) = address in candidates
        fun scanSlotBusy() = candidates.any { it != hint }
    }

    @Volatile private var activeReach: Reach? = null
    private val reachMutex = kotlinx.coroutines.sync.Mutex()

    /**
     * Addresses a finished reach was still connecting, each with the appliance
     * that reach was for. The link is closed when the reach ends, but its
     * identity read may already be queued behind that close; it is judged
     * against the same appliance, so a non-target is still recorded nowhere.
     */
    internal val abandonedCandidates = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()

    /**
     * The appliance an identity read on the link at [address] must name: the
     * active reach's, when [address] is its candidate; else the one a finished
     * reach was connecting it for (taken once); else none — not a reach.
     */
    internal fun takeExpectedIdentity(address: String): ByteArray =
        activeReach?.takeIf { it.isCandidate(address) }?.deviceId
            ?: abandonedCandidates.remove(address)
            ?: ByteArray(0)

    /**
     * Reach for the appliance [deviceId]: connect to [hint] first, and scan,
     * connecting to DSM advertisers one at a time until the identity read on
     * one names [deviceId]. An appliance that is not it is disconnected and
     * excluded for this reach, and Rust records nothing about it. Returns the
     * route once that link is ready, or null when the budget ends first — no
     * route; the frame stays owed. One reach at a time.
     */
    suspend fun reach(deviceId: ByteArray, hint: String): BleRoute? = reachMutex.withLock {
        resolveRoute(deviceId, hint)?.let { return@withLock it }
        val reach = Reach(deviceId, hint)
        // Candidates of earlier reaches whose identity read never came: nothing is owed them.
        abandonedCandidates.clear()
        activeReach = reach
        try {
            // Prime the reverse path: the appliance may reach our server first.
            runOperationBool(BleOpLane.LIFECYCLE) {
                gattServer.ensureStarted()
                if (!advertiser.isAdvertising()) {
                    val requested = advertiser.startAdvertising()
                    Log.i("BleCoordinator", "reach ${reach.target}: advertising for the reverse path requested=$requested")
                }
                true
            }
            if (hint.isNotEmpty()) {
                reach.seen.add(hint)
                runOperation(BleOpLane.LIFECYCLE) { tryCandidate(reach, hint) }
            }
            Log.i("BleCoordinator", "reach ${reach.target}: hint='$hint', up to ${REACH_BUDGET_MS}ms")
            val deadline = android.os.SystemClock.elapsedRealtime() + REACH_BUDGET_MS
            while (android.os.SystemClock.elapsedRealtime() < deadline) {
                resolveRoute(deviceId, hint)?.let { return@withLock it }
                if (!scanner.isScanning() && startScanning()) {
                    reach.startedScan = true
                }
                kotlinx.coroutines.withTimeoutOrNull(REACH_POLL_MS) { reach.found.await() }
                    ?.let { return@withLock it }
            }
            Log.i("BleCoordinator", "reach ${reach.target}: not reached within ${REACH_BUDGET_MS}ms (excluded ${reach.excluded.size})")
            null
        } finally {
            activeReach = null
            if (reach.startedScan) stopScanning()
            // Candidates still connecting belong to no reach now.
            val leftover = reach.candidates.toList()
            reach.candidates.clear()
            for (address in leftover) abandonedCandidates[address] = reach.deviceId
            if (leftover.isNotEmpty()) {
                runOperation(BleOpLane.LIFECYCLE) {
                    for (address in leftover) {
                        val peer = peers[address] ?: continue
                        if (!peer.clientRouteReady) {
                            clearClient(peer)
                            if (peer.isEmpty) peers.remove(address)
                        }
                    }
                }
            }
        }
    }

    /** On the dispatcher: connect to [address] for [reach], or queue it behind the candidate in flight. */
    private fun tryCandidate(reach: Reach, address: String) {
        if (activeReach !== reach || address in reach.excluded) return
        val existing = peers[address]
        if (existing?.gattClientSession != null) {
            // A link there already: anchored to another appliance, it is not this
            // one; otherwise its own identity read decides and resolveRoute sees it.
            val other = existing.identity?.let { !it.deviceId.contentEquals(reach.deviceId) } == true
            if (other) reach.excluded.add(address)
            return
        }
        if (reach.isCandidate(address)) return
        if (address != reach.hint && reach.scanSlotBusy()) {
            if (!reach.waiting.contains(address)) reach.waiting.addLast(address)
            return
        }
        reach.candidates.add(address)
        Log.i("BleCoordinator", "reach ${reach.target}: connecting to candidate $address")
        val session = getOrCreateSession(address)
        val peer = peers.getOrPut(address) { PeerSession(address) }
        // Marks the connect in flight (eviction and discovery leave it alone);
        // completed when the identity read anchors the link, or by clearClientState.
        peer.connectResult = peer.connectResult ?: CompletableDeferred()
        if (!session.connect()) rejectCandidate(reach, address, "connect_init_failed")
    }

    /** On the dispatcher: [address] is not the appliance [reach] is for; try the next one. */
    private fun rejectCandidate(reach: Reach, address: String, reason: String) {
        if (!reach.candidates.remove(address)) return
        Log.i("BleCoordinator", "reach ${reach.target}: $address excluded ($reason)")
        reach.excluded.add(address)
        peers[address]?.let { peer ->
            clearClient(peer)
            if (peer.isEmpty) peers.remove(address)
        }
        while (!reach.scanSlotBusy()) {
            val next = reach.waiting.pollFirst() ?: break
            tryCandidate(reach, next)
        }
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
