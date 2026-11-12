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
    // Pairing is Rust's: the link handshake Rust runs on each link (DSM Amendment
    // A27) authenticates its peer and pairs it. Kotlin moves the link's bytes only.


    init {
        // Wire scanner callback so discovered devices trigger GATT connections
        scanner.setCallback(this)

        // Wire peer lookup so GattServerHost delegates per-device state to PeerSession
        gattServer.peerLookup = { address -> peers.getOrPut(address) { PeerSession(address) } }
        gattServer.peerForget = { address -> peers[address]?.takeIf { it.isEmpty }?.let { peers.remove(address) } }
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
        this.gattServer.peerForget = { address -> peers[address]?.takeIf { it.isEmpty }?.let { peers.remove(address) } }
        this.gattServer.peerEntries = { peers.values }
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
            // and every link Rust opened.
            if (peers.values.any { it.gattClientSession != null }) {
                val staleAddresses = mutableListOf<String>()
                for ((addr, peer) in peers) {
                    if (peer.gattClientSession == null) continue
                    val isActive = (
                        peer.clientRouteReady ||
                        peer.connectionPending ||
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
            scanDownshiftHandler.removeCallbacks(scanDownshiftRunnable)
            val wasScanning = scanner.isScanning()
            val stopped = scanner.stopScanning()
            // Only a scan that ran holds back the next start: a stop with nothing
            // scanning must not make a reach that needs the scanner wait.
            if (wasScanning) lastScanStopTimestamp = System.currentTimeMillis()
            if (wasScanning && stopped) radioEvents.scanStopped()
            stopped
        }
    }

    /**
     * Pairing's stop. While Rust is reaching for a contact by scan ([requestConnect]
     * left it to the next device the scan finds), the scan is the reach's: pairing
     * finishing must not end it. The reach's scan stops at the device it connects to.
     */
    fun stopPairingScan(): Boolean {
        val reaching = pendingTarget != null
        if (reaching) Log.i("BleCoordinator", "pairing scan stop: a reach for a contact is scanning; left on")
        return reaching || stopScanning()
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
            // A contact Rust asked to reach with no address: this link's handshake
            // says Hello to it first.
            pendingTarget?.let { target ->
                reachTargets[address] = target
                pendingTarget = null
            }
            // Mark connection in-flight via a sentinel deferred so connectionPending returns true.
            // This prevents double-connectGatt from scan overlap. The deferred is completed
            // when Rust opens the link, or by clearClientState.
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
            is BleSessionEvent.MtuNegotiated -> BleOpLane.PAIRING
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
                        // Remove stale session so future scans can reconnect to this peer
                        clearClient(peer)
                        if (peer.isEmpty) peers.remove(event.deviceAddress)
                        // A link that closed before Rust opened it leaves its reach target to
                        // the scan's next link.
                        reachTargets.remove(event.deviceAddress)?.let { pendingTarget = it }
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
                        // The link is ready. Rust opens it (DSM Amendment A27) and hands
                        // back its first Hello; who answered is learned by the handshake.
                        val session = peer.gattClientSession
                        if (session != null) {
                            val address = event.deviceAddress
                            val target = reachTargets.remove(address) ?: ByteArray(0)
                            val hello = try {
                                com.dsm.wallet.bridge.Unified.bleLinkOpened(address, BleConstants.LINK_ROLE_CLIENT, target)
                            } catch (t: Throwable) {
                                Log.w("BleCoordinator", "The link to $address was not opened", t)
                                null
                            }
                            if (hello == null) {
                                clearClient(peer)
                                if (peer.isEmpty) peers.remove(address)
                                resumePairingScan(address, "link_not_opened")
                            } else {
                                peer.clientRouteReady = true
                                peer.connectResult?.let { result ->
                                    peer.connectResult = null
                                    result.complete(true)
                                }
                                bleScope.launch {
                                    val sent = com.dsm.wallet.bridge.Unified.dispatchRustBleFollowUp(
                                        address,
                                        BleConstants.LINK_ROLE_CLIENT,
                                        hello,
                                    )
                                    Log.i("BleCoordinator", "Link Hello to $address written=$sent")
                                }
                            }
                        }
                    }
                    is BleSessionEvent.ServiceDiscoveryCompleted -> {
                        peer.serviceDiscoveryCompleted = event.success
                        if (!event.success) {
                            diagnostics.recordError(BleErrorCategory.SERVICE_DISCOVERY_FAILED, "coordinator_service_discovery")
                        }
                    }
                    is BleSessionEvent.ResponseReceived -> {
                        // All routing — chunk vs envelope dispatch, frame-type detection, and
                        // bilateral follow-up chunking — is performed by Rust via processIncomingBleData.
                        // Kotlin MUST NOT inspect data[0] or branch on protocol frame type codes.
                        try {
                            val responseProto = com.dsm.wallet.bridge.Unified.processIncomingBleData(
                                event.deviceAddress,
                                BleConstants.LINK_ROLE_CLIENT,
                                event.data,
                            )
                            // Bytes Rust refused (a handshake that failed, a record that
                            // does not open) end the link: its next connection runs the
                            // handshake again.
                            if (com.dsm.wallet.bridge.Unified.isErrorEnvelope(responseProto) != 0) {
                                Log.w("BleCoordinator", "The link to ${event.deviceAddress} refused its bytes; closing it")
                                clearClient(peer)
                                if (peer.isEmpty) peers.remove(event.deviceAddress)
                                return@runOperation
                            }
                            val chunks = com.dsm.wallet.bridge.Unified.bleDataResponseExtractChunks(responseProto)
                            Log.i("BleTransferTrace", "Response received from ${event.deviceAddress}|chunks=${chunks.size}")

                            // What Rust answers goes back on this link, outside the actor:
                            // dispatchRustBleFollowUp blocks until the link takes it.
                            if (chunks.isNotEmpty()) {
                                val addr = event.deviceAddress
                                bleScope.launch {
                                    val queued = com.dsm.wallet.bridge.Unified.dispatchRustBleFollowUp(
                                        addr,
                                        BleConstants.LINK_ROLE_CLIENT,
                                        chunks,
                                    )
                                    Log.i("BleCoordinator", "Queued answer to $addr: chunks=${chunks.size}, queued=$queued")
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
                    is BleSessionEvent.ErrorOccurred -> {
                        if (event.status == 133) {
                            Log.w("BleCoordinator", "GATT 133 observed. Scheduling delay recovery...")
                            bleScope.launch {
                                kotlinx.coroutines.delay(1500)
                                runOperation(BleOpLane.LIFECYCLE) {
                                    val currentPeer = peers[event.deviceAddress]
                                    if (currentPeer != null && currentPeer.gattClientSession == null && !currentPeer.connectionPending) {
                                        getOrCreateSession(event.deviceAddress).connect()
                                    }
                                }
                            }
                        }

                        // The link failed at its connection, discovery or MTU step, so
                        // the session is unusable. A message write that fails is not
                        // reported here: it fails that message alone.
                        // connectResult deferred is completed by clearClientState() below.
                        peer.lastError = event
                        diagnostics.recordError(event.category, event.details, event.deviceAddress, event.status)

                        Log.w("BleCoordinator", "ErrorOccurred for ${event.deviceAddress} (${event.category}/${event.details}) — closing the session")
                        // A link Rust never opened resumes the pairing scan; a contact Rust
                        // still owes frames is reached for again by Rust.
                        val opened = peer.clientRouteReady
                        clearClient(peer)
                        if (peer.isEmpty) peers.remove(event.deviceAddress)
                        // A contact Rust asked to reach at an address it last saw there: the
                        // address may have rotated, so the scan's next link names it instead.
                        reachTargets.remove(event.deviceAddress)?.let { pendingTarget = it }
                        if (!opened) {
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
     * Close our client link to [peer]. A link Rust opened is closed in Rust too:
     * its session is dropped, and a contact it was paired with is reached for
     * again while frames are owed.
     */
    private fun clearClient(peer: PeerSession) {
        val opened = peer.clientRouteReady
        peer.clearClientState()
        if (opened) {
            try {
                com.dsm.wallet.bridge.Unified.bleLinkClosed(peer.address, BleConstants.LINK_ROLE_CLIENT)
            } catch (t: Throwable) {
                Log.e("BleCoordinator", "Closing the link to ${peer.address} failed", t)
            }
        }
    }

    /**
     * Addresses connected for a contact Rust asked to reach, each with that
     * contact's device id: the link's handshake says Hello to it first. Taken
     * once, when the link opens.
     */
    private val reachTargets = java.util.concurrent.ConcurrentHashMap<String, ByteArray>()

    /** The contact the next DSM device the scan finds is connected for. */
    @Volatile private var pendingTarget: ByteArray? = null

    /**
     * Rust asks for a link to the contact [deviceId] (DSM Amendment A27: Rust
     * chooses the link; Kotlin connects). Connect to [hint] when it names an
     * address with no link yet, else scan. The link that opens names
     * [deviceId] as its target; the handshake on it decides who answered.
     */
    fun requestConnect(deviceId: ByteArray, hint: String) {
        runOperation(BleOpLane.LIFECYCLE) {
            gattServer.ensureStarted()
            if (!advertiser.isAdvertising()) {
                val requested = advertiser.startAdvertising()
                Log.i("BleCoordinator", "requestConnect: advertising for the reverse path requested=$requested")
            }
            if (hint.isNotEmpty() && peers[hint]?.gattClientSession == null) {
                reachTargets[hint] = deviceId
                val peer = peers.getOrPut(hint) { PeerSession(hint) }
                peer.connectResult = peer.connectResult ?: CompletableDeferred()
                if (!getOrCreateSession(hint).connect()) {
                    reachTargets.remove(hint)
                    clearClient(peer)
                    if (peer.isEmpty) peers.remove(hint)
                    pendingTarget = deviceId
                    resumePairingScan(hint, "reach_connect_failed")
                }
            } else {
                pendingTarget = deviceId
                resumePairingScan(hint, "reach")
            }
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
