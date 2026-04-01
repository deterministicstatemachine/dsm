package com.dsm.wallet.bridge.ble

import android.bluetooth.BluetoothDevice
import com.dsm.wallet.bridge.BleOutboxItem
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.sync.Mutex
import java.util.UUID

/**
 * Identity anchor for a DSM peer. Keyed by deviceId (32 bytes) which is
 * stable across BLE address rotations. The genesisHash is carried for
 * display/verification but identity equality is based on deviceId alone.
 */
data class PeerIdentity(
    val deviceId: ByteArray,
    val genesisHash: ByteArray,
) {
    /** Hex key for map lookups. */
    val key: String get() = deviceId.joinToString("") { "%02x".format(it) }

    override fun equals(other: Any?): Boolean =
        other is PeerIdentity && deviceId.contentEquals(other.deviceId)
    override fun hashCode(): Int = deviceId.contentHashCode()
}

/**
 * Unified per-peer state object. Replaces the 10 address-keyed maps that were
 * previously spread across BleCoordinator (sessionStates, activeSessions,
 * pendingConnectionAddresses, pendingPairingConfirms) and GattServerHost
 * (connectedServerClients, cccdEnabledByDevice, notificationCompletions,
 * chunkAckCompletions, notificationSendLocks, writeBudgets).
 *
 * A single `ConcurrentHashMap<String, PeerSession>` in BleCoordinator replaces
 * all of them. Disconnect cleanup becomes one-step, and no map can get out of
 * sync with another.
 *
 * Transport-level state only — all protocol decisions are made by Rust.
 */
data class PeerSession(
    val address: String,

    // ── Client-side state (was BleSessionState + activeSessions) ──────────
    var gattClientSession: GattClientSession? = null,
    var isConnected: Boolean = false,
    var negotiatedMtu: Int = 23,
    var serviceDiscoveryCompleted: Boolean = false,
    var lastError: BleSessionEvent.ErrorOccurred? = null,
    var currentTransaction: BleOutboxItem? = null,
    var identityExchangeInProgress: Boolean = false,
    var pairingInProgress: Boolean = false,

    // ── Connection lifecycle (was pendingConnectionAddresses + polling loop) ─
    // When non-null, a connect is in flight. Completed by handleSessionEvent
    // on MtuNegotiated (true) or Disconnected/Error (false).
    @Transient var connectResult: CompletableDeferred<Boolean>? = null,

    // ── Pairing retry (was pendingPairingConfirms) ───────────────────────
    var pendingPairingConfirm: ByteArray? = null,

    // ── Server-side state (was GattServerHost's 6 maps) ──────────────────
    var serverDevice: BluetoothDevice? = null,
    var subscribedCccds: MutableMap<UUID, Boolean> = mutableMapOf(),
    var notificationCompletion: CompletableDeferred<Boolean>? = null,
    var chunkAckChannel: Channel<Int>? = null,
    var notificationSendLock: Mutex = Mutex(),
    var writeBudget: BleWriteBudget = BleWriteBudget(),

    // ── Identity anchor (stable across RPA rotations) ──────────────────
    @Transient var identity: PeerIdentity? = null,

    // ── Transfer nonce ───────────────────────────────────────────────────
    var serverTransferNonce: Byte = 0,

    // ── Reconnection backoff ─────────────────────────────────────────────
    // Tracks exponential backoff across connect/disconnect cycles.
    // NOT reset in clearClientState() — must persist to prevent rapid reconnect loops.
    // Reset by BleCoordinator on successful MtuNegotiated.
    var reconnectAttemptCount: Int = 0,
) {
    /** True if a GATT connect is in flight for this peer. */
    val connectionPending: Boolean
        get() = connectResult != null

    /** True if we have a live GATT client connection to this peer. */
    val hasActiveClientSession: Boolean
        get() = gattClientSession != null && isConnected

    /** True if this peer is connected to our GATT server. */
    val isServerClient: Boolean
        get() = serverDevice != null

    /** Check if this peer has subscribed to a specific CCCD on our GATT server. */
    fun isSubscribedTo(characteristicUuid: UUID): Boolean =
        subscribedCccds[characteristicUuid] == true

    /** Reset all client-side state. Called on GATT client disconnect. */
    fun clearClientState() {
        gattClientSession?.closeQuietly()
        gattClientSession = null
        isConnected = false
        negotiatedMtu = 23
        serviceDiscoveryCompleted = false
        lastError = null
        currentTransaction = null
        identityExchangeInProgress = false
        pairingInProgress = false
        connectResult?.complete(false)
        connectResult = null
        pendingPairingConfirm = null
    }

    /** Reset all server-side state. Called when peer disconnects from our GATT server. */
    fun clearServerState() {
        serverDevice = null
        subscribedCccds.clear()
        notificationCompletion?.cancel()
        notificationCompletion = null
        chunkAckChannel?.close()
        chunkAckChannel = null
        writeBudget = BleWriteBudget()
    }

    /** True if both client and server sides are gone — safe to remove from peers map. */
    val isEmpty: Boolean
        get() = gattClientSession == null && serverDevice == null && connectResult == null
}
