// SPDX-License-Identifier: MIT OR Apache-2.0

@file:Suppress("UNUSED_PARAMETER")

package com.dsm.wallet.bridge

import androidx.annotation.Keep

// ============================================================================
// DSM APP INTEGRATION BOUNDARY -- Native Android JNI Facade
// ============================================================================
//
// If you are building a native Android app (Jetpack Compose, no WebView),
// this object is your primary interface to the DSM Rust core.
//
// HOW TO HOOK IN:
//   1. Unified initializes automatically (System.loadLibrary("dsm_sdk")).
//   2. Bootstrap: SinglePathWebViewBridge.bootstrapFromPrefs() or the
//      shared startup/ingress boundary plus host measurement capture.
//   3. Shared ingress: Unified.dispatchIngress(requestBytes) -> ByteArray
//   5. Decode:   strip 0x03 prefix -> Envelope.parseFrom(rest)
//
// PROTOCOL RULES:
//   - All payloads are protobuf ByteArray. No serialization libraries.
//   - All responses carry 0x03 framing prefix + Envelope v3 protobuf.
//   - DO NOT use wall-clock APIs in protocol logic -- clockless.
//   - All crypto (SPHINCS+, ML-KEM-768) handled in Rust beneath.
//
// DOMAIN GROUPS:
//   Protocol:  processEnvelopeV3
//   Shared boundary: dispatchStartup, dispatchIngress
//   Bilateral: acceptBilateralByCommitment, ...
//   BLE:       initBleCoordinator, bleLinkOpened, processIncomingBleData, ...
//   Contacts:  hasContactForDeviceId
//
// Full method list: UnifiedNativeApi.kt holds every external declaration.
// ============================================================================

/**
 * Unified JNI facade (protobuf-only, context-free).
 * - No JSON, no wall clocks.
 * - All externals are @Keep @JvmStatic to survive R8/Proguard.
 * - No reflection-based dispatch; strict surface.
 */
object Unified {

    init {
        // Load the native library with JNI exports.
        // The `Unified_*` JNI surface is implemented in the Rust SDK shared library.
        @Suppress("SwallowedException")
        try {
            System.loadLibrary("dsm_sdk")
        } catch (t: Throwable) {
            // Fail-closed-ish: without JNI, nothing works. Log loudly.
            android.util.Log.e("Unified", "Failed to load native library dsm_sdk", t)
            throw RuntimeException("Failed to load native library dsm_sdk", t)
        }
    }

    // ---------- Protobuf-only externals ----------
    @Keep @JvmStatic fun initSdk(baseDir: String): Boolean =
        UnifiedNativeApi.initSdk(baseDir)
    @Keep @JvmStatic fun initStorageBaseDir(path: ByteArray) {
        UnifiedNativeApi.initStorageBaseDir(path)
    }
    @Keep @JvmStatic fun initDsmSdk(configPath: String) {
        UnifiedNativeApi.initDsmSdk(configPath)
    }

    // Phone->Pico USB-OTG bridge. Rust up-calls this with an OPAQUE, already-framed request
    // (LE32 length ++ protobuf); this just moves the bytes over USB to the Pico and returns the
    // response body (Rust decodes it). We understand NOTHING about the payload — no TROPIC frames,
    // no key material. Empty return on any failure -> Rust fails closed to online recovery.
    // `LocalPicoUsb.init(context)` must have been called at startup.
    @Keep @JvmStatic fun picoUsbTransceive(frame: ByteArray): ByteArray =
        LocalPicoUsb.transceive(frame)

    // A board's one-time burns from the phone alone (owner, 2026-11-11): Rust (`dsm-android-anchor`
    // `board_setup`) drives the board's own USB bootloader through these, and they only move bytes.
    // `BootselUsb.init(context)` is called at startup beside `LocalPicoUsb.init`.
    @Keep @JvmStatic fun bootselOpen(): String? = BootselUsb.open()
    @Keep @JvmStatic fun bootselLastError(): String = BootselUsb.lastError()
    @Keep @JvmStatic fun bootselBulkOut(data: ByteArray): Int = BootselUsb.bulkOut(data)
    @Keep @JvmStatic fun bootselBulkIn(max: Int): ByteArray? = BootselUsb.bulkIn(max)
    @Keep @JvmStatic fun bootselAckIn(): Int = BootselUsb.ackIn()
    @Keep @JvmStatic fun bootselCommandStatus(): ByteArray? = BootselUsb.commandStatus()
    @Keep @JvmStatic fun bootselHaltedEndpoints(): IntArray? = BootselUsb.haltedEndpoints()
    @Keep @JvmStatic fun bootselFileDescriptor(): Int = BootselUsb.fileDescriptor()
    @Keep @JvmStatic fun bootselInterfaceReset(): Int = BootselUsb.interfaceReset()
    @Keep @JvmStatic fun bootselClose(): Int = BootselUsb.close()
    // The production release the app carries (the signing's public outputs, from its assets).
    @Keep @JvmStatic fun anchorReleaseFile(path: String): ByteArray? = BootselUsb.releaseFile(path)

    // GATED sender-transport install (only in on_device_installs-feature .so; absent otherwise):
    // installs the USB anchor appliance factory so offline-bearer sends drive the phone's own
    // physical RP2350/TROPIC01 (v2: the receiver needs NO hardware — this is the entire device
    // install story). Fail-closed: without it every offline-bearer send errors ("offline = chips").
    // `DsmInitProvider` registers it once at app start. Catch UnsatisfiedLinkError.
    @Keep @JvmStatic external fun installAnchorTransport(): Boolean
    @Keep @JvmStatic fun dispatchStartup(requestBytes: ByteArray): ByteArray =
        UnifiedNativeApi.dispatchStartup(requestBytes)
    @Keep @JvmStatic fun dispatchIngress(requestBytes: ByteArray): ByteArray =
        UnifiedNativeApi.dispatchIngress(requestBytes)
    @Keep @JvmStatic fun getTransportHeadersV3Status(): Byte =
        UnifiedNativeApi.getTransportHeadersV3Status()
    @Keep @JvmStatic fun getTransportHeadersV3(): ByteArray =
        UnifiedNativeApi.getTransportHeadersV3()
    /**
     * The local envelope entry: an Envelope v3 this device's own app layer built.
     * Never a peer's bytes — those go to processIncomingBleData (TX writes and
     * notifications), through the link session.
     */
    @Keep @JvmStatic fun processEnvelopeV3(envelope: ByteArray): ByteArray =
        UnifiedNativeApi.processEnvelopeV3(envelope)
    /**
     * Fetch all token balances (strict, protobuf-encoded).
     * Returns: ByteArray (protobuf-encoded TokenBalanceView[])
     */
    @Keep @JvmStatic fun getAllBalancesStrict(): ByteArray =
        UnifiedNativeApi.getAllBalancesStrict()


    // BLE bilateral operations

    /**
     * Ensure the AppRouter is installed (safe to call multiple times; idempotent).
     * Returns true if AppRouter is installed/available, false otherwise.
     * This is critical for wallet/contacts screens to function after app restart.
     */
    @Keep @JvmStatic fun ensureAppRouterInstalled(): Boolean =
        UnifiedNativeApi.ensureAppRouterInstalled()

    /**
     * Get a compact AppRouter status code (native):
     * 0 = NOT_READY_NO_GENESIS
     * 1 = ROUTER_NOT_READY
     * 2 = INSTALLED
     */
    @Keep @JvmStatic fun getAppRouterStatus(): Int = UnifiedNativeApi.getAppRouterStatus()

    // ---------- BLE unified surface ----------
    @Keep @JvmStatic fun initBleCoordinator(context: android.content.Context) {
        UnifiedBleBridge.initBleCoordinator(context) { eventName, detail ->
            dispatchBlePermissionEvent(eventName, detail)
        }
    }

    /**
     * Start BLE pairing in advertiser role using the instance-bound service.
     * Returns false if BLE service is not initialized.
     */
    @Keep @JvmStatic fun startBlePairingAdvertise(): Boolean {
        return UnifiedBleBridge.startBlePairingAdvertise()
    }

    /**
     * Start BLE pairing in scanner role using the instance-bound service.
     * Returns false if BLE service is not initialized.
     */
    @Keep @JvmStatic fun startBlePairingScan(): Boolean {
        return UnifiedBleBridge.startBlePairingScan()
    }

    /**
     * Stop BLE scanning. Called by Rust pairing loop on exit to prevent lingering scans.
     */
    @Keep @JvmStatic fun stopBlePairingScan(): Boolean {
        return UnifiedBleBridge.stopBlePairingScan()
    }

    // ---------- Event notifications ----------
    /**
     * A GATT link came up at [address], this device on it as [role]
     * (BleConstants.LINK_ROLE_CLIENT / LINK_ROLE_SERVER). The client names the
     * contact it reached for in [target] (empty when it connected to any DSM
     * device). Returns the radio bytes to write on the link: the client's
     * first Hello (DSM Amendment A27); nothing for the server. Throws when
     * Rust does not open the link: close it.
     */
    @Keep @JvmStatic fun bleLinkOpened(address: String, role: Int, target: ByteArray): Array<ByteArray> =
        UnifiedNativeApi.bleLinkOpened(address, role, target)
            ?: throw IllegalStateException("BLE link: Rust panicked opening $address")

    /** The GATT link at [address], this device on it as [role], closed. */
    @Keep @JvmStatic fun bleLinkClosed(address: String, role: Int) {
        UnifiedNativeApi.bleLinkClosed(address, role)
    }

    /**
     * Check if a contact exists for the given device_id (32 bytes).
     * Used by BLE layer to gate binding before attempting offline operations.
     * Returns true if contact exists, false otherwise.
     */
    @Keep @JvmStatic fun hasContactForDeviceId(deviceId: ByteArray): Boolean =
        UnifiedNativeApi.hasContactForDeviceId(deviceId)
    /**
     * Check if a BLE address is fully paired (has BLE mapping in contact database).
     * Returns true if the address has a completed pairing with ble_address stored, false otherwise.
     */
    @Keep @JvmStatic fun isBleAddressPaired(address: String): Boolean =
        UnifiedNativeApi.isBleAddressPaired(address)
    
    /**
     * Check if an envelope contains a BilateralCommit UniversalTx.
     * Used to determine if the commit needs to be sent back to the receiver.
     */
    @Keep @JvmStatic fun isCommitEnvelope(envelope: ByteArray): Boolean =
        UnifiedNativeApi.isCommitEnvelope(envelope)

    @Keep @JvmStatic fun onDeviceConnected(address: String) {
        UnifiedBleEvents.onDeviceConnected(address)
    }
    
    @Keep @JvmStatic fun onDeviceDisconnected(address: String) {
        UnifiedBleEvents.onDeviceDisconnected(address)
    }
    
    @Keep @JvmStatic fun onScanStarted() {
        UnifiedBleEvents.onScanStarted()
    }

    @Keep @JvmStatic fun onScanStopped() {
        UnifiedBleEvents.onScanStopped()
    }

    @Keep @JvmStatic fun onDeviceFound(address: String, name: String, rssi: Int) {
        UnifiedBleEvents.onDeviceFound(address, name, rssi)
    }

    @Keep @JvmStatic fun onAdvertisingStarted() {
        UnifiedBleEvents.onAdvertisingStarted()
    }

    @Keep @JvmStatic fun onAdvertisingStopped() {
        UnifiedBleEvents.onAdvertisingStopped()
    }
    
    /**
     * Direct relay for Rust -> WebView events (Protobuf Bytes).
     * Strictly transport only. No logic.
     */
    @Keep @JvmStatic fun dispatchToWebView(envelopeBytes: ByteArray) {
        if (envelopeBytes.isNotEmpty()) {
            BleEventRelay.dispatchEnvelope(envelopeBytes)
        }
    }

    // ---------- Envelope helpers for BLE events ----------
    @Keep @JvmStatic fun createTransactionErrorEnvelope(address: String, code: Int, message: String): ByteArray? =
        UnifiedNativeApi.createTransactionErrorEnvelope(address, code, message)
        
    // ---------- Bilateral BLE operations ----------
    
    /**
     * Check if BleFrameCoordinator has been injected and is ready to process BLE chunks.
     * Rust builds the coordinator during SDK init once an identity exists.
     * Returns true if coordinator is ready, false otherwise.
     */
    @Keep @JvmStatic fun isBleCoordinatorReady(): Boolean = UnifiedNativeApi.isBleCoordinatorReady()

    /**
     * Detect the BLE frame type for an envelope based on its payload.
     * Returns:
     *   1 = BilateralPrepare
     *   2 = BilateralPrepareResponse
        *   3 = BilateralPrepareReject
     *   4 = BilateralCommit
     *   5 = BilateralCommitResponse
        *   8 = ChainHistoryRequest
        *   9 = ChainHistoryResponse
        *   10 = ReconciliationRequest
        *   11 = ReconciliationResponse
     *   0 = Unspecified/Unknown
     */
    @Keep @JvmStatic fun detectEnvelopeFrameType(envelopeBytes: ByteArray): Int =
        UnifiedNativeApi.detectEnvelopeFrameType(envelopeBytes)

    /**
     * The radio's entry: bytes a peer wrote over BLE (a TX_REQUEST write or a
     * TX_RESPONSE notification) on the link at [deviceAddress], this device on
     * it as [role]. Rust takes a link handshake fragment or a sealed record and
     * refuses anything else. Returns a serialized BleIncomingDataResponse (not
     * Envelope v3 framed) whose chunks are written back verbatim on the same
     * link, or an error envelope: close the link.
     * Kotlin MUST NOT inspect the bytes — call this instead.
     */
    @Keep @JvmStatic fun processIncomingBleData(deviceAddress: String, role: Int, data: ByteArray): ByteArray =
        UnifiedNativeApi.processIncomingBleData(deviceAddress, role, data)

    /** Extract response_chunks from a BleIncomingDataResponse proto (returned by processIncomingBleData). */
    @Keep @JvmStatic fun bleDataResponseExtractChunks(responseProto: ByteArray): Array<ByteArray> =
        UnifiedNativeApi.bleDataResponseExtractChunks(responseProto)

    /** Extract use_reliable_write from a BleIncomingDataResponse proto. */
    @Keep @JvmStatic fun bleDataResponseUsesReliableWrite(responseProto: ByteArray): Boolean =
        UnifiedNativeApi.bleDataResponseUsesReliableWrite(responseProto)

    /**
     * Ask the transport for a link to the contact [deviceId] (invoked by Rust,
     * DSM Amendment A27): connect, [addressHint] first, and name [deviceId] as
     * the link's handshake target. Rust delivers what it owes once the link
     * pairs.
     */
    @Keep @JvmStatic fun requestGattConnect(deviceId: ByteArray, addressHint: String) {
        UnifiedBleBridge.requestGattConnect(deviceId, addressHint)
    }

    /**
     * Write [chunks], sealed by Rust, on exactly the link at [deviceAddress]
     * where this device is [role] (invoked by Rust: Rust chooses the link).
     * False when that link is gone or refused them: nothing switches links.
     */
    @Keep @JvmStatic fun dispatchRustBleFollowUp(deviceAddress: String, role: Int, chunks: Array<ByteArray>): Boolean {
        return UnifiedBleBridge.dispatchRustFollowUp(deviceAddress, role, chunks)
    }

    /**
     * Accept a pending bilateral proposal by commitment hash (new flow).
     * commitmentHashBytes: 32-byte commitment hash of the pending proposal
     * Returns: Protobuf-encoded accept response envelope (to be chunked and sent via BLE)
     */
    @Keep @JvmStatic fun acceptBilateralByCommitment(commitmentHashBytes: ByteArray): ByteArray =
        UnifiedNativeApi.acceptBilateralByCommitment(commitmentHashBytes)

    /**
     * Reject an incoming bilateral prepare request.
     * commitmentHashBytes: 32-byte commitment hash to reject
     * reason: Human-readable rejection reason
     * Returns: Protobuf-encoded reject response envelope (to be chunked and sent via BLE)
     */
    @Keep @JvmStatic fun rejectBilateralByCommitment(commitmentHashBytes: ByteArray, reason: String): ByteArray =
        UnifiedNativeApi.rejectBilateralByCommitment(commitmentHashBytes, reason)
    @Keep @JvmStatic fun cancelBilateralByCommitment(commitmentHashBytes: ByteArray, reason: String): ByteArray =
        UnifiedNativeApi.cancelBilateralByCommitment(commitmentHashBytes, reason)

    // Device + envelope inspection helpers
    @Keep @JvmStatic fun getDeviceIdBin(): ByteArray = UnifiedNativeApi.getDeviceIdBin()

    /**
     * App-backgrounded transition. Rust owns the whole decision (stop the poller or
     * keep polling because settlement is in flight) and returns ONE directive:
     * true = keep the foreground service alive. Kotlin relays it, nothing more.
     */
    @Keep @JvmStatic fun onAppBackgrounded(): Boolean =
        try { UnifiedNativeApi.onAppBackgrounded() } catch (_: Throwable) { false }
    @Keep @JvmStatic fun getGenesisHashBin(): ByteArray = UnifiedNativeApi.getGenesisHashBin()
    /**
     * Resolve the persisted peer identity for a BLE address.
     * Returns 64 bytes ordered as [device_id(32)][genesis_hash(32)], or empty if unknown.
     */
    @Keep @JvmStatic fun isRejectEnvelope(envelopeBytes: ByteArray): ByteArray =
        UnifiedNativeApi.isRejectEnvelope(envelopeBytes)
    @Keep @JvmStatic fun isErrorEnvelope(envelopeBytes: ByteArray): Int =
        UnifiedNativeApi.isErrorEnvelope(envelopeBytes)

    // ---------- BLE diagnostics helpers (non-external; pure-Kotlin wrappers) ----------
    @Keep @JvmStatic fun getBleStats(deviceAddress: String): ByteArray {
        return UnifiedBleBridge.getBleStats(deviceAddress)
    }

    // ---------- Bluetooth pairing status API ----------
    
    /**
     * Get list of devices with active GATT connections.
     * Returns binary-encoded list of BLE MAC addresses ready for offline transfers.
     * Format: [u32BE count][u32BE len1][addr1_utf8]...[u32BE lenN][addrN_utf8]
     * Note: DSM uses app-level pairing (stored contacts), NOT OS-level bonding.
     * Access control is via contact list, so we only check for active GATT connection here.
     */
    @Keep @JvmStatic fun getConnectedBluetoothDevices(): ByteArray {
        val result = UnifiedBleBridge.getConnectedBluetoothDevices()
        android.util.Log.d("Unified", "getConnectedBluetoothDevices: returning ${result.size} bytes")
        return result
    }
    
    /**
     * Check if a specific device is ready for offline transfers.
     * Returns true if device has active GATT connection.
     * Note: DSM uses app-level pairing (stored contacts), NOT OS-level bonding.
     * Access control is via contact list, so we only check for active GATT connection here.
     */
    @Keep @JvmStatic fun isBluetoothDeviceReady(deviceAddress: String): Boolean {
        val ready = UnifiedBleBridge.isBluetoothDeviceReady(deviceAddress)
        android.util.Log.d("Unified", "isBluetoothDeviceReady($deviceAddress): $ready")
        return ready
    }

    @Keep @JvmStatic fun onConnectionFailed(address: String, reason: String) {
        UnifiedBleEvents.onConnectionFailed(address, reason)
    }

    /**
     * Dispatch BLE permission events to the frontend via JavaScript events.
     */
    @Keep @JvmStatic fun dispatchBlePermissionEvent(eventName: String, detail: String) {
        UnifiedUiBridge.dispatchBlePermissionEvent(eventName, detail)
    }

    // ── Session state (Rust authority) ─────────────────────────────────────

    /**
     * Get the current session snapshot from Rust.
     * Returns naked AppSessionStateProto bytes — relay to WebView untouched.
     */
    @Keep @JvmStatic fun getSessionSnapshot(): ByteArray =
        UnifiedNativeApi.getSessionSnapshot()

    /**
     * Push hardware facts to Rust, get back computed session state.
     * [factsBytes] = SessionHardwareFactsProto encoded bytes (Kotlin encodes hardware facts).
     * Returns naked AppSessionStateProto bytes — relay to WebView untouched.
     */
    @Keep @JvmStatic fun updateSessionHardwareFacts(factsBytes: ByteArray): ByteArray =
        UnifiedNativeApi.updateSessionHardwareFacts(factsBytes)

    /**
     * Set a fatal error on the Rust session manager.
     * Used for pre-bootstrap failures (env config errors).
     * Returns naked AppSessionStateProto bytes — relay to WebView untouched.
     */
    @Keep @JvmStatic fun setSessionFatalError(message: String): ByteArray =
        UnifiedNativeApi.setSessionFatalError(message.toByteArray(Charsets.UTF_8))

    /**
     * Clear the fatal error on the Rust session manager.
     * Returns naked AppSessionStateProto bytes — relay to WebView untouched.
     */
    @Keep @JvmStatic fun clearSessionFatalError(): ByteArray =
        UnifiedNativeApi.clearSessionFatalError()
}
