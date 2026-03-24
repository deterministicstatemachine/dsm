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
//   2. Bootstrap: SinglePathWebViewBridge.bootstrapFromPrefs() or manual
//      Unified.sdkBootstrap(...) with device_id, genesis, DBRW entropy.
//   3. Queries:  Unified.appRouterQueryFramed(framedRequest) -> ByteArray
//   4. Invokes:  Unified.appRouterInvokeFramed(framedRequest) -> ByteArray
//   5. Decode:   strip 0x03 prefix -> Envelope.parseFrom(rest)
//
// PROTOCOL RULES:
//   - All payloads are protobuf ByteArray. No serialization libraries.
//   - All responses carry 0x03 framing prefix + Envelope v3 protobuf.
//   - DO NOT use wall-clock APIs in protocol logic -- clockless.
//   - All crypto (SPHINCS+, ML-KEM-768, DBRW) handled in Rust beneath.
//
// DOMAIN GROUPS:
//   Identity:  sdkBootstrap, extractGenesisIdentity, recordPeerIdentity
//   Protocol:  processEnvelopeV3, processEnvelopeV3WithAddress
//   AppRouter: appRouterQueryFramed, appRouterInvokeFramed
//   Bilateral: bilateralOfflineSend, acceptBilateralByCommitment, ...
//   BLE:       initBleCoordinator, processBleChunk, chunkEnvelopeForBle, ...
//   Contacts:  removeContact, handleContactQrV3, hasContactForDeviceId
//
// Full method list: See UnifiedNativeApi.kt for all 87+ external declarations.
// See docs/INTEGRATION_GUIDE.md for the full developer onboarding guide.
// ============================================================================

/**
 * Unified JNI facade (protobuf-only, context-free).
 * - No JSON, no wall clocks.
 * - All externals are @Keep @JvmStatic to survive R8/Proguard.
 * - No reflection-based dispatch; strict surface.
 */
object Unified {

    /**
     * Called when a peer's identity (genesis hash + device ID) is read from BLE GATT.
     * This should be bridged to Rust/JS as needed.
     */
    @Keep
    @JvmStatic
    fun recordPeerIdentity(address: String, identity: ByteArray) {
        UnifiedNativeApi.recordPeerIdentity(address, identity)
    }

    @Keep
    @JvmStatic
    fun onPeerIdentityReceived(address: String, identity: ByteArray) {
        // Forward to native layer to maintain device_id -> BLE address mapping (no hex at app layer)
        recordPeerIdentity(address, identity)
    }

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
    @Keep @JvmStatic fun initSdkV3(baseDir: String): ByteArray =
        UnifiedNativeApi.initSdkV3(baseDir)
    @Keep @JvmStatic fun initStorageBaseDir(path: ByteArray) {
        UnifiedNativeApi.initStorageBaseDir(path)
    }
    @Keep @JvmStatic fun initDsmSdk(configPath: String) {
        UnifiedNativeApi.initDsmSdk(configPath)
    }
    @Keep @JvmStatic fun getTransportHeadersV3Status(): Byte =
        UnifiedNativeApi.getTransportHeadersV3Status()
    @Keep @JvmStatic fun getTransportHeadersV3(): ByteArray =
        UnifiedNativeApi.getTransportHeadersV3()
    @Keep @JvmStatic fun processEnvelopeV3(envelope: ByteArray): ByteArray =
        UnifiedNativeApi.processEnvelopeV3(envelope)
    @Keep @JvmStatic fun processEnvelopeV3WithAddress(envelope: ByteArray, deviceAddress: String): ByteArray =
        UnifiedNativeApi.processEnvelopeV3WithAddress(envelope, deviceAddress)
    @Keep @JvmStatic fun initializeSdkContext(
        deviceId: ByteArray,
        genesisHash: ByteArray,
        entropy: ByteArray
    ): Boolean = UnifiedNativeApi.initializeSdkContext(deviceId, genesisHash, entropy)

    /**
     * Extract device_id and genesis_hash from a GenesisCreated envelope
     * Returns byte array: [device_id 32 bytes][genesis_hash 32 bytes] or empty on error
     */
    @Keep @JvmStatic fun extractGenesisIdentity(envelopeBytes: ByteArray): ByteArray =
        UnifiedNativeApi.extractGenesisIdentity(envelopeBytes)

    /**
     * Fetch all token balances (strict, protobuf-encoded).
     * Returns: ByteArray (protobuf-encoded TokenBalanceView[])
     */
    @Keep @JvmStatic fun getAllBalancesStrict(): ByteArray =
        UnifiedNativeApi.getAllBalancesStrict()

    /**
     * Fetch wallet history (strict, protobuf-encoded).
     * Returns: ByteArray (protobuf-encoded WalletHistoryResponse)
     */
    @Keep @JvmStatic fun getWalletHistoryStrict(): ByteArray =
        UnifiedNativeApi.getWalletHistoryStrict()

    // App router operations (protobuf payload transport)
    // Query input format: [8-byte reqId][AppRouterPayload protobuf bytes]
    // Invoke input format: [AppRouterPayload protobuf bytes]
    // Query response format: [8-byte reqId][payload]
    @Keep @JvmStatic fun appRouterQueryFramed(framedRequest: ByteArray): ByteArray? =
        UnifiedNativeApi.appRouterQueryFramed(framedRequest)
    @Keep @JvmStatic fun appRouterInvokeFramed(framedRequest: ByteArray): ByteArray? =
        UnifiedNativeApi.appRouterInvokeFramed(framedRequest)

    // BLE bilateral operations
    @Keep @JvmStatic fun bilateralOfflineSend(deviceAddress: String, envelope: ByteArray): ByteArray {
        return UnifiedNativeApi.bilateralOfflineSend(envelope, deviceAddress)
    }

    /**
     * Returns the current monotonic tick from the Rust core.
     * This is the single source of truth for time/ordering in the system.
     */
    @Keep @JvmStatic fun nowTick(): Long = UnifiedNativeApi.nowTick()

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
     * 1 = DBRW_NOT_READY
     * 2 = INSTALLED
     */
    @Keep @JvmStatic fun getAppRouterStatus(): Int = UnifiedNativeApi.getAppRouterStatus()

    /**
     * Compute deterministic b0x address for (genesis, deviceId, tip).
     * All inputs MUST be 32-byte arrays. Returns Base32 Crockford string.
     */
    @Keep @JvmStatic fun computeB0xAddress(genesis: ByteArray, deviceId: ByteArray, tip: ByteArray): String =
        UnifiedNativeApi.computeB0xAddress(genesis, deviceId, tip)

    // ---------- BLE unified surface ----------
    @Keep @JvmStatic fun initBleCoordinator(context: android.content.Context) {
        UnifiedBleBridge.initBleCoordinator(context) { eventName, detail ->
            dispatchBlePermissionEvent(eventName, detail)
        }
    }

    /**
     * Request a GATT write to the DSM TX characteristic of the given device.
     * Returns true if the async flow was successfully started.
     */
    @Keep @JvmStatic fun requestGattWrite(deviceAddress: String, transactionData: ByteArray): Boolean {
        return UnifiedBleBridge.requestGattWrite(deviceAddress, transactionData)
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

    /**
     * Stop BLE advertising. Called by Rust pairing loop on exit to prevent lingering advertise.
     */
    @Keep @JvmStatic fun stopBlePairingAdvertise(): Boolean {
        return UnifiedBleBridge.stopBlePairingAdvertise()
    }

    // ---------- Event notifications ----------
    @Keep @JvmStatic fun bleNotifyConnectionState(address: String, connected: Boolean) {
        UnifiedNativeApi.bleNotifyConnectionState(address, connected)
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

    /**
     * Notify the pairing orchestrator that a BLE identity was observed.
     * This should be called after successfully reading a peer's identity characteristic.
     * address: BLE MAC address
     * genesisHash: 32-byte genesis hash from identity
     * deviceId: 32-byte device ID from identity
     */
    @Keep @JvmStatic fun notifyBleIdentityObserved(address: String, genesisHash: ByteArray, deviceId: ByteArray) {
        UnifiedNativeApi.notifyBleIdentityObserved(address, genesisHash, deviceId)
    }
    
    /**
     * Check if there are any contacts that are not yet BLE-capable (need pairing).
     * Used to determine if persistent BLE scanning should be active.
     * Returns true if there are unpaired contacts, false if all contacts are BleCapable.
     */
    @Keep @JvmStatic fun hasUnpairedContacts(): Boolean = UnifiedNativeApi.hasUnpairedContacts()

    
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
    @Keep @JvmStatic fun processBleIdentityEnvelope(envelopeBytes: ByteArray, senderBleAddress: String): ByteArray =
        UnifiedNativeApi.processBleIdentityEnvelope(envelopeBytes, senderBleAddress)

    /**
     * Atomic pairing Phase 3b (scanner side).
     * Finalizes the scanner session after the BlePairingConfirm GATT write is acknowledged
     * by the BLE stack (onCharacteristicWrite → PairingConfirmWritten event).
     * Persists ble_address to SQLite and marks the session Complete.
     * Returns true on success; false if no ConfirmSent session found (benign on retry).
     */
    @Keep @JvmStatic fun finalizeScannerPairing(bleAddress: String): Boolean =
        UnifiedNativeApi.finalizeScannerPairing(bleAddress)

    /**
     * Encode genesis_hash + device_id as protobuf BleIdentityCharValue.
     * Returns proto bytes to set on the GATT identity characteristic.
     * Kotlin MUST NOT concatenate raw bytes — this is the canonical encoder.
     */
    @Keep @JvmStatic fun encodeIdentityCharValue(genesisHash: ByteArray, deviceId: ByteArray): ByteArray =
        UnifiedNativeApi.encodeIdentityCharValue(genesisHash, deviceId)

    /**
     * Process raw protobuf bytes read from the GATT identity characteristic.
     * Rust decodes BleIdentityCharValue, dispatches identity events, and returns
     * BleGattIdentityReadResult with the write-back envelope.
     * Kotlin MUST NOT split or interpret identity bytes.
     */
    @Keep @JvmStatic fun processGattIdentityRead(bleAddress: String, rawProtoBytes: ByteArray): ByteArray =
        UnifiedNativeApi.processGattIdentityRead(bleAddress, rawProtoBytes)

    @Keep @JvmStatic fun createTransactionErrorEnvelope(address: String, code: Int, message: String): ByteArray? =
        UnifiedNativeApi.createTransactionErrorEnvelope(address, code, message)
        
    // ---------- Contact management ----------
    @Keep @JvmStatic fun removeContact(contactId: String): Byte =
        UnifiedNativeApi.removeContact(contactId)
    @Keep @JvmStatic fun handleContactQrV3(contactQrV3Bytes: ByteArray): ByteArray =
        UnifiedNativeApi.handleContactQrV3(contactQrV3Bytes)

    // ---------- Bilateral BLE operations ----------
    
    /**
     * Check if BleFrameCoordinator has been injected and is ready to process BLE chunks.
     * MUST be called before passing any BLE chunks to processBleChunk to avoid dropping frames.
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
     * Process incoming BLE chunk (bilateral frame).
     * Returns empty array if chunk is buffered (multi-chunk reassembly in progress).
     * Returns response envelope bytes if frame is complete and processed.
     * 
     * IMPORTANT: Call isBleCoordinatorReady() before calling this method.
     * If coordinator is not ready, chunks will be dropped silently.
     */
    /**
     * Process incoming BLE chunk (bilateral frame) for a specific device address.
     * NOTE: Signature updated to include deviceAddress to match JNI binding in unified_protobuf_bridge.rs
     */
    @Keep @JvmStatic fun processBleChunk(deviceAddress: String, chunkBytes: ByteArray): ByteArray =
        UnifiedNativeApi.processBleChunk(deviceAddress, chunkBytes)

    /**
     * Returns true if the payload is a framed Envelope v3 (0x03 prefix) that expects
     * a protocol acknowledgment before the BLE transaction is marked complete.
     * Kotlin MUST NOT inspect payload[0] — call this instead.
     */
    @Keep @JvmStatic fun requiresBleAck(payloadBytes: ByteArray): Boolean =
        UnifiedNativeApi.requiresBleAck(payloadBytes)

    /**
     * Unified BLE incoming data router. Returns a serialized BleIncomingDataResponse
     * (not Envelope v3 framed) containing pre-chunked response bytes to write back.
     * Kotlin MUST NOT inspect data[0] or branch on frame type — call this instead.
     */
    @Keep @JvmStatic fun processIncomingBleData(deviceAddress: String, data: ByteArray): ByteArray =
        UnifiedNativeApi.processIncomingBleData(deviceAddress, data)

    /** Extract response_chunks from a BleIncomingDataResponse proto (returned by processIncomingBleData). */
    @Keep @JvmStatic fun bleDataResponseExtractChunks(responseProto: ByteArray): Array<ByteArray> =
        UnifiedNativeApi.bleDataResponseExtractChunks(responseProto)

    /** Extract flags from a BleIncomingDataResponse proto. Bit 0 = pairing_complete, bit 1 = use_reliable_write. */
    @Keep @JvmStatic fun bleDataResponseGetFlags(responseProto: ByteArray): Int =
        UnifiedNativeApi.bleDataResponseGetFlags(responseProto)

    /** Extract exact BilateralConfirm commitment hash from a BleIncomingDataResponse proto, if present. */
    @Keep @JvmStatic fun bleDataResponseExtractConfirmCommitmentHash(responseProto: ByteArray): ByteArray =
        UnifiedNativeApi.bleDataResponseExtractConfirmCommitmentHash(responseProto)

    /** Extract success flag from a BleGattIdentityReadResult proto (returned by processGattIdentityRead). */
    @Keep @JvmStatic fun identityReadResultGetSuccess(responseProto: ByteArray): Boolean =
        UnifiedNativeApi.identityReadResultGetSuccess(responseProto)

    /** Extract write_back_envelope bytes from a BleGattIdentityReadResult proto. */
    @Keep @JvmStatic fun identityReadResultExtractWriteBack(responseProto: ByteArray): ByteArray =
        UnifiedNativeApi.identityReadResultExtractWriteBack(responseProto)

    /**
     * Called after bilateral prepare succeeds.
     * deviceAddress: BLE MAC address of recipient
     * chunks: Array of byte arrays, each containing a protobuf BleChunk
     * Returns true if async send was successfully initiated.
     */
    @Keep @JvmStatic fun sendBleChunks(deviceAddress: String, chunks: Array<ByteArray>): Boolean =
        UnifiedNativeApi.sendBleChunks(deviceAddress, chunks)

    /**
     * Optimized multi-chunk writer invoked by JNI (sendBleChunks) after chunk diagnostics.
     * Reuses / establishes a SINGLE GATT connection and writes all provided BleChunk protobuf
     * messages sequentially, advancing only after onCharacteristicWrite callbacks succeed.
     * Falls back to per-chunk failure envelope on first error.
     */
    @Keep @JvmStatic fun requestGattWriteChunks(deviceAddress: String, chunks: Array<ByteArray>): Boolean {
        return UnifiedBleBridge.requestGattWriteChunks(deviceAddress, chunks)
    }

    @Keep @JvmStatic fun dispatchRustBleFollowUp(deviceAddress: String, chunks: Array<ByteArray>, useReliableWrite: Boolean): Boolean {
        return UnifiedBleBridge.dispatchRustFollowUp(deviceAddress, chunks, useReliableWrite)
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

    /**
     * Notify Rust that the BilateralConfirm envelope was successfully delivered to the receiver
     * over BLE. Transitions the sender's session from ConfirmPending → Committed, prunes the
     * persisted session, and fires BilateralEventTransferComplete so the sender UI refreshes.
     * commitmentHashBytes: exactly 32 bytes — the commitment hash of the completed transfer.
     * Returns true on success, false if the session is not found or already committed (idempotent).
     */
    @Keep @JvmStatic fun markBilateralConfirmDelivered(commitmentHashBytes: ByteArray): Boolean =
        UnifiedNativeApi.markBilateralConfirmDelivered(commitmentHashBytes)

    /**
     * No-argument variant: sweeps all ConfirmPending sessions and marks each Committed.
     * Use this when the 32-byte commitment hash is not available at the Kotlin call-site
     * (e.g., post BilateralConfirm chunk queueing in BleCoordinator).
     * Returns the number of sessions transitioned; typically 1 for a BLE connection.
     */
    @Keep @JvmStatic fun markAnyBilateralConfirmDelivered(): Int =
        UnifiedNativeApi.markAnyBilateralConfirmDelivered()

    /**
     * Canonical offline send validation + response generation.
     * Returns a response Envelope (UniversalRx) with BilateralPrepareResponse results or an error Envelope.
     * Rust prepends 0x03 framing; both success and error paths return Envelope v3.
     */
    @Keep @JvmStatic fun bilateralOfflineSend(envelopeBytes: ByteArray, bleAddress: String): ByteArray =
        UnifiedNativeApi.bilateralOfflineSend(envelopeBytes, bleAddress)

    /**
     * Passthrough for bilateralOfflineSend — propagates Rust exceptions to the caller.
     * Rust returns Envelope v3 (0x03 framed) for both success and error; no status-byte
     * framing is applied here. Callers should wrap with try/catch.
     */
    @Keep @JvmStatic fun bilateralOfflineSendSafe(deviceAddress: String, envelope: ByteArray): ByteArray =
        bilateralOfflineSend(envelope, deviceAddress)



    // Device + envelope inspection helpers
    @Keep @JvmStatic fun getDeviceIdBin(): ByteArray = UnifiedNativeApi.getDeviceIdBin()
    @Keep @JvmStatic fun getGenesisHashBin(): ByteArray = UnifiedNativeApi.getGenesisHashBin()
    /**
     * Get the local signing public key (64 bytes for SPHINCS+ SPX256s).
     * Used for bilateral transaction verification and QR code generation.
     * @return 64-byte signing public key or empty array if not initialized
     */
    @Keep @JvmStatic fun getSigningPublicKeyBin(): ByteArray =
        UnifiedNativeApi.getSigningPublicKeyBin()
    /**
     * Get the current BLE MAC address for a device_id by searching identity cache.
     * @param deviceId Raw 32-byte device ID
     * @return UTF-8 BLE MAC address bytes or empty array if not found/connected
     */
    @Keep @JvmStatic fun resolveBleAddressForDeviceIdBin(deviceId: ByteArray): ByteArray =
        UnifiedNativeApi.resolveBleAddressForDeviceIdBin(deviceId)
    /**
     * Retrieve 32-byte local chain tip for a remote device (for identity payload composition).
     * @param deviceAddress MAC address or hex device ID
     * @return 32-byte chain tip or empty array if unavailable
     */
    @Keep @JvmStatic fun getLocalChainTipBin(deviceAddress: String): ByteArray =
        UnifiedNativeApi.getLocalChainTipBin(deviceAddress)
    @Keep @JvmStatic fun isRejectEnvelope(envelopeBytes: ByteArray): ByteArray =
        UnifiedNativeApi.isRejectEnvelope(envelopeBytes)
    @Keep @JvmStatic fun isErrorEnvelope(envelopeBytes: ByteArray): Int =
        UnifiedNativeApi.isErrorEnvelope(envelopeBytes)

    /**
     * Chunk a response envelope into BLE chunks for transmission.
     * Returns array of BleChunk protobuf messages ready to send.
     */
    @Keep @JvmStatic fun chunkEnvelopeForBle(envelopeBytes: ByteArray, frameType: Int): Array<ByteArray> =
        UnifiedNativeApi.chunkEnvelopeForBle(envelopeBytes, frameType)
    
    /**
     * Chunk a response envelope into BLE chunks for transmission with explicit counterparty.
     * Use this for response envelopes (like BilateralPrepareResponse) where the counterparty
     * cannot be extracted from the payload.
     * @param envelopeBytes The protobuf-encoded envelope to chunk
     * @param frameType BLE frame type (1=prepare, 2=prepare_response, 3=commit, etc.)
     * @param counterpartyDeviceId 32-byte device ID of the counterparty
     * Returns array of BleChunk protobuf messages ready to send.
     */
    @Keep @JvmStatic fun chunkEnvelopeForBleWithCounterparty(
        envelopeBytes: ByteArray, 
        frameType: Int, 
        counterpartyDeviceId: ByteArray
    ): Array<ByteArray> = UnifiedNativeApi.chunkEnvelopeForBleWithCounterparty(
        envelopeBytes,
        frameType,
        counterpartyDeviceId
    )
    
    /**
     * Force initialization of the BLE frame coordinator if genesis-time injection was skipped.
     * Returns true if coordinator is present or injected successfully.
     */
    @Keep @JvmStatic fun forceBleCoordinatorInit(): Boolean = UnifiedNativeApi.forceBleCoordinatorInit()

    // ---------- Bilateral manual accept gate ----------
    @Keep @JvmStatic fun setManualAcceptEnabled(enabled: Boolean) {
        UnifiedNativeApi.setManualAcceptEnabled(enabled)
    }

    // ---------- BLE diagnostics + retry helpers (non-external; pure-Kotlin wrappers) ----------
    @Keep @JvmStatic fun getBleStats(deviceAddress: String): ByteArray {
        return UnifiedBleBridge.getBleStats(deviceAddress)
    }

    @Keep @JvmStatic fun retryLastBleTransaction(deviceAddress: String): Boolean {
        return UnifiedBleBridge.retryLastBleTransaction(deviceAddress)
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

    // ---------- Runtime JNI surface self-test (non-fatal) ----------
    /**
     * Performs lightweight invocation tests of core JNI externals.
     * Returns binary report: [u32BE count] then per entry [u16BE nameLen][name][ok_byte][u16BE detailLen][detail].
     * Never throws; failure details captured per entry.
     */
    @Keep @JvmStatic fun runNativeBridgeSelfTest(): ByteArray {
        return UnifiedNativeDiagnostics.runNativeBridgeSelfTest()
    }

    /**
     * Collect a live Android-side C-DBRW runtime snapshot for the Rust `dbrw.status` route.
     *
     * The returned bytes use the fixed binary layout defined in `UnifiedCdbrwBridge`.
     * Empty means runtime metrics are currently unavailable (for example, no active activity).
     */
    @Keep @JvmStatic fun getCdbrwRuntimeSnapshot(): ByteArray {
        return UnifiedCdbrwBridge.collectRuntimeSnapshot()
    }

    // ---------- BLE pairing orchestration (Rust-driven loop) ----------

    /**
     * Start the Rust pairing orchestrator loop that scans all unpaired contacts
     * and drives BLE pairing automatically. Fire-and-forget — status updates are
     * delivered via PairingStatusUpdate BleEvent envelopes through the event bus.
     */
    @Keep @JvmStatic fun startPairingAll() {
        UnifiedNativeApi.startPairingAll()
    }

    /**
     * Signal the Rust pairing orchestrator to stop its loop at the next cycle boundary.
     */
    @Keep @JvmStatic fun stopPairingAll() {
        UnifiedNativeApi.stopPairingAll()
    }

    @Keep @JvmStatic fun onConnectionFailed(address: String, reason: String) {
        UnifiedBleEvents.onConnectionFailed(address, reason)
    }

    /**
     * Safe wrapper for appRouterInvokeFramed that returns binary error envelope on failure.
     */
    @Keep @JvmStatic fun appRouterInvokeFramedSafe(framedRequest: ByteArray): ByteArray {
        return UnifiedNativeDiagnostics.appRouterInvokeFramedSafe(framedRequest)
    }

    /**
     * Safe wrapper for appRouterQueryFramed that returns binary error envelope on failure.
     */
    @Keep @JvmStatic fun appRouterQueryFramedSafe(framedRequest: ByteArray): ByteArray {
        return UnifiedNativeDiagnostics.appRouterQueryFramedSafe(framedRequest)
    }

    /**
     * Receive a deferred BlePairingAccept from Rust's async identity retry.
     * Called from a tokio background thread via JNI when the contact was not in
     * SQLite at identity-write time but appeared during the polling window.
     */
    @Keep @JvmStatic fun deliverDeferredPairingAck(deviceAddress: String, ackBytes: ByteArray) {
        UnifiedBleBridge.deliverDeferredPairingAck(deviceAddress, ackBytes)
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
