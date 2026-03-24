package com.dsm.wallet.bridge

import android.util.Log
import androidx.annotation.Keep

// ============================================================================
// DSM APP INTEGRATION BOUNDARY -- JNI Symbol Table
// ============================================================================
//
// This file declares all 87+ JNI symbols implemented in the Rust SDK shared
// library (libdsm_sdk.so). Each method maps 1:1 to a Rust function named
// Java_com_dsm_wallet_bridge_UnifiedNativeApi_<method>.
//
// STABILITY:
//   These method signatures are the stable JNI ABI. Do NOT rename, reorder
//   parameters, or change return types without updating the corresponding
//   Rust export in dsm_sdk/src/jni/unified_protobuf_bridge.rs.
//
// VERIFICATION:
//   nm -gU libdsm_sdk.so | grep -c Java_   -> expect 87+
//   If count drops after a Rust rebuild, a symbol was accidentally removed.
//
// ALL METHODS:
//   - Accept/return ByteArray (protobuf bytes) or primitive types.
//   - NO JSON, NO String-encoded payloads in protocol methods.
//   - @Keep @JvmStatic external -- survived R8/Proguard minification.
//
// See Unified.kt for the public-facing facade that wraps these declarations.
// See docs/INTEGRATION_GUIDE.md for the full developer onboarding guide.
// ============================================================================

/**
 * Native JNI surface grouped under a thin wrapper to reduce Unified.kt size.
 * All methods delegate to JNI externals defined on Unified.
 */
internal object UnifiedNativeApi {
    init {
        @Suppress("SwallowedException")
        try {
            System.loadLibrary("dsm_sdk")
        } catch (t: Throwable) {
            Log.e("UnifiedNativeApi", "Failed to load native library dsm_sdk", t)
            throw RuntimeException("Failed to load native library dsm_sdk", t)
        }
    }

    @Keep @JvmStatic external fun recordPeerIdentity(address: String, identity: ByteArray)
    @Keep @JvmStatic external fun initSdk(baseDir: String): Boolean
    @Keep @JvmStatic external fun initSdkV3(baseDir: String): ByteArray
    @Keep @JvmStatic external fun initStorageBaseDir(path: ByteArray)
    @Keep @JvmStatic external fun initDsmSdk(configPath: String)
    @Keep @JvmStatic external fun getTransportHeadersV3Status(): Byte
    @Keep @JvmStatic external fun getTransportHeadersV3(): ByteArray
    @Keep @JvmStatic external fun processEnvelopeV3(envelope: ByteArray): ByteArray
    @Keep @JvmStatic external fun processEnvelopeV3WithAddress(envelope: ByteArray, deviceAddress: String): ByteArray
    @Keep @JvmStatic external fun initializeSdkContext(deviceId: ByteArray, genesisHash: ByteArray, entropy: ByteArray): Boolean
    @Keep @JvmStatic external fun extractGenesisIdentity(envelopeBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun getAllBalancesStrict(): ByteArray
    @Keep @JvmStatic external fun getWalletHistoryStrict(): ByteArray
    @Keep @JvmStatic external fun appRouterQueryFramed(framedRequest: ByteArray): ByteArray?
    @Keep @JvmStatic external fun appRouterInvokeFramed(framedRequest: ByteArray): ByteArray?
    @Keep @JvmStatic external fun bilateralOfflineSend(envelopeBytes: ByteArray, bleAddress: String): ByteArray
    @Keep @JvmStatic external fun nowTick(): Long
    @Keep @JvmStatic external fun ensureAppRouterInstalled(): Boolean
    @Keep @JvmStatic external fun getAppRouterStatus(): Int
    @Keep @JvmStatic external fun computeB0xAddress(genesis: ByteArray, deviceId: ByteArray, tip: ByteArray): String
    @Keep @JvmStatic external fun cdbrwDomainHash(tag: ByteArray, data: ByteArray): ByteArray?
    @Keep @JvmStatic external fun cdbrwEncapsDeterministic(
        publicKey: ByteArray,
        chainTip: ByteArray,
        commitmentPreimage: ByteArray,
        deviceId: ByteArray,
        kDbrw: ByteArray
    ): Array<ByteArray>?
    @Keep @JvmStatic external fun cdbrwEnsureVerifierPublicKey(): ByteArray?
    @Keep @JvmStatic external fun cdbrwSignResponse(
        chainTip: ByteArray,
        commitmentPreimage: ByteArray,
        kStep: ByteArray,
        kDbrw: ByteArray,
        gamma: ByteArray,
        ciphertext: ByteArray,
        challenge: ByteArray
    ): Array<ByteArray>?
    @Keep @JvmStatic external fun cdbrwVerifyChallengeResponse(
        challenge: ByteArray,
        gamma: ByteArray,
        ciphertext: ByteArray,
        signature: ByteArray,
        ephemeralPublicKey: ByteArray,
        chainTip: ByteArray,
        commitmentPreimage: ByteArray,
        enrollmentAnchor: ByteArray,
        epsilonIntra: Float,
        epsilonInter: Float
    ): ByteArray?
    @Keep @JvmStatic external fun cdbrwVerifyResponseSignature(
        ephemeralPublicKey: ByteArray,
        gamma: ByteArray,
        ciphertext: ByteArray,
        challenge: ByteArray,
        signature: ByteArray
    ): Boolean
    @Keep @JvmStatic external fun bleNotifyConnectionState(address: String, connected: Boolean)
    @Keep @JvmStatic external fun hasContactForDeviceId(deviceId: ByteArray): Boolean
    @Keep @JvmStatic external fun isBleAddressPaired(address: String): Boolean
    @Keep @JvmStatic external fun isCommitEnvelope(envelope: ByteArray): Boolean
    @Keep @JvmStatic external fun notifyBleIdentityObserved(address: String, genesisHash: ByteArray, deviceId: ByteArray)
    @Keep @JvmStatic external fun hasUnpairedContacts(): Boolean
    @Keep @JvmStatic external fun createTransactionErrorEnvelope(address: String, code: Int, message: String): ByteArray?
    @Keep @JvmStatic external fun removeContact(contactId: String): Byte
    @Keep @JvmStatic external fun handleContactQrV3(contactQrV3Bytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun isBleCoordinatorReady(): Boolean
    @Keep @JvmStatic external fun detectEnvelopeFrameType(envelopeBytes: ByteArray): Int
    @Keep @JvmStatic external fun processBleChunk(deviceAddress: String, chunkBytes: ByteArray): ByteArray
    /** Returns true if payload is a framed Envelope v3 that expects a BLE protocol ACK. */
    @Keep @JvmStatic external fun requiresBleAck(payloadBytes: ByteArray): Boolean
    /** Unified BLE incoming data router. Returns serialized BleIncomingDataResponse. */
    @Keep @JvmStatic external fun processIncomingBleData(deviceAddress: String, data: ByteArray): ByteArray
    /** Extract response_chunks from a BleIncomingDataResponse proto. */
    @Keep @JvmStatic external fun bleDataResponseExtractChunks(responseProto: ByteArray): Array<ByteArray>
    /** Extract flags from a BleIncomingDataResponse proto. Bit 0 = pairing_complete, bit 1 = use_reliable_write. */
    @Keep @JvmStatic external fun bleDataResponseGetFlags(responseProto: ByteArray): Int
    /** Extract exact BilateralConfirm commitment hash from a BleIncomingDataResponse proto, if present. */
    @Keep @JvmStatic external fun bleDataResponseExtractConfirmCommitmentHash(responseProto: ByteArray): ByteArray
    /** Extract success flag from a BleGattIdentityReadResult proto. */
    @Keep @JvmStatic external fun identityReadResultGetSuccess(responseProto: ByteArray): Boolean
    /** Extract write_back_envelope bytes from a BleGattIdentityReadResult proto. */
    @Keep @JvmStatic external fun identityReadResultExtractWriteBack(responseProto: ByteArray): ByteArray
    @Keep @JvmStatic external fun sendBleChunks(deviceAddress: String, chunks: Array<ByteArray>): Boolean
    @Keep @JvmStatic external fun acceptBilateralByCommitment(commitmentHashBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun rejectBilateralByCommitment(commitmentHashBytes: ByteArray, reason: String): ByteArray
    @Keep @JvmStatic external fun chunkEnvelopeForBle(envelopeBytes: ByteArray, frameType: Int): Array<ByteArray>
    @Keep @JvmStatic external fun chunkEnvelopeForBleWithCounterparty(envelopeBytes: ByteArray, frameType: Int, counterpartyDeviceId: ByteArray): Array<ByteArray>
    @Keep @JvmStatic external fun forceBleCoordinatorInit(): Boolean
    @Keep @JvmStatic external fun markBilateralConfirmDelivered(commitmentHashBytes: ByteArray): Boolean
    @Keep @JvmStatic external fun markAnyBilateralConfirmDelivered(): Int
    @Keep @JvmStatic external fun setManualAcceptEnabled(enabled: Boolean)
    @Keep @JvmStatic external fun getDeviceIdBin(): ByteArray
    @Keep @JvmStatic external fun getGenesisHashBin(): ByteArray
    @Keep @JvmStatic external fun getSigningPublicKeyBin(): ByteArray
    @Keep @JvmStatic external fun resolveBleAddressForDeviceIdBin(deviceId: ByteArray): ByteArray
    @Keep @JvmStatic external fun getLocalChainTipBin(deviceAddress: String): ByteArray
    @Keep @JvmStatic external fun isRejectEnvelope(envelopeBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun isErrorEnvelope(envelopeBytes: ByteArray): Int

    // BLE identity envelope processor (decodes protobuf envelope + uses GATT sender address)
    @Keep @JvmStatic external fun processBleIdentityEnvelope(envelopeBytes: ByteArray, senderBleAddress: String): ByteArray

    // Atomic pairing Phase 3b (scanner side): finalize after BlePairingConfirm GATT write ACK.
    // Called from BleCoordinator.PairingConfirmWritten (onCharacteristicWrite callback).
    // Returns true on success, false if no matching ConfirmSent session (benign — already finalized).
    @Keep @JvmStatic external fun finalizeScannerPairing(bleAddress: String): Boolean

    // Encode genesis_hash + device_id as protobuf BleIdentityCharValue for GATT characteristic.
    // Kotlin MUST NOT concatenate raw bytes — this is the canonical encoder.
    @Keep @JvmStatic external fun encodeIdentityCharValue(genesisHash: ByteArray, deviceId: ByteArray): ByteArray

    // Process raw protobuf bytes read from GATT identity characteristic.
    // Decodes BleIdentityCharValue, dispatches identity events, returns BleGattIdentityReadResult.
    // Kotlin MUST NOT split or interpret the raw bytes.
    @Keep @JvmStatic external fun processGattIdentityRead(bleAddress: String, rawProtoBytes: ByteArray): ByteArray

    // BLE event envelope builders (JNI symbols in ble_events.rs)
    @Keep @JvmStatic external fun createBleDeviceFoundEnvelope(address: String, name: String, rssi: Int): ByteArray
    @Keep @JvmStatic external fun createBleScanStartedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createBleScanStoppedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createBleAdvertisingStartedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createBleAdvertisingStoppedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createBleConnectionEstablishedEnvelope(address: String, name: String): ByteArray
    @Keep @JvmStatic external fun createBleConnectionLostEnvelope(address: String): ByteArray
    // Genesis lifecycle envelopes — Rust authors all content, Kotlin relays verbatim
    @Keep @JvmStatic external fun createGenesisStartedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createGenesisOkEnvelope(): ByteArray
    @Keep @JvmStatic external fun createGenesisErrorEnvelope(): ByteArray
    @Keep @JvmStatic external fun createGenesisSecuringDeviceEnvelope(): ByteArray
    @Keep @JvmStatic external fun createGenesisSecuringProgressEnvelope(progress: Int): ByteArray
    @Keep @JvmStatic external fun createGenesisSecuringCompleteEnvelope(): ByteArray
    @Keep @JvmStatic external fun createGenesisSecuringAbortedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createBlePermissionDeniedEnvelope(operation: String): ByteArray
    @Keep @JvmStatic external fun createNfcRecoveryCapsuleEnvelope(payload: ByteArray): ByteArray
    @Keep @JvmStatic external fun createNfcBackupWrittenEnvelope(): ByteArray

    // BLE pairing orchestration (Rust-driven loop)
    @Keep @JvmStatic external fun startPairingAll()
    @Keep @JvmStatic external fun stopPairingAll()

    // Session state — Rust owns session computation, Kotlin relays bytes to WebView
    @Keep @JvmStatic external fun getSessionSnapshot(): ByteArray
    @Keep @JvmStatic external fun updateSessionHardwareFacts(factsBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun setSessionFatalError(message: ByteArray): ByteArray
    @Keep @JvmStatic external fun clearSessionFatalError(): ByteArray

    // NFC Ring Backup — Rust owns all capsule creation/content; Kotlin writes raw bytes to NFC tag
    @Keep @JvmStatic external fun getPendingRecoveryCapsule(): ByteArray
    @Keep @JvmStatic external fun prepareNfcWritePayload(capsuleBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun clearPendingRecoveryCapsule()
    /** Silently refresh pending NFC capsule after state mutations. No-op if backup disabled. */
    @Keep @JvmStatic external fun maybeRefreshNfcCapsule()
}
