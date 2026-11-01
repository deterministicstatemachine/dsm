// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import android.util.Log
import androidx.annotation.Keep

// ============================================================================
// DSM APP INTEGRATION BOUNDARY -- JNI Symbol Table
// ============================================================================
//
// This file declares every JNI symbol implemented in the Rust SDK shared
// library (libdsm_sdk.so). Each method maps 1:1 to a Rust function named
// Java_com_dsm_wallet_bridge_UnifiedNativeApi_<method>.
//
// STABILITY:
//   These method signatures are the stable JNI ABI. Do NOT rename, reorder
//   parameters, or change return types without updating the corresponding
//   Rust export in dsm_sdk/src/jni/unified_protobuf_bridge.rs.
//
// VERIFICATION:
//   nm -gU libdsm_sdk.so | grep -c Java_   -> must match `external fun` count
//   If the check fails after a Rust rebuild, a symbol was accidentally
//   added or removed without updating the Kotlin side.
//
// ALL METHODS:
//   - Accept/return ByteArray (protobuf bytes) or primitive types.
//   - NO JSON, NO String-encoded payloads in protocol methods.
//   - @Keep @JvmStatic external -- survived R8/Proguard minification.
//
// See Unified.kt for the public-facing facade that wraps these declarations.
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

    @Keep @JvmStatic external fun initSdk(baseDir: String): Boolean
    @Keep @JvmStatic external fun initStorageBaseDir(path: ByteArray)
    @Keep @JvmStatic external fun initDsmSdk(configPath: String)
    @Keep @JvmStatic external fun dispatchStartup(requestBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun dispatchIngress(requestBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun getTransportHeadersV3Status(): Byte
    @Keep @JvmStatic external fun getTransportHeadersV3(): ByteArray
    @Keep @JvmStatic external fun processEnvelopeV3(envelope: ByteArray): ByteArray
    @Keep @JvmStatic external fun getAllBalancesStrict(): ByteArray
    @Keep @JvmStatic external fun ensureAppRouterInstalled(): Boolean
    @Keep @JvmStatic external fun getAppRouterStatus(): Int
    @Keep @JvmStatic external fun hasContactForDeviceId(deviceId: ByteArray): Boolean
    @Keep @JvmStatic external fun isBleAddressPaired(address: String): Boolean
    @Keep @JvmStatic external fun isCommitEnvelope(envelope: ByteArray): Boolean
    @Keep @JvmStatic external fun createTransactionErrorEnvelope(address: String, code: Int, message: String): ByteArray?
    @Keep @JvmStatic external fun isBleCoordinatorReady(): Boolean
    @Keep @JvmStatic external fun detectEnvelopeFrameType(envelopeBytes: ByteArray): Int
    /** The radio's entry: bytes a peer wrote over BLE. Returns serialized BleIncomingDataResponse. */
    @Keep @JvmStatic external fun processIncomingBleData(deviceAddress: String, role: Int, data: ByteArray): ByteArray
    /** A GATT link came up; returns the radio bytes to write on it (DSM Amendment A27). */
    @Keep @JvmStatic external fun bleLinkOpened(address: String, role: Int, target: ByteArray): Array<ByteArray>
    /** A GATT link closed. */
    @Keep @JvmStatic external fun bleLinkClosed(address: String, role: Int)
    /** Extract response_chunks from a BleIncomingDataResponse proto. */
    @Keep @JvmStatic external fun bleDataResponseExtractChunks(responseProto: ByteArray): Array<ByteArray>
    /** Extract use_reliable_write from a BleIncomingDataResponse proto. */
    @Keep @JvmStatic external fun bleDataResponseUsesReliableWrite(responseProto: ByteArray): Boolean
    @Keep @JvmStatic external fun acceptBilateralByCommitment(commitmentHashBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun rejectBilateralByCommitment(commitmentHashBytes: ByteArray, reason: String): ByteArray
    @Keep @JvmStatic external fun cancelBilateralByCommitment(commitmentHashBytes: ByteArray, reason: String): ByteArray
    @Keep @JvmStatic external fun getDeviceIdBin(): ByteArray

    /**
     * App-backgrounded transition. Rust stops the poller (or declines to) and returns
     * the directive: true = the host MUST keep its foreground service alive.
     */
    @Keep @JvmStatic external fun onAppBackgrounded(): Boolean
    @Keep @JvmStatic external fun getGenesisHashBin(): ByteArray
    @Keep @JvmStatic external fun isRejectEnvelope(envelopeBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun isErrorEnvelope(envelopeBytes: ByteArray): Int



    // BLE event envelope builders (JNI symbols in ble_events.rs)
    @Keep @JvmStatic external fun createBleDeviceFoundEnvelope(address: String, name: String, rssi: Int): ByteArray
    @Keep @JvmStatic external fun createBleScanStartedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createBleScanStoppedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createBleAdvertisingStartedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createBleAdvertisingStoppedEnvelope(): ByteArray
    @Keep @JvmStatic external fun createBleConnectionEstablishedEnvelope(address: String, name: String): ByteArray
    @Keep @JvmStatic external fun createBleConnectionLostEnvelope(address: String): ByteArray
    @Keep @JvmStatic external fun createBlePermissionDeniedEnvelope(operation: String): ByteArray

    // BLE pairing orchestration (Rust-driven loop)

    // Session state — Rust owns session computation, Kotlin relays bytes to WebView
    @Keep @JvmStatic external fun getSessionSnapshot(): ByteArray
    @Keep @JvmStatic external fun updateSessionHardwareFacts(factsBytes: ByteArray): ByteArray
    @Keep @JvmStatic external fun setSessionFatalError(message: ByteArray): ByteArray
    @Keep @JvmStatic external fun clearSessionFatalError(): ByteArray
}
