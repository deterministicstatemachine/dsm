// File: android/app/src/main/java/com/dsm/native/DsmNative.kt
// SPDX-License-Identifier: Apache-2.0
// JNI bridge for DSM native functions (Rust SDK)

package com.dsm.native

/**
 * Native JNI functions implemented in Rust dsm_sdk.
 * Library is loaded via Unified class.
 */
object DsmNative {
    init {
        try {
            System.loadLibrary("dsm_sdk")
        } catch (t: Throwable) {
            // Log and fail fast - in dev we might have issues, but this is critical for DBRW
            android.util.Log.e("DsmNative", "Failed to load dsm_sdk library", t)
            throw RuntimeException("Failed to load dsm_sdk library", t)
        }
    }

    /**
     * Initialize the UnilateralSDK and inject it into the bilateral handler.
     * Must be called after genesis creation and SDK context initialization.
     * Implemented in dsm_sdk/src/jni/unified_protobuf_bridge.rs
     * @return true on success, false on failure
     */
    @JvmStatic
    external fun initializeBilateralSdk(): Boolean

    /**
     * Extract device_id and genesis_hash from a GenesisCreated envelope
     * @param envelopeBytes Protobuf-encoded envelope
     * @return Byte array: [device_id 32 bytes][genesis_hash 32 bytes] or empty on error
     */
    @JvmStatic
    external fun extractGenesisIdentity(envelopeBytes: ByteArray): ByteArray
}

class DsmNativeException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
