package com.dsm.wallet.security

import com.dsm.wallet.bridge.UnifiedNativeApi

/**
 * Rust-backed bridge for C-DBRW deterministic ML-KEM-768 encapsulation.
 *
 * Implements Alg. 3 steps 3-4:
 *   coins = BLAKE3("DSM/kyber-coins\0" || h_n || C_pre || DevID || K_DBRW)[0:32]
 *   (ct, ss) = ML-KEM-768.Encaps(pk, coins)
 *   k_step = BLAKE3("DSM/kyber-ss\0" || ss)
 */
object CdbrwKyberNative {
    const val PUBLIC_KEY_BYTES = 1184
    const val SECRET_KEY_BYTES = 2400
    const val CIPHERTEXT_BYTES = 1088

    /**
     * High-level encapsulation returning a typed result.
     */
    data class EncapsResult(val ciphertext: ByteArray, val kStep: ByteArray)

    @JvmStatic
    fun encaps(
        pk: ByteArray, hn: ByteArray, cPre: ByteArray,
        devId: ByteArray, kDbrw: ByteArray
    ): EncapsResult {
        require(pk.size >= PUBLIC_KEY_BYTES) { "pk must be >= $PUBLIC_KEY_BYTES bytes" }
        require(hn.size >= 32 && cPre.size >= 32 && devId.size >= 32 && kDbrw.size >= 32) {
            "All inputs must be >= 32 bytes"
        }
        val result = UnifiedNativeApi.cdbrwEncapsDeterministic(pk, hn, cPre, devId, kDbrw)
            ?: throw IllegalStateException("Rust ML-KEM-768 encapsulation failed")
        require(result.size == 2) { "Rust ML-KEM-768 encapsulation returned malformed result" }
        return EncapsResult(ciphertext = result[0], kStep = result[1])
    }
}
