package com.dsm.wallet.security

import com.dsm.wallet.bridge.UnifiedNativeApi

/**
 * Rust-backed bridge for C-DBRW SPHINCS+ response signing and verification.
 */
object CdbrwSphincsNative {
    data class SignResult(
        val signature: ByteArray,
        val ephemeralPublicKey: ByteArray
    )

    @JvmStatic
    fun signResponse(
        chainTip: ByteArray,
        commitmentPreimage: ByteArray,
        kStep: ByteArray,
        kDbrw: ByteArray,
        gamma: ByteArray,
        ciphertext: ByteArray,
        challenge: ByteArray
    ): SignResult {
        val result = UnifiedNativeApi.cdbrwSignResponse(
            chainTip,
            commitmentPreimage,
            kStep,
            kDbrw,
            gamma,
            ciphertext,
            challenge
        ) ?: throw IllegalStateException("Rust SPHINCS+ response signing failed")
        require(result.size == 2) { "Rust SPHINCS+ response signing returned malformed result" }
        return SignResult(signature = result[0], ephemeralPublicKey = result[1])
    }

    @JvmStatic
    fun verifyResponseSignature(
        ephemeralPublicKey: ByteArray,
        gamma: ByteArray,
        ciphertext: ByteArray,
        challenge: ByteArray,
        signature: ByteArray
    ): Boolean = UnifiedNativeApi.cdbrwVerifyResponseSignature(
        ephemeralPublicKey,
        gamma,
        ciphertext,
        challenge,
        signature
    )
}
