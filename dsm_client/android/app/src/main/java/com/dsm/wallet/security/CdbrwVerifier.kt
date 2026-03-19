package com.dsm.wallet.security

import com.dsm.wallet.bridge.UnifiedNativeApi
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Rust-backed C-DBRW verifier bridge.
 *
 * Kotlin does not hold the verifier decapsulation key or reimplement protocol
 * crypto. It only marshals inputs to the authoritative Rust verifier.
 */
object CdbrwVerifier {
    data class VerificationResult(
        val accepted: Boolean,
        val reason: String,
        val gammaDistance: Float = 0f,
        val threshold: Float = 0f
    )

    @JvmStatic
    fun ensureVerifierPublicKey(): ByteArray =
        UnifiedNativeApi.cdbrwEnsureVerifierPublicKey()
            ?: throw IllegalStateException("Rust verifier public key unavailable")

    /**
     * Verify a device's challenge response using the Rust verifier.
     *
     * @param challenge The original 32-byte challenge sent to device
     * @param gamma Device's orbit-bound response (32 bytes)
     * @param ciphertext ML-KEM-768 ciphertext from device (1088 bytes)
     * @param signature SPHINCS+ signature over (gamma || ct || c)
     * @param ephemeralPk Device's derived ephemeral SPHINCS+ public key
     * @param chainTip Current hash chain tip h_n (32 bytes)
     * @param commitmentPreimage Commitment preimage C_pre (32 bytes)
     * @param enrollmentAnchor Device's enrolled reference anchor (32 bytes)
     * @param epsilonIntra Device's enrolled intra-device variance
     * @param epsilonInter Estimated inter-device variance
     */
    @JvmStatic
    fun verify(
        challenge: ByteArray,
        gamma: ByteArray,
        ciphertext: ByteArray,
        signature: ByteArray,
        ephemeralPk: ByteArray,
        chainTip: ByteArray,
        commitmentPreimage: ByteArray,
        enrollmentAnchor: ByteArray,
        epsilonIntra: Float,
        epsilonInter: Float
    ): VerificationResult {
        val encoded = UnifiedNativeApi.cdbrwVerifyChallengeResponse(
            challenge = challenge,
            gamma = gamma,
            ciphertext = ciphertext,
            signature = signature,
            ephemeralPublicKey = ephemeralPk,
            chainTip = chainTip,
            commitmentPreimage = commitmentPreimage,
            enrollmentAnchor = enrollmentAnchor,
            epsilonIntra = epsilonIntra,
            epsilonInter = epsilonInter
        ) ?: throw IllegalStateException("Rust verifier failed")

        require(encoded.size >= 9) { "Rust verifier returned malformed result" }
        val gammaDistance =
            ByteBuffer.wrap(encoded, 1, 4).order(ByteOrder.LITTLE_ENDIAN).float
        val threshold =
            ByteBuffer.wrap(encoded, 5, 4).order(ByteOrder.LITTLE_ENDIAN).float
        val reason =
            encoded.copyOfRange(9, encoded.size).toString(Charsets.UTF_8)
        return VerificationResult(
            accepted = encoded[0].toInt() != 0,
            reason = reason,
            gammaDistance = gammaDistance,
            threshold = threshold
        )
    }
}
