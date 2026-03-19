package com.dsm.wallet.security

/**
 * C-DBRW Ephemeral Key Derivation — Rust-backed helper facade (Phase 4).
 *
 * Implements Alg. 3 steps 5-8 from the C-DBRW paper:
 *   - Derive k_step = BLAKE3("DSM/kyber-ss\0" || ss)
 *   - Derive E_{n+1} = BLAKE3("DSM/ek\0" || h_n || C_pre || k_step || K_DBRW)
 *   - Generate ephemeral SPHINCS+ keypair from E_{n+1} (via Rust JNI)
 *   - Sign (gamma || ct || c) with EK_sk
 *
 * The actual SPHINCS+ keygen/signing and BLAKE3 domain hashing are handled
 * in Rust via the unified `dsm_sdk` JNI surface. This wrapper remains only
 * as a convenience facade for the DBRW formulas.
 */
object CdbrwEphemeralNative {
    private const val TAG = "CdbrwEphemeral"

    /**
     * Derive the Kyber step key from a shared secret.
     *
     * `k_step = BLAKE3("DSM/kyber-ss\0" || ss)`
     *
     * @param sharedSecret Kyber shared secret (32 bytes)
     * @return 32-byte step key
     */
    @JvmStatic
    fun deriveKStep(sharedSecret: ByteArray): ByteArray {
        require(sharedSecret.size == 32) { "sharedSecret must be 32 bytes" }
        return CdbrwBlake3Native.domainHash("DSM/kyber-ss", sharedSecret)
    }

    /**
     * Derive the ephemeral key seed E_{n+1}.
     *
     * `E_{n+1} = BLAKE3("DSM/ek\0" || h_n || C_pre || k_step || K_DBRW)`
     *
     * @param chainTip Current hash chain tip h_n (32 bytes)
     * @param commitmentPreimage Pre-commitment C_pre (32 bytes)
     * @param kStep Kyber step key (32 bytes)
     * @param kDbrw C-DBRW binding key (32 bytes)
     * @return 32-byte ephemeral seed
     */
    @JvmStatic
    fun deriveEphemeralSeed(
        chainTip: ByteArray,
        commitmentPreimage: ByteArray,
        kStep: ByteArray,
        kDbrw: ByteArray
    ): ByteArray {
        require(chainTip.size == 32) { "chainTip must be 32 bytes" }
        require(commitmentPreimage.size == 32) { "commitmentPreimage must be 32 bytes" }
        require(kStep.size == 32) { "kStep must be 32 bytes" }
        require(kDbrw.size == 32) { "kDbrw must be 32 bytes" }

        val input = ByteArray(128) // 4 * 32
        System.arraycopy(chainTip, 0, input, 0, 32)
        System.arraycopy(commitmentPreimage, 0, input, 32, 32)
        System.arraycopy(kStep, 0, input, 64, 32)
        System.arraycopy(kDbrw, 0, input, 96, 32)

        return CdbrwBlake3Native.domainHash("DSM/ek", input)
    }

    /**
     * Derive deterministic coins for Kyber encapsulation.
     *
     * `coins = BLAKE3("DSM/kyber-coins\0" || h_n || C_pre || DevID || K_DBRW)[0:32]`
     *
     * @param chainTip Current hash chain tip h_n (32 bytes)
     * @param commitmentPreimage Pre-commitment C_pre (32 bytes)
     * @param deviceId Device identity (32 bytes)
     * @param kDbrw C-DBRW binding key (32 bytes)
     * @return 32-byte deterministic coins
     */
    @JvmStatic
    fun deriveKyberCoins(
        chainTip: ByteArray,
        commitmentPreimage: ByteArray,
        deviceId: ByteArray,
        kDbrw: ByteArray
    ): ByteArray {
        require(chainTip.size == 32) { "chainTip must be 32 bytes" }
        require(commitmentPreimage.size == 32) { "commitmentPreimage must be 32 bytes" }
        require(deviceId.size == 32) { "deviceId must be 32 bytes" }
        require(kDbrw.size == 32) { "kDbrw must be 32 bytes" }

        val input = ByteArray(128) // 4 * 32
        System.arraycopy(chainTip, 0, input, 0, 32)
        System.arraycopy(commitmentPreimage, 0, input, 32, 32)
        System.arraycopy(deviceId, 0, input, 64, 32)
        System.arraycopy(kDbrw, 0, input, 96, 32)

        return CdbrwBlake3Native.domainHash("DSM/kyber-coins", input)
    }
}
