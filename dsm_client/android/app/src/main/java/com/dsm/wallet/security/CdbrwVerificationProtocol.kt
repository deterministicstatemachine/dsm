package com.dsm.wallet.security

import android.content.Context
import android.util.Log

/**
 * C-DBRW 2-Round Verification Protocol — Device Side (Protocol 6.2).
 *
 * Round 1: Verifier sends challenge `c` (32 random bytes).
 * Round 2: Device responds with `(gamma, ct, sigma)`:
 *   - gamma = BLAKE3("DSM/cdbrw-response\0" || H_bar || c)
 *     where H_bar is the current orbit histogram (Alg. 3, step 2).
 *   - ct = ML-KEM-768.Encaps(pk_verifier, coins)
 *     with coins = BLAKE3("DSM/kyber-coins\0" || h_n || C_pre || DevID || K_DBRW)
 *   - sigma = SPHINCS+.Sign(EK_sk, gamma || ct || c) using a deterministic
 *     ephemeral keypair derived from the current chain state.
 */
class CdbrwVerificationProtocol(
    private val siliconFp: SiliconFingerprint = SiliconFingerprint()
) {
    companion object {
        private const val TAG = "CdbrwVerify"
    }

    /**
     * Device response to a verifier challenge.
     */
    data class DeviceResponse(
        val gamma: ByteArray,         // 32 bytes: orbit-bound response
        val ciphertext: ByteArray,    // 1088 bytes: ML-KEM-768 ciphertext
        val signature: ByteArray,     // SPHINCS+ signature over (gamma || ct || c)
        val ephemeralPublicKey: ByteArray, // SPHINCS+ ephemeral public key
        val healthResult: CdbrwEntropyHealth.HealthResult
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as DeviceResponse
            return gamma.contentEquals(other.gamma) &&
                    ciphertext.contentEquals(other.ciphertext) &&
                    signature.contentEquals(other.signature) &&
                    ephemeralPublicKey.contentEquals(other.ephemeralPublicKey)
        }
        override fun hashCode(): Int {
            var result = gamma.contentHashCode()
            result = 31 * result + ciphertext.contentHashCode()
            result = 31 * result + signature.contentHashCode()
            result = 31 * result + ephemeralPublicKey.contentHashCode()
            return result
        }
    }

    /**
     * Respond to verifier challenge `c`.
     *
     * @param context Android context for silicon fingerprint access
     * @param challenge 32-byte verifier challenge
     * @param verifierPk Verifier's ML-KEM-768 public key (1184 bytes)
     * @param deviceId Device identity (32 bytes)
     * @param kDbrw C-DBRW binding key (32 bytes)
     * @param chainTip Current hash chain tip h_n (32 bytes)
     * @param commitmentPreimage Commitment preimage C_pre (32 bytes)
     * @return DeviceResponse or null on failure
     */
    fun respondToChallenge(
        context: Context,
        challenge: ByteArray,
        verifierPk: ByteArray,
        deviceId: ByteArray,
        kDbrw: ByteArray,
        chainTip: ByteArray,
        commitmentPreimage: ByteArray
    ): DeviceResponse {
        require(challenge.size == 32) { "Challenge must be 32 bytes" }
        require(verifierPk.size >= CdbrwKyberNative.PUBLIC_KEY_BYTES) { "Invalid verifier public key" }
        require(deviceId.size >= 32 && kDbrw.size >= 32) { "deviceId and kDbrw must be >= 32 bytes" }

        Log.d(TAG, "Processing challenge (${challenge.take(4).joinToString("") { "%02x".format(it) }}...)")

        // Step 1: Capture fresh orbit and run entropy health test
        val env = environmentBytes(context)
        val rawTimings = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = env,
            arenaBytes = siliconFp.config.arenaBytes,
            probes = CdbrwEntropyHealth.HEALTH_N,
            stepsPerProbe = siliconFp.config.stepsPerProbe,
            warmupRounds = siliconFp.config.warmupRounds,
            rotationBits = siliconFp.config.rotationBits
        ) ?: throw IllegalStateException("Silicon fingerprint capture failed")

        // Step 2: Health test (3-condition, before any auth)
        val healthResult = CdbrwEntropyHealth.healthTest(rawTimings, siliconFp.config.histogramBins)
        if (!healthResult.passed) {
            Log.w(TAG, "Entropy health test rejected challenge response: status=${healthResult.resonantStatus}, H=${healthResult.hHat}, rho=${healthResult.rhoHat}, L=${healthResult.lHat}")
            throw IllegalStateException("Device entropy health failed; cannot authenticate challenge")
        }

        // Step 3: Build histogram -> H_bar
        val histogram = CdbrwMath.buildHistogram(rawTimings, siliconFp.config.histogramBins)
        val hBarBytes = CdbrwMath.histogramToBytes(histogram)

        // Step 4: gamma = BLAKE3("DSM/cdbrw-response\0" || H_bar || c) — Alg. 3, step 2
        val gammaInput = ByteArray(hBarBytes.size + challenge.size)
        System.arraycopy(hBarBytes, 0, gammaInput, 0, hBarBytes.size)
        System.arraycopy(challenge, 0, gammaInput, hBarBytes.size, challenge.size)
        val gamma = CdbrwBlake3Native.domainHash("DSM/cdbrw-response", gammaInput)

        // Step 5: ML-KEM-768 deterministic encapsulation
        val encapsResult = CdbrwKyberNative.encaps(
            pk = verifierPk,
            hn = chainTip,
            cPre = commitmentPreimage,
            devId = deviceId,
            kDbrw = kDbrw
        )

        // Step 6: Sign (gamma || ct || c) with a Rust-derived ephemeral SPHINCS+ keypair.
        val signResult = CdbrwSphincsNative.signResponse(
            chainTip = chainTip,
            commitmentPreimage = commitmentPreimage,
            kStep = encapsResult.kStep,
            kDbrw = kDbrw,
            gamma = gamma,
            ciphertext = encapsResult.ciphertext,
            challenge = challenge
        )

        Log.d(TAG, "Challenge response: gamma=${gamma.take(4).joinToString("") { "%02x".format(it) }}..., status=${healthResult.resonantStatus}")

        return DeviceResponse(
            gamma = gamma,
            ciphertext = encapsResult.ciphertext,
            signature = signResult.signature,
            ephemeralPublicKey = signResult.ephemeralPublicKey,
            healthResult = healthResult
        )
    }

    @Suppress("DEPRECATION")
    private fun environmentBytes(context: Context): ByteArray {
        val s = buildString {
            append("DSM/silicon_env/v2\u0000")
            append(android.os.Build.BOARD); append('|')
            append(android.os.Build.BRAND); append('|')
            append(android.os.Build.DEVICE); append('|')
            append(android.os.Build.HARDWARE); append('|')
            append(android.os.Build.MANUFACTURER); append('|')
            append(android.os.Build.MODEL); append('|')
            if (android.os.Build.VERSION.SDK_INT >= 31) {
                try {
                    val socModel = android.os.Build::class.java.getField("SOC_MODEL").get(null) as? String
                    append(socModel ?: "unknown")
                } catch (_: Throwable) { append("unavailable") }
            } else { append("pre31") }
            append('|')
            append(context.packageName)
        }
        return s.toByteArray(Charsets.UTF_8)
    }
}
