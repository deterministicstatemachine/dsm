package com.dsm.wallet.security

import android.content.Context
import android.util.Log

/**
 * Hardware anchor result from silicon fingerprint probing.
 */
data class HardwareAnchorResult(
    val anchor: ByteArray?,
    val accessLevel: AccessLevel,
    val trustScore: Float = 1.0f
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is HardwareAnchorResult) return false
        return anchor.contentEquals(other.anchor) &&
            accessLevel == other.accessLevel &&
            trustScore == other.trustScore
    }

    override fun hashCode(): Int {
        var result = anchor?.contentHashCode() ?: 0
        result = 31 * result + accessLevel.hashCode()
        result = 31 * result + trustScore.hashCode()
        return result
    }
}

/**
 * Android-side anti-clone gate — wired to C-DBRW verification protocol.
 *
 * Uses SiliconFingerprint (NDK pointer-chase PUF) for hardware binding,
 * CdbrwEntropyHealth for 3-condition health test, and Rust-backed DBRW
 * crypto helpers for domain-separated hashing, ML-KEM-768, and SPHINCS+.
 *
 * Beta mode: observe-only. Logs anomalies but does not gate access.
 * tau = (epsilon_intra + epsilon_inter) / 2
 */
class AntiCloneGate(private val context: Context) {

    companion object {
        private const val TAG = "AntiCloneGate"

        fun getStableHwAnchorMonitoring(context: Context): HardwareAnchorResult {
            return AntiCloneGate(context).getStableHwAnchorMonitoring()
        }

        fun getEnvironmentFingerprint(context: Context): ByteArray {
            return AntiCloneGate(context).generateEnvironmentFingerprint()
        }

        fun getStableHwAnchorWithTrust(context: Context, fastMode: Boolean = false): HardwareAnchorResult {
            return AntiCloneGate(context).getStableHwAnchorWithTrust(fastMode)
        }
    }

    private val siliconFp = SiliconFingerprint()
    private val verificationProtocol = CdbrwVerificationProtocol(siliconFp)

    /**
     * Get hardware anchor in monitoring mode.
     * Uses SiliconFingerprint for real hardware probing when enrolled,
     * falls back to static hash otherwise. Always grants FULL_ACCESS in beta.
     */
    fun getStableHwAnchorMonitoring(): HardwareAnchorResult {
        return try {
            if (siliconFp.isEnrolled(context)) {
                val derived = siliconFp.derive(context)
                Log.d(TAG, "C-DBRW monitoring: matchScore=${derived.matchScore}, w1=${derived.w1Distance}")
                HardwareAnchorResult(
                    anchor = derived.anchor32,
                    accessLevel = AccessLevel.FULL_ACCESS,
                    trustScore = derived.matchScore
                )
            } else {
                Log.d(TAG, "C-DBRW: not enrolled, returning BLAKE3 hardware hash")
                HardwareAnchorResult(
                    anchor = getBlake3HardwareHash(),
                    accessLevel = AccessLevel.FULL_ACCESS,
                    trustScore = 1.0f
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "C-DBRW monitoring failed, fallback to static hash: ${e.message}")
            HardwareAnchorResult(
                anchor = getBlake3HardwareHash(),
                accessLevel = AccessLevel.FULL_ACCESS,
                trustScore = 0.5f
            )
        }
    }

    /**
     * Get hardware anchor with trust scoring.
     * Runs entropy health test when not in fast mode.
     * Beta: always grants FULL_ACCESS regardless of health test result.
     */
    fun getStableHwAnchorWithTrust(fastMode: Boolean = false): HardwareAnchorResult {
        return try {
            if (!siliconFp.isEnrolled(context)) {
                Log.d(TAG, "C-DBRW: not enrolled, returning BLAKE3 hardware hash")
                return HardwareAnchorResult(
                    anchor = getBlake3HardwareHash(),
                    accessLevel = AccessLevel.FULL_ACCESS,
                    trustScore = 1.0f
                )
            }

            val derived = siliconFp.derive(context)
            var trustScore = derived.matchScore

            // Run entropy health test unless fast mode
            if (!fastMode) {
                try {
                    val env = generateEnvironmentFingerprint()
                    val rawTimings = SiliconFingerprintNative.captureOrbitDensity(
                        envBytes = env,
                        arenaBytes = siliconFp.config.arenaBytes,
                        probes = CdbrwEntropyHealth.HEALTH_N,
                        stepsPerProbe = siliconFp.config.stepsPerProbe,
                        warmupRounds = siliconFp.config.warmupRounds,
                        rotationBits = siliconFp.config.rotationBits
                    )
                    if (rawTimings != null) {
                        val healthResult = CdbrwEntropyHealth.healthTest(rawTimings, siliconFp.config.histogramBins)
                        if (!healthResult.passed) {
                            Log.w(TAG, "Entropy health FAILED: H=${healthResult.hHat}, rho=${healthResult.rhoHat}, L=${healthResult.lHat}")
                            trustScore *= 0.5f // Degrade trust but don't block (beta)
                        } else {
                            Log.d(TAG, "Entropy health PASSED: H=${healthResult.hHat}, rho=${healthResult.rhoHat}, L=${healthResult.lHat}")
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Entropy health test failed: ${e.message}")
                }
            }

            HardwareAnchorResult(
                anchor = derived.anchor32,
                accessLevel = AccessLevel.FULL_ACCESS, // Beta: no gating
                trustScore = trustScore
            )
        } catch (e: Exception) {
            Log.w(TAG, "C-DBRW trust check failed: ${e.message}")
            HardwareAnchorResult(
                anchor = getBlake3HardwareHash(),
                accessLevel = AccessLevel.FULL_ACCESS,
                trustScore = 0.5f
            )
        }
    }

    /**
     * Generate environment fingerprint using BLAKE3 domain-separated hash.
     */
    @Suppress("DEPRECATION")
    fun generateEnvironmentFingerprint(): ByteArray {
        val envData = buildString {
            append(android.os.Build.BOARD); append('|')
            append(android.os.Build.BOOTLOADER); append('|')
            append(android.os.Build.BRAND); append('|')
            append(android.os.Build.DEVICE); append('|')
            append(android.os.Build.HARDWARE); append('|')
            append(android.os.Build.MANUFACTURER); append('|')
            append(android.os.Build.MODEL); append('|')
            append(android.os.Build.PRODUCT); append('|')
            if (android.os.Build.VERSION.SDK_INT >= 31) {
                try {
                    append(android.os.Build.SOC_MANUFACTURER); append('|')
                    append(android.os.Build.SOC_MODEL)
                } catch (_: Throwable) { append("unavailable") }
            } else {
                append("pre31")
            }
        }.toByteArray(Charsets.UTF_8)

        return CdbrwBlake3Native.domainHash("DSM/dbrw-bind", envData)
    }

    /**
     * BLAKE3 hardware hash from Build properties (replaces SHA-256 fallback).
     */
    @Suppress("DEPRECATION")
    private fun getBlake3HardwareHash(): ByteArray {
        val hwData = buildString {
            append(android.os.Build.FINGERPRINT); append('|')
            append(android.os.Build.HARDWARE); append('|')
            append(android.os.Build.BOARD); append('|')
            if (android.os.Build.VERSION.SDK_INT >= 31) {
                try { append(android.os.Build.SOC_MODEL) } catch (_: Throwable) { append("unknown") }
            } else {
                append("pre31")
            }
        }.toByteArray(Charsets.UTF_8)

        return CdbrwBlake3Native.domainHash("DSM/silicon_fp/v4", hwData)
    }
}
