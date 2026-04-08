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
     * Returns a live C-DBRW anchor when enrollment is present.
     */
    fun getStableHwAnchorMonitoring(): HardwareAnchorResult {
        return try {
            if (!siliconFp.isEnrolled(context)) {
                Log.w(TAG, "C-DBRW monitoring blocked: device is not enrolled")
                return HardwareAnchorResult(
                    anchor = null,
                    accessLevel = AccessLevel.BLOCKED,
                    trustScore = 0.0f
                )
            }

            val derived = siliconFp.derive(context)
            val drifted = derived.w1Distance > derived.w1Threshold
            val accessLevel = if (drifted) AccessLevel.PIN_REQUIRED else AccessLevel.FULL_ACCESS
            if (drifted) {
                Log.w(TAG, "C-DBRW monitoring detected reference drift; escalating to PIN_REQUIRED")
            } else {
                Log.d(TAG, "C-DBRW monitoring: matchScore=${derived.matchScore}, w1=${derived.w1Distance}")
            }

            HardwareAnchorResult(
                anchor = derived.anchor32,
                accessLevel = accessLevel,
                trustScore = derived.matchScore.coerceIn(0.0f, 1.0f)
            )
        } catch (e: Exception) {
            Log.e(TAG, "C-DBRW monitoring failed", e)
            HardwareAnchorResult(
                anchor = null,
                accessLevel = AccessLevel.BLOCKED,
                trustScore = 0.0f
            )
        }
    }

    /**
     * Get hardware anchor with trust scoring.
     * Runs entropy health test when not in fast mode.
     */
    fun getStableHwAnchorWithTrust(fastMode: Boolean = false): HardwareAnchorResult {
        return try {
            if (!siliconFp.isEnrolled(context)) {
                Log.w(TAG, "C-DBRW trust check blocked: device is not enrolled")
                return HardwareAnchorResult(
                    anchor = null,
                    accessLevel = AccessLevel.BLOCKED,
                    trustScore = 0.0f
                )
            }

            val derived = siliconFp.derive(context)
            var trustScore = derived.matchScore.coerceIn(0.0f, 1.0f)
            var resonantStatus: CdbrwEntropyHealth.ResonantStatus? = null

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
                        resonantStatus = healthResult.resonantStatus
                        when (healthResult.resonantStatus) {
                            CdbrwEntropyHealth.ResonantStatus.PASS,
                            CdbrwEntropyHealth.ResonantStatus.RESONANT -> {
                                Log.d(TAG, "Entropy health accepted: status=${healthResult.resonantStatus}, H=${healthResult.hHat}, rho=${healthResult.rhoHat}, L=${healthResult.lHat}")
                            }
                            CdbrwEntropyHealth.ResonantStatus.ADAPTED -> {
                                trustScore *= 0.75f
                                Log.w(TAG, "Entropy health adapted: longer orbit or step-up auth required; H=${healthResult.hHat}, rho=${healthResult.rhoHat}, L=${healthResult.lHat}")
                            }
                            CdbrwEntropyHealth.ResonantStatus.FAIL -> {
                                trustScore = 0.0f
                                Log.w(TAG, "Entropy health rejected: H=${healthResult.hHat}, rho=${healthResult.rhoHat}, L=${healthResult.lHat}")
                            }
                        }
                    } else {
                        resonantStatus = CdbrwEntropyHealth.ResonantStatus.FAIL
                        trustScore = 0.0f
                        Log.w(TAG, "Entropy health failed: orbit capture returned no samples")
                    }
                } catch (e: Exception) {
                    resonantStatus = CdbrwEntropyHealth.ResonantStatus.FAIL
                    trustScore = 0.0f
                    Log.e(TAG, "Entropy health test failed", e)
                }
            }

            val drifted = derived.w1Distance > derived.w1Threshold
            val accessLevel = resolveAccessLevel(resonantStatus, drifted)

            HardwareAnchorResult(
                anchor = derived.anchor32,
                accessLevel = accessLevel,
                trustScore = trustScore
            )
        } catch (e: Exception) {
            Log.e(TAG, "C-DBRW trust check failed", e)
            HardwareAnchorResult(
                anchor = null,
                accessLevel = AccessLevel.BLOCKED,
                trustScore = 0.0f
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

    private fun resolveAccessLevel(
        resonantStatus: CdbrwEntropyHealth.ResonantStatus?,
        drifted: Boolean
    ): AccessLevel {
        return when {
            resonantStatus == CdbrwEntropyHealth.ResonantStatus.FAIL -> AccessLevel.READ_ONLY
            drifted -> AccessLevel.PIN_REQUIRED
            resonantStatus == CdbrwEntropyHealth.ResonantStatus.ADAPTED -> AccessLevel.PIN_REQUIRED
            else -> AccessLevel.FULL_ACCESS
        }
    }
}
