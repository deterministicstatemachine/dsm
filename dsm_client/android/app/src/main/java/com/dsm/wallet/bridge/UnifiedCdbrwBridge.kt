package com.dsm.wallet.bridge

import android.content.Context
import android.util.Log
import com.dsm.wallet.security.AntiCloneGate
import com.dsm.wallet.security.CdbrwEntropyHealth
import com.dsm.wallet.security.SiliconFingerprint
import com.dsm.wallet.security.SiliconFingerprintNative
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream

internal object UnifiedCdbrwBridge {
    private const val TAG = "UnifiedCdbrwBridge"
    private const val SNAPSHOT_VERSION = 1
    private const val FLAG_RUNTIME_AVAILABLE = 1 shl 0
    private const val FLAG_ENROLLED = 1 shl 1
    private const val FLAG_ANCHOR_PRESENT = 1 shl 2
    private const val FLAG_HEALTH_RAN = 1 shl 3
    private const val FLAG_HEALTH_PASSED = 1 shl 4
    private const val FLAG_DERIVE_RAN = 1 shl 5
    private const val FLAG_DERIVE_PASSED = 1 shl 6
    private const val PREFIX_BYTES = 10

    private data class RuntimeSnapshot(
        val enrolled: Boolean,
        val accessLevel: String,
        val trustScore: Float,
        val healthRan: Boolean,
        val healthPassed: Boolean,
        val hHat: Float,
        val rhoHat: Float,
        val lHat: Float,
        val matchScore: Float,
        val w1Distance: Float,
        val w1Threshold: Float,
        val anchorPrefix: ByteArray,
        val deriveRan: Boolean,
        val derivePassed: Boolean,
        val errorMessage: String,
    ) {
        fun encode(): ByteArray {
            var flags = FLAG_RUNTIME_AVAILABLE
            if (enrolled) flags = flags or FLAG_ENROLLED
            if (anchorPrefix.isNotEmpty()) flags = flags or FLAG_ANCHOR_PRESENT
            if (healthRan) flags = flags or FLAG_HEALTH_RAN
            if (healthPassed) flags = flags or FLAG_HEALTH_PASSED
            if (deriveRan) flags = flags or FLAG_DERIVE_RAN
            if (derivePassed) flags = flags or FLAG_DERIVE_PASSED

            return ByteArrayOutputStream().use { baos ->
                DataOutputStream(baos).use { out ->
                    out.writeInt(SNAPSHOT_VERSION)
                    out.writeInt(flags)
                    out.writeFloat(trustScore)
                    out.writeFloat(matchScore)
                    out.writeFloat(w1Distance)
                    out.writeFloat(w1Threshold)
                    out.writeFloat(hHat)
                    out.writeFloat(rhoHat)
                    out.writeFloat(lHat)
                    out.writeInt(anchorPrefix.size)
                    out.write(anchorPrefix)
                    writeUtf8(out, accessLevel)
                    writeUtf8(out, errorMessage)
                }
                baos.toByteArray()
            }
        }
    }

    @JvmStatic
    fun collectRuntimeSnapshot(): ByteArray {
        val context = com.dsm.wallet.ui.MainActivity.getActiveInstance()?.applicationContext
            ?: return ByteArray(0)
        return try {
            collectRuntimeSnapshot(context).encode()
        } catch (t: Throwable) {
            Log.w(TAG, "collectRuntimeSnapshot failed", t)
            RuntimeSnapshot(
                enrolled = false,
                accessLevel = "UNAVAILABLE",
                trustScore = 0f,
                healthRan = false,
                healthPassed = false,
                hHat = 0f,
                rhoHat = 0f,
                lHat = 0f,
                matchScore = 0f,
                w1Distance = 0f,
                w1Threshold = 0f,
                anchorPrefix = ByteArray(0),
                deriveRan = false,
                derivePassed = false,
                errorMessage = t.message ?: "runtime snapshot failed",
            ).encode()
        }
    }

    private fun collectRuntimeSnapshot(context: Context): RuntimeSnapshot {
        val siliconFp = SiliconFingerprint()
        val enrolled = siliconFp.isEnrolled(context)
        val errors = mutableListOf<String>()

        var accessLevel = "FULL_ACCESS"
        var trustScore = 1.0f
        var matchScore = 0f
        var w1Distance = 0f
        var w1Threshold = 0f
        var hHat = 0f
        var rhoHat = 0f
        var lHat = 0f
        var healthRan = false
        var healthPassed = false
        var deriveRan = false
        var derivePassed = false
        var anchorPrefix = ByteArray(0)

        val monitoringAnchor = try {
            val result = AntiCloneGate.getStableHwAnchorMonitoring(context)
            accessLevel = result.accessLevel.name
            trustScore = result.trustScore
            result.anchor
        } catch (t: Throwable) {
            errors += "monitoring=${t.message ?: "failed"}"
            null
        }

        if (monitoringAnchor != null && monitoringAnchor.isNotEmpty()) {
            anchorPrefix = monitoringAnchor.copyOfRange(0, minOf(PREFIX_BYTES, monitoringAnchor.size))
        }

        if (enrolled) {
            try {
                deriveRan = true
                val derived = siliconFp.derive(context)
                derivePassed = true
                matchScore = derived.matchScore
                w1Distance = derived.w1Distance
                w1Threshold = derived.w1Threshold
                trustScore = derived.matchScore
                if (derived.anchor32.isNotEmpty()) {
                    anchorPrefix = derived.anchor32.copyOfRange(0, minOf(PREFIX_BYTES, derived.anchor32.size))
                }
            } catch (t: Throwable) {
                errors += "derive=${t.message ?: "failed"}"
            }

            try {
                val env = AntiCloneGate.getEnvironmentFingerprint(context)
                val rawTimings = SiliconFingerprintNative.captureOrbitDensity(
                    envBytes = env,
                    arenaBytes = siliconFp.config.arenaBytes,
                    probes = CdbrwEntropyHealth.HEALTH_N,
                    stepsPerProbe = siliconFp.config.stepsPerProbe,
                    warmupRounds = siliconFp.config.warmupRounds,
                    rotationBits = siliconFp.config.rotationBits,
                )
                if (rawTimings != null) {
                    val health = CdbrwEntropyHealth.healthTest(rawTimings, siliconFp.config.histogramBins)
                    healthRan = true
                    healthPassed = health.passed
                    hHat = health.hHat
                    rhoHat = health.rhoHat
                    lHat = health.lHat
                    // Trust penalty scaled by resonant tier (C-DBRW spec §7, §8.1)
                    when (health.resonantStatus) {
                        CdbrwEntropyHealth.ResonantStatus.PASS,
                        CdbrwEntropyHealth.ResonantStatus.RESONANT -> { /* no penalty */ }
                        CdbrwEntropyHealth.ResonantStatus.ADAPTED -> trustScore *= 0.75f
                        CdbrwEntropyHealth.ResonantStatus.FAIL -> trustScore *= 0.5f
                    }
                } else {
                    errors += "health=no_samples"
                }
            } catch (t: Throwable) {
                errors += "health=${t.message ?: "failed"}"
            }
        }

        return RuntimeSnapshot(
            enrolled = enrolled,
            accessLevel = accessLevel,
            trustScore = trustScore,
            healthRan = healthRan,
            healthPassed = healthPassed,
            hHat = hHat,
            rhoHat = rhoHat,
            lHat = lHat,
            matchScore = matchScore,
            w1Distance = w1Distance,
            w1Threshold = w1Threshold,
            anchorPrefix = anchorPrefix,
            deriveRan = deriveRan,
            derivePassed = derivePassed,
            errorMessage = errors.joinToString("; "),
        )
    }

    private fun writeUtf8(out: DataOutputStream, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        out.writeInt(bytes.size)
        out.write(bytes)
    }
}
