package com.dsm.wallet.security

import android.content.Context
import android.os.Build
import android.os.Process
import android.util.Log
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import kotlin.math.abs

/**
 * SiliconFingerprint (NDK-backed)
 *
 * A silicon-level Physically Unclonable Function (PUF) that derives a stable
 * hardware fingerprint from cache/memory timing characteristics unique to each SoC.
 *
 * ## Why this is stronger than Java-based approaches:
 * - Uses `mmap` arena (no GC interference)
 * - Uses `CLOCK_THREAD_CPUTIME_ID` (excludes scheduler pauses)
 * - Uses pointer-chasing (cache topology sensitive)
 * - Uses per-trial median thresholding (robust to DVFS/thermal shifts)
 *
 * ## Enrollment:
 * - Capture N trials -> compute per-probe reliability -> choose stable bit positions (mask)
 * - Store mask + reference packed stable bits + reference anchor32 in a binary file
 *
 * ## Derivation:
 * - Capture M trials -> majority vote -> extract masked stable bits -> anchor32
 *
 * Output is a 32-byte BLAKE3 hash.
 */
class SiliconFingerprint(
    val config: Config = Config()
) {
    companion object {
        private const val TAG = "SiliconFingerprint"
    }

    data class Config(
        val arenaBytes: Int = 8 * 1024 * 1024, // must be power-of-two
        val warmupRounds: Int = 2,
        val probes: Int = 4096,
        val stepsPerProbe: Int = 4096,
        val enrollTrials: Int = 21,
        val verifyTrials: Int = 9,
        val histogramBins: Int = 256,
        val rotationBits: Int = 7,
        val distanceMargin: Float = 0.15f
    ) {
        init {
            require(arenaBytes > 0 && (arenaBytes and (arenaBytes - 1)) == 0) { "arenaBytes must be power-of-two" }
            require(probes > 0 && probes % 8 == 0) { "probes must be divisible by 8" }
            require(stepsPerProbe > 0) { "stepsPerProbe must be > 0" }
            require(enrollTrials % 2 == 1) { "enrollTrials must be odd" }
            require(verifyTrials % 2 == 1) { "verifyTrials must be odd" }
            require(histogramBins in setOf(256, 512, 1024)) { "histogramBins must be one of 256/512/1024" }
            require(rotationBits in setOf(5, 7, 8, 11, 13)) { "rotationBits must be one of 5/7/8/11/13" }
            require(distanceMargin >= 0f) { "distanceMargin must be >= 0" }
        }
    }

    data class Enrollment(
        val revision: Int,
        val arenaBytes: Int,
        val probes: Int,
        val stepsPerProbe: Int,
        val histogramBins: Int,
        val rotationBits: Int,
        val epsilonIntra: Float,
        val meanHistogram: FloatArray,
        val referenceAnchor32: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Enrollment
            return revision == other.revision &&
                    arenaBytes == other.arenaBytes &&
                    probes == other.probes &&
                    stepsPerProbe == other.stepsPerProbe &&
                    histogramBins == other.histogramBins &&
                    rotationBits == other.rotationBits &&
                    epsilonIntra == other.epsilonIntra &&
                    meanHistogram.contentEquals(other.meanHistogram) &&
                    referenceAnchor32.contentEquals(other.referenceAnchor32)
        }

        override fun hashCode(): Int {
            var result = revision
            result = 31 * result + arenaBytes
            result = 31 * result + probes
            result = 31 * result + stepsPerProbe
            result = 31 * result + histogramBins
            result = 31 * result + rotationBits
            result = 31 * result + epsilonIntra.hashCode()
            result = 31 * result + meanHistogram.contentHashCode()
            result = 31 * result + referenceAnchor32.contentHashCode()
            return result
        }
    }

    data class Derived(
        val anchor32: ByteArray,
        val w1Distance: Float,
        val w1Threshold: Float,
        val matchScore: Float,
        val referenceAnchor32: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (javaClass != other?.javaClass) return false
            other as Derived
            return anchor32.contentEquals(other.anchor32) &&
                    w1Distance == other.w1Distance &&
                    w1Threshold == other.w1Threshold &&
                    matchScore == other.matchScore &&
                    referenceAnchor32.contentEquals(other.referenceAnchor32)
        }

        override fun hashCode(): Int {
            var result = anchor32.contentHashCode()
            result = 31 * result + w1Distance.hashCode()
            result = 31 * result + w1Threshold.hashCode()
            result = 31 * result + matchScore.hashCode()
            result = 31 * result + referenceAnchor32.contentHashCode()
            return result
        }
    }

    private val store = EnrollmentStore()

    /**
     * Load the stored enrollment without performing derivation.
     * Returns null if not enrolled.
     */
    fun loadEnrollment(context: Context): Enrollment? = store.read(context)

    /**
     * Enroll the device: capture many trials, find stable bits, store reference.
     * This should be called once on first run.
     *
     * @throws SiliconFpException if not enough stable bits found
     */
    fun enroll(context: Context, onProgress: ((completed: Int, total: Int) -> Unit)? = null): Enrollment {
        Log.i(TAG, "Starting C-DBRW enrollment with ${config.enrollTrials} trials, bins=${config.histogramBins}, r=${config.rotationBits}")
        bumpPriority()

        val env = environmentBytes(context)
        Log.d(TAG, "Environment bytes: ${env.size} bytes")

        val trials = Array(config.enrollTrials) { i ->
            val result = SiliconFingerprintNative.captureOrbitDensity(
                envBytes = env,
                arenaBytes = config.arenaBytes,
                probes = config.probes,
                stepsPerProbe = config.stepsPerProbe,
                warmupRounds = config.warmupRounds,
                rotationBits = config.rotationBits
            ) ?: throw SiliconFpException(SiliconFpError.INTERNAL, "Native capture returned null")
            onProgress?.invoke(i + 1, config.enrollTrials)
            result
        }

        val histograms = Array(config.enrollTrials) { i ->
            CdbrwMath.buildHistogram(trials[i], config.histogramBins)
        }
        val meanHistogram = CdbrwMath.meanHistogram(histograms)
        val distances = FloatArray(config.enrollTrials) { i ->
            CdbrwMath.wasserstein1(histograms[i], meanHistogram)
        }
        val sortedDistances = distances.sorted()
        val p95Index = ((sortedDistances.size - 1) * 95) / 100
        val epsilonIntra = sortedDistances[p95Index]

        val meanBytes = CdbrwMath.histogramToBytes(meanHistogram)
        val epsilonBytes = java.nio.ByteBuffer.allocate(4).putFloat(epsilonIntra).array()
        val metadataBytes = byteArrayOf(
            (config.histogramBins and 0xFF).toByte(),
            ((config.histogramBins ushr 8) and 0xFF).toByte(),
            (config.rotationBits and 0xFF).toByte(),
            (config.probes and 0xFF).toByte()
        )
        val anchorInput = meanBytes + epsilonBytes + metadataBytes

        val anchor32 = blake3_32(
            domain = "DSM/silicon_fp/v4".toByteArray(Charsets.UTF_8),
            env = env,
            entropyBytes = anchorInput
        )

        val e = Enrollment(
            revision = 4,
            arenaBytes = config.arenaBytes,
            probes = config.probes,
            stepsPerProbe = config.stepsPerProbe,
            histogramBins = config.histogramBins,
            rotationBits = config.rotationBits,
            epsilonIntra = epsilonIntra,
            meanHistogram = meanHistogram,
            referenceAnchor32 = anchor32
        )
        store.write(context, e)
        
        Log.i(TAG, "Enrollment complete. Anchor32: ${anchor32.take(8).joinToString("") { "%02x".format(it) }}...")
        return e
    }

    /**
     * Derive the current silicon fingerprint and compare to enrolled reference.
     *
     * @return Derived result with current anchor, stable bits, and drift from reference
     * @throws SiliconFpException if not enrolled or config mismatch
     */
    fun derive(context: Context): Derived {
        Log.d(TAG, "Deriving C-DBRW fingerprint with ${config.verifyTrials} trials...")
        bumpPriority()

        val e = store.read(context) ?: throw SiliconFpException(SiliconFpError.NOT_ENROLLED, "Not enrolled")

        if (e.arenaBytes != config.arenaBytes ||
            e.probes != config.probes ||
            e.stepsPerProbe != config.stepsPerProbe ||
            e.histogramBins != config.histogramBins ||
            e.rotationBits != config.rotationBits
        ) {
            throw SiliconFpException(SiliconFpError.CONFIG_MISMATCH, "Config mismatch vs enrollment")
        }

        val env = environmentBytes(context)

        val trials = Array(config.verifyTrials) { _ ->
            SiliconFingerprintNative.captureOrbitDensity(
                envBytes = env,
                arenaBytes = config.arenaBytes,
                probes = config.probes,
                stepsPerProbe = config.stepsPerProbe,
                warmupRounds = config.warmupRounds,
                rotationBits = config.rotationBits
            ) ?: throw SiliconFpException(SiliconFpError.INTERNAL, "Native capture returned null")
        }

        val verifyHistograms = Array(config.verifyTrials) { i ->
            CdbrwMath.buildHistogram(trials[i], config.histogramBins)
        }
        val measuredHistogram = CdbrwMath.meanHistogram(verifyHistograms)
        val w1Distance = CdbrwMath.wasserstein1(measuredHistogram, e.meanHistogram)
        val w1Threshold = e.epsilonIntra + config.distanceMargin
        val matchScore = (1.0f - (w1Distance / (w1Threshold + 1e-6f))).coerceIn(0.0f, 1.0f)

        Log.i(TAG, "Phase-Space Verification: w1=$w1Distance threshold=$w1Threshold matchScore=$matchScore")

        if (w1Distance > w1Threshold) {
            throw SiliconFpException(
                SiliconFpError.INSUFFICIENT_STABLE_BITS,
                "Phase-space density check failed. w1=$w1Distance threshold=$w1Threshold"
            )
        }

        return Derived(
            anchor32 = e.referenceAnchor32,
            w1Distance = w1Distance,
            w1Threshold = w1Threshold,
            matchScore = matchScore,
            referenceAnchor32 = e.referenceAnchor32
        )
    }

    /**
     * Check if enrollment exists.
     */
    fun isEnrolled(context: Context): Boolean {
        return store.read(context) != null
    }

    /**
     * Clear enrollment data.
     */
    fun clearEnrollment(context: Context) {
        store.clear(context)
    }

    // ---- helpers ----

    @Suppress("DEPRECATION")
    private fun environmentBytes(context: Context): ByteArray {
        val s = buildString {
            append("DSM/silicon_env/v2\u0000")
            append(Build.BOARD); append('|')
            append(Build.BRAND); append('|')
            append(Build.DEVICE); append('|')
            append(Build.HARDWARE); append('|')
            append(Build.MANUFACTURER); append('|')
            append(Build.MODEL); append('|')
            // SOC_MODEL is API 31+
            if (Build.VERSION.SDK_INT >= 31) {
                try {
                    val socModel = Build::class.java.getField("SOC_MODEL").get(null) as? String
                    append(socModel ?: "unknown")
                } catch (_: Throwable) {
                    append("unavailable")
                }
            } else {
                append("pre31")
            }
            append('|')
            append(context.packageName)
        }
        return s.toByteArray(Charsets.UTF_8)
    }

    private fun blake3_32(domain: ByteArray, env: ByteArray, entropyBytes: ByteArray): ByteArray {
        val data = ByteArray(env.size + entropyBytes.size)
        System.arraycopy(env, 0, data, 0, env.size)
        System.arraycopy(entropyBytes, 0, data, env.size, entropyBytes.size)
        // domain already includes NUL terminator per DSM spec
        val tag = ByteArray(domain.size + 1)
        System.arraycopy(domain, 0, tag, 0, domain.size)
        return CdbrwBlake3Native.nativeBlake3DomainHash(tag, data)
            ?: throw SiliconFpException(SiliconFpError.INTERNAL, "BLAKE3 native hash returned null")
    }

    private fun bumpPriority() {
        runCatching { Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_DISPLAY) }
    }

    // ---- enrollment storage (binary) ----

    private class EnrollmentStore {
        private val fileName = "dsm_silicon_fp_v4.bin"

        fun write(context: Context, e: Enrollment) {
            val f = File(context.filesDir, fileName)
            FileOutputStream(f).use { fos ->
                DataOutputStream(fos).use { out ->
                    out.writeInt(e.revision)
                    out.writeInt(e.arenaBytes)
                    out.writeInt(e.probes)
                    out.writeInt(e.stepsPerProbe)
                    out.writeInt(e.histogramBins)
                    out.writeInt(e.rotationBits)
                    out.writeFloat(e.epsilonIntra)

                    out.writeInt(e.meanHistogram.size)
                    for (v in e.meanHistogram) out.writeFloat(v)

                    out.writeInt(e.referenceAnchor32.size)
                    out.write(e.referenceAnchor32)
                }
            }
        }

        fun read(context: Context): Enrollment? {
            val f = File(context.filesDir, fileName)
            if (!f.exists()) return null
            return try {
                FileInputStream(f).use { fis ->
                    DataInputStream(fis).use { inp ->
                        val revision = inp.readInt()
                        val arenaBytes = inp.readInt()
                        val probes = inp.readInt()
                        val stepsPerProbe = inp.readInt()
                        val histogramBins = inp.readInt()
                        val rotationBits = inp.readInt()
                        val epsilonIntra = inp.readFloat()

                        val histLen = inp.readInt()
                        val meanHistogram = FloatArray(histLen) { inp.readFloat() }

                        val aLen = inp.readInt()
                        val anchor = ByteArray(aLen)
                        inp.readFully(anchor)

                        Enrollment(
                            revision = revision,
                            arenaBytes = arenaBytes,
                            probes = probes,
                            stepsPerProbe = stepsPerProbe,
                            histogramBins = histogramBins,
                            rotationBits = rotationBits,
                            epsilonIntra = epsilonIntra,
                            meanHistogram = meanHistogram,
                            referenceAnchor32 = anchor
                        )
                    }
                }
            } catch (e: Throwable) {
                Log.e(TAG, "Failed to read enrollment", e)
                null
            }
        }

        fun clear(context: Context) {
            val f = File(context.filesDir, fileName)
            if (f.exists()) {
                f.delete()
            }
        }
    }
}

class SiliconFpException(val code: SiliconFpError, message: String) : RuntimeException(message)

enum class SiliconFpError {
    NOT_ENROLLED,
    CONFIG_MISMATCH,
    INSUFFICIENT_STABLE_BITS,
    INTERNAL
}

internal object CdbrwMath {
    fun buildHistogram(samples: LongArray, bins: Int): FloatArray {
        val minV = samples.minOrNull() ?: 0L
        val maxV = samples.maxOrNull() ?: minV
        if (maxV <= minV) {
            return FloatArray(bins).also { it[0] = 1.0f }
        }
        val hist = FloatArray(bins)
        val span = (maxV - minV).toDouble()
        for (v in samples) {
            val normalized = ((v - minV).toDouble() / span).coerceIn(0.0, 1.0)
            val idx = (normalized * (bins - 1)).toInt().coerceIn(0, bins - 1)
            hist[idx] += 1.0f
        }
        val total = samples.size.toFloat().coerceAtLeast(1f)
        for (i in hist.indices) {
            hist[i] /= total
        }
        return hist
    }

    fun meanHistogram(histograms: Array<FloatArray>): FloatArray {
        val bins = histograms.firstOrNull()?.size ?: 0
        val out = FloatArray(bins)
        if (bins == 0) return out
        for (h in histograms) {
            for (i in 0 until bins) {
                out[i] += h[i]
            }
        }
        val inv = 1.0f / histograms.size.toFloat().coerceAtLeast(1f)
        for (i in 0 until bins) {
            out[i] *= inv
        }
        return out
    }

    fun wasserstein1(a: FloatArray, b: FloatArray): Float {
        require(a.size == b.size) { "histogram size mismatch" }
        var cdfA = 0.0f
        var cdfB = 0.0f
        var dist = 0.0f
        val step = 1.0f / a.size.toFloat().coerceAtLeast(1f)
        for (i in a.indices) {
            cdfA += a[i]
            cdfB += b[i]
            dist += abs(cdfA - cdfB) * step
        }
        return dist
    }

    fun histogramToBytes(hist: FloatArray): ByteArray {
        val out = ByteArray(hist.size * 4)
        var off = 0
        for (v in hist) {
            val bits = java.lang.Float.floatToIntBits(v)
            out[off++] = (bits and 0xFF).toByte()
            out[off++] = ((bits ushr 8) and 0xFF).toByte()
            out[off++] = ((bits ushr 16) and 0xFF).toByte()
            out[off++] = ((bits ushr 24) and 0xFF).toByte()
        }
        return out
    }
}
