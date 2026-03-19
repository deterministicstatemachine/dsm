package com.dsm.wallet.security

/**
 * Native JNI wrapper for Silicon Fingerprint capture.
 * 
 * Uses NDK C++ with:
 * - mmap'd arena (no JVM heap, no GC interference)
 * - CLOCK_THREAD_CPUTIME_ID (per-thread CPU time, excludes scheduler pauses)
 * - Pointer-chasing (cache/memory topology sensitive)
 * - Per-trial median thresholding (self-normalizing against DVFS/thermal shifts)
 */
object SiliconFingerprintNative {
    init {
        System.loadLibrary("siliconfp")
    }

    /**
     * Returns raw timing distributions (orbit density) for the chaotic pointer chase.
     *
     * @param envBytes Stable environment bytes (Build constants, package name, etc).
     * @param arenaBytes MUST be power-of-two.
     * @param probes MUST be divisible by 8.
     * @param stepsPerProbe Number of pointer-chase steps per probe.
     * @param warmupRounds Number of warmup rounds before measurement.
     * @return Array of raw timings (nanoseconds) or null on failure.
     */
    @JvmStatic
    external fun captureOrbitDensity(
        envBytes: ByteArray,
        arenaBytes: Int,
        probes: Int,
        stepsPerProbe: Int,
        warmupRounds: Int,
        rotationBits: Int
    ): LongArray?
}
