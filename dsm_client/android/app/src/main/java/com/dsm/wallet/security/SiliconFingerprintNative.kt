package com.dsm.wallet.security

/**
 * Native JNI wrapper for the C-DBRW silicon fingerprint probe.
 *
 * Reads instantaneous silicon substrate state via:
 *   - `thermalBytes` (16 bytes from Kotlin: PowerManager thermal headroom +
 *     thermal status) — the Android-sanctioned thermal HAL path. Required
 *     because Samsung/modern OEM SELinux policies block app-context reads
 *     of /sys/class/thermal/thermal_zone&#42;/temp. PowerManager returns the same kernel
 *     thermal sensor data, just through a managed API.
 *   - /sys/devices/system/cpu/cpu&#42;/cpufreq/scaling_cur_freq — DVFS state,
 *     readable in the app sandbox on stock Android.
 *   - `perf_event_open(PERF_COUNT_HW_CPU_CYCLES | CACHE_MISSES)` — gated by
 *     `perf_event_paranoid` (allowed on this device).
 *   - `mrs cntvct_el0` — ARMv8 userspace virtual counter, always allowed.
 *
 * Folds all of these via the canonical DSM domain hash to produce µ_n per
 * Def 3.2, then drives the ARX interrogation map on a pinned core with
 * `mlockall` + `SCHED_FIFO` best-effort. K_DBRW is read from the in-process
 * Rust binding-key slot via `dsm_get_cdbrw_binding_key` and never crosses
 * the JNI boundary as a parameter.
 *
 * No software PRNG fallback. If every entropy channel returns degenerate
 * data, `captureOrbitDensity` returns null rather than producing a
 * placeholder result — Def 9.1(b) forbids the synthetic fallback the
 * pre-rewrite code relied on.
 */
object SiliconFingerprintNative {
    init {
        System.loadLibrary("siliconfp")
    }

    /**
     * Run one challenge-seeded orbit and return raw cycle-counter deltas
     * (`CNTVCT_EL0` on ARM64) per probe.
     *
     * @param envBytes Stable environment fingerprint (Build constants, package).
     *                 Carried for ABI back-compat but no longer drives the orbit
     *                 seed — Alg 1 uses the challenge + K_DBRW exclusively.
     * @param challenge Per-trial 32-byte CSPRNG challenge (Alg 1 step 1,
     *                  Alg 2 line 1491).
     * @param thermalBytes 16-byte snapshot of `PowerManager.getThermalHeadroom`
     *                 + `currentThermalStatus`. Sampled in Kotlin because the
     *                 underlying APIs are Java/Android-managed (NOT a PRNG —
     *                 these are kernel HAL thermal sensor reads). May contain
     *                 NaN floats / -1 status on devices where the API is
     *                 unavailable; the native fold incorporates whatever is
     *                 present and gates on the entropy health test.
     * @param arenaBytes MUST be a power of two.
     * @param probes MUST be divisible by 8.
     * @param stepsPerProbe Number of ARX steps per probe.
     * @param warmupRounds Cache/page warmup rounds before measurement.
     * @param rotationBits ARX rotation parameter r ∈ {5, 7, 8, 11, 13}.
     * @return Cycle-counter deltas per probe, or `null` if every entropy
     *         channel is unreachable.
     */
    @JvmStatic
    external fun captureOrbitDensity(
        envBytes: ByteArray,
        challenge: ByteArray,
        thermalBytes: ByteArray,
        arenaBytes: Int,
        probes: Int,
        stepsPerProbe: Int,
        warmupRounds: Int,
        rotationBits: Int
    ): LongArray?
}
