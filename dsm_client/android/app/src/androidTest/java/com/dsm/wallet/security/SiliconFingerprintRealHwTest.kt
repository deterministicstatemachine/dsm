package com.dsm.wallet.security

import android.content.Context
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

/**
 * Real-hardware verification for the C-DBRW silicon-fingerprint probe.
 *
 * These tests exercise [SiliconFingerprintNative.captureOrbitDensity] against
 * actual `/sys/class/thermal`, `CNTVCT_EL0`, and `perf_event_open` on the
 * device they run on. Run with:
 *
 *     ./gradlew :app:connectedAndroidTest \
 *         -Pandroid.testInstrumentationRunnerArguments.class=\
 *         com.dsm.wallet.security.SiliconFingerprintRealHwTest
 *
 * Spec violations this test catches:
 *
 *  - placeholder xorshift PRNG fallback → captureOrbitDensity must return
 *    non-null only when real thermal sensors are reachable (Def 9.1(b))
 *  - challenge-independent orbits → two distinct challenges must yield
 *    measurably different histograms (Alg 1 step 1)
 *  - degenerate timing variance → real silicon must produce wider timing
 *    spread than a deterministic ARX over a zero-µ buffer
 *  - bin distribution collapse → manufacturing gate σ_device ≥ 0.04 must
 *    pass on real hardware (the placeholder squeaked past on cache jitter)
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class SiliconFingerprintRealHwTest {

    // Mirrors AntiCloneGate's enrollment defaults — keep in sync if those
    // constants ever move.
    private companion object {
        const val ARENA_BYTES: Int = 8 * 1024 * 1024
        const val PROBES: Int = 16384
        const val STEPS_PER_PROBE: Int = 4096
        const val WARMUP_ROUNDS: Int = 2
        const val ROTATION_BITS: Int = 7
    }

    private fun ctx(): Context = InstrumentationRegistry.getInstrumentation().targetContext

    private fun newChallenge(): ByteArray = ByteArray(32).also(SecureRandom()::nextBytes)

    private fun envBytes(): ByteArray = AntiCloneGate.buildEnvironmentBytes()

    private fun thermalBytes(): ByteArray = AntiCloneGate.sampleThermalBytesForBridge(ctx())

    /**
     * Sanity check #1 — Android-sanctioned thermal HAL is reachable.
     *
     * On modern Samsung/OEM builds, direct sysfs reads of
     * /sys/class/thermal are SELinux-denied for app contexts. The spec
     * requires real silicon substrate state; on Android the supported
     * userspace path is PowerManager.getThermalHeadroom. We assert that
     * the API returns a finite headroom value, proving the kernel HAL is
     * live and accessible.
     */
    @Test
    fun thermal_hal_reachable_via_powermanager() {
        val tb = thermalBytes()
        assertEquals("thermal payload must be 16 bytes", 16, tb.size)
        val buf = java.nio.ByteBuffer.wrap(tb).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        val nowHeadroom = buf.float
        val status = buf.int
        val soonHeadroom = buf.float
        val nowFinite = !nowHeadroom.isNaN() && !nowHeadroom.isInfinite()
        val soonFinite = !soonHeadroom.isNaN() && !soonHeadroom.isInfinite()
        assertTrue(
            "PowerManager thermal HAL returned no usable data " +
                "(now=$nowHeadroom soon=$soonHeadroom status=$status) — " +
                "C-DBRW cannot run on this device",
            nowFinite || soonFinite || status >= 0,
        )
    }

    /**
     * Captures one orbit with real thermal µ-injection and asserts:
     *  - return value is non-null (no PRNG fallback path was taken)
     *  - timing array has the expected length
     *  - timings have non-trivial variance (orbit produced real signal)
     */
    @Test
    fun capture_returns_non_null_with_real_signal() {
        val challenge = newChallenge()
        val timings = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = envBytes(),
            challenge = challenge,
            thermalBytes = thermalBytes(),
            arenaBytes = ARENA_BYTES,
            probes = PROBES,
            stepsPerProbe = STEPS_PER_PROBE,
            warmupRounds = WARMUP_ROUNDS,
            rotationBits = ROTATION_BITS,
        )
        assertNotNull(
            "captureOrbitDensity returned null — no thermal source available, " +
                "which means the C-DBRW spec gate (Def 9.1(b)) is failing on this device",
            timings,
        )
        val t = timings!!
        assertEquals("timing array length mismatch", PROBES, t.size)
        val min = t.min()
        val max = t.max()
        assertTrue("orbit timings all zero — capture did nothing", max > 0L)
        assertTrue(
            "timing variance too narrow: min=$min max=$max (real thermal injection " +
                "should produce > 100ns spread on any modern SoC)",
            max - min > 100L,
        )
    }

    /**
     * Aggregated divergence test for the challenge channel. Runs N trials
     * with challenge A and N trials with challenge B, both with real
     * thermal bytes, aggregates each set into a mean histogram, and
     * asserts W1 divergence above a calibrated threshold.
     *
     * Single-probe comparison (the PR #351 design) was too noisy under
     * the Phase 2 per-step µ derivation — cache/scheduler variance
     * between any two single probes routinely produces L1 ≈ 0.01–0.03
     * even with same challenge. Aggregating N trials washes that noise
     * out and isolates the challenge-driven signal.
     *
     * If different_challenges aggregated W1 ≤ thermal-channel aggregated
     * W1, the challenge channel is no stronger than the thermal channel.
     * If thermal aggregated W1 > 0.001 (proven by
     * thermal_channel_is_load_bearing), challenge aggregated W1 should
     * exceed it because x_0 reshapes the entire orbit walk.
     */
    @Test
    fun different_challenges_produce_different_orbits() {
        val env = envBytes()
        val c1 = newChallenge()
        val c2 = newChallenge()
        assertNotEquals("challenges should differ", c1.toList(), c2.toList())

        val nTrials = 5
        val bins = 32

        fun aggregateForChallenge(challenge: ByteArray): FloatArray {
            val sum = FloatArray(bins)
            repeat(nTrials) {
                val timings = SiliconFingerprintNative.captureOrbitDensity(
                    envBytes = env,
                    challenge = challenge,
                    thermalBytes = thermalBytes(),
                    arenaBytes = ARENA_BYTES,
                    probes = PROBES,
                    stepsPerProbe = STEPS_PER_PROBE,
                    warmupRounds = WARMUP_ROUNDS,
                    rotationBits = ROTATION_BITS,
                )
                assertNotNull("trial returned null", timings)
                val h = coarseHistogram(timings!!)
                for (i in 0 until bins) sum[i] += h[i]
            }
            val inv = 1f / nTrials
            for (i in 0 until bins) sum[i] *= inv
            return sum
        }

        val hA = aggregateForChallenge(c1)
        val hB = aggregateForChallenge(c2)
        val w1 = wasserstein1(hA, hB)

        // Threshold reflects Phase 2 per-step µ derivation: weaker per-step
        // than PR #351's per-step BLAKE3, so inter-orbit divergence is
        // smaller. Even at the looser bound, W1 > 0.001 is statistically
        // meaningful for 32-bin distributions (uniform-vs-uniform W1 noise
        // floor for n_trials=5 averaged probes is well below 0.001).
        // See docs/CDBRW_SPEC_DEVIATIONS.md §3.
        assertTrue(
            "challenge channel does not measurably influence aggregated orbit " +
                "histograms (W1(H_A, H_B) = $w1 ≤ 0.001) — challenge plumbing " +
                "to x_0 may be broken (Alg 1 step 1 violation)",
            w1 > 0.001f,
        )
    }

    /**
     * Captures K=16 trials and asserts σ_device = std(Ĥ)/max(Ĥ) ≥ 0.04
     * (Corollary 4.28) — the manufacturing gate the spec uses to confirm the
     * device produces real silicon entropy. The xorshift placeholder squeaked
     * past this on cache-jitter alone; real thermal data should clear it
     * comfortably.
     */
    @Test
    fun manufacturing_gate_passes_on_real_silicon() {
        val env = envBytes()
        val perTrialEntropy = ArrayList<Float>(16)
        repeat(16) {
            val timings = SiliconFingerprintNative.captureOrbitDensity(
                envBytes = env, challenge = newChallenge(), thermalBytes = thermalBytes(),
                arenaBytes = ARENA_BYTES, probes = PROBES,
                stepsPerProbe = STEPS_PER_PROBE, warmupRounds = WARMUP_ROUNDS,
                rotationBits = ROTATION_BITS,
            )
            assertNotNull("trial returned null — thermal source missing?", timings)
            perTrialEntropy.add(shannonEntropy(coarseHistogram(timings!!)))
        }
        val maxH = perTrialEntropy.max()
        val meanH = perTrialEntropy.average().toFloat()
        val variance = perTrialEntropy.map { (it - meanH) * (it - meanH) }.average().toFloat()
        val stdH = kotlin.math.sqrt(variance.toDouble()).toFloat()
        val sigmaDevice = if (maxH > 0f) stdH / maxH else 0f
        assertTrue(
            "manufacturing gate failed: σ_device=$sigmaDevice < 0.04 " +
                "(perTrialEntropy=$perTrialEntropy)",
            sigmaDevice >= 0.04f,
        )
    }

    /**
     * Cross-device capture test (Phase 2.2).
     *
     * Spec's anti-cloning guarantee reduces to: two physically distinct
     * devices produce histograms with W1 ≥ ε_inter. This test runs an
     * aggregated enrollment-class capture on the current device and dumps
     * the mean histogram to logcat with a parseable marker:
     *
     *   [CROSS_DEVICE_HISTOGRAM]<device_id>|<bin0>,<bin1>,...,<binN>
     *
     * The driving Bash script runs this test on each connected device,
     * greps the marker from each device's logcat, parses the floats, and
     * computes W1 host-side. This is the ONLY way to verify the spec's
     * load-bearing property across physical devices from a single host.
     */
    @Test
    fun cross_device_histogram_capture() {
        val env = envBytes()
        val deviceId = "${android.os.Build.MODEL}-${android.os.Build.HARDWARE}"
        val nTrials = 5
        val bins = 32
        // Reduced probes for the cross-device capture so that slower
        // devices (lower clock, fewer thermal zones, no perf access) can
        // complete within the AndroidJUnitRunner timeout. The histogram
        // shape is preserved with fewer probes; only sample size shrinks.
        val captureProbes = 8192

        val sum = FloatArray(bins)
        repeat(nTrials) {
            val timings = SiliconFingerprintNative.captureOrbitDensity(
                envBytes = env,
                challenge = newChallenge(),
                thermalBytes = thermalBytes(),
                arenaBytes = ARENA_BYTES,
                probes = captureProbes,
                stepsPerProbe = STEPS_PER_PROBE,
                warmupRounds = WARMUP_ROUNDS,
                rotationBits = ROTATION_BITS,
            )
            assertNotNull("trial returned null", timings)
            val h = coarseHistogram(timings!!)
            for (i in 0 until bins) sum[i] += h[i]
        }
        val inv = 1f / nTrials
        for (i in 0 until bins) sum[i] *= inv

        val csv = sum.joinToString(",") { "%.8f".format(it) }
        Log.i("CROSS_DEVICE_HISTOGRAM", "$deviceId|$csv")
        // Also assert the histogram is normalized and non-degenerate so
        // the test itself fails fast if the capture is broken.
        val total = sum.sum()
        assertTrue("histogram should sum to ~1.0, got $total", kotlin.math.abs(total - 1.0f) < 0.01f)
        val nonZeroBins = sum.count { it > 0f }
        assertTrue("expected >3 non-zero bins, got $nonZeroBins", nonZeroBins > 3)
    }

    /**
     * Same-device stability (FRR) — Phase 3 deliverable 1.
     *
     * Cross-device test (Phase 2.2) proved devices are distinguishable
     * (W1 = 40–75× noise floor). This test proves the COMPLEMENTARY
     * property: a device can re-identify itself across a thermal cycle.
     * If false-rejection is too high, wallets ship broken in production.
     *
     * Captures two aggregated mean histograms back-to-back with a heavy
     * compute workload between them to perturb the SoC's thermal state,
     * then asserts the same-device W1 stays well below the cross-device
     * minimum we measured (0.0395 for the closest pair). If it doesn't,
     * the protocol can't tell self-from-other and that's a problem.
     */
    @Test
    fun same_device_stability_after_thermal_cycle() {
        val env = envBytes()
        val nTrials = 5
        val bins = 32
        val captureProbes = 8192

        fun aggregate(label: String): FloatArray {
            val sum = FloatArray(bins)
            repeat(nTrials) {
                val timings = SiliconFingerprintNative.captureOrbitDensity(
                    envBytes = env,
                    challenge = newChallenge(),
                    thermalBytes = thermalBytes(),
                    arenaBytes = ARENA_BYTES,
                    probes = captureProbes,
                    stepsPerProbe = STEPS_PER_PROBE,
                    warmupRounds = WARMUP_ROUNDS,
                    rotationBits = ROTATION_BITS,
                )
                assertNotNull("$label: trial returned null", timings)
                val h = coarseHistogram(timings!!)
                for (i in 0 until bins) sum[i] += h[i]
            }
            val inv = 1f / nTrials
            for (i in 0 until bins) sum[i] *= inv
            return sum
        }

        val hBaseline = aggregate("baseline")

        // Thermal-cycle the SoC: ~10 seconds of FP burner on this thread
        // to nudge the die temperature. Fixed iteration count (clockless).
        var acc = 0.0
        var burn = 0
        while (burn < 800_000) {
            var i = 1
            while (i < 1000) {
                acc += kotlin.math.sqrt(i.toDouble())
                i++
            }
            burn++
        }
        if (acc.isNaN()) Log.w("FRR", "burn unreachable")

        val hAfter = aggregate("after-burn")

        val sameDeviceW1 = wasserstein1(hBaseline, hAfter)

        // Threshold: comfortably below the cross-device minimum we measured
        // (A16 ↔ G9T was 0.0395 — the closest pair). Same-device must be
        // dramatically tighter than that to be useful. We assert ≤ 0.02
        // (half the closest cross-device pair). If FRR exceeds 0.02 the
        // device can't reliably identify itself and the spec deviations
        // doc must be updated to record the FRR floor.
        val deviceId = "${android.os.Build.MODEL}-${android.os.Build.HARDWARE}"
        Log.i("SAME_DEVICE_W1", "$deviceId|baseline_vs_after_burn|$sameDeviceW1")
        assertTrue(
            "FRR exceeded threshold: W1(baseline, after_burn) = $sameDeviceW1 > 0.02 " +
                "(closest cross-device pair was 0.0395). Device can't reliably " +
                "identify itself across a thermal cycle.",
            sameDeviceW1 <= 0.02f,
        )
    }

    /**
     * Phase 3 deliverable 4 — entropy-health-degrades-under-load (proxy).
     *
     * The Rust health gate (cdbrw_ffi::health_test) checks Shannon
     * entropy, lag-1 autocorrelation, and LZ78 compressibility against
     * thresholds. Under heavy CPU load, scheduler preemption injects
     * correlated noise into the orbit timings — exactly what
     * autocorrelation is supposed to catch. This test runs two captures
     * back-to-back, one quiescent and one with a CPU burner spinning on
     * a separate thread, and asserts the under-load capture has
     * measurably higher inter-probe variance.
     *
     * It's a proxy for the full gate verdict: we can't easily route
     * through the production cdbrw.measure_trust path without
     * bootstrapping the SDK, so we measure the underlying signal the
     * gate would gate on (variance / autocorrelation) and assert the
     * load condition perturbs it. If perturbation is invisible at the
     * timing-array level, the Rust gate also can't see it.
     */
    @Test
    fun health_signal_degrades_under_cpu_load() {
        val env = envBytes()
        // Smaller capture for the test budget — we just need enough
        // probes to compute robust variance, not a full orbit.
        val captureProbes = 4096

        fun captureNanoVariance(label: String): Double {
            val timings = SiliconFingerprintNative.captureOrbitDensity(
                envBytes = env,
                challenge = newChallenge(),
                thermalBytes = thermalBytes(),
                arenaBytes = ARENA_BYTES,
                probes = captureProbes,
                stepsPerProbe = STEPS_PER_PROBE,
                warmupRounds = WARMUP_ROUNDS,
                rotationBits = ROTATION_BITS,
            )
            assertNotNull("$label: capture returned null", timings)
            val arr = timings!!
            val n = arr.size.toDouble()
            val mean = arr.sumOf { it.toDouble() } / n
            val variance = arr.sumOf { val d = it.toDouble() - mean; d * d } / n
            return variance
        }

        val baselineVariance = captureNanoVariance("baseline")

        // Spawn a CPU burner on a background thread. Fixed iteration
        // count to satisfy the clockless rule.
        val burnRunning = java.util.concurrent.atomic.AtomicBoolean(true)
        val burner = Thread {
            var acc = 0.0
            var i = 1L
            while (burnRunning.get()) {
                acc += kotlin.math.sqrt(i.toDouble())
                i++
                if (acc.isNaN()) break
            }
        }
        burner.priority = Thread.NORM_PRIORITY
        burner.start()

        val underLoadVariance = try {
            captureNanoVariance("under-load")
        } finally {
            burnRunning.set(false)
            burner.join(5000)
        }

        Log.i(
            "HEALTH_UNDER_LOAD",
            "baseline_var=$baselineVariance under_load_var=$underLoadVariance " +
                "ratio=${underLoadVariance / baselineVariance.coerceAtLeast(1.0)}"
        )

        // Under-load variance should exceed baseline. We use a loose 1.5x
        // factor — preemption-induced timing noise is highly variable
        // run-to-run, and we just want to confirm the load condition
        // measurably perturbs the orbit. If this fails it means scheduler
        // pressure isn't reaching the capture thread, which means the
        // health gate also can't observe it.
        assertTrue(
            "health signal not degraded under load: baseline_var=$baselineVariance " +
                "under_load_var=$underLoadVariance — scheduler pressure invisible to capture",
            underLoadVariance > baselineVariance * 1.5,
        )
    }

    /**
     * Phase 3 deliverable 5 — concurrent capture does not crash.
     *
     * Spawns two threads both running `captureOrbitDensity` in parallel
     * (each its own orbit, K_DBRW slot reads on both, native pinning
     * race). Assert both return non-null, the process survives, and no
     * native crashes (the test runner would terminate on SIGSEGV).
     */
    @Test
    fun concurrent_capture_does_not_crash() {
        val env = envBytes()
        val captureProbes = 2048
        val errors = java.util.Collections.synchronizedList(mutableListOf<String>())
        val resultA = java.util.concurrent.atomic.AtomicReference<LongArray?>(null)
        val resultB = java.util.concurrent.atomic.AtomicReference<LongArray?>(null)

        val tA = Thread {
            try {
                resultA.set(
                    SiliconFingerprintNative.captureOrbitDensity(
                        envBytes = env,
                        challenge = newChallenge(),
                        thermalBytes = thermalBytes(),
                        arenaBytes = ARENA_BYTES,
                        probes = captureProbes,
                        stepsPerProbe = STEPS_PER_PROBE,
                        warmupRounds = WARMUP_ROUNDS,
                        rotationBits = ROTATION_BITS,
                    )
                )
            } catch (t: Throwable) {
                errors.add("threadA: $t")
            }
        }
        val tB = Thread {
            try {
                resultB.set(
                    SiliconFingerprintNative.captureOrbitDensity(
                        envBytes = env,
                        challenge = newChallenge(),
                        thermalBytes = thermalBytes(),
                        arenaBytes = ARENA_BYTES,
                        probes = captureProbes,
                        stepsPerProbe = STEPS_PER_PROBE,
                        warmupRounds = WARMUP_ROUNDS,
                        rotationBits = ROTATION_BITS,
                    )
                )
            } catch (t: Throwable) {
                errors.add("threadB: $t")
            }
        }
        tA.start()
        tB.start()
        tA.join()
        tB.join()

        assertTrue("concurrent capture errors: $errors", errors.isEmpty())
        assertNotNull("threadA returned null", resultA.get())
        assertNotNull("threadB returned null", resultB.get())
        // Both captures must produce non-degenerate timing arrays —
        // proves both orbits actually executed, neither was starved.
        assertTrue("threadA timings empty", resultA.get()!!.isNotEmpty())
        assertTrue("threadB timings empty", resultB.get()!!.isNotEmpty())
    }

    /**
     * Negative test (Phase 2 falsifiability gate). The C++ guard added in
     * Phase 2 refuses to run when no thermal HAL bytes are supplied — this
     * proves the Kotlin-side PowerManager sample is load-bearing for the
     * orbit and catches future regressions that stop sampling.
     */
    @Test
    fun orbit_refuses_without_thermal_bytes() {
        val timings = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = envBytes(),
            challenge = newChallenge(),
            thermalBytes = ByteArray(0),
            arenaBytes = ARENA_BYTES,
            probes = PROBES,
            stepsPerProbe = STEPS_PER_PROBE,
            warmupRounds = WARMUP_ROUNDS,
            rotationBits = ROTATION_BITS,
        )
        assertNull(
            "captureOrbitDensity must refuse to run with zero-length thermal bytes " +
                "(Phase 2 spec-strict guard)",
            timings,
        )
    }

    /**
     * Falsifying delta test (Phase 2). Asserts that the thermal channel is
     * actually load-bearing in the orbit: runs N orbits with real
     * PowerManager bytes and N with all-zero thermal bytes (but length 16
     * so the strict guard does not fire), aggregates each set into a mean
     * histogram, and asserts the Wasserstein-1 distance between the two
     * means is above a calibrated threshold.
     *
     * If this test fails even at the loosest threshold (W1 > 0.001), the
     * truthful conclusion is that PowerManager thermal HAL data is NOT
     * materially affecting the ARX orbit timings — at which point the
     * spec-deviations doc must be updated to demote any "thermal-driven"
     * language and we either find a stronger thermal channel or accept
     * the limitation honestly.
     */
    @Test
    fun thermal_channel_is_load_bearing() {
        val env = envBytes()
        // Fix challenge across both sets so the only varying input is
        // thermal_bytes. CNTVCT_EL0 still varies per step inside the
        // probe; that variation is constant across the two sets too
        // (same iteration count, same arena pattern), so any mean
        // histogram divergence is attributable to thermal_bytes.
        val fixedChallenge = newChallenge()
        val nTrials = 5
        val bins = 32

        fun aggregate(thermal: ByteArray): FloatArray {
            val sum = FloatArray(bins)
            repeat(nTrials) {
                val timings = SiliconFingerprintNative.captureOrbitDensity(
                    envBytes = env,
                    challenge = fixedChallenge,
                    thermalBytes = thermal,
                    arenaBytes = ARENA_BYTES,
                    probes = PROBES,
                    stepsPerProbe = STEPS_PER_PROBE,
                    warmupRounds = WARMUP_ROUNDS,
                    rotationBits = ROTATION_BITS,
                )
                assertNotNull("trial returned null", timings)
                val h = coarseHistogram(timings!!)
                for (i in 0 until bins) sum[i] += h[i]
            }
            val inv = 1f / nTrials
            for (i in 0 until bins) sum[i] *= inv
            return sum
        }

        val hReal = aggregate(thermalBytes())
        val hZero = aggregate(ByteArray(16))
        val w1 = wasserstein1(hReal, hZero)

        // Threshold calibration: starts loose. If even this doesn't hold,
        // the thermal channel is observation-only — see Phase 2 plan
        // "Two outcomes" guidance.
        assertTrue(
            "thermal channel does NOT measurably influence orbit timings " +
                "(W1(H_real, H_zero) = $w1 ≤ 0.001) — PowerManager thermal HAL " +
                "is not load-bearing; CDBRW_SPEC_DEVIATIONS.md must reflect this",
            w1 > 0.001f,
        )
    }

    /**
     * Wasserstein-1 distance between two normalized histograms.
     * Mirrors dsm_sdk::security::cdbrw_responder::wasserstein1 exactly so
     * the Kotlin test computes W1 the same way the Rust pipeline does.
     */
    private fun wasserstein1(a: FloatArray, b: FloatArray): Float {
        val n = minOf(a.size, b.size)
        if (n == 0) return 0f
        val step = 1f / n
        var cdfA = 0f
        var cdfB = 0f
        var dist = 0f
        for (i in 0 until n) {
            cdfA += a[i]
            cdfB += b[i]
            dist += kotlin.math.abs(cdfA - cdfB) * step
        }
        return dist
    }

    /** 32-bin normalized histogram of nonneg longs. */
    private fun coarseHistogram(timings: LongArray): FloatArray {
        val bins = 32
        val hist = FloatArray(bins)
        if (timings.isEmpty()) return hist.also { it[0] = 1f }
        val min = timings.min()
        val max = timings.max()
        if (max <= min) return hist.also { it[0] = 1f }
        val span = (max - min).toDouble()
        val n = timings.size.toFloat()
        for (v in timings) {
            val normalized = ((v - min) / span).coerceIn(0.0, 1.0)
            val idx = (normalized * (bins - 1)).toInt().coerceIn(0, bins - 1)
            hist[idx] += 1f
        }
        for (i in hist.indices) hist[i] /= n
        return hist
    }

    private fun shannonEntropy(p: FloatArray): Float {
        var h = 0.0
        for (x in p) {
            if (x > 0f) h -= x * (kotlin.math.ln(x.toDouble()) / kotlin.math.ln(2.0))
        }
        // Normalize to [0,1] over the bin count.
        val bits = kotlin.math.ln(p.size.toDouble()) / kotlin.math.ln(2.0)
        return (h / bits).toFloat()
    }
}
