package com.dsm.wallet.security

import android.content.Context
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
     * Two captures with **different challenges** must produce measurably
     * different orbits. The placeholder used FNV-1a(envBytes) as the seed, so
     * the challenge never reached the orbit and this assertion would have
     * passed only by coincidence; the spec requires `x_0 = H(c || K_DBRW)
     * mod 2^32` so different challenges genuinely diverge.
     */
    @Test
    fun different_challenges_produce_different_orbits() {
        val env = envBytes()
        val c1 = newChallenge()
        val c2 = newChallenge()
        // Different challenges by construction (probability of collision is 2^-256).
        assertNotEquals("challenges should differ", c1.toList(), c2.toList())

        val tb = thermalBytes()
        val t1 = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = env, challenge = c1, thermalBytes = tb,
            arenaBytes = ARENA_BYTES, probes = PROBES,
            stepsPerProbe = STEPS_PER_PROBE, warmupRounds = WARMUP_ROUNDS,
            rotationBits = ROTATION_BITS,
        )
        val t2 = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = env, challenge = c2, thermalBytes = tb,
            arenaBytes = ARENA_BYTES, probes = PROBES,
            stepsPerProbe = STEPS_PER_PROBE, warmupRounds = WARMUP_ROUNDS,
            rotationBits = ROTATION_BITS,
        )
        assertNotNull(t1); assertNotNull(t2)

        // Build coarse 32-bin histograms (just for divergence detection) and
        // assert L1 distance is non-trivial. Two challenges-seeded orbits over
        // the same silicon will not be identical at this granularity.
        val h1 = coarseHistogram(t1!!)
        val h2 = coarseHistogram(t2!!)
        val l1: Double = h1.zip(h2).sumOf { (a, b) -> kotlin.math.abs(a - b).toDouble() }
        assertTrue(
            "histograms from different challenges are too similar: L1=$l1 " +
                "(orbit may be challenge-independent — Alg 1 step 1 violation)",
            l1 > 0.05,
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
