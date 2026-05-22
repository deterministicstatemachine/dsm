// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.security

import android.content.Context
import android.util.Log
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import com.dsm.wallet.bridge.Unified
import com.dsm.wallet.ui.MainActivity
import org.junit.Assert.assertNotNull
import org.junit.Assume
import org.junit.Test
import org.junit.runner.RunWith
import java.security.SecureRandom

/**
 * Diagnostic test for the C-DBRW entropy collapse seen on Samsung Galaxy
 * A16.  Captures one orbit via [SiliconFingerprintNative.captureOrbitDensity]
 * using the same parameters production enrollment uses, then dumps the raw
 * `LongArray` deltas to logcat along with derived statistics:
 *
 *  - distinct-value count, min/max/median, p1/p50/p99
 *  - Shannon entropy at 32 / 64 / 128 / 256 bins
 *  - top-20 most-frequent timing values
 *
 * No router, no balance, no genesis required — this only needs the JNI lib
 * loaded.  Output lines are prefixed with `SOFI_FP_STATS:` and key=value
 * pairs so the host can scrape and compare across devices.
 *
 * Run:
 *   ./gradlew :app:connectedAndroidTest \
 *       -Pandroid.testInstrumentationRunnerArguments.class=\
 *       com.dsm.wallet.security.SiliconFpStatsDumpTest
 *
 * Watch:
 *   adb logcat -s SOFI_FP_STATS
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class SiliconFpStatsDumpTest {

    private companion object {
        const val TAG = "SOFI_FP_STATS"

        // Match production enrollment params exactly.
        const val ARENA_BYTES: Int = 8 * 1024 * 1024
        const val WARMUP_ROUNDS: Int = 2
        const val PROBES: Int = 16384
        const val STEPS_PER_PROBE: Int = 4096
        const val ROTATION_BITS: Int = 7
    }

    private fun ctx(): Context = InstrumentationRegistry.getInstrumentation().targetContext

    private var activity: ActivityScenario<MainActivity>? = null

    @Test
    fun t01_dump_orbit_timings_for_diagnosis() {
        // Boot MainActivity so initStorageBaseDir + initDsmSdk + native lib
        // load all run.  We don't need genesis, just SDK readiness.
        activity = ActivityScenario.launch(MainActivity::class.java)

        // Bounded poll for SDK readiness — the native lib is the only thing
        // we actually need; ensureAppRouterInstalled is a stricter signal
        // than necessary, but it's the cheapest available readiness check.
        var sdkReady = false
        for (i in 0 until 600) {
            sdkReady = try {
                Unified.ensureAppRouterInstalled()
            } catch (_: Throwable) {
                false
            }
            if (sdkReady) break
            android.os.SystemClock.sleep(100)
        }
        Assume.assumeTrue(
            "SDK never came up — install + config issue, not an entropy bug",
            sdkReady,
        )

        val envBytes = AntiCloneGate.buildEnvironmentBytes()
        val thermalBytes = AntiCloneGate.sampleThermalBytesForBridge(ctx())
        val challenge = ByteArray(32).also(SecureRandom()::nextBytes)

        Log.i(
            TAG,
            "PARAMS arena=$ARENA_BYTES probes=$PROBES steps=$STEPS_PER_PROBE " +
                "warmup=$WARMUP_ROUNDS rotation=$ROTATION_BITS thermal_len=${thermalBytes.size} " +
                "env_len=${envBytes.size}",
        )

        // Dump the thermal byte values so we can see whether they're constant
        // across runs on a given device (degenerate substrate input).
        Log.i(TAG, "THERMAL_BYTES " + thermalBytes.joinToString(",") { (it.toInt() and 0xff).toString() })

        val timings = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = envBytes,
            challenge = challenge,
            thermalBytes = thermalBytes,
            arenaBytes = ARENA_BYTES,
            probes = PROBES,
            stepsPerProbe = STEPS_PER_PROBE,
            warmupRounds = WARMUP_ROUNDS,
            rotationBits = ROTATION_BITS,
        )
        assertNotNull("captureOrbitDensity returned null", timings)
        val t = timings!!
        Log.i(TAG, "RAW_COUNT n=${t.size}")

        // ─── per-sample statistics ──────────────────────────────────────
        val sorted = t.sortedArray()
        val n = sorted.size
        val min = sorted.first()
        val max = sorted.last()
        val median = sorted[n / 2]
        val p1 = sorted[(n * 1) / 100]
        val p99 = sorted[(n * 99) / 100]
        val mean = t.sumOf { it.toDouble() } / n
        val variance = t.sumOf { (it - mean) * (it - mean) } / n
        val stddev = kotlin.math.sqrt(variance)

        Log.i(
            TAG,
            "SAMPLES n=$n min=$min p1=$p1 median=$median p99=$p99 max=$max " +
                "mean=${"%.1f".format(mean)} stddev=${"%.1f".format(stddev)} " +
                "range=${max - min}",
        )

        // ─── distinct-value count ───────────────────────────────────────
        val distinct = sorted.toHashSet()
        Log.i(TAG, "DISTINCT n_distinct=${distinct.size} ratio=${"%.4f".format(distinct.size.toDouble() / n)}")

        // ─── top-20 most-frequent values (smoking gun if collapsed) ─────
        val freq = HashMap<Long, Int>()
        for (v in t) freq[v] = (freq[v] ?: 0) + 1
        val top20 = freq.entries.sortedByDescending { it.value }.take(20)
        val top20Coverage = top20.sumOf { it.value }
        Log.i(
            TAG,
            "TOP20 coverage=$top20Coverage/${n} (${"%.2f".format(100.0 * top20Coverage / n)}%) " +
                "values=" + top20.joinToString(",") { "${it.key}:${it.value}" },
        )

        // ─── Shannon entropy: LEGACY [min, max] binning ──────────────────
        for (bins in intArrayOf(32, 64, 128, 256, 512)) {
            val h = shannonEntropy(t, bins)
            Log.i(TAG, "H_HAT_LEGACY bins=$bins h_hat=${"%.4f".format(h)}")
        }

        // ─── Shannon entropy: ROBUST [P0.5, P99.5] binning (Phase-2 fix) ──
        // Same binning the Rust enrollment writer + health_test_in_range
        // use post-fix.  This is what production h_hat will look like
        // after the schema-6 enrollment lands.
        val pLow = sorted[(n * 5) / 1000]     // P0.5
        val pHigh = sorted[(n * 995) / 1000]  // P99.5
        Log.i(TAG, "ROBUST_RANGE p0.5=$pLow p99.5=$pHigh span=${pHigh - pLow}")
        for (bins in intArrayOf(32, 64, 128, 256, 512)) {
            val h = shannonEntropyInRange(t, bins, pLow, pHigh)
            Log.i(TAG, "H_HAT_ROBUST bins=$bins h_hat=${"%.4f".format(h)}")
        }

        // ─── lag-1 autocorrelation ──────────────────────────────────────
        val rho = lag1Autocorrelation(t)
        Log.i(TAG, "RHO_HAT rho_hat=${"%.4f".format(rho)}")

        // ─── compressibility complement (LZ78) ──────────────────────────
        val lhat = lz78Compressibility(t)
        Log.i(TAG, "L_HAT l_hat=${"%.4f".format(lhat)}")

        // ─── verdict: legacy gate (broken on outlier-prone devices) ──
        val passLegacy = shannonEntropy(t, 256) >= 0.45f &&
            kotlin.math.abs(rho) <= 0.3f &&
            lhat >= 0.45f
        Log.i(
            TAG,
            "VERDICT_LEGACY gate(bins=256,h>=0.45,|rho|<=0.3,l>=0.45) -> " +
                if (passLegacy) "PASS" else "FAIL",
        )

        // ─── verdict: post-fix gate using robust [P0.5, P99.5] range ──
        val passRobust = shannonEntropyInRange(t, 256, pLow, pHigh) >= 0.45f &&
            kotlin.math.abs(rho) <= 0.3f &&
            lhat >= 0.45f
        Log.i(
            TAG,
            "VERDICT_ROBUST gate(bins=256,h_hat_robust>=0.45,|rho|<=0.3,l>=0.45) -> " +
                if (passRobust) "PASS" else "FAIL",
        )

        try {
            activity?.close()
        } catch (_: Throwable) {
            /* best-effort */
        }
    }

    // ─────────────────────────────────────────────────────────────────────
    // Helpers — ported verbatim from cdbrw_ffi.rs so we can compute the
    // same metrics the production gate uses, plus parameterised bin count.
    // ─────────────────────────────────────────────────────────────────────

    private fun shannonEntropy(samples: LongArray, bins: Int): Float {
        if (samples.isEmpty() || bins < 2) return 0f
        val min = samples.min()
        val max = samples.max()
        return shannonEntropyInRange(samples, bins, min, max)
    }

    /**
     * Robust [low, high] form: mirrors the Rust-side
     * `cdbrw_ffi::health_test_in_range` Layer-1 fix.  Samples outside
     * the supplied range clamp to the edge bins, so a single outlier
     * doesn't compress the bin space.
     */
    private fun shannonEntropyInRange(samples: LongArray, bins: Int, low: Long, high: Long): Float {
        if (samples.isEmpty() || bins < 2) return 0f
        val range = (high - low).coerceAtLeast(1L)
        val counts = IntArray(bins)
        for (s in samples) {
            val clipped = s.coerceIn(low, high)
            val b = (((clipped - low).toDouble() / range.toDouble()) * (bins - 1))
                .toInt().coerceIn(0, bins - 1)
            counts[b]++
        }
        val n = samples.size.toDouble()
        var h = 0.0
        for (c in counts) {
            if (c > 0) {
                val p = c / n
                h -= p * (kotlin.math.ln(p) / kotlin.math.ln(2.0))
            }
        }
        val maxH = kotlin.math.ln(bins.toDouble()) / kotlin.math.ln(2.0)
        return (h / maxH).coerceIn(0.0, 1.0).toFloat()
    }

    private fun lag1Autocorrelation(samples: LongArray): Float {
        val n = samples.size
        if (n < 3) return 0f
        val mean = samples.sumOf { it.toDouble() } / n
        var variance = 0.0
        var cov = 0.0
        for (i in 0 until n) {
            val d = samples[i].toDouble() - mean
            variance += d * d
            if (i > 0) cov += d * (samples[i - 1].toDouble() - mean)
        }
        if (variance < 1e-12) return 0f
        return (cov / variance).coerceIn(-1.0, 1.0).toFloat()
    }

    private fun lz78Compressibility(samples: LongArray): Float {
        val n = samples.size
        if (n == 0) return 0f
        val min = samples.min()
        val max = samples.max()
        val range = (max - min).coerceAtLeast(1L)
        val symbols = ByteArray(n) { i ->
            val s = samples[i]
            val q = (((s - min).toLong() * 255L) / range).coerceIn(0L, 255L)
            q.toByte()
        }
        // Bounded LZ78 trie: count distinct phrases.
        val trie = HashMap<String, Int>()
        var current = StringBuilder()
        var phrases = 0
        for (b in symbols) {
            current.append((b.toInt() and 0xff).toChar())
            val key = current.toString()
            if (!trie.containsKey(key)) {
                trie[key] = phrases
                phrases++
                current = StringBuilder()
            }
            if (trie.size > 65536) break
        }
        if (phrases == 0) return 1f
        val phrasesD = phrases.toDouble()
        val nD = n.toDouble()
        return (1.0 - (phrasesD / nD)).coerceIn(0.0, 1.0).toFloat()
    }
}
