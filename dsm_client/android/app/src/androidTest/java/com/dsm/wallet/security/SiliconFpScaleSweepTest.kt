// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.security

import android.content.Context
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * Measurement-altitude sweep for the C-DBRW timing fingerprint.
 *
 * The orbit-state histogram is uniform on every device because a 67M-step
 * marginal distribution is the "outer space" view — full mixing averages all
 * device structure away. The device signal lives in LOCAL execution: the time
 * to run a small number of ARX steps + memory accesses, which reflects per-die
 * cache/DRAM/critical-path latency. `captureOrbitDensity(stepsPerProbe = G)`
 * already exposes the altitude knob: G is the number of ARX steps folded into
 * one timing sample.
 *   G = 1     → nano: one memory access + one ARX op per sample (raw silicon latency)
 *   G = 4096  → outer space: current production probe size (washed toward common-mode)
 *
 * This test sweeps G under a FIXED challenge with a CONSTANT sample count
 * (PROBES timings per capture) so the 256-bin timing histograms are
 * statistically comparable across altitudes. The host computes intra-device vs
 * inter-device W1 per altitude and finds where same-model separation peaks.
 *
 * Output per (scale, trial): `g<G>_t<ti>.hist` (256-bin normalized timing
 * histogram) under <filesDir>/cdbrw_scale/ + a CDBRW_SCALE logcat line.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class SiliconFpScaleSweepTest {

    private companion object {
        const val TAG = "CDBRW_SCALE"
        const val ARENA_BYTES: Int = 8 * 1024 * 1024
        const val WARMUP_ROUNDS: Int = 2
        const val ROTATION_BITS: Int = 7
        const val BINS: Int = 256
        // Constant number of timing samples per capture → equal histogram
        // statistics at every altitude (must be divisible by 8).
        const val PROBES: Int = 8192
        const val DEFAULT_TRIALS: Int = 10
        // Altitudes: ARX steps folded into one timing sample, nano → outer space.
        val DEFAULT_SCALES: IntArray = intArrayOf(1, 4, 16, 64, 256, 1024, 4096)
    }

    private fun ctx(): Context = InstrumentationRegistry.getInstrumentation().targetContext

    // Optional instrumentation args so the sweep can be re-parameterized without
    // recompiling: -e scales 64,128,256,512  -e trials 24
    private fun args() = InstrumentationRegistry.getArguments()
    private fun scales(): IntArray =
        args().getString("scales")?.split(",")?.mapNotNull { it.trim().toIntOrNull() }
            ?.filter { it > 0 }?.toIntArray()?.takeIf { it.isNotEmpty() } ?: DEFAULT_SCALES
    private fun trials(): Int = args().getString("trials")?.toIntOrNull()?.takeIf { it > 0 } ?: DEFAULT_TRIALS
    private fun fixedChallenge(): ByteArray = ByteArray(32) { i -> ((i * 7 + 0x42) and 0xff).toByte() }
    private fun envBytes(): ByteArray = AntiCloneGate.buildEnvironmentBytes()
    private fun thermalBytes(): ByteArray = AntiCloneGate.sampleThermalBytesForBridge(ctx())

    private fun histogram(timings: LongArray): FloatArray {
        val hist = FloatArray(BINS)
        if (timings.isEmpty()) return hist.also { it[0] = 1f }
        val min = timings.min(); val max = timings.max()
        if (max <= min) return hist.also { it[0] = 1f }
        val span = (max - min).toDouble(); val n = timings.size.toFloat()
        for (v in timings) {
            val norm = ((v - min) / span).coerceIn(0.0, 1.0)
            hist[(norm * (BINS - 1)).toInt().coerceIn(0, BINS - 1)] += 1f
        }
        for (i in hist.indices) hist[i] /= n
        return hist
    }

    @Test
    fun t01_sweep_measurement_altitude() {
        val env = envBytes()
        val challenge = fixedChallenge()
        val scales = scales()
        val nTrials = trials()
        val dir = java.io.File(ctx().filesDir, "cdbrw_scale")
        dir.deleteRecursively()
        assertTrue("mkdir failed", dir.mkdirs())
        Log.i(
            TAG,
            "begin device=${android.os.Build.MODEL}-${android.os.Build.HARDWARE} " +
                "probes=$PROBES trials=$nTrials scales=${scales.joinToString(",")}",
        )

        for (g in scales) {
            for (ti in 0 until nTrials) {
                val timings = SiliconFingerprintNative.captureOrbitDensity(
                    envBytes = env,
                    challenge = challenge,
                    thermalBytes = thermalBytes(),
                    arenaBytes = ARENA_BYTES,
                    probes = PROBES,
                    stepsPerProbe = g,
                    warmupRounds = WARMUP_ROUNDS,
                    rotationBits = ROTATION_BITS,
                )
                assertNotNull("capture null (g=$g t=$ti)", timings)
                val h = histogram(timings!!)
                val csv = h.joinToString(",") { "%.8f".format(it) }
                java.io.File(dir, "g${g}_t${ti}.hist").writeText(csv)
                // also log a couple of raw stats so we can see the floor/spread per altitude
                val srt = timings.sorted()
                Log.i(TAG, "g=$g t=$ti min=${srt.first()} med=${srt[srt.size/2]} max=${srt.last()}")
            }
            Log.i(TAG, "scale $g done")
        }
        val n = dir.listFiles()?.size ?: 0
        Log.i(TAG, "done files=$n")
        assertTrue("expected ${scales.size * nTrials} files, got $n", n == scales.size * nTrials)
    }
}
