// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.security

import android.content.Context
import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.filters.LargeTest
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * C-DBRW extractor sweep collector.
 *
 * The bin-scale (altitude) is only one extraction knob. This collector sweeps
 * the EXTRACTOR itself — the walk-altering knobs — and dumps the raw per-probe
 * timing vector + µ histogram per config so the host can derive every candidate
 * summary observable offline and score same-model separation above a shuffle
 * control. Device-side grid:
 *   - rotation r        (-e rots   "5,7,11,13,17")
 *   - injection cadence k (-e cadences "1,2,4")
 *   - core lane         (-e cores  "-1,0,6"  ; -1 merged, 0 LITTLE, 6 big)
 *   - trials            (-e trials 10)
 *   - base altitude     (-e steps  256)   host re-bins coarser for multi-scale
 *
 * Output per config+trial: <filesDir>/cdbrw_extract/r<r>_k<k>_c<core>_t<ti>.bin
 *   binary little-endian i64: [probes timing deltas][256 µ-histogram counts].
 * Pull: adb -s <serial> exec-out run-as com.dsm.wallet tar -cf - files/cdbrw_extract | tar -xf - -C <dest>
 *
 * Fixed challenge, one session — binding-time vector uniqueness.
 */
@RunWith(AndroidJUnit4::class)
@LargeTest
class SiliconFpExtractorSweepTest {

    private companion object {
        const val TAG = "CDBRW_EXTRACT"
        const val ARENA_BYTES: Int = 8 * 1024 * 1024
        const val WARMUP_ROUNDS: Int = 2
        const val DEFAULT_PROBES: Int = 4096
    }

    private fun ctx(): Context = InstrumentationRegistry.getInstrumentation().targetContext
    private fun args() = InstrumentationRegistry.getArguments()
    private fun fixedChallenge(): ByteArray = ByteArray(32) { i -> ((i * 7 + 0x42) and 0xff).toByte() }
    private fun envBytes(): ByteArray = AntiCloneGate.buildEnvironmentBytes()
    private fun thermalBytes(): ByteArray = AntiCloneGate.sampleThermalBytesForBridge(ctx())

    private fun intList(key: String, dflt: List<Int>): List<Int> =
        args().getString(key)?.split(",")?.mapNotNull { it.trim().toIntOrNull() }?.takeIf { it.isNotEmpty() } ?: dflt
    private fun intArg(key: String, dflt: Int): Int = args().getString(key)?.toIntOrNull()?.takeIf { it > 0 } ?: dflt

    @Test
    fun t01_extractor_sweep() {
        val env = envBytes()
        val challenge = fixedChallenge()
        val rots = intList("rots", listOf(5, 7, 11, 13, 17))
        val cadences = intList("cadences", listOf(1, 2, 4))
        val cores = intList("cores", listOf(-1, 0, 6))
        val trials = intArg("trials", 10)
        val steps = intArg("steps", 256)
        val probes = intArg("probes", DEFAULT_PROBES).let { if (it % 8 == 0) it else (it / 8) * 8 }

        val dir = java.io.File(ctx().filesDir, "cdbrw_extract")
        dir.deleteRecursively()
        assertTrue("mkdir failed", dir.mkdirs())
        Log.i(
            TAG,
            "begin device=${android.os.Build.MODEL}-${android.os.Build.HARDWARE} " +
                "probes=$probes steps=$steps trials=$trials rots=$rots cadences=$cadences cores=$cores",
        )

        var written = 0
        var pinFail = 0
        for (r in rots) for (k in cadences) for (core in cores) {
            for (ti in 0 until trials) {
                val raw = SiliconFingerprintNative.captureOrbitRaw(
                    envBytes = env,
                    challenge = challenge,
                    thermalBytes = thermalBytes(),
                    arenaBytes = ARENA_BYTES,
                    probes = probes,
                    stepsPerProbe = steps,
                    warmupRounds = WARMUP_ROUNDS,
                    rotationBits = r,
                    injectionCadence = k,
                    cpuCore = core,
                )
                if (raw == null) {
                    pinFail++
                    if (ti == 0) Log.w(TAG, "null capture r=$r k=$k core=$core (pin/substrate) — skipping config")
                    continue
                }
                val f = java.io.File(dir, "r${r}_k${k}_c${core}_t${ti}.bin")
                java.io.DataOutputStream(java.io.FileOutputStream(f).buffered()).use { out ->
                    for (v in raw) out.writeLong(java.lang.Long.reverseBytes(v))
                }
                written++
            }
            Log.i(TAG, "config r=$r k=$k core=$core done (written=$written pinFail=$pinFail)")
        }
        Log.i(TAG, "done written=$written pinFail=$pinFail dir=${dir.absolutePath}")
        assertTrue("nothing written", written > 0)
    }
}
