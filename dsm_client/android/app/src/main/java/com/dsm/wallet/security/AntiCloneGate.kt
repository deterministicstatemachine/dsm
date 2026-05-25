package com.dsm.wallet.security

import android.content.Context
import android.os.Build
import android.os.PowerManager
import android.os.Process
import android.util.Log
import com.dsm.wallet.bridge.NativeBoundaryBridge
import com.google.protobuf.ByteString
import dsm.types.proto.CdbrwAccessLevel
import dsm.types.proto.CdbrwEnrollRequest
import dsm.types.proto.CdbrwMeasureTrustRequest
import dsm.types.proto.CdbrwOrbitTrial
import dsm.types.proto.CdbrwTrustSnapshot
import dsm.types.proto.Envelope
import dsm.types.proto.IngressResponse
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/**
 * Hardware anchor result from C-DBRW enrollment / trust measurement.
 *
 * The `anchor` is the full 32-byte `AC_D` attractor commitment computed by
 * the Rust enrollment writer. `accessLevel` is the live verdict from the
 * Rust access gate after the operation published its trust snapshot.
 */
data class HardwareAnchorResult(
    val anchor: ByteArray?,
    val accessLevel: AccessLevel,
    val trustScore: Float = 1.0f,
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
 * Android-side transport shim for the Rust C-DBRW subsystem.
 *
 * All protocol logic — histogram math, Wasserstein-1 distance, AC_D
 * commitment, entropy health, resonant classification, access-level
 * derivation — lives in `dsm_sdk/src/security/cdbrw_*`. This object's
 * job:
 *
 *  1. Drive the NDK silicon-PUF probe ([`SiliconFingerprintNative`]) to
 *     collect K orbit trials, each seeded with a fresh CSPRNG challenge
 *     (cdbrw.instructions.md Alg 2 line 1491) and preceded by a varied
 *     workload pattern (Alg 2 line 1490).
 *  2. Ship the per-trial timings + challenge bytes to Rust through
 *     `NativeBoundaryBridge.routerQuery` against `cdbrw.enroll` /
 *     `cdbrw.measure_trust`.
 *  3. Surface the resulting [`HardwareAnchorResult`] to bootstrap.
 */
object AntiCloneGate {
    private const val TAG = "AntiCloneGate"

    /**
     * C-DBRW §6.1 enrollment defaults. The Rust enrollment writer validates
     * the same constraints (256 histogram bins, rotation ∈ {5,7,8,11,13},
     * K ≥ 16 trials) so these values must stay in sync with
     * [`cdbrw_enrollment_writer`].
     */
    private const val ARENA_BYTES: Int = 8 * 1024 * 1024
    private const val WARMUP_ROUNDS: Int = 2
    private const val PROBES: Int = 16384
    private const val STEPS_PER_PROBE: Int = 4096
    /** K — trials per admission sample (§6.1). */
    private const val ENROLL_TRIALS: Int = 21
    /**
     * Phase 9 median-of-M admission rule.  Capture M independent
     * K-trial samples back-to-back and ship them to Rust as a single
     * batched request.  Rust partitions by `trialsPerSample` and runs
     * `classify_resonant_m_sample` on the per-sample health metrics.
     *
     * Must equal `dsm_sdk::security::cdbrw_responder::ADMISSION_M`
     * — Rust rejects a mismatch as `AdmissionShapeMismatch`.
     */
    private const val ADMISSION_SAMPLES: Int = 3
    /** Total trials shipped per enroll = M * K (default 3 * 21 = 63). */
    private const val TOTAL_ENROLL_TRIALS: Int = ADMISSION_SAMPLES * ENROLL_TRIALS
    private const val HISTOGRAM_BINS: Int = 256
    private const val ROTATION_BITS: Int = 7

    private val secureRandom: SecureRandom = SecureRandom()

    /** Workload pattern applied before each enrollment trial (Alg 2 line 1490). */
    private enum class WorkloadMode { BURN, IDLE, ALLOC, IO }

    /**
     * Sample the Android-sanctioned thermal HAL.
     *
     * On modern Samsung (and most non-AOSP) builds, SELinux denies
     * app-context reads of /sys/class/thermal/thermal_zone&#42;/temp even
     * though spec Def 9.1(b) names that path. The PowerManager API is the
     * supported userspace entry point to the same kernel thermal sensors,
     * just behind a managed interface — it is NOT a software PRNG, it
     * returns real substrate state.
     *
     * We deliberately use getThermalHeadroom(0) (current headroom) TWICE
     * rather than once-now + once-forecast. The forecast variant is a
     * HAL-modeled forward projection of throttle ETA, not a substrate
     * reading — including it would conflate modeled output with raw
     * sensor data (Phase 2 adversarial follow-up). Two (0) samples a few
     * microseconds apart fold in scheduler-jitter-driven variance between
     * successive HAL reads, which IS substrate-influenced.
     *
     * Layout (16 bytes, little-endian) — preserved for JNI ABI stability:
     *   [0..4]   IEEE 754 bits of getThermalHeadroom(0) (first read)
     *   [4..8]   getCurrentThermalStatus() as i32 (or -1 if API < 29)
     *   [8..12]  IEEE 754 bits of getThermalHeadroom(0) (second read)
     *   [12..16] reserved (zero) for forward compatibility
     */
    /**
     * Public alias for [sampleThermalBytes] so other Kotlin transport shims
     * (e.g. the WebView bridge) can produce a spec-conformant thermal
     * payload without duplicating the PowerManager call site.
     */
    fun sampleThermalBytesForBridge(context: Context): ByteArray = sampleThermalBytes(context)

    private fun sampleThermalBytes(context: Context): ByteArray {
        // 16-byte layout (little-endian):
        //   [0..4]   headroom_f32  — PowerManager.getThermalHeadroom(0)
        //   [4..8]   status_i32    — PowerManager.currentThermalStatus
        //   [8..12]  cpufreq_i32   — first readable scaling_cur_freq
        //   [12..16] elapsed_ns_i32 — low 32 bits of elapsedRealtimeNanos
        //
        // Phase-2 follow-up: the previous layout did two getThermalHeadroom
        // calls bracketing currentThermalStatus, but the second call gets
        // throttled to NaN by Android's PowerManager (~1 Hz rate limit).
        // That left 4 of 16 substrate bytes always zero, weakening the
        // µ-byte derivation on devices that already had marginal silicon
        // entropy.  We replace headroom2 with a /sys/devices cpufreq read
        // (real silicon DVFS state) plus the low 32 bits of
        // SystemClock.elapsedRealtimeNanos (microsecond-scale scheduler
        // jitter) — both are substrate-influenced and don't trip any
        // throttling.
        val buf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN)
        var headroom = Float.NaN
        var status = -1
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            if (pm != null) {
                runCatching { headroom = pm.getThermalHeadroom(0) }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    runCatching { status = pm.currentThermalStatus }
                }
            }
        }
        // Best-effort cpufreq read.  Most Android builds permit
        // app-context reads of /sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq;
        // failures yield 0 and the BLAKE3 fold in the C++ orbit treats
        // a zero byte the same as any other.
        var cpufreqKhz = 0
        runCatching {
            for (cpu in 0..7) {
                val f = java.io.File("/sys/devices/system/cpu/cpu$cpu/cpufreq/scaling_cur_freq")
                if (f.canRead()) {
                    val v = f.readText().trim().toIntOrNull()
                    if (v != null && v > 0) {
                        cpufreqKhz = v
                        break
                    }
                }
            }
        }
        // Low 32 bits of elapsedRealtimeNanos — adds microsecond-scale
        // jitter that bracketing the headroom + status reads produces.
        // Like SystemClock.sleep this is scheduler-domain, not wall-
        // clock; the protocol's clockless rule applies to consensus /
        // hash inputs, not substrate-jitter sampling.
        val elapsedLow = android.os.SystemClock.elapsedRealtimeNanos().toInt()
        buf.putFloat(headroom)
        buf.putInt(status)
        buf.putInt(cpufreqKhz)
        buf.putInt(elapsedLow)
        return buf.array()
    }

    /**
     * Collect K orbit trials with per-trial CSPRNG challenges and varied
     * workload patterns, then hand them to Rust for enrollment.
     *
     * Returns the 32-byte `AC_D` reference anchor and the trust snapshot
     * published by the Rust writer.
     *
     * @param onProgress called once per trial with (completed, total).
     */
    @Throws(AntiCloneGateException::class)
    fun enroll(
        context: Context,
        onProgress: ((completed: Int, total: Int) -> Unit)? = null,
    ): HardwareAnchorResult {
        val envBytes = buildEnvironmentBytes()
        // Phase 9: capture M*K=63 trials in one shot so Rust does the
        // admission protocol composition transactionally.  Progress
        // callback fires over the full M*K span so the UI reflects the
        // real enrollment cost (~15min on a mid-range SoC).
        val trials = captureTrials(
            context,
            envBytes,
            TOTAL_ENROLL_TRIALS,
            PROBES,
            onProgress,
        )

        val request = CdbrwEnrollRequest.newBuilder()
            .setEnvBytes(ByteString.copyFrom(envBytes))
            .apply {
                trials.forEach { (timings, challenge) ->
                    addTrials(
                        CdbrwOrbitTrial.newBuilder()
                            .addAllTimings(timings.toList())
                            .setChallenge(ByteString.copyFrom(challenge))
                            .build()
                    )
                }
            }
            .setArenaBytes(ARENA_BYTES)
            .setProbes(PROBES)
            .setStepsPerProbe(STEPS_PER_PROBE)
            .setHistogramBins(HISTOGRAM_BINS)
            .setRotationBits(ROTATION_BITS)
            .setAdmissionSamples(ADMISSION_SAMPLES)
            .setTrialsPerSample(ENROLL_TRIALS)
            .build()

        val ingressResponseBytes = NativeBoundaryBridge.routerQuery(
            method = "cdbrw.enroll",
            args = request.toByteArray(),
        )
        val envelope = unpackOkEnvelope(ingressResponseBytes, "cdbrw.enroll")
        if (envelope.payloadCase != Envelope.PayloadCase.CDBRW_ENROLL_RESPONSE) {
            throw AntiCloneGateException(
                "cdbrw.enroll: unexpected payload ${envelope.payloadCase}"
            )
        }
        val resp = envelope.cdbrwEnrollResponse
        val anchor = resp.referenceAnchor.toByteArray()
        if (anchor.size != 32) {
            throw AntiCloneGateException(
                "cdbrw.enroll: reference_anchor must be 32 bytes, got ${anchor.size}"
            )
        }
        val trust = resp.trust ?: throw AntiCloneGateException("cdbrw.enroll: missing trust snapshot")
        Log.i(
            TAG,
            "cdbrw.enroll: revision=${resp.revision} eps_intra=${resp.epsilonIntra} " +
                "access=${trust.accessLevel} score=${trust.trustScore}",
        )
        return HardwareAnchorResult(
            anchor = anchor,
            accessLevel = toAccessLevel(trust.accessLevel),
            trustScore = trust.trustScore.coerceIn(0.0f, 1.0f),
        )
    }

    /**
     * Run a single live trust-measurement probe against the stored
     * enrollment. The orbit is challenge-seeded with a fresh CSPRNG value;
     * the stored mean histogram is invariant under any challenge by
     * Theorem 4.5 (attractor convergence), so a new challenge does not
     * change the device's enrolled identity.
     *
     * @param anchorHint cached anchor from the last successful enroll —
     *                   returned unchanged in the result so callers can
     *                   uniformly handle enroll/measure responses.
     */
    @Throws(AntiCloneGateException::class)
    fun measureTrust(
        context: Context,
        anchorHint: ByteArray?,
    ): HardwareAnchorResult {
        val envBytes = buildEnvironmentBytes()
        val challenge = ByteArray(32).also(secureRandom::nextBytes)
        val thermalBytes = sampleThermalBytes(context)
        val timings = runOnSoftRtThread {
            SiliconFingerprintNative.captureOrbitDensity(
                envBytes = envBytes,
                challenge = challenge,
                thermalBytes = thermalBytes,
                arenaBytes = ARENA_BYTES,
                probes = PROBES,
                stepsPerProbe = STEPS_PER_PROBE,
                warmupRounds = WARMUP_ROUNDS,
                rotationBits = ROTATION_BITS,
            )
        } ?: throw AntiCloneGateException(
            "cdbrw.measure_trust: NDK probe returned no timings (no thermal source or sandboxed)",
        )

        val request = CdbrwMeasureTrustRequest.newBuilder()
            .setEnvBytes(ByteString.copyFrom(envBytes))
            .setOrbit(
                CdbrwOrbitTrial.newBuilder()
                    .addAllTimings(timings.toList())
                    .setChallenge(ByteString.copyFrom(challenge))
                    .build()
            )
            .setHistogramBins(HISTOGRAM_BINS)
            .build()

        val ingressResponseBytes = NativeBoundaryBridge.routerQuery(
            method = "cdbrw.measure_trust",
            args = request.toByteArray(),
        )
        val envelope = unpackOkEnvelope(ingressResponseBytes, "cdbrw.measure_trust")
        if (envelope.payloadCase != Envelope.PayloadCase.CDBRW_TRUST_SNAPSHOT) {
            throw AntiCloneGateException(
                "cdbrw.measure_trust: unexpected payload ${envelope.payloadCase}"
            )
        }
        val snapshot: CdbrwTrustSnapshot = envelope.cdbrwTrustSnapshot
        Log.d(
            TAG,
            "cdbrw.measure_trust: access=${snapshot.accessLevel} score=${snapshot.trustScore} " +
                "w1=${snapshot.w1Distance}/${snapshot.w1Threshold}",
        )
        return HardwareAnchorResult(
            anchor = anchorHint,
            accessLevel = toAccessLevel(snapshot.accessLevel),
            trustScore = snapshot.trustScore.coerceIn(0.0f, 1.0f),
        )
    }

    /**
     * Build constants fingerprint — Rust hashes these into K_DBRW via
     * `cdbrw_binding::derive_cdbrw_binding_key`. Stable across boots.
     */
    @Suppress("DEPRECATION")
    fun buildEnvironmentBytes(): ByteArray {
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
                } catch (_: Throwable) {
                    append("unavailable")
                }
            } else {
                append("pre31")
            }
        }
        return envData.toByteArray(Charsets.UTF_8)
    }

    /**
     * Capture `trials` orbits. Each trial:
     *   1. Picks a workload pattern from a round-robin schedule (Alg 2 line 1490).
     *   2. Runs that workload for ~300ms to perturb the thermal/voltage state.
     *   3. Generates a fresh 32-byte CSPRNG challenge (Alg 2 line 1491).
     *   4. Runs the orbit on a soft-RT pinned thread.
     *
     * Fails fast on any NDK failure — a partial trial set silently weakens
     * the enrollment.
     */
    private fun captureTrials(
        context: Context,
        envBytes: ByteArray,
        trials: Int,
        probes: Int,
        onProgress: ((completed: Int, total: Int) -> Unit)?,
    ): List<Pair<LongArray, ByteArray>> {
        val patterns = WorkloadMode.values()
        val out = ArrayList<Pair<LongArray, ByteArray>>(trials)
        for (i in 0 until trials) {
            inducePattern(patterns[i % patterns.size])
            val challenge = ByteArray(32).also(secureRandom::nextBytes)
            val thermalBytes = sampleThermalBytes(context)
            val timings = runOnSoftRtThread {
                SiliconFingerprintNative.captureOrbitDensity(
                    envBytes = envBytes,
                    challenge = challenge,
                    thermalBytes = thermalBytes,
                    arenaBytes = ARENA_BYTES,
                    probes = probes,
                    stepsPerProbe = STEPS_PER_PROBE,
                    warmupRounds = WARMUP_ROUNDS,
                    rotationBits = ROTATION_BITS,
                )
            } ?: throw AntiCloneGateException(
                "cdbrw.enroll: NDK probe returned no timings on trial $i/$trials " +
                    "(thermal source missing or sandboxed)",
            )
            if (timings.isEmpty()) {
                throw AntiCloneGateException(
                    "cdbrw.enroll: NDK probe returned empty trial $i/$trials"
                )
            }
            out.add(timings to challenge)
            onProgress?.invoke(i + 1, trials)
        }
        return out
    }

    /**
     * Run `block` on a thread promoted to URGENT_AUDIO priority — Android's
     * closest userspace equivalent to SCHED_FIFO without root. The C++ side
     * additionally calls `pthread_setschedparam(SCHED_FIFO, max)` and
     * `mlockall`, both best-effort. If either escalation fails the C++ side
     * logs and continues; the entropy health test catches the case where
     * preemption noise dominates.
     */
    private inline fun <T> runOnSoftRtThread(crossinline block: () -> T): T {
        val previous = Process.getThreadPriority(Process.myTid())
        return try {
            Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO)
            block()
        } finally {
            runCatching { Process.setThreadPriority(previous) }
        }
    }

    /**
     * Apply a workload pattern to perturb thermal/voltage state before the
     * next orbit. Uses fixed iteration counts (not wall-clock deadlines —
     * DSM's deterministic-time invariant bans `System.nanoTime`/etc. in app
     * code). The iteration counts were tuned to approximate ~300 ms on a
     * mid-range Android SoC; precise duration doesn't matter, only that the
     * silicon state genuinely shifts between trials.
     */
    private fun inducePattern(mode: WorkloadMode) {
        when (mode) {
            WorkloadMode.BURN -> {
                // ~300 ms of FP work on a Galaxy A54-class big core.
                var acc = 0.0
                var outer = 0
                while (outer < 32_000) {
                    var i = 1
                    while (i < 10_000) {
                        acc += Math.sqrt(i.toDouble())
                        i++
                    }
                    outer++
                }
                if (acc.isNaN()) Log.w(TAG, "burn workload unreachable")
            }
            WorkloadMode.IDLE -> {
                try {
                    // Thread.sleep is not a wall-clock API in the protocol
                    // sense — it's a scheduler hint, not a clock read. The
                    // build guard's ban list explicitly excludes it.
                    Thread.sleep(300)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                }
            }
            WorkloadMode.ALLOC -> {
                // ~80 MB total allocation pressure across small + large blocks.
                var iter = 0
                while (iter < 24) {
                    val big = ByteArray(16 * 1024 * 1024)
                    big[big.size - 1] = 1
                    val small = ByteArray(256 * 1024)
                    small[small.size - 1] = 1
                    // Let GC reclaim — the allocation pressure is the point.
                    iter++
                }
            }
            WorkloadMode.IO -> {
                var iter = 0
                while (iter < 400) {
                    runCatching {
                        java.io.FileInputStream("/proc/cpuinfo").use { it.readBytes() }
                    }
                    iter++
                }
            }
        }
    }

    private fun unpackOkEnvelope(ingressResponseBytes: ByteArray, method: String): Envelope {
        val ingressResponse = try {
            IngressResponse.parseFrom(ingressResponseBytes)
        } catch (e: Exception) {
            throw AntiCloneGateException("$method: failed to parse IngressResponse: ${e.message}", e)
        }
        val okBytes = when (ingressResponse.resultCase) {
            IngressResponse.ResultCase.OK_BYTES -> ingressResponse.okBytes.toByteArray()
            IngressResponse.ResultCase.ERROR ->
                throw AntiCloneGateException("$method: ${ingressResponse.error.message}")
            else ->
                throw AntiCloneGateException("$method: ingress returned no result")
        }
        if (okBytes.isEmpty()) {
            throw AntiCloneGateException("$method: empty envelope bytes")
        }
        val raw = if (okBytes[0] == 0x03.toByte() && okBytes.size > 1) {
            okBytes.copyOfRange(1, okBytes.size)
        } else {
            okBytes
        }
        return try {
            Envelope.parseFrom(raw)
        } catch (e: Exception) {
            throw AntiCloneGateException("$method: failed to parse Envelope: ${e.message}", e)
        }
    }

    private fun toAccessLevel(proto: CdbrwAccessLevel): AccessLevel {
        return when (proto) {
            CdbrwAccessLevel.CDBRW_ACCESS_FULL_ACCESS -> AccessLevel.FULL_ACCESS
            CdbrwAccessLevel.CDBRW_ACCESS_PIN_REQUIRED -> AccessLevel.PIN_REQUIRED
            CdbrwAccessLevel.CDBRW_ACCESS_READ_ONLY -> AccessLevel.READ_ONLY
            // `proto` is the non-nullable `CdbrwAccessLevel` enum, so the
            // `null ->` branch the compiler used to warn about is dead.
            // BLOCKED + UNSPECIFIED + UNRECOGNIZED all map to BLOCKED as
            // the safe-default access level.
            CdbrwAccessLevel.CDBRW_ACCESS_BLOCKED,
            CdbrwAccessLevel.CDBRW_ACCESS_UNSPECIFIED,
            CdbrwAccessLevel.UNRECOGNIZED -> AccessLevel.BLOCKED
        }
    }
}

class AntiCloneGateException(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)
