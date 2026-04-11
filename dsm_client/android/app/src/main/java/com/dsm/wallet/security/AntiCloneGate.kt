package com.dsm.wallet.security

import android.content.Context
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
 * only job is:
 *
 *  1. Drive the NDK silicon-PUF probe ([`SiliconFingerprintNative`]) to
 *     collect raw orbit timings.
 *  2. Ship those timings to Rust through `NativeBoundaryBridge.routerQuery`
 *     against the `cdbrw.enroll` / `cdbrw.measure_trust` routes.
 *  3. Surface the resulting [`HardwareAnchorResult`] to the bootstrap flow.
 *
 * The Kotlin side never touches histograms, anchors, ciphertexts, or
 * signatures. If a field doesn't show up in `CdbrwEnrollResponse` /
 * `CdbrwTrustSnapshot`, it shouldn't be computed on this side.
 */
object AntiCloneGate {
    private const val TAG = "AntiCloneGate"

    /**
     * C-DBRW §6.1 enrollment defaults.
     *
     * The Rust enrollment writer validates the same constraints
     * (256 histogram bins, rotation ∈ {5,7,8,11,13}, K ≥ 16 trials) so
     * these values must stay in sync with [`cdbrw_enrollment_writer`].
     * The Kotlin side is transport-only — these constants just describe
     * how much orbit data to collect before handing it to Rust.
     */
    private const val ARENA_BYTES: Int = 8 * 1024 * 1024
    private const val WARMUP_ROUNDS: Int = 2
    private const val PROBES: Int = 4096
    private const val STEPS_PER_PROBE: Int = 4096
    private const val ENROLL_TRIALS: Int = 21
    private const val HISTOGRAM_BINS: Int = 256
    private const val ROTATION_BITS: Int = 7

    /**
     * Collect `K` orbit trials and hand them to Rust for enrollment.
     *
     * Returns the 32-byte `AC_D` reference anchor and the trust snapshot
     * published by the Rust writer. The raw orbit timings never leave the
     * process boundary in an unhashed form — `cdbrw.enroll` computes the
     * mean histogram and anchor inside the SDK.
     *
     * @param onProgress called once per trial with (completed, total).
     */
    @Throws(AntiCloneGateException::class)
    fun enroll(
        context: Context,
        onProgress: ((completed: Int, total: Int) -> Unit)? = null,
    ): HardwareAnchorResult {
        val envBytes = buildEnvironmentBytes()
        val trials = captureTrials(envBytes, ENROLL_TRIALS, PROBES, onProgress)

        val request = CdbrwEnrollRequest.newBuilder()
            .setEnvBytes(ByteString.copyFrom(envBytes))
            .apply { trials.forEach { addTrials(CdbrwOrbitTrial.newBuilder().addAllTimings(it.toList()).build()) } }
            .setArenaBytes(ARENA_BYTES)
            .setProbes(PROBES)
            .setStepsPerProbe(STEPS_PER_PROBE)
            .setHistogramBins(HISTOGRAM_BINS)
            .setRotationBits(ROTATION_BITS)
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
     * Run a single trust-measurement probe against the stored enrollment.
     *
     * This is what the UI should call for a "fresh" trust verdict between
     * boots — the anchor itself does NOT come back on this path, because
     * Rust already has it on disk. The caller is expected to have cached
     * the anchor from a prior `enroll()` call.
     *
     * @param anchorHint the cached anchor from the last successful enroll.
     *                   Returned unchanged inside the result so callers can
     *                   uniformly treat both code paths.
     */
    @Throws(AntiCloneGateException::class)
    fun measureTrust(
        context: Context,
        anchorHint: ByteArray?,
    ): HardwareAnchorResult {
        val envBytes = buildEnvironmentBytes()
        val timings = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = envBytes,
            arenaBytes = ARENA_BYTES,
            probes = PROBES,
            stepsPerProbe = STEPS_PER_PROBE,
            warmupRounds = WARMUP_ROUNDS,
            rotationBits = ROTATION_BITS,
        ) ?: throw AntiCloneGateException(
            "cdbrw.measure_trust: NDK probe returned no timings (native layer failure)"
        )

        val request = CdbrwMeasureTrustRequest.newBuilder()
            .setEnvBytes(ByteString.copyFrom(envBytes))
            .setOrbit(CdbrwOrbitTrial.newBuilder().addAllTimings(timings.toList()).build())
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
     * Raw Build-constants fingerprint bytes. Rust hashes these into K_DBRW
     * via `cdbrw_binding::derive_cdbrw_binding_key`, so the Kotlin side
     * does NOT need to pre-hash them — shipping the raw string is stable
     * across boots and keeps the BLAKE3 domain logic in one place.
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
     * Capture `trials` × [`SiliconFingerprintNative.captureOrbitDensity`]
     * calls, streaming progress updates to the bootstrap UI.
     *
     * Fails fast on the first NDK failure — a partial trial set would
     * silently weaken the enrollment, so we surface the error instead of
     * shipping a short batch to Rust.
     */
    private fun captureTrials(
        envBytes: ByteArray,
        trials: Int,
        probes: Int,
        onProgress: ((completed: Int, total: Int) -> Unit)?,
    ): List<LongArray> {
        val out = ArrayList<LongArray>(trials)
        for (i in 0 until trials) {
            val timings = SiliconFingerprintNative.captureOrbitDensity(
                envBytes = envBytes,
                arenaBytes = ARENA_BYTES,
                probes = probes,
                stepsPerProbe = STEPS_PER_PROBE,
                warmupRounds = WARMUP_ROUNDS,
                rotationBits = ROTATION_BITS,
            ) ?: throw AntiCloneGateException(
                "cdbrw.enroll: NDK probe returned no timings on trial $i/$trials"
            )
            if (timings.isEmpty()) {
                throw AntiCloneGateException(
                    "cdbrw.enroll: NDK probe returned empty trial $i/$trials"
                )
            }
            out.add(timings)
            onProgress?.invoke(i + 1, trials)
        }
        return out
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
        // Rust ordinals: Blocked=1 < ReadOnly=2 < PinRequired=3 < FullAccess=4.
        // Proto enum numbering tracks those ordinals plus the UNSPECIFIED=0
        // sentinel, which we treat as BLOCKED (fail-closed).
        return when (proto) {
            CdbrwAccessLevel.CDBRW_ACCESS_FULL_ACCESS -> AccessLevel.FULL_ACCESS
            CdbrwAccessLevel.CDBRW_ACCESS_PIN_REQUIRED -> AccessLevel.PIN_REQUIRED
            CdbrwAccessLevel.CDBRW_ACCESS_READ_ONLY -> AccessLevel.READ_ONLY
            CdbrwAccessLevel.CDBRW_ACCESS_BLOCKED,
            CdbrwAccessLevel.CDBRW_ACCESS_UNSPECIFIED,
            CdbrwAccessLevel.UNRECOGNIZED,
            null -> AccessLevel.BLOCKED
        }
    }
}

class AntiCloneGateException(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)
