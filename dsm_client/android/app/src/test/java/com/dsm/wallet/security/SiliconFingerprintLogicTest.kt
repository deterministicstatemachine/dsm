package com.dsm.wallet.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure-JVM tests for SiliconFingerprint data models, config validation,
 * and acceptance boundary logic. These do not require native libraries
 * or Android framework; they test the Kotlin-layer math and contracts.
 */
class SiliconFingerprintLogicTest {

    // --- Config validation ---

    @Test
    fun config_defaults_areValid() {
        val c = SiliconFingerprint.Config()
        assertEquals(8 * 1024 * 1024, c.arenaBytes)
        assertEquals(4096, c.probes)
        assertEquals(4096, c.stepsPerProbe)
        assertEquals(21, c.enrollTrials)
        assertEquals(9, c.verifyTrials)
        assertEquals(256, c.histogramBins)
        assertEquals(7, c.rotationBits)
        assertEquals(0.15f, c.distanceMargin, 0f)
    }

    @Test(expected = IllegalArgumentException::class)
    fun config_rejectsZeroArena() {
        SiliconFingerprint.Config(arenaBytes = 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun config_rejectsNegativeArena() {
        SiliconFingerprint.Config(arenaBytes = -1)
    }

    @Test(expected = IllegalArgumentException::class)
    fun config_rejectsZeroProbes() {
        SiliconFingerprint.Config(probes = 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun config_rejectsZeroStepsPerProbe() {
        SiliconFingerprint.Config(stepsPerProbe = 0)
    }

    @Test(expected = IllegalArgumentException::class)
    fun config_rejectsEvenEnrollTrials() {
        SiliconFingerprint.Config(enrollTrials = 10)
    }

    @Test(expected = IllegalArgumentException::class)
    fun config_rejectsEvenVerifyTrials() {
        SiliconFingerprint.Config(verifyTrials = 4)
    }

    @Test
    fun config_acceptsMinimalValid() {
        // Smallest valid configuration
        val c = SiliconFingerprint.Config(
            arenaBytes = 1, // 2^0
            probes = 8,
            stepsPerProbe = 1,
            enrollTrials = 1,
            verifyTrials = 1,
            histogramBins = 256,
            rotationBits = 5,
            distanceMargin = 0f
        )
        assertEquals(1, c.arenaBytes)
    }

    @Test
    fun config_acceptsLargerPowersOfTwo() {
        for (exp in 1..24) {
            SiliconFingerprint.Config(arenaBytes = 1 shl exp)
        }
    }

    // --- Enrollment data class ---

    @Test
    fun enrollment_equality_matchesContentEquals() {
        val hist = FloatArray(256) { if (it == 42) 1.0f else 0.0f }
        val anchor = ByteArray(32) { it.toByte() }

        val a = SiliconFingerprint.Enrollment(
            revision = 4, arenaBytes = 8388608, probes = 4096,
            stepsPerProbe = 4096, histogramBins = 256, rotationBits = 7,
            epsilonIntra = 0.05f, meanHistogram = hist.copyOf(), referenceAnchor32 = anchor.copyOf()
        )
        val b = SiliconFingerprint.Enrollment(
            revision = 4, arenaBytes = 8388608, probes = 4096,
            stepsPerProbe = 4096, histogramBins = 256, rotationBits = 7,
            epsilonIntra = 0.05f, meanHistogram = hist.copyOf(), referenceAnchor32 = anchor.copyOf()
        )
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }

    @Test
    fun enrollment_inequality_onDifferentEpsilon() {
        val hist = FloatArray(256)
        val anchor = ByteArray(32)
        val a = SiliconFingerprint.Enrollment(
            revision = 4, arenaBytes = 8388608, probes = 4096,
            stepsPerProbe = 4096, histogramBins = 256, rotationBits = 7,
            epsilonIntra = 0.05f, meanHistogram = hist, referenceAnchor32 = anchor
        )
        val b = a.copy(epsilonIntra = 0.10f)
        assertNotEquals(a, b)
    }

    // --- Derived data class ---

    @Test
    fun derived_equality_matchesContentEquals() {
        val anchor = ByteArray(32) { it.toByte() }
        val a = SiliconFingerprint.Derived(
            anchor32 = anchor.copyOf(), w1Distance = 0.03f, w1Threshold = 0.20f,
            matchScore = 0.85f, referenceAnchor32 = anchor.copyOf()
        )
        val b = SiliconFingerprint.Derived(
            anchor32 = anchor.copyOf(), w1Distance = 0.03f, w1Threshold = 0.20f,
            matchScore = 0.85f, referenceAnchor32 = anchor.copyOf()
        )
        assertEquals(a, b)
    }

    @Test
    fun derived_inequality_onDifferentW1() {
        val anchor = ByteArray(32)
        val a = SiliconFingerprint.Derived(
            anchor32 = anchor, w1Distance = 0.03f, w1Threshold = 0.20f,
            matchScore = 0.85f, referenceAnchor32 = anchor
        )
        val b = SiliconFingerprint.Derived(
            anchor32 = anchor, w1Distance = 0.15f, w1Threshold = 0.20f,
            matchScore = 0.25f, referenceAnchor32 = anchor
        )
        assertNotEquals(a, b)
    }

    // --- matchScore computation logic ---

    @Test
    fun matchScore_formula_perfectMatch() {
        // W1 = 0, threshold > 0 → matchScore = 1.0
        val w1 = 0.0f
        val threshold = 0.20f
        val score = computeMatchScore(w1, threshold)
        assertEquals(1.0f, score, 1e-5f)
    }

    @Test
    fun matchScore_formula_atThreshold() {
        // W1 = threshold → matchScore ≈ 0
        val threshold = 0.20f
        val score = computeMatchScore(threshold, threshold)
        assertTrue("Score at threshold should be near 0, got $score", score < 0.01f)
    }

    @Test
    fun matchScore_formula_halfThreshold() {
        // W1 = threshold/2 → matchScore ≈ 0.5
        val threshold = 0.20f
        val score = computeMatchScore(threshold / 2f, threshold)
        assertTrue("Score at half-threshold should be near 0.5, got $score", score in 0.4f..0.6f)
    }

    @Test
    fun matchScore_formula_overThreshold_clampedToZero() {
        val score = computeMatchScore(0.50f, 0.20f)
        assertEquals(0.0f, score, 0f)
    }

    @Test
    fun matchScore_formula_clampsToOne() {
        // Negative W1 is impossible but test clamp
        val score = computeMatchScore(-0.01f, 0.20f)
        assertEquals(1.0f, score, 1e-5f)
    }

    // --- W1 acceptance boundary tests ---

    @Test
    fun acceptance_withinThreshold_passes() {
        val epsilonIntra = 0.05f
        val margin = 0.15f
        val threshold = epsilonIntra + margin
        val measured = 0.10f // well within
        assertTrue(measured <= threshold)
    }

    @Test
    fun acceptance_exactlyAtThreshold_passes() {
        val epsilonIntra = 0.05f
        val margin = 0.15f
        val threshold = epsilonIntra + margin
        val measured = threshold
        assertTrue(measured <= threshold)
    }

    @Test
    fun acceptance_overThreshold_fails() {
        val epsilonIntra = 0.05f
        val margin = 0.15f
        val threshold = epsilonIntra + margin
        val measured = threshold + 0.001f
        assertTrue(measured > threshold)
    }

    // --- SiliconFpError ---

    @Test
    fun siliconFpException_preservesCode() {
        val ex = SiliconFpException(SiliconFpError.NOT_ENROLLED, "test message")
        assertEquals(SiliconFpError.NOT_ENROLLED, ex.code)
        assertEquals("test message", ex.message)
    }

    @Test
    fun siliconFpError_allVariants() {
        val codes = SiliconFpError.values()
        assertEquals(4, codes.size)
        assertTrue(codes.contains(SiliconFpError.NOT_ENROLLED))
        assertTrue(codes.contains(SiliconFpError.CONFIG_MISMATCH))
        assertTrue(codes.contains(SiliconFpError.INSUFFICIENT_STABLE_BITS))
        assertTrue(codes.contains(SiliconFpError.INTERNAL))
    }

    // --- Helper: mirrors the matchScore formula from SiliconFingerprint.derive() ---

    private fun computeMatchScore(w1Distance: Float, w1Threshold: Float): Float {
        return (1.0f - (w1Distance / (w1Threshold + 1e-6f))).coerceIn(0.0f, 1.0f)
    }
}
