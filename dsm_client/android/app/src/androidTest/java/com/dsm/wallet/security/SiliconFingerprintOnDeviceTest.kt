// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.FixMethodOrder
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.MethodSorters

/**
 * ON-DEVICE PROOF: C-DBRW Silicon Fingerprint Correctness
 *
 * These tests run on a real Android device (via ./gradlew connectedAndroidTest).
 * They prove the full native -> Kotlin -> gate pipeline works correctly:
 *
 *   1. libsiliconfp.so loads and captureOrbitDensity() returns valid timing data
 *   2. Timing data has realistic properties (positive, variance, non-degenerate histogram)
 *   3. Enrollment produces valid, persistent data with normalized histograms
 *   4. Derive matches the enrolled reference on the same device (W1 acceptance)
 *   5. Results are stable and reproducible across consecutive calls
 *   6. Config edge cases (small configs, mismatches) behave correctly
 *   7. AntiCloneGate full pipeline (runs LAST — production config is resource-heavy)
 *
 * NO network, NO BLE, NO second device required.
 *
 * Run:
 *   ./gradlew connectedAndroidTest \
 *     -Pandroid.testInstrumentationRunnerArguments.class=com.dsm.wallet.security.SiliconFingerprintOnDeviceTest
 */
@RunWith(AndroidJUnit4::class)
@FixMethodOrder(MethodSorters.NAME_ASCENDING)
class SiliconFingerprintOnDeviceTest {

    companion object {
        // Cache gate result across tests to avoid repeated 60-second enrollments.
        // AntiCloneGate uses production-default config (8MB, 21 trials) which is expensive.
        @Volatile
        private var cachedGateResult: HardwareAnchorResult? = null
    }

    private lateinit var ctx: Context

    private val testConfig = SiliconFingerprint.Config(
        arenaBytes = 1 * 1024 * 1024,
        probes = 512,
        stepsPerProbe = 512,
        enrollTrials = 5,
        verifyTrials = 3,
        histogramBins = 256,
        rotationBits = 7,
        distanceMargin = 0.15f
    )

    private val testEnvBytes = "DSM/silicon_env/test\u0000test|device".toByteArray(Charsets.UTF_8)

    @Before
    fun setUp() {
        ctx = ApplicationProvider.getApplicationContext()
    }

    // =========================================================================
    // SECTION 1: Native Library Loading
    // =========================================================================

    @Test
    fun t01_nativeLibrary_loads() {
        val samples = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = testEnvBytes,
            arenaBytes = testConfig.arenaBytes,
            probes = testConfig.probes,
            stepsPerProbe = testConfig.stepsPerProbe,
            warmupRounds = 2,
            rotationBits = testConfig.rotationBits
        )
        assertNotNull("captureOrbitDensity must return non-null", samples)
    }

    @Test
    fun t02_nativeCapture_returnsExpectedSize() {
        val samples = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = testEnvBytes,
            arenaBytes = testConfig.arenaBytes,
            probes = testConfig.probes,
            stepsPerProbe = testConfig.stepsPerProbe,
            warmupRounds = 2,
            rotationBits = testConfig.rotationBits
        )!!
        assertEquals("Sample count must equal probes", testConfig.probes, samples.size)
    }

    // =========================================================================
    // SECTION 2: Capture Quality
    // =========================================================================

    @Test
    fun t10_capture_timingsArePositive() {
        val samples = captureOnce()
        for (i in samples.indices) {
            assertTrue("Timing[$i] must be > 0, got ${samples[i]}", samples[i] > 0)
        }
    }

    @Test
    fun t11_capture_hasVariance() {
        val samples = captureOnce()
        val distinct = samples.toSet().size
        assertTrue(
            "Capture must have variance (distinct values: $distinct out of ${samples.size})",
            distinct > 1
        )
    }

    @Test
    fun t12_capture_histogram_normalizesToOne() {
        val samples = captureOnce()
        val hist = CdbrwMath.buildHistogram(samples, testConfig.histogramBins)
        val sum = hist.sum()
        assertEquals("Histogram must normalize to 1.0", 1.0f, sum, 1e-4f)
    }

    @Test
    fun t13_capture_histogram_notDegenerate() {
        val samples = captureOnce()
        val hist = CdbrwMath.buildHistogram(samples, testConfig.histogramBins)
        val nonZeroBins = hist.count { it > 0f }
        assertTrue(
            "Histogram must have > 1 non-zero bin (got $nonZeroBins)",
            nonZeroBins > 1
        )
    }

    @Test
    fun t14_capture_repeatability() {
        val a = captureOnce()
        val b = captureOnce()
        val histA = CdbrwMath.buildHistogram(a, testConfig.histogramBins)
        val histB = CdbrwMath.buildHistogram(b, testConfig.histogramBins)
        val w1 = CdbrwMath.wasserstein1(histA, histB)
        assertTrue(
            "Two captures on same device should have W1 < 0.5, got $w1",
            w1 < 0.5f
        )
    }

    // =========================================================================
    // SECTION 3: Enrollment
    // =========================================================================

    @Test
    fun t20_enroll_succeeds() {
        val fp = SiliconFingerprint(testConfig)
        fp.clearEnrollment(ctx)
        val enrollment = fp.enroll(ctx)
        assertNotNull("Enrollment must not be null", enrollment)
    }

    @Test
    fun t21_enroll_meanHistogram_normalized() {
        val fp = ensureTestEnrollment()
        val enrollment = fp.loadEnrollment(ctx)!!
        val sum = enrollment.meanHistogram.sum()
        assertEquals("Mean histogram must sum to ~1.0", 1.0f, sum, 0.05f)
    }

    @Test
    fun t22_enroll_referenceAnchor_is32Bytes() {
        val fp = ensureTestEnrollment()
        val enrollment = fp.loadEnrollment(ctx)!!
        assertEquals("Reference anchor must be 32 bytes", 32, enrollment.referenceAnchor32.size)
    }

    @Test
    fun t23_enroll_referenceAnchor_notAllZeros() {
        val fp = ensureTestEnrollment()
        val enrollment = fp.loadEnrollment(ctx)!!
        assertTrue(
            "Reference anchor must not be all zeros",
            enrollment.referenceAnchor32.any { it != 0.toByte() }
        )
    }

    @Test
    fun t24_enroll_persistsToStorage() {
        val fp = ensureTestEnrollment()
        assertTrue("Must be enrolled after enroll()", fp.isEnrolled(ctx))
        val loaded = fp.loadEnrollment(ctx)
        assertNotNull("loadEnrollment must return non-null", loaded)
    }

    // =========================================================================
    // SECTION 4: Derive (Enroll -> Derive Round-Trip)
    // =========================================================================

    @Test
    fun t30_derive_afterEnroll_succeeds() {
        val fp = ensureTestEnrollment()
        val derived = fp.derive(ctx)
        assertNotNull("Derived must not be null", derived)
    }

    @Test
    fun t31_derive_matchScore_aboveThreshold() {
        val fp = ensureTestEnrollment()
        val derived = fp.derive(ctx)
        assertTrue(
            "matchScore on same device must be >= 0.65, got ${derived.matchScore}",
            derived.matchScore >= 0.65f
        )
    }

    @Test
    fun t32_derive_w1Distance_belowThreshold() {
        val fp = ensureTestEnrollment()
        val derived = fp.derive(ctx)
        assertTrue(
            "W1 distance (${derived.w1Distance}) must be <= threshold (${derived.w1Threshold})",
            derived.w1Distance <= derived.w1Threshold
        )
    }

    @Test
    fun t33_derive_anchor_matches_enrolledReference() {
        val fp = ensureTestEnrollment()
        val derived = fp.derive(ctx)
        assertTrue(
            "Derived anchor must match enrolled reference",
            derived.anchor32.contentEquals(derived.referenceAnchor32)
        )
    }

    @Test
    fun t34_derive_w1Distance_isNonNegative() {
        val fp = ensureTestEnrollment()
        val derived = fp.derive(ctx)
        assertTrue(
            "W1 distance must be >= 0, got ${derived.w1Distance}",
            derived.w1Distance >= 0.0f
        )
    }

    @Test
    fun t35_derive_withoutEnrollment_throws() {
        val fp = SiliconFingerprint(testConfig)
        fp.clearEnrollment(ctx)
        try {
            fp.derive(ctx)
            fail("derive() without enrollment must throw SiliconFpException")
        } catch (e: SiliconFpException) {
            assertEquals(
                "Error code must be NOT_ENROLLED",
                SiliconFpError.NOT_ENROLLED,
                e.code
            )
        }
    }

    // =========================================================================
    // SECTION 5: Stability & Reproducibility
    // =========================================================================

    @Test
    fun t40_derive_twoConsecutiveCalls_sameAnchor() {
        val fp = ensureTestEnrollment()
        val d1 = fp.derive(ctx)
        val d2 = fp.derive(ctx)
        assertTrue(
            "Two consecutive derives must produce same anchor",
            d1.anchor32.contentEquals(d2.anchor32)
        )
    }

    @Test
    fun t41_derive_twoConsecutiveCalls_similarW1() {
        val fp = ensureTestEnrollment()
        val d1 = fp.derive(ctx)
        val d2 = fp.derive(ctx)
        val ratio = if (d1.w1Distance > 0f && d2.w1Distance > 0f) {
            maxOf(d1.w1Distance, d2.w1Distance) / minOf(d1.w1Distance, d2.w1Distance)
        } else {
            1.0f
        }
        assertTrue(
            "W1 distances should be within 3x of each other (ratio=$ratio, d1=${d1.w1Distance}, d2=${d2.w1Distance})",
            ratio < 3.0f
        )
    }

    @Test
    fun t42_environmentFingerprint_deterministic() {
        val fp1 = AntiCloneGate.getEnvironmentFingerprint(ctx)
        val fp2 = AntiCloneGate.getEnvironmentFingerprint(ctx)
        assertTrue(
            "Environment fingerprint must be deterministic",
            fp1.contentEquals(fp2)
        )
    }

    @Test
    fun t43_enrollment_survivesClearAndReenroll() {
        val fp = SiliconFingerprint(testConfig)
        fp.clearEnrollment(ctx)
        fp.enroll(ctx)
        fp.clearEnrollment(ctx)
        assertTrue("Must not be enrolled after clear", !fp.isEnrolled(ctx))

        fp.enroll(ctx)
        assertTrue("Must be enrolled after re-enroll", fp.isEnrolled(ctx))

        val derived = fp.derive(ctx)
        // Relaxed threshold (0.50) for this test: clear+re-enroll creates a new baseline
        // from scratch, and the lightweight testConfig (512 probes, 5 trials) has higher
        // variance than production config. A matchScore > 0.50 still proves same-device.
        assertTrue(
            "Derive after re-enroll must pass, got matchScore=${derived.matchScore}",
            derived.matchScore >= 0.50f
        )
    }

    // =========================================================================
    // SECTION 6: Config Edge Cases
    // =========================================================================

    @Test
    fun t50_smallConfig_enroll_succeeds() {
        val smallConfig = SiliconFingerprint.Config(
            arenaBytes = 1 * 1024 * 1024,
            probes = 64,
            stepsPerProbe = 64,
            enrollTrials = 3,
            verifyTrials = 3,
            histogramBins = 256,
            rotationBits = 7,
            distanceMargin = 0.20f
        )
        val fp = SiliconFingerprint(smallConfig)
        fp.clearEnrollment(ctx)
        val enrollment = fp.enroll(ctx)
        assertNotNull("Small config enrollment must succeed", enrollment)
        assertEquals("Anchor must be 32 bytes", 32, enrollment.referenceAnchor32.size)
    }

    @Test
    fun t51_smallConfig_derive_succeeds() {
        val smallConfig = SiliconFingerprint.Config(
            arenaBytes = 1 * 1024 * 1024,
            probes = 64,
            stepsPerProbe = 64,
            enrollTrials = 3,
            verifyTrials = 3,
            histogramBins = 256,
            rotationBits = 7,
            distanceMargin = 0.20f
        )
        val fp = SiliconFingerprint(smallConfig)
        fp.clearEnrollment(ctx)
        fp.enroll(ctx)
        val derived = fp.derive(ctx)
        assertNotNull("Small config derive must succeed", derived)
        assertTrue("W1 must be non-negative", derived.w1Distance >= 0f)
    }

    @Test
    fun t52_configMismatch_derive_throws() {
        val configA = SiliconFingerprint.Config(
            arenaBytes = 1 * 1024 * 1024,
            probes = 512,
            stepsPerProbe = 512,
            enrollTrials = 3,
            verifyTrials = 3,
            histogramBins = 256,
            rotationBits = 7,
            distanceMargin = 0.15f
        )
        val configB = SiliconFingerprint.Config(
            arenaBytes = 1 * 1024 * 1024,
            probes = 256,
            stepsPerProbe = 256,
            enrollTrials = 3,
            verifyTrials = 3,
            histogramBins = 256,
            rotationBits = 7,
            distanceMargin = 0.15f
        )

        val fpA = SiliconFingerprint(configA)
        fpA.clearEnrollment(ctx)
        fpA.enroll(ctx)

        try {
            SiliconFingerprint(configB).derive(ctx)
            fail("derive() with mismatched config must throw SiliconFpException")
        } catch (e: SiliconFpException) {
            assertEquals(
                "Error code must be CONFIG_MISMATCH",
                SiliconFpError.CONFIG_MISMATCH,
                e.code
            )
        }
    }

    // =========================================================================
    // SECTION 7: AntiCloneGate Full Pipeline
    //
    // These run LAST (t60+) because AntiCloneGate uses production config
    // (8MB arena, 21 trials, 4096 probes) which is resource-intensive.
    // If the native mmap allocation crashes the process on a constrained device,
    // sections 1-6 (25 tests) have already completed successfully.
    //
    // Tests share a single gate invocation via cachedGateResult to avoid
    // repeated 60-second production-config enrollments.
    // =========================================================================

    @Test
    fun t60_antiCloneGate_sameDevice_notBlocked() {
        // Clear any test-config enrollment left by earlier sections to avoid
        // CONFIG_MISMATCH when AntiCloneGate enrolls with default production config.
        SiliconFingerprint(testConfig).clearEnrollment(ctx)
        val result = getOrComputeGateResult()
        assertTrue(
            "Same device must not be BLOCKED, got ${result.accessLevel}",
            result.accessLevel != AccessLevel.BLOCKED
        )
    }

    @Test
    fun t61_antiCloneGate_anchor_is32Bytes() {
        val result = getOrComputeGateResult()
        assertNotNull("Anchor must not be null", result.anchor)
        assertEquals("Anchor must be 32 bytes", 32, result.anchor!!.size)
    }

    @Test
    fun t62_antiCloneGate_w1Fields_populated() {
        val result = getOrComputeGateResult()
        assertTrue(
            "w1Distance must be >= 0, got ${result.w1Distance}",
            result.w1Distance >= 0f
        )
        assertTrue(
            "w1Threshold must be > 0, got ${result.w1Threshold}",
            result.w1Threshold > 0f
        )
    }

    @Test
    fun t63_antiCloneGate_monitoring_alwaysFullAccess() {
        val result = AntiCloneGate.getStableHwAnchorMonitoring(ctx)
        assertEquals(
            "Monitoring mode must return FULL_ACCESS",
            AccessLevel.FULL_ACCESS,
            result.accessLevel
        )
    }

    @Test
    fun t64_antiCloneGate_monitoring_anchorNonNull() {
        val result = AntiCloneGate.getStableHwAnchorMonitoring(ctx)
        assertNotNull("Monitoring mode must always provide an anchor", result.anchor)
        assertEquals("Anchor must be 32 bytes", 32, result.anchor!!.size)
    }

    // =========================================================================
    // Helpers
    // =========================================================================

    private fun captureOnce(): LongArray {
        return SiliconFingerprintNative.captureOrbitDensity(
            envBytes = testEnvBytes,
            arenaBytes = testConfig.arenaBytes,
            probes = testConfig.probes,
            stepsPerProbe = testConfig.stepsPerProbe,
            warmupRounds = 2,
            rotationBits = testConfig.rotationBits
        ) ?: fail("captureOrbitDensity returned null") as LongArray
    }

    private fun ensureTestEnrollment(): SiliconFingerprint {
        val fp = SiliconFingerprint(testConfig)
        val existing = fp.loadEnrollment(ctx)
        if (existing == null ||
            existing.probes != testConfig.probes ||
            existing.stepsPerProbe != testConfig.stepsPerProbe ||
            existing.arenaBytes != testConfig.arenaBytes
        ) {
            fp.clearEnrollment(ctx)
            fp.enroll(ctx)
        }
        return fp
    }

    private fun getOrComputeGateResult(): HardwareAnchorResult {
        cachedGateResult?.let { return it }
        val result = AntiCloneGate.getStableHwAnchorWithTrust(ctx)
        cachedGateResult = result
        return result
    }
}
