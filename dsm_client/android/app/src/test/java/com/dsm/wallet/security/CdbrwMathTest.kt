package com.dsm.wallet.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class CdbrwMathTest {

    @Test
    fun buildHistogram_normalizesToOne() {
        val samples = longArrayOf(1, 2, 3, 4, 5, 6, 7, 8)
        val hist = CdbrwMath.buildHistogram(samples, 256)
        val sum = hist.sum()

        assertEquals(1.0f, sum, 1e-5f)
    }

    @Test
    fun wasserstein_isZeroForIdenticalDistributions() {
        val h = FloatArray(256)
        h[10] = 0.25f
        h[20] = 0.75f

        val d = CdbrwMath.wasserstein1(h, h.copyOf())
        assertEquals(0.0f, d, 1e-7f)
    }

    @Test
    fun wasserstein_increasesForShiftedMass() {
        val a = FloatArray(256)
        val b = FloatArray(256)
        a[10] = 1.0f
        b[30] = 1.0f

        val d = CdbrwMath.wasserstein1(a, b)
        assertTrue(d > 0.0f)
    }

    @Test
    fun meanHistogram_averagesInputs() {
        val a = FloatArray(4)
        val b = FloatArray(4)
        a[0] = 1.0f
        b[2] = 1.0f

        val mean = CdbrwMath.meanHistogram(arrayOf(a, b))
        assertEquals(0.5f, mean[0], 1e-6f)
        assertEquals(0.5f, mean[2], 1e-6f)
    }

    @Test
    fun config_rejectsInvalidRotationBits() {
        var threw = false
        try {
            SiliconFingerprint.Config(rotationBits = 6)
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun buildHistogram_handlesDegenerateSamples() {
        val samples = longArrayOf(7, 7, 7, 7)
        val hist = CdbrwMath.buildHistogram(samples, 256)

        assertEquals(1.0f, hist[0], 1e-6f)
        assertEquals(1.0f, hist.sum(), 1e-6f)
    }

    @Test
    fun histogramToBytes_hasDeterministicLength() {
        val hist = FloatArray(256)
        hist[42] = 1.0f

        val bytes = CdbrwMath.histogramToBytes(hist)
        assertEquals(256 * 4, bytes.size)
    }

    // --- New tests ---

    @Test
    fun wasserstein_isSymmetric() {
        val a = FloatArray(64)
        val b = FloatArray(64)
        a[5] = 0.3f; a[20] = 0.7f
        b[10] = 0.5f; b[50] = 0.5f

        val ab = CdbrwMath.wasserstein1(a, b)
        val ba = CdbrwMath.wasserstein1(b, a)
        assertEquals(ab, ba, 1e-6f)
    }

    @Test
    fun wasserstein_triangleInequality() {
        val a = FloatArray(32)
        val b = FloatArray(32)
        val c = FloatArray(32)
        a[0] = 1.0f
        b[15] = 1.0f
        c[31] = 1.0f

        val ab = CdbrwMath.wasserstein1(a, b)
        val bc = CdbrwMath.wasserstein1(b, c)
        val ac = CdbrwMath.wasserstein1(a, c)
        assertTrue("W1 must satisfy triangle inequality: $ac <= $ab + $bc", ac <= ab + bc + 1e-5f)
    }

    @Test
    fun wasserstein_scalesWithBinDistance() {
        // Moving mass 1 bin should be less than moving it 10 bins
        val ref = FloatArray(64)
        ref[0] = 1.0f

        val near = FloatArray(64)
        near[1] = 1.0f

        val far = FloatArray(64)
        far[10] = 1.0f

        val dNear = CdbrwMath.wasserstein1(ref, near)
        val dFar = CdbrwMath.wasserstein1(ref, far)
        assertTrue("Farther shift should produce larger W1: $dFar > $dNear", dFar > dNear)
    }

    @Test
    fun histogramToBytes_roundTrip() {
        val hist = FloatArray(16)
        hist[0] = 0.25f; hist[3] = 0.5f; hist[15] = 0.25f

        val bytes = CdbrwMath.histogramToBytes(hist)
        assertEquals(16 * 4, bytes.size)

        // Reconstruct and verify
        val reconstructed = FloatArray(16)
        for (i in 0 until 16) {
            val off = i * 4
            val bits = (bytes[off].toInt() and 0xFF) or
                    ((bytes[off + 1].toInt() and 0xFF) shl 8) or
                    ((bytes[off + 2].toInt() and 0xFF) shl 16) or
                    ((bytes[off + 3].toInt() and 0xFF) shl 24)
            reconstructed[i] = java.lang.Float.intBitsToFloat(bits)
        }
        for (i in hist.indices) {
            assertEquals("Bin $i round-trip", hist[i], reconstructed[i], 0f)
        }
    }

    @Test
    fun meanHistogram_singleInput() {
        val h = FloatArray(8)
        h[2] = 0.6f; h[5] = 0.4f
        val mean = CdbrwMath.meanHistogram(arrayOf(h))
        for (i in h.indices) {
            assertEquals(h[i], mean[i], 1e-6f)
        }
    }

    @Test
    fun meanHistogram_threeInputs() {
        val a = FloatArray(4); a[0] = 0.3f; a[1] = 0.7f
        val b = FloatArray(4); b[0] = 0.6f; b[1] = 0.4f
        val c = FloatArray(4); c[0] = 0.9f; c[1] = 0.1f
        val mean = CdbrwMath.meanHistogram(arrayOf(a, b, c))
        assertEquals(0.6f, mean[0], 1e-5f)
        assertEquals(0.4f, mean[1], 1e-5f)
    }

    @Test
    fun buildHistogram_uniformSpread() {
        // 256 distinct values should spread across bins
        val samples = LongArray(256) { it.toLong() }
        val hist = CdbrwMath.buildHistogram(samples, 256)
        assertEquals(1.0f, hist.sum(), 1e-4f)
        // With 256 evenly spread values in 256 bins, each bin should get ~1/256
        val expected = 1.0f / 256f
        for (v in hist) {
            assertTrue("Each bin should be near $expected, got $v", v <= expected * 3)
        }
    }

    @Test
    fun buildHistogram_respectsBinCount() {
        val samples = LongArray(100) { it.toLong() }
        for (bins in listOf(256, 512, 1024)) {
            val hist = CdbrwMath.buildHistogram(samples, bins)
            assertEquals(bins, hist.size)
            assertEquals(1.0f, hist.sum(), 1e-4f)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun wasserstein_rejectsMismatchedSizes() {
        CdbrwMath.wasserstein1(FloatArray(10), FloatArray(20))
    }

    @Test
    fun config_acceptsAllValidRotationBits() {
        for (r in listOf(5, 7, 8, 11, 13)) {
            SiliconFingerprint.Config(rotationBits = r)
        }
    }

    @Test
    fun config_acceptsAllValidBinCounts() {
        for (b in listOf(256, 512, 1024)) {
            SiliconFingerprint.Config(histogramBins = b)
        }
    }

    @Test
    fun config_rejectsNonPowerOfTwoArena() {
        var threw = false
        try {
            SiliconFingerprint.Config(arenaBytes = 1000)
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun config_rejectsEvenTrials() {
        var threw = false
        try {
            SiliconFingerprint.Config(enrollTrials = 20)
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun config_rejectsProbesNotDivisibleBy8() {
        var threw = false
        try {
            SiliconFingerprint.Config(probes = 100)
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun config_rejectsNegativeDistanceMargin() {
        var threw = false
        try {
            SiliconFingerprint.Config(distanceMargin = -0.1f)
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun config_rejectsInvalidBinCount() {
        var threw = false
        try {
            SiliconFingerprint.Config(histogramBins = 128)
        } catch (_: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }
}
