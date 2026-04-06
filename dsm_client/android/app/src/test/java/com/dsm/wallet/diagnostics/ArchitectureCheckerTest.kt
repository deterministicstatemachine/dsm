package com.dsm.wallet.diagnostics

import android.os.Build
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import org.robolectric.util.ReflectionHelpers

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class ArchitectureCheckerTest {

    // ── Helpers ────────────────────────────────────────────────────────────

    private fun setSupportedAbis(vararg abis: String) {
        ReflectionHelpers.setStaticField(Build::class.java, "SUPPORTED_ABIS", abis)
    }

    private fun setSdkInt(sdk: Int) {
        ReflectionHelpers.setStaticField(Build.VERSION::class.java, "SDK_INT", sdk)
    }

    @Before
    fun resetDefaults() {
        setSupportedAbis("arm64-v8a")
        setSdkInt(33)
    }

    // ── checkCompatibility ─────────────────────────────────────────────────

    @Test
    fun arm64_api33_isFullyCompatible() {
        setSupportedAbis("arm64-v8a")
        setSdkInt(33)
        val result = ArchitectureChecker.checkCompatibility()
        assertEquals(ArchitectureChecker.ArchStatus.COMPATIBLE, result.status)
        assertTrue(result.message.contains("ARM64"))
    }

    @Test
    fun armv7_api33_isCompatibleWithWarning() {
        setSupportedAbis("armeabi-v7a")
        setSdkInt(33)
        val result = ArchitectureChecker.checkCompatibility()
        assertEquals(ArchitectureChecker.ArchStatus.COMPATIBLE, result.status)
        assertTrue(result.message.contains("ARMv7"))
        assertTrue(result.message.contains("reduced performance"))
    }

    @Test
    fun x86_only_isUnsupported() {
        setSupportedAbis("x86_64", "x86")
        setSdkInt(33)
        val result = ArchitectureChecker.checkCompatibility()
        assertEquals(ArchitectureChecker.ArchStatus.UNSUPPORTED_ABI, result.status)
    }

    @Test
    fun api25_isIncompatibleJvm() {
        setSupportedAbis("arm64-v8a")
        setSdkInt(25)
        val result = ArchitectureChecker.checkCompatibility()
        assertEquals(ArchitectureChecker.ArchStatus.INCOMPATIBLE_JVM, result.status)
        assertTrue(result.message.contains("API 25"))
    }

    @Test
    fun api26_isMinimumCompatible() {
        setSupportedAbis("arm64-v8a")
        setSdkInt(26)
        val result = ArchitectureChecker.checkCompatibility()
        assertEquals(ArchitectureChecker.ArchStatus.COMPATIBLE, result.status)
    }

    @Test
    fun x86WithArm64Secondary_usesSecondaryAbi() {
        setSupportedAbis("x86_64", "arm64-v8a")
        setSdkInt(33)
        val result = ArchitectureChecker.checkCompatibility()
        assertEquals(ArchitectureChecker.ArchStatus.COMPATIBLE, result.status)
        assertTrue(result.message.contains("secondary ABI"))
    }

    @Test
    fun unsupportedAbi_abiCheck_beforeSdkCheck() {
        setSupportedAbis("x86")
        setSdkInt(25)
        val result = ArchitectureChecker.checkCompatibility()
        assertEquals(ArchitectureChecker.ArchStatus.UNSUPPORTED_ABI, result.status)
    }

    @Test
    fun result_containsDeviceArch() {
        setSupportedAbis("arm64-v8a")
        val result = ArchitectureChecker.checkCompatibility()
        assertEquals("arm64-v8a", result.deviceArch)
    }

    @Test
    fun result_containsSupportedAbis() {
        setSupportedAbis("arm64-v8a", "armeabi-v7a")
        val result = ArchitectureChecker.checkCompatibility()
        assertEquals(listOf("arm64-v8a", "armeabi-v7a"), result.supportedAbis)
    }

    @Test
    fun result_messageIsNotBlank() {
        val result = ArchitectureChecker.checkCompatibility()
        assertTrue(result.message.isNotBlank())
    }

    @Test
    fun result_recommendationIsNotBlank() {
        val result = ArchitectureChecker.checkCompatibility()
        assertTrue(result.recommendation.isNotBlank())
    }

    // ── isDeviceBlocked ────────────────────────────────────────────────────

    @Test
    fun isDeviceBlocked_falseForArm64() {
        setSupportedAbis("arm64-v8a")
        setSdkInt(33)
        assertFalse(ArchitectureChecker.isDeviceBlocked())
    }

    @Test
    fun isDeviceBlocked_trueForX86() {
        setSupportedAbis("x86")
        setSdkInt(33)
        assertTrue(ArchitectureChecker.isDeviceBlocked())
    }

    @Test
    fun isDeviceBlocked_trueForOldApi() {
        setSupportedAbis("arm64-v8a")
        setSdkInt(24)
        assertTrue(ArchitectureChecker.isDeviceBlocked())
    }

    @Test
    fun isDeviceBlocked_falseForArmv7() {
        setSupportedAbis("armeabi-v7a")
        setSdkInt(28)
        assertFalse(ArchitectureChecker.isDeviceBlocked())
    }

    // ── getBlockingErrorMessage ────────────────────────────────────────────

    @Test
    fun getBlockingErrorMessage_nullForCompatible() {
        setSupportedAbis("arm64-v8a")
        setSdkInt(33)
        assertNull(ArchitectureChecker.getBlockingErrorMessage())
    }

    @Test
    fun getBlockingErrorMessage_nonNullForUnsupportedAbi() {
        setSupportedAbis("x86")
        setSdkInt(33)
        val msg = ArchitectureChecker.getBlockingErrorMessage()
        assertNotNull(msg)
        assertTrue(msg!!.contains("Unsupported"))
    }

    @Test
    fun getBlockingErrorMessage_nonNullForIncompatibleJvm() {
        setSupportedAbis("arm64-v8a")
        setSdkInt(21)
        val msg = ArchitectureChecker.getBlockingErrorMessage()
        assertNotNull(msg)
        assertTrue(msg!!.contains("too old"))
    }

    @Test
    fun getBlockingErrorMessage_containsRecommendation() {
        setSupportedAbis("x86")
        setSdkInt(33)
        val msg = ArchitectureChecker.getBlockingErrorMessage()!!
        assertTrue(msg.contains("ARM"))
    }

    // ── getArchitectureSummary ─────────────────────────────────────────────

    @Test
    fun getArchitectureSummary_containsPrimaryAbi() {
        setSupportedAbis("arm64-v8a")
        val summary = ArchitectureChecker.getArchitectureSummary()
        assertTrue(summary.contains("arm64-v8a"))
    }

    @Test
    fun getArchitectureSummary_containsStatusName() {
        setSupportedAbis("arm64-v8a")
        setSdkInt(33)
        val summary = ArchitectureChecker.getArchitectureSummary()
        assertTrue(summary.contains("COMPATIBLE"))
    }

    @Test
    fun getArchitectureSummary_containsMultipleAbis() {
        setSupportedAbis("arm64-v8a", "armeabi-v7a")
        val summary = ArchitectureChecker.getArchitectureSummary()
        assertTrue(summary.contains("arm64-v8a"))
        assertTrue(summary.contains("armeabi-v7a"))
    }

    @Test
    fun getArchitectureSummary_hasExpectedSections() {
        val summary = ArchitectureChecker.getArchitectureSummary()
        assertTrue(summary.contains("Device Architecture:"))
        assertTrue(summary.contains("Primary ABI:"))
        assertTrue(summary.contains("All ABIs:"))
        assertTrue(summary.contains("Status:"))
        assertTrue(summary.contains("Message:"))
    }

    // ── ArchStatus enum ────────────────────────────────────────────────────

    @Test
    fun archStatus_has4Values() {
        assertEquals(4, ArchitectureChecker.ArchStatus.entries.size)
    }

    @Test
    fun archStatus_valueOfRoundTrips() {
        for (s in ArchitectureChecker.ArchStatus.entries) {
            assertEquals(s, ArchitectureChecker.ArchStatus.valueOf(s.name))
        }
    }

    // ── ArchCompatibility data class ───────────────────────────────────────

    @Test
    fun archCompatibility_copyPreservesFields() {
        val orig = ArchitectureChecker.ArchCompatibility(
            status = ArchitectureChecker.ArchStatus.COMPATIBLE,
            deviceArch = "arm64-v8a",
            supportedAbis = listOf("arm64-v8a"),
            message = "OK",
            recommendation = "None"
        )
        val copy = orig.copy(message = "Updated")
        assertEquals("Updated", copy.message)
        assertEquals(orig.status, copy.status)
        assertEquals(orig.deviceArch, copy.deviceArch)
    }

    @Test
    fun archCompatibility_equalityWorks() {
        val a = ArchitectureChecker.ArchCompatibility(
            status = ArchitectureChecker.ArchStatus.UNKNOWN,
            deviceArch = "x",
            supportedAbis = emptyList(),
            message = "m",
            recommendation = "r"
        )
        val b = a.copy()
        assertEquals(a, b)
        assertEquals(a.hashCode(), b.hashCode())
    }
}
