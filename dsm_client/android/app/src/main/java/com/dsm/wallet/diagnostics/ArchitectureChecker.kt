package com.dsm.wallet.diagnostics

import android.content.Context
import android.os.Build
import android.util.Log

/**
 * ArchitectureChecker - Validates device architecture compatibility with DSM native libraries.
 * 
 * Checks CPU architecture, ABI compatibility, and JVM requirements to ensure the
 * native Rust/JNI components can be loaded and executed correctly.
 * 
 * Clockless, deterministic validation - no time-based checks.
 */
object ArchitectureChecker {
    private const val TAG = "ArchitectureChecker"
    
    /**
     * Architecture compatibility status
     */
    enum class ArchStatus {
        COMPATIBLE,           // Device architecture is fully supported
        UNSUPPORTED_ABI,      // CPU architecture not supported (e.g., x86, ARMv7)
        INCOMPATIBLE_JVM,     // JVM/Dalvik version incompatible
        UNKNOWN               // Unable to determine architecture
    }
    
    data class ArchCompatibility(
        val status: ArchStatus,
        val deviceArch: String,
        val supportedAbis: List<String>,
        val message: String,
        val recommendation: String
    )
    
    /**
     * Supported ABIs for DSM native libraries (Rust compiled for these targets)
     */
    private val SUPPORTED_ABIS = setOf(
        "arm64-v8a",    // 64-bit ARM (primary target)
        "armeabi-v7a"   // 32-bit ARM (secondary, may have reduced performance)
    )
    
    /**
     * Check if device architecture is compatible with DSM.
     * 
     * @return ArchCompatibility with detailed status and recommendations
     */
    fun checkCompatibility(): ArchCompatibility {
        val supportedAbis = Build.SUPPORTED_ABIS.toList()
        val primaryAbi = Build.SUPPORTED_ABIS.getOrNull(0) ?: "unknown"
        
        Log.i(TAG, "Device architecture check:")
        Log.i(TAG, "  Primary ABI: $primaryAbi")
        Log.i(TAG, "  All ABIs: ${supportedAbis.joinToString(", ")}")
        Log.i(TAG, "  Android SDK: ${Build.VERSION.SDK_INT}")
        Log.i(TAG, "  Device: ${Build.MANUFACTURER} ${Build.MODEL}")
        
        // Check if any supported ABI is present
        val hasCompatibleAbi = supportedAbis.any { it in SUPPORTED_ABIS }
        
        return when {
            !hasCompatibleAbi -> {
                val unsupportedAbis = supportedAbis.joinToString(", ")
                ArchCompatibility(
                    status = ArchStatus.UNSUPPORTED_ABI,
                    deviceArch = primaryAbi,
                    supportedAbis = supportedAbis,
                    message = "Unsupported CPU architecture: $unsupportedAbis",
                    recommendation = "DSM requires ARM64 (arm64-v8a) or ARMv7 (armeabi-v7a). " +
                            "This device uses $primaryAbi which is not supported. " +
                            "Please use an ARM-based Android device."
                )
            }
            Build.VERSION.SDK_INT < Build.VERSION_CODES.O -> {
                // Android 8.0 (API 26) is minimum for BLE extended advertising + JNI/NDK
                ArchCompatibility(
                    status = ArchStatus.INCOMPATIBLE_JVM,
                    deviceArch = primaryAbi,
                    supportedAbis = supportedAbis,
                    message = "Android version too old: API ${Build.VERSION.SDK_INT}",
                    recommendation = "DSM requires Android 8.0 (API 26) or higher. " +
                            "Current device: Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}). " +
                            "Please upgrade to a newer Android version."
                )
            }
            primaryAbi == "armeabi-v7a" -> {
                // ARMv7 is supported but not optimal
                ArchCompatibility(
                    status = ArchStatus.COMPATIBLE,
                    deviceArch = primaryAbi,
                    supportedAbis = supportedAbis,
                    message = "Compatible (ARMv7 - reduced performance)",
                    recommendation = "This device uses 32-bit ARM (armeabi-v7a). " +
                            "DSM will work but with reduced performance. " +
                            "For optimal performance, use a 64-bit ARM device (arm64-v8a)."
                )
            }
            primaryAbi == "arm64-v8a" -> {
                // Optimal configuration
                ArchCompatibility(
                    status = ArchStatus.COMPATIBLE,
                    deviceArch = primaryAbi,
                    supportedAbis = supportedAbis,
                    message = "Fully compatible (ARM64 - optimal)",
                    recommendation = "This device has optimal architecture for DSM (64-bit ARM)."
                )
            }
            else -> {
                // Compatible ABI found but not primary
                val compatibleAbi = supportedAbis.first { it in SUPPORTED_ABIS }
                ArchCompatibility(
                    status = ArchStatus.COMPATIBLE,
                    deviceArch = compatibleAbi,
                    supportedAbis = supportedAbis,
                    message = "Compatible (using secondary ABI: $compatibleAbi)",
                    recommendation = "Device primary ABI is $primaryAbi, but DSM will use $compatibleAbi. " +
                            "Performance may vary."
                )
            }
        }
    }
    
    /**
     * Get a user-friendly architecture summary string.
     * 
     * @return Human-readable summary of device architecture
     */
    fun getArchitectureSummary(): String {
        val compat = checkCompatibility()
        return buildString {
            appendLine("Device Architecture:")
            appendLine("  Primary ABI: ${compat.deviceArch}")
            appendLine("  All ABIs: ${compat.supportedAbis.joinToString(", ")}")
            appendLine("  Status: ${compat.status.name}")
            appendLine("  Message: ${compat.message}")
            if (compat.recommendation.isNotEmpty()) {
                appendLine("  Note: ${compat.recommendation}")
            }
        }
    }
    
    /**
     * Check if device is blocked from running DSM.
     * Returns true if device should be prevented from proceeding.
     */
    fun isDeviceBlocked(): Boolean {
        val compat = checkCompatibility()
        return compat.status == ArchStatus.UNSUPPORTED_ABI || 
               compat.status == ArchStatus.INCOMPATIBLE_JVM
    }
    
    /**
     * Get blocking error message if device is incompatible.
     * Returns null if device is compatible.
     */
    fun getBlockingErrorMessage(): String? {
        val compat = checkCompatibility()
        return when (compat.status) {
            ArchStatus.UNSUPPORTED_ABI, ArchStatus.INCOMPATIBLE_JVM -> {
                "${compat.message}\n\n${compat.recommendation}"
            }
            else -> null
        }
    }
}
