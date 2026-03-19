package com.dsm.wallet.bridge.ble

/**
 * BLE Error Categories with user guidance for hardware issues.
 */
enum class BleErrorCategory {
    BLUETOOTH_DISABLED,
    PERMISSION_DENIED,
    HARDWARE_UNAVAILABLE,
    MTU_TOO_SMALL,
    MTU_NEGOTIATION_FAILED,
    CONNECTION_FAILED,
    SERVICE_DISCOVERY_FAILED,
    CHARACTERISTIC_READ_FAILED,
    CHARACTERISTIC_WRITE_FAILED,
    CHARACTERISTIC_ERROR,
    ADVERTISING_FAILED,
    SCANNING_FAILED,
    PROTOCOL_TIMEOUT,
    UNKNOWN;

    fun getUserMessage(): String = when (this) {
        BLUETOOTH_DISABLED -> "Bluetooth is disabled. Enable Bluetooth in Settings and try again."
        PERMISSION_DENIED -> "Bluetooth permission required. Grant location permission and try again."
        HARDWARE_UNAVAILABLE -> "Bluetooth hardware unavailable. Restart device or check for hardware issues."
        MTU_TOO_SMALL -> "Device incompatible. Requires Android 8.0+ with BLE 4.2+. Update device firmware."
        MTU_NEGOTIATION_FAILED -> "MTU negotiation failed. Restart both devices and try again."
        CONNECTION_FAILED -> "Connection failed. Ensure devices are close together (within 10 meters) and try again."
        SERVICE_DISCOVERY_FAILED -> "Service discovery failed. Restart both devices and try again."
        CHARACTERISTIC_READ_FAILED -> "Data read failed. Ensure stable connection and try again."
        CHARACTERISTIC_WRITE_FAILED -> "Data send failed. Ensure stable connection and try again."
        CHARACTERISTIC_ERROR -> "Communication error. Clear app data or restart devices."
        ADVERTISING_FAILED -> "Advertising failed. Close other apps using Bluetooth and try again."
        SCANNING_FAILED -> "Scanning failed. Move to open area and avoid WiFi interference."
        PROTOCOL_TIMEOUT -> "Connection timeout. Ensure stable Bluetooth signal and try again."
        UNKNOWN -> "Unknown Bluetooth error. Restart app and try again."
    }

    fun getTroubleshootingSteps(): List<String> = when (this) {
        BLUETOOTH_DISABLED -> listOf(
            "Go to Settings > Bluetooth",
            "Toggle Bluetooth OFF then ON",
            "Return to app and try again"
        )
        PERMISSION_DENIED -> listOf(
            "Go to Settings > Apps > DSM Wallet > Permissions",
            "Enable Location permission",
            "Restart app"
        )
        HARDWARE_UNAVAILABLE -> listOf(
            "Restart your device",
            "Check if Bluetooth works in other apps",
            "Contact device manufacturer for hardware support"
        )
        MTU_TOO_SMALL -> listOf(
            "Update device to Android 8.0 or higher",
            "Check device BLE version (4.2 minimum)",
            "Update device firmware if available"
        )
        CONNECTION_FAILED -> listOf(
            "Move devices closer together (within 10 meters)",
            "Remove physical obstructions",
            "Disable battery optimization for this app",
            "Try connecting from different angles"
        )
        SERVICE_DISCOVERY_FAILED -> listOf(
            "Restart both devices",
            "Clear app data on both devices",
            "Disable/re-enable Bluetooth on both devices"
        )
        MTU_NEGOTIATION_FAILED -> listOf(
            "Restart both devices",
            "Try connecting with devices closer together",
            "Check for Android system updates"
        )
        CHARACTERISTIC_READ_FAILED -> listOf(
            "Ensure stable Bluetooth connection",
            "Move devices closer together",
            "Restart connection attempt"
        )
        CHARACTERISTIC_WRITE_FAILED -> listOf(
            "Ensure stable Bluetooth connection",
            "Move devices closer together",
            "Restart connection attempt"
        )
        CHARACTERISTIC_ERROR -> listOf(
            "Clear app data",
            "Restart both devices",
            "Try different device pair"
        )
        ADVERTISING_FAILED -> listOf(
            "Close other apps using Bluetooth",
            "Restart device",
            "Check battery level"
        )
        SCANNING_FAILED -> listOf(
            "Move to open area away from WiFi routers",
            "Disable WiFi temporarily",
            "Restart device"
        )
        PROTOCOL_TIMEOUT -> listOf(
            "Ensure stable Bluetooth connection",
            "Move away from interference sources",
            "Try connecting with devices closer together"
        )
        UNKNOWN -> listOf(
            "Restart app",
            "Clear app data",
            "Check for app updates",
            "Contact support if issue persists"
        )
    }
}