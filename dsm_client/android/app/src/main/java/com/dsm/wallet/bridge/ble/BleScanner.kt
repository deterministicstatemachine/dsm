package com.dsm.wallet.bridge.ble

import android.annotation.SuppressLint
import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import android.util.Log
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Handles Bluetooth LE scanning operations.
 *
 * This component manages:
 * - Starting/stopping BLE scans
 * - Scan filters and settings
 * - Scan result processing and callbacks
 * - Debouncing and duplicate suppression
 */
class BleScanner(private val context: Context) {

    interface Callback {
        fun onDeviceDiscovered(device: BluetoothDevice, rssi: Int)
        fun onScanFailed(errorCode: Int)
    }

    private val scanning = AtomicBoolean(false)
    private var bluetoothLeScanner: BluetoothLeScanner? = null
    private var currentSessionMode: BleSessionMode = BleSessionMode.IDLE
    private var callback: Callback? = null

    fun setCallback(callback: Callback) {
        this.callback = callback
    }

    // Scan callback - processes discovered devices
    private val scanCallback = object : ScanCallback() {
        @SuppressLint("HardwareIds")
        override fun onScanResult(callbackType: Int, result: ScanResult?) {
            val device = result?.device ?: return
            val scanRecord = result.scanRecord ?: return

            Log.d("BleScanner", "Scan result: ${device.address}, services: ${scanRecord.serviceUuids}")

            // Primary: check for DSM service UUID in advertised services
            val hasServiceUuid = scanRecord.serviceUuids?.any { it.uuid == BleConstants.DSM_SERVICE_UUID_V2 } == true

            // Secondary check: if serviceUuids is null/empty (truncated advertisement on some
            // Samsung/Qualcomm devices), check manufacturer-specific data for DSM magic.
            val hasManufacturerMagic = if (!hasServiceUuid) {
                val mfrData = scanRecord.getManufacturerSpecificData(BleConstants.DSM_MANUFACTURER_ID)
                mfrData != null && mfrData.size >= BleConstants.DSM_MANUFACTURER_MAGIC.size &&
                    mfrData.copyOfRange(0, BleConstants.DSM_MANUFACTURER_MAGIC.size)
                        .contentEquals(BleConstants.DSM_MANUFACTURER_MAGIC)
            } else {
                false
            }

            if (hasServiceUuid || hasManufacturerMagic) {
                if (hasManufacturerMagic && !hasServiceUuid) {
                    Log.i("BleScanner", "Device ${device.address} matched via manufacturer data (truncated ad)")
                }
                callback?.onDeviceDiscovered(device, result.rssi)
                Log.d("BleScanner", "Processing discovered device: ${device.address}")
            }
        }

        override fun onScanFailed(errorCode: Int) {
            Log.e("BleScanner", "Scan failed with error code: $errorCode")
            scanning.set(false)
            callback?.onScanFailed(errorCode)
        }
    }

    fun setSessionMode(mode: BleSessionMode) {
        currentSessionMode = mode
    }

    /**
     * Start BLE scanning.
     *
     * @param lowLatency If true (default), uses SCAN_MODE_LOW_LATENCY (100% duty cycle)
     *   which finds devices in 1-3s but is battery-intensive. If false, uses
     *   SCAN_MODE_BALANCED (~33% duty cycle) for sustained background scanning.
     *   BleCoordinator auto-downshifts from low-latency to balanced after 12s.
     */
    @SuppressLint("MissingPermission")
    fun startScanning(lowLatency: Boolean = true): Boolean {
        if (scanning.get()) {
            Log.d("BleScanner", "Already scanning")
            return true
        }

        val adapter = getBluetoothAdapter() ?: run {
            Log.w("BleScanner", "No Bluetooth adapter available")
            return false
        }

        bluetoothLeScanner = adapter.bluetoothLeScanner ?: run {
            Log.w("BleScanner", "No BLE scanner available")
            return false
        }

        // Primary filter: DSM service UUID
        val uuidFilter = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(BleConstants.DSM_SERVICE_UUID_V2))
            .build()

        // Secondary filter: manufacturer data magic bytes (for truncated advertisements)
        val mfrFilter = ScanFilter.Builder()
            .setManufacturerData(BleConstants.DSM_MANUFACTURER_ID, BleConstants.DSM_MANUFACTURER_MAGIC)
            .build()

        val scanMode = if (lowLatency) ScanSettings.SCAN_MODE_LOW_LATENCY else ScanSettings.SCAN_MODE_BALANCED

        val settings = ScanSettings.Builder()
            .setScanMode(scanMode)
            .setCallbackType(ScanSettings.CALLBACK_TYPE_ALL_MATCHES)
            .build()

        return try {
            // Android treats multiple ScanFilters as OR — match either UUID or manufacturer data
            val filters = listOf(uuidFilter, mfrFilter)

            bluetoothLeScanner?.startScan(filters, settings, scanCallback)
            scanning.set(true)
            val modeLabel = if (lowLatency) "LOW_LATENCY" else "BALANCED"
            Log.i("BleScanner", "BLE scan started ($modeLabel), mode: $currentSessionMode")
            true
        } catch (t: Throwable) {
            Log.e("BleScanner", "Failed to start scan", t)
            false
        }
    }

    @SuppressLint("MissingPermission")
    fun stopScanning(): Boolean {
        if (!scanning.get()) {
            Log.d("BleScanner", "Not scanning")
            return true
        }

        return try {
            bluetoothLeScanner?.stopScan(scanCallback)
            scanning.set(false)
            Log.i("BleScanner", "BLE scan stopped")
            true
        } catch (t: Throwable) {
            Log.e("BleScanner", "Failed to stop scan", t)
            false
        }
    }

    fun isScanning(): Boolean = scanning.get()

    private fun getBluetoothAdapter() = BlePermissionsGate(context).getBluetoothAdapter()
}
