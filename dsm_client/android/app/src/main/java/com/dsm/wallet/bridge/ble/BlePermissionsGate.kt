package com.dsm.wallet.bridge.ble

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.os.Build
import android.util.Log
import androidx.core.app.ActivityCompat
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Handles Bluetooth permissions and adapter state monitoring.
 *
 * This component is responsible for:
 * - Checking BLE-related permissions (CONNECT, SCAN, ADVERTISE)
 * - Monitoring Bluetooth adapter state changes
 * - Providing readiness status for BLE operations
 * - Tracking permission failures for feature toggling
 * - Providing permission recovery mechanisms
 */
class BlePermissionsGate(private val context: Context) {

    private val appContext = context.applicationContext
    private val bleReady = AtomicBoolean(false)
    private val btStateReceiverRegistered = AtomicBoolean(false)

    // Track permission failures for feature toggling
    private val permissionFailureCount = AtomicInteger(0)
    private val PERMISSION_FAILURE_THRESHOLD = 3 // Disable BLE after 3 consecutive failures

    // Permission recovery callback
    var onPermissionRecoveryNeeded: (() -> Unit)? = null

    private val btStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
            val readyNow = state == BluetoothAdapter.STATE_ON
            updateBleReadyState(readyNow)
        }
    }

    fun initialize() {
        registerBtStateReceiver()
        checkInitialBleState()
    }

    fun cleanup() {
        unregisterBtStateReceiver()
    }

    fun hasConnectPermission(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ActivityCompat.checkSelfPermission(
                appContext,
                Manifest.permission.BLUETOOTH_CONNECT
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            ActivityCompat.checkSelfPermission(
                appContext,
                Manifest.permission.BLUETOOTH
            ) == PackageManager.PERMISSION_GRANTED
        }

    fun hasScanPermission(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ActivityCompat.checkSelfPermission(
                appContext,
                Manifest.permission.BLUETOOTH_SCAN
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            ActivityCompat.checkSelfPermission(
                appContext,
                Manifest.permission.BLUETOOTH
            ) == PackageManager.PERMISSION_GRANTED
        }

    fun hasAdvertisePermission(): Boolean =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ActivityCompat.checkSelfPermission(
                appContext,
                Manifest.permission.BLUETOOTH_ADVERTISE
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            ActivityCompat.checkSelfPermission(
                appContext,
                Manifest.permission.BLUETOOTH
            ) == PackageManager.PERMISSION_GRANTED
        }

    fun isBleReady(): Boolean = bleReady.get()

    /**
     * Check if BLE should be disabled due to repeated permission failures
     */
    fun shouldDisableBleFeatures(): Boolean {
        return permissionFailureCount.get() >= PERMISSION_FAILURE_THRESHOLD
    }

    /**
     * Record a permission failure for feature toggling
     */
    fun recordPermissionFailure() {
        val currentCount = permissionFailureCount.incrementAndGet()
        Log.w("BlePermissionsGate", "BLE permission failure recorded (count: $currentCount)")

        if (currentCount >= PERMISSION_FAILURE_THRESHOLD) {
            Log.w("BlePermissionsGate", "BLE features disabled due to repeated permission failures")
        }
    }

    /**
     * Record a successful permission check to reset failure count
     */
    fun recordPermissionSuccess() {
        if (permissionFailureCount.get() > 0) {
            permissionFailureCount.set(0)
            Log.i("BlePermissionsGate", "BLE permission success - resetting failure count")
        }
    }

    /**
     * Attempt permission recovery
     */
    fun attemptPermissionRecovery(): Boolean {
        Log.i("BlePermissionsGate", "Attempting permission recovery")

        // Check if permissions are now granted
        val hasPermissions = hasConnectPermission() && hasScanPermission() && hasAdvertisePermission()

        if (hasPermissions) {
            recordPermissionSuccess()
            Log.i("BlePermissionsGate", "Permission recovery successful")
            return true
        } else {
            // Trigger permission request callback
            onPermissionRecoveryNeeded?.invoke()
            return false
        }
    }

    fun getBluetoothAdapter(): BluetoothAdapter? {
        val manager = appContext.getSystemService(Context.BLUETOOTH_SERVICE) as? BluetoothManager
        return manager?.adapter
    }

    private fun registerBtStateReceiver() {
        if (!btStateReceiverRegistered.compareAndSet(false, true)) return
        try {
            val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                appContext.registerReceiver(btStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                appContext.registerReceiver(btStateReceiver, filter)
            }
            Log.d("BlePermissionsGate", "Bluetooth state receiver registered")
        } catch (t: Throwable) {
            btStateReceiverRegistered.set(false)
            Log.w("BlePermissionsGate", "Failed to register Bluetooth state receiver: ${t.message}")
        }
    }

    private fun unregisterBtStateReceiver() {
        if (!btStateReceiverRegistered.compareAndSet(true, false)) return
        try {
            appContext.unregisterReceiver(btStateReceiver)
            Log.d("BlePermissionsGate", "Bluetooth state receiver unregistered")
        } catch (t: Throwable) {
            Log.w("BlePermissionsGate", "Failed to unregister Bluetooth state receiver: ${t.message}")
        }
    }

    private fun checkInitialBleState() {
        val adapter = getBluetoothAdapter()
        val ready = adapter?.isEnabled == true
        updateBleReadyState(ready)
    }

    private fun updateBleReadyState(ready: Boolean) {
        val prev = bleReady.getAndSet(ready)
        if (ready && !prev) {
            Log.i("BlePermissionsGate", "BLE adapter became ready")
        } else if (!ready && prev) {
            Log.w("BlePermissionsGate", "BLE adapter became unavailable")
        }
    }
}