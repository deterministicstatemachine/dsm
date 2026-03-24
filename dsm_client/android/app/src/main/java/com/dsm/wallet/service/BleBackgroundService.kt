package com.dsm.wallet.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Binder
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.dsm.wallet.R
import com.dsm.wallet.bridge.ble.BleCoordinator
import com.dsm.wallet.ui.MainActivity

/**
 * Foreground service that keeps BLE advertising and GATT server running
 * in the background for offline bilateral transfers.
 * 
 * This service ensures that:
 * 1. BLE advertising remains active so peers can discover this device
 * 2. GATT server stays registered to receive incoming connections
 * 3. Persistent connections to paired devices are maintained
 * 
 * Without this, offline transfers would fail when the app is backgrounded
 * because Android kills BLE advertising/GATT when apps lose foreground status.
 */
class BleBackgroundService : Service() {

    companion object {
        private const val NOTIFICATION_ID = 8341
        private const val CHANNEL_ID = "dsm_ble_background"
        private const val TAG = "BleBackgroundService"

        /**
         * Start the BLE background service to enable offline transfers
         */
        fun start(context: Context) {
            val intent = Intent(context, BleBackgroundService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /**
         * Stop the BLE background service
         */
        fun stop(context: Context) {
            val intent = Intent(context, BleBackgroundService::class.java)
            context.stopService(intent)
        }
    }

    private var bleCoordinator: BleCoordinator? = null
    private var isAdvertising = false
    private var advertisingDesired = false
    private val binder = LocalBinder()

    inner class LocalBinder : Binder() {
        fun getService(): BleBackgroundService = this@BleBackgroundService
    }

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "BLE background service created")
        
        // Create notification channel (required for Android O+)
        createNotificationChannel()
        
        // Start foreground with notification + explicit service type (required API 34+)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                createNotification(),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                    or ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC
            )
        } else {
            startForeground(NOTIFICATION_ID, createNotification())
        }
        
        // Initialize BLE coordinator
        bleCoordinator = BleCoordinator.getInstance(applicationContext)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "BLE background service started (idle until explicitly requested)")
        // BLE advertising is NOT started here. It only starts when the UI explicitly
        // calls setAdvertisingDesired(true) through a bridge RPC (device.ble.advertise.start).
        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "BLE background service destroyed")
        advertisingDesired = false
        applyAdvertisingState()

        // Cleanup timeout jobs to prevent resource leaks
        bleCoordinator?.cleanup()

        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
        return binder
    }

    @Synchronized
    fun setAdvertisingDesired(desired: Boolean) {
        advertisingDesired = desired
        applyAdvertisingState()
    }

    fun ensureGattServerStarted(): Boolean {
        return bleCoordinator?.ensureGattServerStarted() ?: false
    }

    fun startScanning(): Boolean {
        return bleCoordinator?.startScanning() ?: false
    }

    fun stopScanning(): Boolean {
        return bleCoordinator?.stopScanning() ?: false
    }

    fun isScanningActive(): Boolean {
        return try {
            bleCoordinator?.isScanning() ?: false
        } catch (_: Throwable) {
            false
        }
    }

    fun isAdvertisingActive(): Boolean {
        return try {
            bleCoordinator?.isAdvertising() ?: isAdvertising
        } catch (_: Throwable) {
            isAdvertising
        }
    }

    fun setIdentityValue(genesisHash: ByteArray, deviceId: ByteArray) {
        bleCoordinator?.setIdentityValue(genesisHash, deviceId)
    }

    @Synchronized
    private fun applyAdvertisingState() {
        bleCoordinator?.let { ble ->
            if (advertisingDesired && !isAdvertising) {
                var hasIdentity = false
                try {
                    val deviceIdBytes = try { com.dsm.wallet.bridge.Unified.getDeviceIdBin() } catch (_: Throwable) { byteArrayOf() }
                    val genesisHashBytes = try { com.dsm.wallet.bridge.Unified.getGenesisHashBin() } catch (_: Throwable) { byteArrayOf() }
                    if (deviceIdBytes.size == 32 && genesisHashBytes.size == 32) {
                        ble.setIdentityValue(genesisHashBytes, deviceIdBytes)
                        hasIdentity = true
                        Log.i(TAG, "applyAdvertisingState: local BLE identity published before advertise")
                    } else {
                        Log.w(TAG, "applyAdvertisingState: local identity unavailable before advertise (genesis=${genesisHashBytes.size}, device=${deviceIdBytes.size})")
                    }
                } catch (t: Throwable) {
                    Log.w(TAG, "applyAdvertisingState: failed to publish local identity before advertise", t)
                }
                if (!hasIdentity) {
                    Log.w(TAG, "BLE advertising requested but local identity is unavailable")
                    return
                }
                val gattOk = ble.ensureGattServerStarted()
                if (gattOk) {
                    ble.startAdvertising()
                    isAdvertising = true
                    Log.i(TAG, "BLE advertising started in background")
                } else {
                    Log.w(TAG, "BLE advertising requested but GATT not ready")
                }
            } else if (!advertisingDesired && isAdvertising) {
                ble.stopAdvertising()
                isAdvertising = false
                Log.i(TAG, "BLE advertising stopped")
            } else {
                // No-op: advertising state already matches desired state.
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "DSM Offline Transfers",
                NotificationManager.IMPORTANCE_LOW // Low importance = no sound/vibration
            ).apply {
                description = "Keeps Bluetooth active for offline wallet transfers"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        // Intent to open app when notification is tapped
        val notificationIntent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            notificationIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("DSM Offline Mode Active")
            .setContentText("Ready for Bluetooth transfers")
            .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth) // Use system Bluetooth icon
            .setContentIntent(pendingIntent)
            .setOngoing(true) // Cannot be dismissed by user
            .setSilent(true) // No sound
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
}
