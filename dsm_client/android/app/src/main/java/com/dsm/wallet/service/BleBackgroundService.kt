// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.bluetooth.BluetoothAdapter
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.Binder
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.dsm.wallet.R
import com.dsm.wallet.bridge.Unified
import com.dsm.wallet.bridge.ble.BleCoordinator
import com.dsm.wallet.ui.MainActivity
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

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
 *
 * It is the one owner of advertising. Advertising follows the identity: a
 * device Rust knows advertises, so a peer can find it for a transfer or a
 * pairing; a device without one does not. The screen the user is on has no
 * say — the frontend used to start advertising on the wallet screen and stop
 * it on leaving, and on a cold start nothing else ever started it.
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
    private val binder = LocalBinder()

    // The coordinator's lifecycle operations block their caller (up to 15 s);
    // they run here, one at a time and in order, never on the main thread.
    private val lifecycle: ExecutorService =
        Executors.newSingleThreadExecutor { r -> Thread(r, "ble-advertising") }

    // Bluetooth turned back on: advertising is due again if the identity is.
    private val adapterStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action != BluetoothAdapter.ACTION_STATE_CHANGED) return
            val state = intent.getIntExtra(BluetoothAdapter.EXTRA_STATE, BluetoothAdapter.ERROR)
            if (state == BluetoothAdapter.STATE_ON) refreshAdvertising()
        }
    }

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

        val filter = IntentFilter(BluetoothAdapter.ACTION_STATE_CHANGED)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(adapterStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(adapterStateReceiver, filter)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "BLE background service started")
        refreshAdvertising()
        return START_STICKY
    }

    override fun onDestroy() {
        Log.i(TAG, "BLE background service destroyed")
        try {
            unregisterReceiver(adapterStateReceiver)
        } catch (_: IllegalArgumentException) {
            // Not registered.
        }
        val ble = bleCoordinator
        lifecycle.execute {
            ble?.stopAdvertising()
            // Cleanup timeout jobs to prevent resource leaks
            ble?.cleanup()
        }
        lifecycle.shutdown()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? {
        return binder
    }

    /**
     * Bring advertising in line with the identity, from Rust: the GATT server
     * up and advertising on when there is one, advertising off when there is
     * not. Called on every event that can change the answer — the service
     * starting, the activity resuming or binding, native init finding the
     * identity, a Bluetooth permission granted, the adapter turned on.
     * Idempotent: advertising already on stays on.
     */
    fun refreshAdvertising() {
        val ble = bleCoordinator ?: return
        onLifecycleThread("refreshAdvertising") {
            if (!localIdentityAvailable()) {
                if (ble.isAdvertising()) ble.stopAdvertising()
                Log.i(TAG, "refreshAdvertising: no local identity; not advertising")
                return@onLifecycleThread
            }
            val gattOk = ble.ensureGattServerStarted()
            val advertising = gattOk && ble.startAdvertising()
            Log.i(TAG, "refreshAdvertising: GATT=$gattOk advertising=$advertising")
        }
    }

    /** What the radio is doing, for the session snapshot Rust publishes. */
    fun isScanningActive(): Boolean = try {
        bleCoordinator?.isScanning() ?: false
    } catch (_: Throwable) {
        false
    }

    fun isAdvertisingActive(): Boolean = try {
        bleCoordinator?.isAdvertising() ?: false
    } catch (_: Throwable) {
        false
    }

    /** Stale GATT sessions from before a pause, closed off the main thread. */
    fun closeStaleGattSessions() {
        val ble = bleCoordinator ?: return
        onLifecycleThread("closeStaleGattSessions") { ble.closeStaleGattSessions() }
    }

    // A caller holding this service after it was destroyed gets a log line,
    // not a RejectedExecutionException on its own (main) thread.
    private fun onLifecycleThread(what: String, block: () -> Unit) {
        try {
            lifecycle.execute {
                try {
                    block()
                } catch (t: Throwable) {
                    Log.w(TAG, "$what failed", t)
                }
            }
        } catch (_: java.util.concurrent.RejectedExecutionException) {
            Log.w(TAG, "$what: the service is destroyed")
        }
    }

    private fun localIdentityAvailable(): Boolean = try {
        Unified.getDeviceIdBin().size == 32 && Unified.getGenesisHashBin().size == 32
    } catch (_: Throwable) {
        false
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
