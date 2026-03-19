package com.dsm.wallet.proximity

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import com.dsm.wallet.R
import com.dsm.wallet.mcp.McpService
import com.dsm.wallet.mcp.McpServiceBus

class ProximityScanService : Service() {

    companion object {
        const val CHANNEL_ID = "proximity_scan"
        const val NOTIF_ID = 0xD5 // 213, "D5" == DSM :)
        const val ACTION_START = "com.dsm.wallet.proximity.START"
        const val ACTION_STOP  = "com.dsm.wallet.proximity.STOP"
        private const val TAG = "ProximityService"
    }

    override fun onCreate() {
        super.onCreate()
        // Ensure Unified class is loaded early; Unified guards native calls
        try { Class.forName("com.dsm.wallet.bridge.Unified") } catch (_: Throwable) {}
        createChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForeground(NOTIF_ID, buildNotification("Scanning for nearby drops"))
                // Ensure MCP runtime (BLE + JNI execution hub) is active
                McpService.ensureRunning(applicationContext)

                // BLE scan is initiated by MCP runtime now; no direct JNI command needed here.
                Log.i(TAG, "Proximity scanning active via MCP runtime")
                    }
        }
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val mgr = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val ch = NotificationChannel(
                CHANNEL_ID,
                "Proximity Scanner",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Always-on vault proximity scanning"
                setShowBadge(false)
                enableVibration(false)
                setSound(null, null)
            }
            mgr.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(text: String): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("Vault proximity scanning")
            .setContentText(text)
            .setSmallIcon(R.mipmap.ic_launcher)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .build()
    }
}