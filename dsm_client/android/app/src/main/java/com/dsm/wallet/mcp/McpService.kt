package com.dsm.wallet.mcp

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.util.Log
import androidx.annotation.Keep

/**
 * MCP Foreground Service
 * - Single execution hub for BLE + JNI calls
 * - No wall clocks: event-driven via JNI/Rust
 * - Protobuf-only across JNI; no JSON anywhere
 * - Uses DsmInitManager as the single init authority
 */
class McpService : Service() {

    companion object {
        private const val TAG = "MCP"
        private const val CHANNEL_ID = "dsm_mcp"
        private const val CHANNEL_NAME = "DSM MCP"
        private const val NOTIF_ID = 1

        /** Convenience: idempotent start */
        fun ensureRunning(ctx: Context) {
            try {
                val appCtx = ctx.applicationContext
                // Ensure Unified class is loaded early (idempotent)
                try { Class.forName("com.dsm.wallet.bridge.Unified") } catch (_: Throwable) {}

                val i = Intent(appCtx, McpService::class.java)
                if (Build.VERSION.SDK_INT >= 26) {
                    appCtx.startForegroundService(i)
                } else {
                    appCtx.startService(i)
                }
            } catch (t: Throwable) {
                Log.e(TAG, "ensureRunning failed", t)
            }
        }
    }

    private val binder = LocalBinder()

    override fun onCreate() {
        super.onCreate()
        // Early class-load to ensure JNI lib is ready; Unified guards native calls
        try { Class.forName("com.dsm.wallet.bridge.Unified") } catch (_: Throwable) {}

        startAsForeground()
        Log.i(TAG, "McpService created (foreground)")
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Deterministic event loop is owned by JNI/Rust; keep process sticky.
        return START_STICKY
    }

    private fun startAsForeground() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager

        if (Build.VERSION.SDK_INT >= 26) {
            val ch = NotificationChannel(
                CHANNEL_ID,
                CHANNEL_NAME,
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Deterministic bridge runtime"
                setShowBadge(false)
                enableVibration(false)
                setSound(null, null)
            }
            nm.createNotificationChannel(ch)
        }

        val notif: Notification =
            if (Build.VERSION.SDK_INT >= 26) {
                Notification.Builder(this, CHANNEL_ID)
                    .setContentTitle("DSM MCP")
                    .setContentText("Deterministic bridge active")
                    .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                    .setOngoing(true)
                    .build()
            } else {
                @Suppress("DEPRECATION")
                Notification.Builder(this)
                    .setContentTitle("DSM MCP")
                    .setContentText("Deterministic bridge active")
                    .setSmallIcon(android.R.drawable.stat_sys_data_bluetooth)
                    .setOngoing(true)
                    .build()
            }

        try {
            startForeground(NOTIF_ID, notif)
        } catch (e: Exception) {
            // Android 12+ ForegroundServiceStartNotAllowedException when started from background
            // Service will run without foreground status; acceptable for now
            Log.w(TAG, "Could not start foreground (expected on Android 12+ from background): ${e.message}")
        }
    }

    inner class LocalBinder : Binder() {
        fun getService(): McpService = this@McpService
    }
}

/**
 * In-process bus facade used by the bridge. JNI endpoints are protobuf-only.
 * No timing logic: native/Rust side drives state transitions.
 */
object McpServiceBus {
    @Keep @JvmStatic external fun jniSubmitEnvelope(input: ByteArray): ByteArray
    @Keep @JvmStatic external fun jniGetDeviceId(): ByteArray
    @Keep @JvmStatic external fun jniSendBleProto(bytes: ByteArray): Boolean
    @Keep @JvmStatic external fun jniGetTransportHeaders(): ByteArray

    fun submitEnvelope(input: ByteArray): ByteArray = jniSubmitEnvelope(input)
    fun getDeviceId(): ByteArray = jniGetDeviceId()
    fun sendBleProto(bytes: ByteArray): Boolean = jniSendBleProto(bytes)
    fun getTransportHeaders(): ByteArray = jniGetTransportHeaders()
}