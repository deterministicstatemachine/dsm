// File: android/app/src/main/java/com/dsm/faucet/FaucetService.kt
@file:Suppress("UNUSED_PARAMETER")

package com.dsm.faucet

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.location.Location
import android.location.LocationListener
import android.location.LocationManager
import android.os.Build
import android.os.Bundle
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.dsm.wallet.mcp.McpServiceBus
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

// Faucet availability checks should be performed via unified ops or server polling.
class FaucetService : Service() {

    companion object {
        private const val TAG = "FaucetService"
        private const val CH_ID = "faucet_channel"
        private const val NOTI_ID = 7421

        fun ensureRunning(ctx: Context) {
            val i = Intent(ctx, FaucetService::class.java)
            ContextCompat.startForegroundService(ctx, i)
        }

        fun stop(ctx: Context) {
            ctx.stopService(Intent(ctx, FaucetService::class.java))
        }
    }

    private var locationManager: LocationManager? = null

    private val listener = object : LocationListener {
        override fun onLocationChanged(location: Location) {
            scan(location.latitude, location.longitude)
        }

        override fun onProviderEnabled(provider: String) {}
        override fun onProviderDisabled(provider: String) {}

        @Deprecated("Deprecated in API 29")
        override fun onStatusChanged(provider: String?, status: Int, extras: Bundle?) {}
    }

    override fun onCreate() {
        super.onCreate()

        // Ensure Unified class is loaded early (triggers System.loadLibrary)
        try { Class.forName("com.dsm.wallet.bridge.Unified") } catch (_: Throwable) {}

        createChannel()
        startForeground(NOTI_ID, buildNotification("Scanning idle"))

        locationManager = getSystemService(Context.LOCATION_SERVICE) as? LocationManager
        if (locationManager == null) {
            Log.e(TAG, "LocationManager unavailable")
            stopSelf()
            return
        }

        // Register location updates if permitted; else stop.
        try {
            // GPS first (outdoor accuracy)
            locationManager!!.requestLocationUpdates(
                LocationManager.GPS_PROVIDER,
                60_000L,        // OS-managed pacing is fine (not protocol logic)
                60f,
                listener,
                mainLooper
            )
            // Fallback to network if GPS off
            if (!locationManager!!.isProviderEnabled(LocationManager.GPS_PROVIDER)) {
                locationManager!!.requestLocationUpdates(
                    LocationManager.NETWORK_PROVIDER,
                    60_000L,
                    100f,
                    listener,
                    mainLooper
                )
            }
        } catch (se: SecurityException) {
            Log.e(TAG, "Missing location permission; stopping", se)
            stopSelf()
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to request location updates; stopping", t)
            stopSelf()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        updateNotification("Scanning nearby faucets…")
        return START_STICKY
    }

    override fun onDestroy() {
        try {
            locationManager?.removeUpdates(listener)
        } catch (_: Throwable) {
        }
        locationManager = null
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    // Walk-and-claim policy: we only notify availability here.
    private fun scan(lat: Double, lon: Double) {
        // Consume params for clarity and future hook
        Log.d(TAG, "scan @ lat=$lat lon=$lon")

        try {
            val dev = try { McpServiceBus.getDeviceId() } catch (_: Throwable) { ByteArray(0) }
            if (dev.size != 32) {
                updateNotification("Scanning nearby faucets…")
                return
            }

            val qlat = Math.round(lat * 10_000.0).toLong()
            val qlon = Math.round(lon * 10_000.0).toLong()

            val tag = "DSM/geo/check\u0000".toByteArray(Charsets.UTF_8)
            val buf = ByteBuffer.allocate(tag.size + 8 + 8 + 32).order(ByteOrder.LITTLE_ENDIAN)
            buf.put(tag)
            buf.putLong(qlat)
            buf.putLong(qlon)
            buf.put(dev)

            // UI-only hash decision (SHA-256); server uses BLAKE3 for the real query.
            val h = MessageDigest.getInstance("SHA-256").digest(buf.array())
            val available = (h[0].toInt() and 1) == 0

            if (available) {
                updateNotification("Faucet available nearby")
                pushNearbyNotification()
            } else {
                updateNotification("Scanning nearby faucets…")
            }
        } catch (t: Throwable) {
            Log.w(TAG, "scan failed", t)
            updateNotification("Scanning nearby faucets…")
        }
    }

    private fun pushNearbyNotification() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val n = NotificationCompat.Builder(this, CH_ID)
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentTitle("Faucet")
            .setContentText("Tokens nearby. Open app to claim.")
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOnlyAlertOnce(true)
            .build()
        nm.notify(NOTI_ID + 1, n)
    }

    private fun createChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val ch = NotificationChannel(
                CH_ID,
                "Faucet",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Background scanning for nearby claim opportunities"
                setShowBadge(false)
                enableVibration(false)
                setSound(null, null)
            }
            nm.createNotificationChannel(ch)
        }
    }

    private fun buildNotification(text: String): Notification =
        NotificationCompat.Builder(this, CH_ID)
            .setSmallIcon(android.R.drawable.ic_menu_mylocation)
            .setContentTitle("Faucet")
            .setContentText(text)
            .setOnlyAlertOnce(true)
            .setOngoing(true)
            .build()

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTI_ID, buildNotification(text))
    }
}