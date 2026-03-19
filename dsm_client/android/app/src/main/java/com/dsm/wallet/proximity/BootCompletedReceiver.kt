package com.dsm.wallet.proximity

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.util.Log
import androidx.core.content.ContextCompat
import com.dsm.wallet.mcp.McpService

class BootCompletedReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context?, intent: Intent?) {
        val appCtx = context?.applicationContext ?: return
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) return

        // Ensure Unified class is loaded early (idempotent)
        try { Class.forName("com.dsm.wallet.bridge.Unified") } catch (_: Throwable) {}

        // Ensure MCP runtime is up before proximity logic
        McpService.ensureRunning(appCtx)

        val prefs = safePrefs(appCtx)
        val shouldAutoStart = prefs?.let(::wantsAlwaysOn) ?: false
        if (!shouldAutoStart) {
            Log.i(TAG, "Skipping proximity auto-start; not opted in")
            return
        }

        try {
            ContextCompat.startForegroundService(
                appCtx,
                Intent(appCtx, ProximityScanService::class.java).apply {
                    action = ProximityScanService.ACTION_START
                    addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
                }
            )
            Log.i(TAG, "Proximity scan service requested from boot receiver")
        } catch (t: Throwable) {
            Log.e(TAG, "Failed to start ProximityScanService from boot", t)
        }
    }

    private fun safePrefs(context: Context): SharedPreferences? = try {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    } catch (t: Throwable) {
        Log.e(TAG, "Unable to access shared preferences", t)
        null
    }

    private fun wantsAlwaysOn(prefs: SharedPreferences): Boolean {
        // Accept either the boolean flag or a string mode for forward compatibility.
        if (prefs.getBoolean(PREF_ALWAYS_ON_FLAG, false)) return true
        val mode = prefs.getString(PREF_PROXIMITY_MODE, null)
        return mode.equals(PREF_VALUE_ALWAYS_ON, ignoreCase = true)
    }

    companion object {
        private const val TAG = "ProximityBoot"
        private const val PREFS_NAME = "dsm_prefs"
        private const val PREF_ALWAYS_ON_FLAG = "proximity_always_on"
        private const val PREF_PROXIMITY_MODE = "proximity_scan_mode"
        private const val PREF_VALUE_ALWAYS_ON = "always_on"
    }
}