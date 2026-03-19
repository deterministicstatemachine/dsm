package com.dsm.wallet.mcp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.core.content.ContextCompat

/**
 * Ensures DSM is initialised and MCP is alive after app updates.
 * No timers; single broadcast reaction.
 */
class PackageReplacedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_MY_PACKAGE_REPLACED == intent.action) {
            try {
                val appCtx = context.applicationContext
                // Ensure Unified class is loaded early (idempotent)
                try { Class.forName("com.dsm.wallet.bridge.Unified") } catch (_: Throwable) {}

                Log.i("MCP", "Package replaced; starting MCP foreground service")
                ContextCompat.startForegroundService(
                    appCtx,
                    Intent(appCtx, McpService::class.java)
                        .addFlags(Intent.FLAG_INCLUDE_STOPPED_PACKAGES)
                )
            } catch (t: Throwable) {
                Log.e("MCP", "Failed to init DSM / start MCP after package replace", t)
            }
        }
    }
}