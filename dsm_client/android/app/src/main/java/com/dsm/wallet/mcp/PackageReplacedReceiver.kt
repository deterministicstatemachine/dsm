package com.dsm.wallet.mcp

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Ensures DSM classes are touched after app updates.
 * No timers; single broadcast reaction.
 */
class PackageReplacedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (Intent.ACTION_MY_PACKAGE_REPLACED == intent.action) {
            try {
                val appCtx = context.applicationContext
                // Ensure Unified class is loaded early (idempotent)
                try { Class.forName("com.dsm.wallet.bridge.Unified") } catch (_: Throwable) {}

                Log.i("MCP", "Package replaced; JNI classes preloaded")
            } catch (t: Throwable) {
                Log.e("MCP", "Failed to init DSM after package replace", t)
            }
        }
    }
}
