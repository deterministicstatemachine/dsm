// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.ui

import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.os.PowerManager
import android.provider.Settings
import android.util.Log
import androidx.core.content.pm.PackageInfoCompat
import androidx.core.net.toUri

/**
 * Asks once, per install, for DSM to be left out of Android's battery
 * optimisation, so the wallet keeps its own connection to the storage nodes
 * while the phone sleeps. A transfer still settling when the app is left is
 * finished by the background service; with the app optimised, Android cuts its
 * network in Doze and the counterparty waits until the phone wakes.
 *
 * Nothing goes through Google: this is the wallet's own connection, kept open
 * by the system's own setting. The user answers in the system's dialog; a
 * refusal is kept and not asked again.
 */
internal object BatteryExemption {
    private const val TAG = "BatteryExemption"
    private const val PREFS = "dsm_battery_exemption"

    /** The app version that asked, once asked. */
    private const val KEY_ASKED_BY_VERSION = "asked_by_version"

    /**
     * Opens the system's "let this app run in the background" dialog, once,
     * when the app is still optimised. Opens the system's list of optimised
     * apps instead where the dialog does not exist.
     */
    fun askOnce(activity: Activity) {
        val power = activity.getSystemService(Context.POWER_SERVICE) as? PowerManager
        if (power == null) {
            Log.w(TAG, "no power service: the battery exemption cannot be asked for")
            return
        }
        if (power.isIgnoringBatteryOptimizations(activity.packageName)) return
        val prefs = activity.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        if (prefs.contains(KEY_ASKED_BY_VERSION)) return

        val info = activity.packageManager.getPackageInfo(activity.packageName, 0)
        prefs.edit()
            .putLong(KEY_ASKED_BY_VERSION, PackageInfoCompat.getLongVersionCode(info))
            .apply()
        val ask = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
            .setData("package:${activity.packageName}".toUri())
        try {
            activity.startActivity(ask)
        } catch (e: ActivityNotFoundException) {
            Log.w(TAG, "no battery exemption dialog on this phone; opening the list", e)
            try {
                activity.startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
            } catch (none: ActivityNotFoundException) {
                Log.w(TAG, "no battery optimisation settings on this phone", none)
            }
        }
    }
}
