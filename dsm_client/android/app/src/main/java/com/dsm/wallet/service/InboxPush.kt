// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.service

import android.content.Context
import android.util.Log
import com.dsm.wallet.bridge.Unified
import com.google.android.gms.common.ConnectionResult
import com.google.android.gms.common.GoogleApiAvailability
import com.google.firebase.FirebaseApp
import com.google.firebase.messaging.FirebaseMessaging

/**
 * The storage nodes' doorbell on this phone: Firebase Cloud Messaging. Rust puts
 * the doorbells up on the nodes with the token handed over here, and a node
 * pushes the phone when something lands for it ([InboxPushService]). The push is
 * empty; Rust reads and verifies what landed exactly as it always does.
 *
 * Where there is no push — no Google Play services, or a build that names no
 * Firebase project (`app/google-services.json` absent) — Rust is told so and the
 * app keeps today's way of listening off screen: its waits, the foreground
 * service and the battery exemption. Kotlin decides nothing else.
 */
internal object InboxPush {
    private const val TAG = "InboxPush"

    /** Why this phone has no push, or null when it has. */
    fun unavailableBecause(context: Context): String? {
        val play = GoogleApiAvailability.getInstance().isGooglePlayServicesAvailable(context)
        if (play != ConnectionResult.SUCCESS) {
            return "Google Play services unavailable (${ConnectionResult(play)})"
        }
        if (FirebaseApp.getApps(context).isEmpty()) {
            return "this build names no Firebase project (app/google-services.json was absent)"
        }
        return null
    }

    /**
     * Hand Rust this phone's push token, or tell it there is no push. Firebase
     * hands a new token to [InboxPushService.onNewToken] whenever it changes.
     */
    fun start(context: Context) {
        val missing = unavailableBecause(context)
        if (missing != null) {
            Log.w(TAG, "no push on this phone: $missing; long-poll and the foreground service stay")
            Unified.pushUnavailable(missing)
            return
        }
        FirebaseMessaging.getInstance().token.addOnCompleteListener { task ->
            val token = task.takeIf { it.isSuccessful }?.result?.takeIf { it.isNotEmpty() }
            if (token != null) {
                Log.i(TAG, "push token in hand: the storage nodes ring this phone")
                Unified.setPushToken(token)
            } else {
                val why = "Firebase issued no token: ${task.exception?.message ?: "no reason given"}"
                Log.w(TAG, "$why; long-poll and the foreground service stay")
                Unified.pushUnavailable(why)
            }
        }
    }
}
