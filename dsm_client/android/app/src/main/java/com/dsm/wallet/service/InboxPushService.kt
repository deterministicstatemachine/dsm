// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.service

import android.util.Log
import com.dsm.wallet.bridge.Unified
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/**
 * Firebase Cloud Messaging on this phone. A storage node pushes when something
 * lands on a spool the wallet reads; the push carries nothing, and every push is
 * the same wake: Rust runs the sync a wait's answer runs, reading and verifying
 * what landed as always. When Android started this process for the push, the
 * wallet is started first, with no screen ([HeadlessWallet]).
 */
class InboxPushService : FirebaseMessagingService() {

    override fun onNewToken(token: String) {
        Log.i(TAG, "Firebase issued a new push token")
        Unified.setPushToken(token)
    }

    override fun onMessageReceived(message: RemoteMessage) {
        Log.i(TAG, "a storage node rang")
        if (Unified.onPushWake() == WOKEN) return
        if (!HeadlessWallet.start(applicationContext)) {
            Log.w(TAG, "the wallet could not be started for the push; it reads its inbox when opened")
            return
        }
        if (Unified.onPushWake() != WOKEN) {
            Log.w(TAG, "the wallet started but did not take the wake; it reads its inbox when opened")
        }
    }

    private companion object {
        const val TAG = "InboxPushService"

        /** What Rust answers once the sync is under way. */
        const val WOKEN = 1
    }
}
