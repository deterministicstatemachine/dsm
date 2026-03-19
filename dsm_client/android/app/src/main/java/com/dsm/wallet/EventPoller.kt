// File: android/app/src/main/java/com/dsm/wallet/EventPoller.kt
// SPDX-License-Identifier: Apache-2.0
// Event poller is disabled in protobuf-only, clockless DSM.

package com.dsm.wallet

import android.util.Log

object EventPoller {
    @JvmStatic
    fun start() {
        Log.i("EventPoller", "Disabled (protobuf-only, no JSON event queue)")
    }
    @JvmStatic
    fun stop() {
        Log.i("EventPoller", "Stopped")
    }
}
