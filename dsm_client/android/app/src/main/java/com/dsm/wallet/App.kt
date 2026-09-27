// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet

import android.app.Application
import android.util.Log

class App : Application() {
    override fun onCreate() {
        super.onCreate()
        Log.d("DSM-App", "App.onCreate()")
        // BLE events arrive with no context of their own; the relay persists through this one.
        com.dsm.wallet.bridge.BleEventRelay.attach(this)
        // The library load is DsmInitProvider's and SDK initialisation is
        // MainActivity.initDsmAndSignalReady's; this class holds no native work.
    }
}
