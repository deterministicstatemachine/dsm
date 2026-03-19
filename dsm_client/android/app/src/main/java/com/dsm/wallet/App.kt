package com.dsm.wallet

import android.app.Application
import android.util.Log
import java.io.File
import java.io.FileOutputStream

    class App : Application() {
    override fun onCreate() {
        super.onCreate()
        Log.d("DSM-App", "App.onCreate()")
        // Defer all native work to DsmInitManager.ensure() invoked by UI/Services after first frame.
        // This avoids class-initializer crashes during cold start and gives us clearer logs.
    }
}