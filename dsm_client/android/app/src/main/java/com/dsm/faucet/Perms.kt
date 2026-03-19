package com.dsm.faucet

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat

object FaucetPerms {
    private const val REQ_BG = 9911

    fun isBgGranted(a: Activity): Boolean {
        val fine = ContextCompat.checkSelfPermission(a, Manifest.permission.ACCESS_FINE_LOCATION) == PackageManager.PERMISSION_GRANTED
        val bgGranted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ContextCompat.checkSelfPermission(a, Manifest.permission.ACCESS_BACKGROUND_LOCATION) == PackageManager.PERMISSION_GRANTED
        } else {
            true // no separate background perm before Q
        }
        return fine && bgGranted
    }

    fun requestBg(a: Activity) {
        val req = mutableListOf<String>()
        if (ContextCompat.checkSelfPermission(a, Manifest.permission.ACCESS_FINE_LOCATION) != PackageManager.PERMISSION_GRANTED) {
            req += Manifest.permission.ACCESS_FINE_LOCATION
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q &&
            ContextCompat.checkSelfPermission(a, Manifest.permission.ACCESS_BACKGROUND_LOCATION) != PackageManager.PERMISSION_GRANTED
        ) {
            req += Manifest.permission.ACCESS_BACKGROUND_LOCATION
        }
        if (req.isNotEmpty()) {
            ActivityCompat.requestPermissions(a, req.toTypedArray(), REQ_BG)
        }
    }
}