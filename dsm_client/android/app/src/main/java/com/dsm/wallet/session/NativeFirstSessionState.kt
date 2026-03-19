package com.dsm.wallet.session

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.webkit.CookieManager
import android.webkit.WebStorage
import androidx.core.content.ContextCompat
import java.io.File

object NativeFirstCutoverReset {
    private const val PREFS_NAME = "dsm_cutover"
    private const val VERSION_KEY = "native_first_cutover_version"
    private const val VERSION = "native_first_v1"

    private val preservedFiles = setOf(
        "dsm_env_config.toml",
        "dsm_env_config.override.toml",
        "dsm_env_config.local.toml",
        "ca.crt",
    )

    fun resetIfNeeded(context: Context) {
        val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        if (prefs.getString(VERSION_KEY, null) == VERSION) {
            return
        }

        context.deleteSharedPreferences("dsm_prefs")

        WebStorage.getInstance().deleteAllData()
        try {
            CookieManager.getInstance().removeAllCookies(null)
            CookieManager.getInstance().flush()
        } catch (_: Throwable) {
        }

        context.filesDir?.listFiles()?.forEach { file ->
            if (file.name !in preservedFiles) {
                file.deleteRecursively()
            }
        }

        val appWebViewDir = File(context.dataDir, "app_webview")
        if (appWebViewDir.exists()) {
            appWebViewDir.deleteRecursively()
        }

        prefs.edit().putString(VERSION_KEY, VERSION).apply()
    }

    fun hasBlePermissions(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_CONNECT) == PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_SCAN) == PackageManager.PERMISSION_GRANTED &&
                ContextCompat.checkSelfPermission(context, Manifest.permission.BLUETOOTH_ADVERTISE) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    fun hasCameraPermission(context: Context): Boolean {
        return ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED
    }
}
