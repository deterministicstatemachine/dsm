package com.dsm.wallet

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import android.util.Log

/**
 * Early-process initializer to ensure the JNI library is loaded before any Activity/Service.
 * We don't do any heavy work here—just touch the Unified class to trigger static init.
 */
class DsmInitProvider : ContentProvider() {
    override fun onCreate(): Boolean {
        return try {
            // Ensure the SDK JNI surface (libdsm_sdk.so) is loaded.
            // Referencing the object triggers its `init { System.loadLibrary("dsm_sdk") }`.
            @Suppress("UNUSED_VARIABLE")
            val _dsmNative = com.dsm.native.DsmNative

            // Finally, resolve the class to ensure its static initializers run.
            Class.forName("com.dsm.wallet.bridge.Unified")
            
            // Library loaded successfully - clear any previous incompatibility flag
            context?.let {
                it.getSharedPreferences("dsm_system", android.content.Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean("jni_incompatible", false)
                    .apply()
            }
            true
        } catch (e: UnsatisfiedLinkError) {
            Log.e("DsmInitProvider", "UnsatisfiedLinkError: Native library incompatible with this device", e)
            
            // Set flag for MainActivity to show compatibility screen
            context?.let {
                it.getSharedPreferences("dsm_system", android.content.Context.MODE_PRIVATE)
                    .edit()
                    .putBoolean("jni_incompatible", true)
                    .putString("jni_error_message", e.message ?: "Unknown library load error")
                    .apply()
            }
            
            // Return true to allow app to start and show compatibility screen
            // (fail-open for this specific error case only)
            true
        } catch (t: Throwable) {
            Log.e("DsmInitProvider", "Failed to pre-load Unified", t)
            // Fail-closed but return true to avoid app install/runtime issues; Unified guards calls.
            true
        }
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?
    ): Int = 0
}
