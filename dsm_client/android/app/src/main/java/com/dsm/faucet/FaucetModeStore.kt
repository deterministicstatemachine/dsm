package com.dsm.faucet

import android.content.Context
import android.content.SharedPreferences

object FaucetModeStore {
    enum class Mode { OFF, FOREGROUND, BACKGROUND }

    // Keep the pref name stable to preserve user settings across upgrades.
    private const val PREF = "geo_faucet_prefs"
    private const val KEY = "mode"

    fun get(ctx: Context): Mode {
        val v = prefs(ctx).getString(KEY, Mode.OFF.name) ?: Mode.OFF.name
        return try { Mode.valueOf(v) } catch (_: Throwable) { Mode.OFF }
    }

    fun set(ctx: Context, m: Mode) {
        prefs(ctx).edit().putString(KEY, m.name).apply()
    }

    private fun prefs(ctx: Context): SharedPreferences =
        ctx.getSharedPreferences(PREF, Context.MODE_PRIVATE)
}