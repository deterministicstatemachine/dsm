package com.dsm.wallet.bridge

import android.content.SharedPreferences

internal object BridgePreferencesHandler {

    fun getPreference(prefs: SharedPreferences, payload: ByteArray): ByteArray {
        val key = BridgeEnvelopeCodec.decodePreferencePayload(payload)?.key ?: ""
        if (key.isEmpty()) return ByteArray(0)
        val v = prefs.getString(key, null) ?: return ByteArray(0)
        return v.toByteArray(Charsets.UTF_8)
    }

    fun setPreference(prefs: SharedPreferences, payload: ByteArray): ByteArray {
        val parsed = BridgeEnvelopeCodec.decodePreferencePayload(payload)
            ?: throw IllegalArgumentException("setPreference: invalid PreferencePayload")
        val key = parsed.key
        val value = parsed.value ?: ""
        if (key.isEmpty()) return ByteArray(0)
        prefs.edit().putString(key, value).apply()
        return ByteArray(0)
    }
}
