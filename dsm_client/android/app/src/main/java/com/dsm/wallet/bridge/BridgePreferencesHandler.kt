// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import android.content.SharedPreferences

/**
 * The page's preferences: how the wallet looks and sounds, the user's switches, and the
 * pictures the owner set. They share `dsm_prefs` with the identity pointers that
 * [BridgeIdentityHandler.bootstrapFromPrefs] hands to Rust, so the page reads and writes the
 * keys named here and no other: a page script cannot repoint the identity a cold start restores.
 */
internal object BridgePreferencesHandler {

    /** Every key the frontend keeps (runtime/skinKeys.ts and the screens that own the others). */
    private val PAGE_KEYS = setOf(
        "ui_skin",
        "ui_scheme",
        "simple_mode",
        "simple_offline",
        "receipts_email",
        "beta_agreement",
        "ui_theme",
        "sfx_enabled",
        "dev_mode",
        "ui_tour_seen",
        "profile_photo",
        "profile_banner",
        "diagnostics_consent",
        "lock_prompt_dismissed",
    )

    /** A contact's photo, by the contact's device id (components/modern/contactPhotos.ts). */
    private const val CONTACT_PHOTO_PREFIX = "contact_photo_"

    /** A 32-byte device id in Base32 Crockford: 52 characters of its alphabet. */
    private const val DEVICE_ID_B32_LEN = 52
    private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

    /** Whether [key] is one the page keeps. */
    fun pageKeeps(key: String): Boolean = key in PAGE_KEYS || isContactPhotoKey(key)

    private fun isContactPhotoKey(key: String): Boolean {
        val id = key.removePrefix(CONTACT_PHOTO_PREFIX)
        return id.length < key.length && id.length == DEVICE_ID_B32_LEN && id.all { it in CROCKFORD }
    }

    private fun pageKey(method: String, key: String): String {
        require(pageKeeps(key)) { "$method: \"$key\" is not a preference the page keeps" }
        return key
    }

    fun getPreference(prefs: SharedPreferences, payload: ByteArray): ByteArray {
        val parsed = BridgeEnvelopeCodec.decodePreferencePayload(payload)
            ?: throw IllegalArgumentException("getPreference: invalid PreferencePayload")
        val v = prefs.getString(pageKey("getPreference", parsed.key), null) ?: return ByteArray(0)
        return v.toByteArray(Charsets.UTF_8)
    }

    fun setPreference(prefs: SharedPreferences, payload: ByteArray): ByteArray {
        val parsed = BridgeEnvelopeCodec.decodePreferencePayload(payload)
            ?: throw IllegalArgumentException("setPreference: invalid PreferencePayload")
        val key = pageKey("setPreference", parsed.key)
        val value = parsed.value ?: ""
        prefs.edit().putString(key, value).apply()
        return ByteArray(0)
    }
}
