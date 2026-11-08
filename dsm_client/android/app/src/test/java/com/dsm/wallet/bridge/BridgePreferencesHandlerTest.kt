// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import android.content.Context
import android.content.SharedPreferences
import androidx.test.core.app.ApplicationProvider
import dsm.types.proto.PreferencePayload
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Audit 2026-10-15 item 8: the page reads and writes its own preferences and nothing else in
 * `dsm_prefs`. The identity pointers there are what bootstrapFromPrefs hands to Rust on a cold
 * start; a page script that could write them could repoint the identity the wallet restores.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [33])
class BridgePreferencesHandlerTest {
    private lateinit var prefs: SharedPreferences

    private val identityKeys = listOf(
        "device_id_bytes",
        "genesis_hash_bytes",
        "genesis_envelope_bytes",
        "has_identity",
        "device_id",
        "genesis_hash",
        "genesis_created",
    )

    @Before
    fun setUp() {
        prefs = ApplicationProvider.getApplicationContext<Context>()
            .getSharedPreferences("dsm_prefs", Context.MODE_PRIVATE)
        prefs.edit().clear().commit()
    }

    private fun payload(key: String, value: String?): ByteArray {
        val builder = PreferencePayload.newBuilder().setKey(key)
        if (value != null) builder.setValue(value)
        return builder.build().toByteArray()
    }

    private fun read(key: String): String =
        String(BridgePreferencesHandler.getPreference(prefs, payload(key, null)), Charsets.UTF_8)

    @Test
    fun the_page_keeps_its_own_preferences() {
        BridgePreferencesHandler.setPreference(prefs, payload("ui_skin", "modern"))
        assertEquals("modern", read("ui_skin"))

        val photoKey = "contact_photo_" + "7".repeat(52)
        BridgePreferencesHandler.setPreference(prefs, payload(photoKey, "data:image/png;base64,AA"))
        assertEquals("data:image/png;base64,AA", read(photoKey))

        listOf(
            "ui_skin", "ui_scheme", "simple_mode", "simple_offline", "receipts_email", "beta_agreement",
            "ui_theme", "sfx_enabled", "dev_mode", "ui_tour_seen", "profile_photo", "profile_banner",
            "diagnostics_consent", "lock_prompt_dismissed",
        ).forEach { assertTrue(it, BridgePreferencesHandler.pageKeeps(it)) }
    }

    @Test
    fun the_identity_pointers_are_not_the_pages_to_write_or_read() {
        prefs.edit().putString("device_id_bytes", "THE-DEVICES-OWN").commit()
        for (key in identityKeys) {
            assertThrows(key, IllegalArgumentException::class.java) {
                BridgePreferencesHandler.setPreference(prefs, payload(key, "A-PAGE-SCRIPTS"))
            }
            assertThrows(key, IllegalArgumentException::class.java) {
                BridgePreferencesHandler.getPreference(prefs, payload(key, null))
            }
        }
        assertEquals("THE-DEVICES-OWN", prefs.getString("device_id_bytes", null))
        assertNull(prefs.getString("genesis_hash_bytes", null))
    }

    @Test
    fun a_contact_photo_key_names_a_whole_device_id() {
        listOf(
            "contact_photo_",
            "contact_photo_" + "A".repeat(51),
            "contact_photo_" + "A".repeat(53),
            "contact_photo_" + "U".repeat(52),
            "contact_photo_" + "a".repeat(52),
            "x_contact_photo_" + "A".repeat(52),
            "contact_photo_device_id_bytes",
        ).forEach { assertFalse(it, BridgePreferencesHandler.pageKeeps(it)) }
    }
}
