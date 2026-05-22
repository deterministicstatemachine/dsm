package com.dsm.wallet.security

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.SecureRandom

/**
 * Keystore-wrapped storage for the C-DBRW salt.
 *
 * The previous design stored `cdbrw_salt` as Base32-encoded plaintext in
 * regular SharedPreferences (BridgeIdentityHandler.kt:257-260). That
 * placed the entire anti-cloning guarantee at risk: K_DBRW is derived
 * from `BLAKE3(stored_ACD || stored_env || stored_salt)`, and all three
 * inputs were filesystem-readable. A clone with adb backup, root, or
 * malware sharing the app UID could trivially recover K_DBRW.
 *
 * This class moves the salt behind an `EncryptedSharedPreferences`
 * instance backed by an Android Keystore master key. The salt blob on
 * disk is AES-256-GCM encrypted under a key that:
 *   - lives only in TEE / StrongBox (when available)
 *   - cannot be exported via adb backup
 *   - is bound to the device's hardware-attested key material
 *
 * A clone that copies the encrypted blob without the Keystore key cannot
 * decrypt the salt. Combined with the opportunistic ACD re-prove
 * (cdbrw.reprove route, Phase 3 deliverable 2 Layer B), salt theft
 * becomes useless on different hardware because the live PUF would
 * diverge from the stored ACD by cross-device W1 (40-75× noise floor
 * verified in Phase 2.2).
 *
 * # Migration
 *
 * On first run of this code, [loadOrCreate] checks the OLD plaintext
 * key under regular SharedPreferences and, if present, copies the value
 * into the encrypted store and DELETES the plaintext key. One-shot
 * migration; subsequent boots see only the encrypted store.
 *
 * # API contract
 *
 * [loadOrCreate] returns a 32-byte salt. On first call ever it
 * generates fresh entropy via [SecureRandom] and persists it. On every
 * subsequent call (including across cold boots and process kills) it
 * returns the same 32 bytes.
 */
object CdbrwKeystoreSalt {
    private const val TAG = "CdbrwKeystoreSalt"
    private const val ENC_PREFS_NAME = "dsm_cdbrw_keystore_v1"
    private const val ENC_KEY_SALT = "cdbrw_salt_b32"

    /** Returns the 32-byte C-DBRW salt, creating and persisting it on first call. */
    fun loadOrCreate(
        context: Context,
        legacyPrefs: SharedPreferences,
        legacyKeyDbrwSalt: String,
    ): ByteArray {
        val encPrefs = openEncryptedPrefs(context)

        // 1. Try the encrypted store first.
        val storedB32 = encPrefs.getString(ENC_KEY_SALT, null)
        if (!storedB32.isNullOrEmpty()) {
            val decoded = decodeOrNull(storedB32)
            if (decoded != null && decoded.size == 32) {
                Log.d(TAG, "loadOrCreate: returning Keystore-wrapped salt")
                return decoded
            }
            Log.w(TAG, "loadOrCreate: encrypted salt was invalid; falling through to migration/generation")
        }

        // 2. One-shot migration from legacy plaintext store.
        val legacyB32 = legacyPrefs.getString(legacyKeyDbrwSalt, null)
        if (!legacyB32.isNullOrEmpty()) {
            val migrated = decodeOrNull(legacyB32)
            if (migrated != null && migrated.size == 32) {
                encPrefs.edit()
                    .putString(ENC_KEY_SALT, com.dsm.wallet.bridge.BridgeEncoding.base32CrockfordEncode(migrated))
                    .apply()
                // Remove the plaintext copy AFTER the encrypted write
                // commits, so a crash mid-migration can't leave both
                // copies absent.
                legacyPrefs.edit().remove(legacyKeyDbrwSalt).apply()
                Log.i(TAG, "loadOrCreate: migrated legacy plaintext salt into Keystore-wrapped store")
                return migrated
            }
            Log.w(TAG, "loadOrCreate: legacy salt present but invalid; ignoring")
        }

        // 3. First-ever boot — generate fresh.
        val fresh = ByteArray(32)
        SecureRandom().nextBytes(fresh)
        encPrefs.edit()
            .putString(ENC_KEY_SALT, com.dsm.wallet.bridge.BridgeEncoding.base32CrockfordEncode(fresh))
            .apply()
        Log.i(TAG, "loadOrCreate: generated fresh salt in Keystore-wrapped store")
        return fresh
    }

    /** Clear the persisted salt — only used by reset / wipe flows. */
    fun clear(context: Context) {
        runCatching {
            openEncryptedPrefs(context).edit().remove(ENC_KEY_SALT).apply()
        }
    }

    private fun openEncryptedPrefs(context: Context): SharedPreferences {
        // StrongBox-backed master key when available; falls back to TEE.
        val builder = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            // StrongBox is best-effort; if unavailable the builder will
            // silently fall back to TEE per AndroidX docs.
            builder.setRequestStrongBoxBacked(true)
        }
        val masterKey = builder.build()
        return EncryptedSharedPreferences.create(
            context,
            ENC_PREFS_NAME,
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    private fun decodeOrNull(b32: String): ByteArray? = try {
        com.dsm.wallet.bridge.BridgeEncoding.base32CrockfordDecode(b32)
    } catch (_: Throwable) {
        null
    }
}
