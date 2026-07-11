// path: app/src/main/java/com/dsm/wallet/security/KeystoreVault.kt
// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Hardware-backed sealing for the DSM wallet-seed vault.
 *
 * Rust (`sdk::seed_vault`) hands the BIP39 wallet seed across JNI to [seal]; the AES key
 * lives in the `AndroidKeyStore` (hardware-backed on devices with a TEE/StrongBox) and
 * never enters Rust or app memory. [open] reverses it on cold start so the signer rebuilds
 * without re-entering the mnemonic.
 *
 * The current key is created with no user-authentication requirement — the no-lock-wallet
 * case, where the seed auto-unlocks on start. A biometric/PIN-gated variant (a locked
 * wallet) needs a `BiometricPrompt` + `Cipher` `CryptoObject`, which is an async UI flow a
 * synchronous JNI upcall cannot drive; that path is a follow-up and would key on a distinct
 * alias with `setUserAuthenticationRequired(true)`.
 */
object KeystoreVault {
    private const val TAG = "KeystoreVault"
    private const val KEYSTORE = "AndroidKeyStore"
    private const val KEY_ALIAS = "dsm_seed_vault_key_v1"
    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    private const val IV_LEN = 12
    private const val TAG_BITS = 128

    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getEntry(KEY_ALIAS, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(false)
            .build()
        generator.init(spec)
        return generator.generateKey()
    }

    /** Seal `plaintext` under the Keystore key. Returns `iv(12) || ciphertext+tag`. */
    @JvmStatic
    fun seal(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        require(iv.size == IV_LEN) { "unexpected GCM IV length ${iv.size}" }
        val ct = cipher.doFinal(plaintext)
        return iv + ct
    }

    /** Open a blob produced by [seal] on this device. Throws on tamper/auth failure. */
    @JvmStatic
    fun open(blob: ByteArray): ByteArray {
        require(blob.size > IV_LEN) { "sealed blob too short: ${blob.size}" }
        val iv = blob.copyOfRange(0, IV_LEN)
        val ct = blob.copyOfRange(IV_LEN, blob.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(ct)
    }

    /** Drop the sealing key (full wallet wipe / mnemonic change). Sealed blobs become unrecoverable. */
    @JvmStatic
    fun wipeKey() {
        try {
            KeyStore.getInstance(KEYSTORE).apply { load(null) }.deleteEntry(KEY_ALIAS)
        } catch (e: Exception) {
            Log.w(TAG, "wipeKey failed: ${e.message}")
        }
    }
}
