// path: app/src/main/java/com/dsm/wallet/security/KeystoreVault.kt
// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * One `AndroidKeyStore` AES-256/GCM key, named by its alias. What it seals opens only under
 * that same key: the key is generated inside the Keystore (hardware-backed on devices with a
 * TEE/StrongBox) and cannot be exported, so another device — or this one after the key is
 * gone — holds a different key and the GCM tag refuses the blob.
 */
class KeystoreSealer(private val alias: String) {
    private fun getOrCreateKey(): SecretKey {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        (ks.getEntry(alias, null) as? KeyStore.SecretKeyEntry)?.let { return it.secretKey }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            alias,
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

    /** Seal `plaintext` under this alias's Keystore key. Returns `iv(12) || ciphertext+tag`. */
    fun seal(plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, getOrCreateKey())
        val iv = cipher.iv
        require(iv.size == IV_LEN) { "unexpected GCM IV length ${iv.size}" }
        val ct = cipher.doFinal(plaintext)
        return iv + ct
    }

    /** Open a blob produced by [seal] under this alias's key. Throws on tamper or a different key. */
    fun open(blob: ByteArray): ByteArray {
        require(blob.size > IV_LEN) { "sealed blob too short: ${blob.size}" }
        val iv = blob.copyOfRange(0, IV_LEN)
        val ct = blob.copyOfRange(IV_LEN, blob.size)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, getOrCreateKey(), GCMParameterSpec(TAG_BITS, iv))
        return cipher.doFinal(ct)
    }

    private companion object {
        const val KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val IV_LEN = 12
        const val TAG_BITS = 128
    }
}

/**
 * Hardware-backed sealing for the DSM vault: the BIP39 wallet seed and the NFC recovery key.
 *
 * Rust (`sdk::seed_vault`) hands each secret across JNI to [seal]; the AES key lives in the
 * `AndroidKeyStore` and never enters Rust or app memory. [open] reverses it on cold start so
 * the signer rebuilds, and the recovery capsule refreshes, without re-entering the mnemonic.
 *
 * The current key is created with no user-authentication requirement — the no-lock-wallet
 * case, where the seed auto-unlocks on start. A biometric/PIN-gated variant (a locked
 * wallet) needs a `BiometricPrompt` + `Cipher` `CryptoObject`, which is an async UI flow a
 * synchronous JNI upcall cannot drive; that path is a follow-up and would key on a distinct
 * alias with `setUserAuthenticationRequired(true)`.
 */
object KeystoreVault {
    private val vault = KeystoreSealer("dsm_seed_vault_key_v1")

    /** Seal `plaintext` under this device's vault key. Returns `iv(12) || ciphertext+tag`. */
    @JvmStatic
    fun seal(plaintext: ByteArray): ByteArray = vault.seal(plaintext)

    /** Open a blob produced by [seal] on this device. Throws on tamper/auth failure. */
    @JvmStatic
    fun open(blob: ByteArray): ByteArray = vault.open(blob)
}
