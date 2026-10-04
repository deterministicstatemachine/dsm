// path: app/src/androidTest/java/com/dsm/wallet/security/KeystoreVaultTest.kt
// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import javax.crypto.AEADBadTagException
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A sealed vault blob opens only under the Keystore key that sealed it. Each alias here is
 * a real `AndroidKeyStore` key, as a device's vault key is: a second alias is another
 * device's key, and a deleted alias is this device's key gone. The app's own vault alias
 * is never touched, and the test's keys are deleted afterwards.
 */
@RunWith(AndroidJUnit4::class)
class KeystoreVaultTest {
    private val thisDevice = "dsm_vault_test_this_device"
    private val otherDevice = "dsm_vault_test_other_device"
    private val seed = ByteArray(64) { (it * 7 + 3).toByte() }

    @After
    fun dropTheTestKeys() {
        val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keyStore.deleteEntry(thisDevice)
        keyStore.deleteEntry(otherDevice)
    }

    @Test
    fun aBlobSealedOnOneDeviceDoesNotOpenUnderAnotherDevicesKey() {
        val blob = KeystoreSealer(thisDevice).seal(seed)
        assertArrayEquals("its own key opens it", seed, KeystoreSealer(thisDevice).open(blob))
        assertThrows(AEADBadTagException::class.java) { KeystoreSealer(otherDevice).open(blob) }
    }

    @Test
    fun aBlobDoesNotOpenOnceItsKeyIsGone() {
        val blob = KeystoreSealer(thisDevice).seal(seed)
        KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(thisDevice)
        assertThrows(AEADBadTagException::class.java) { KeystoreSealer(thisDevice).open(blob) }
    }

    @Test
    fun aSealedBlobCarriesNoPlaintextAndRefusesTampering() {
        val blob = KeystoreSealer(thisDevice).seal(seed)
        val body = blob.copyOfRange(blob.size - seed.size - 16, blob.size - 16)
        assertNotEquals("the ciphertext is not the seed", seed.toList(), body.toList())
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 0x01).toByte()
        assertThrows(AEADBadTagException::class.java) { KeystoreSealer(thisDevice).open(blob) }
    }
}
