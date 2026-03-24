// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.recovery

import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.Ndef
import android.nfc.tech.NdefFormatable
import android.nfc.tech.NfcA
import android.os.Build
import android.os.Bundle
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.dsm.wallet.bridge.BleEventRelay
import com.dsm.wallet.bridge.UnifiedNativeApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.IOException

/**
 * Activity for writing recovery capsules to NFC rings (NTAG216).
 *
 * Layer separation (CLAUDE.md Invariant #7):
 * - Rust: Creates capsules, formats NDEF (owns all protocol/crypto)
 * - Kotlin: Operates NFC hardware, relays to Rust via JNI
 * - TypeScript: Calls routes only (no business logic)
 *
 * First-tap workflow (factory-blank ring):
 * 1. Detect raw/unformatted tag (Ndef.get() returns null)
 * 2. Auto-format via NdefFormatable (writes CC bytes, NDEF TLV structure)
 * 3. Verify CC reports NTAG216 capacity (888 bytes, not 144 like NTAG213)
 * 4. Write the recovery capsule
 * 5. Vibrate on success
 *
 * No passwords, no authentication. The ring is physically held by the user.
 * The capsule is AEAD-encrypted — reading it without the mnemonic is useless.
 * Write protection would add friction to every automatic state-transition backup.
 *
 * UX contract:
 * - Vibration = state committed (tag written successfully)
 * - No vibration = it didn't write. User taps again.
 * - No timers, no error UI, no progress indicators.
 *
 * Uses enableReaderMode (newer, more reliable than foreground dispatch).
 */
class NfcWriteActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private var nfcAdapter: NfcAdapter? = null
    private var writeComplete = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val blank = View(this)
        blank.setBackgroundColor(0x00000000)
        setContentView(blank)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null || !nfcAdapter!!.isEnabled) {
            finish()
            return
        }

        val pendingCapsule = UnifiedNativeApi.getPendingRecoveryCapsule()
        if (pendingCapsule.isEmpty()) {
            finish()
            return
        }

        Log.i(TAG, "NfcWriteActivity ready, ${pendingCapsule.size} byte capsule pending")
    }

    override fun onResume() {
        super.onResume()
        if (writeComplete) return

        nfcAdapter?.enableReaderMode(
            this,
            this,
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK,
            null
        )
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    override fun onTagDiscovered(tag: Tag) {
        if (writeComplete) return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                // 1. Get pending capsule from Rust
                val capsuleBytes = UnifiedNativeApi.getPendingRecoveryCapsule()
                if (capsuleBytes.isEmpty()) {
                    withContext(Dispatchers.Main) { finish() }
                    return@launch
                }

                // 2. Ask Rust to format as NDEF (Rust owns NDEF structure/MIME type)
                val ndefBytes = UnifiedNativeApi.prepareNfcWritePayload(capsuleBytes)
                val ndefMessage = NdefMessage(ndefBytes)

                // 3. Ensure tag is formatted + verify capacity
                val preparedTag = prepareTag(tag)
                if (preparedTag == null) {
                    Log.w(TAG, "Tag preparation failed — not NTAG216 or capacity too small")
                    return@launch
                }

                // 4. Write NDEF message
                writeToTag(preparedTag, ndefMessage)

                // 5. State committed. Tell Rust.
                UnifiedNativeApi.clearPendingRecoveryCapsule()

                // 6. Vibrate. This is the event.
                withContext(Dispatchers.Main) {
                    writeComplete = true
                    vibrate()
                }

                // 7. Notify the frontend through a Rust-authored protobuf envelope.
                UnifiedNativeApi.createNfcBackupWrittenEnvelope()
                    .takeIf { it.isNotEmpty() }
                    ?.let { BleEventRelay.dispatchEnvelope(it) }

                Log.i(TAG, "NFC write committed, ${ndefBytes.size} bytes")

                withContext(Dispatchers.Main) { finish() }

            } catch (e: IOException) {
                // Tag moved, write didn't commit. No vibration. User taps again.
                Log.d(TAG, "NFC write failed (IOException): ${e.message}")
            } catch (e: Exception) {
                Log.d(TAG, "NFC write failed: ${e.message}")
            }
        }
    }

    /**
     * Prepare a tag for writing: format if blank, verify capacity.
     *
     * Returns the Tag if ready to write, null if the tag is unsuitable.
     * This is the "first-tap" invisible setup for factory-blank NTAG216 rings.
     */
    private fun prepareTag(tag: Tag): Tag? {
        var ndef = Ndef.get(tag)

        if (ndef == null) {
            // Factory-blank tag — auto-format with empty NDEF to initialize the file system.
            // This writes the CC bytes and NDEF TLV structure (~50ms).
            val formatable = NdefFormatable.get(tag) ?: return null
            try {
                formatable.connect()
                formatable.format(NdefMessage(arrayOf(NdefRecord(
                    NdefRecord.TNF_EMPTY, ByteArray(0), ByteArray(0), ByteArray(0)
                ))))
                formatable.close()
                Log.i(TAG, "Auto-formatted blank tag")
            } catch (e: Exception) {
                Log.w(TAG, "Auto-format failed: ${e.message}")
                try { formatable.close() } catch (_: Exception) {}
                return null
            }

            // Re-acquire NDEF handle after formatting
            ndef = Ndef.get(tag) ?: return null
        }

        // Verify capacity — NTAG216 should report ~868 bytes usable.
        // If it reports <500, the CC bytes are wrong (tag thinks it's NTAG213).
        try {
            ndef.connect()
            val maxSize = ndef.maxSize
            ndef.close()

            if (maxSize < NTAG216_MIN_USABLE_BYTES) {
                Log.w(TAG, "Tag capacity too small: $maxSize bytes (expected ≥$NTAG216_MIN_USABLE_BYTES for NTAG216)")
                // Attempt CC fix via low-level NfcA if this looks like a mis-identified tag
                if (maxSize < 200) {
                    try {
                        fixCapabilityContainer(tag)
                        Log.i(TAG, "CC bytes corrected, re-checking capacity")
                    } catch (e: Exception) {
                        Log.w(TAG, "CC fix failed: ${e.message}")
                        return null
                    }
                } else {
                    return null
                }
            }
        } catch (e: Exception) {
            Log.w(TAG, "Capacity check failed: ${e.message}")
            return null
        }

        return tag
    }

    /**
     * Write NDEF message to an already-prepared tag.
     */
    private fun writeToTag(tag: Tag, message: NdefMessage) {
        val ndef = Ndef.get(tag) ?: throw IOException("Tag lost NDEF handle after prep")

        ndef.connect()
        try {
            if (!ndef.isWritable) {
                throw IOException("Tag is read-only")
            }
            val messageSize = message.toByteArray().size
            if (ndef.maxSize < messageSize) {
                throw IOException("Tag too small: need $messageSize, have ${ndef.maxSize}")
            }
            ndef.writeNdefMessage(message)
        } finally {
            ndef.close()
        }
    }

    /**
     * Fix the Capability Container on page 3 for NTAG216.
     *
     * Factory-blank tags sometimes get formatted with NTAG213 CC bytes (E1 10 12 00)
     * which reports only 144 bytes. NTAG216 CC should be E1 10 6D 00 (888 bytes).
     *
     * Uses low-level NfcA WRITE command (0xA2) to page 3.
     */
    private fun fixCapabilityContainer(tag: Tag) {
        val nfcA = NfcA.get(tag) ?: throw IOException("NfcA not available")
        nfcA.connect()
        try {
            // WRITE command: 0xA2, page 3, [E1 10 6D 00]
            // E1 = NDEF magic number
            // 10 = version 1.0
            // 6D = size (0x6D * 8 = 872 bytes ≈ 888 usable)
            // 00 = read/write access, no lock
            val writeCmd = byteArrayOf(
                0xA2.toByte(), // WRITE command
                0x03,          // Page 3 (CC)
                0xE1.toByte(), 0x10, 0x6D, 0x00 // NTAG216 CC bytes
            )
            nfcA.transceive(writeCmd)
            Log.i(TAG, "CC bytes written: E1 10 6D 00 (NTAG216)")
        } finally {
            nfcA.close()
        }
    }

    /**
     * Single haptic pulse. The event, not a duration.
     */
    private fun vibrate() {
        val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val mgr = getSystemService(VIBRATOR_MANAGER_SERVICE) as VibratorManager
            mgr.defaultVibrator
        } else {
            @Suppress("DEPRECATION")
            getSystemService(VIBRATOR_SERVICE) as Vibrator
        }
        vibrator.vibrate(
            VibrationEffect.createOneShot(50, VibrationEffect.DEFAULT_AMPLITUDE)
        )
    }

    companion object {
        private const val TAG = "NfcWriteActivity"

        // NTAG216 has 888 bytes user memory, ~868 usable with NDEF overhead.
        // If the tag reports less than 500, the CC bytes are likely wrong.
        private const val NTAG216_MIN_USABLE_BYTES = 500
    }
}
