// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.recovery

import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.nfc.Tag
import android.nfc.tech.Ndef
import android.os.Bundle
import android.util.Log
import android.view.View
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.dsm.wallet.bridge.BleEventRelay
import com.dsm.wallet.bridge.UnifiedNativeApi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.nio.charset.Charset

/**
 * Activity that reads NDEF recovery capsules from NFC rings.
 *
 * Launched explicitly by Kotlin when the user presses "INSPECT THE RING"
 * on the recovery screen.  Uses enableReaderMode (same approach as
 * NfcWriteActivity) — no manifest intent filter, so the ring will never
 * auto-trigger this activity just by being near the phone.
 *
 * UX contract:
 * - No vibration, no sounds — the frontend shows the "INSPECTING..." state.
 * - Reads the first NDEF capsule record and dispatches it through
 *   Rust JNI → BleEventRelay → WebView.
 * - Finishes immediately after a successful read (or if NFC is unavailable).
 */
class NfcRecoveryActivity : AppCompatActivity(), NfcAdapter.ReaderCallback {

    private var nfcAdapter: NfcAdapter? = null
    private var readComplete = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val blank = View(this)
        blank.setBackgroundColor(0x00000000)
        setContentView(blank)

        nfcAdapter = NfcAdapter.getDefaultAdapter(this)
        if (nfcAdapter == null || !nfcAdapter!!.isEnabled) {
            Log.w(TAG, "NFC not available or disabled")
            finish()
            return
        }

        Log.i(TAG, "NfcRecoveryActivity ready, waiting for ring...")
    }

    override fun onResume() {
        super.onResume()
        if (readComplete) return

        nfcAdapter?.enableReaderMode(
            this,
            this,
            NfcAdapter.FLAG_READER_NFC_A or NfcAdapter.FLAG_READER_NFC_B,
            null
        )
    }

    override fun onPause() {
        super.onPause()
        nfcAdapter?.disableReaderMode(this)
    }

    override fun onTagDiscovered(tag: Tag) {
        if (readComplete) return

        lifecycleScope.launch(Dispatchers.IO) {
            try {
                val ndef = Ndef.get(tag)
                if (ndef == null) {
                    Log.w(TAG, "Tag has no NDEF support")
                    return@launch
                }

                ndef.connect()
                val ndefMessage = try {
                    ndef.ndefMessage
                } finally {
                    ndef.close()
                }

                if (ndefMessage == null) {
                    Log.w(TAG, "Tag has no NDEF message")
                    return@launch
                }

                val record = extractCapsuleRecord(listOf(ndefMessage))
                if (record == null) {
                    Log.w(TAG, "No matching NDEF capsule record found")
                    return@launch
                }

                val payload = record.payload
                val envelope = UnifiedNativeApi.createNfcRecoveryCapsuleEnvelope(payload)
                if (envelope.isNotEmpty()) {
                    BleEventRelay.dispatchEnvelope(envelope)
                }

                Log.i(TAG, "Dispatched recovery capsule (${payload.size} bytes)")

                withContext(Dispatchers.Main) {
                    readComplete = true
                }

                withContext(Dispatchers.Main) { finish() }

            } catch (e: Exception) {
                Log.d(TAG, "NFC read failed: ${e.message}")
            }
        }
    }

    private fun extractCapsuleRecord(messages: List<NdefMessage>): NdefRecord? {
        for (m in messages) {
            for (r in m.records) {
                val tnf = r.tnf
                if (tnf == NdefRecord.TNF_WELL_KNOWN && r.type.contentEquals(NdefRecord.RTD_TEXT)) {
                    return r
                }
                if (tnf == NdefRecord.TNF_MIME_MEDIA) {
                    val mime = try { String(r.type, Charset.forName("US-ASCII")) } catch (_: Throwable) { "" }
                    if (mime.equals("application/vnd.dsm.recovery", ignoreCase = true)) {
                        return r
                    }
                }
            }
        }
        return null
    }

    companion object {
        private const val TAG = "NfcRecoveryActivity"
    }
}
