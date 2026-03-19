// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.recovery

import android.app.Activity
import android.content.Intent
import android.nfc.NdefMessage
import android.nfc.NdefRecord
import android.nfc.NfcAdapter
import android.os.Bundle
import android.util.Log
import com.dsm.wallet.bridge.BleEventRelay
import com.dsm.wallet.bridge.UnifiedNativeApi
import java.nio.charset.Charset

/**
 * Activity that receives NDEF capsules for recovery import.
 * It parses the first text or application/vnd.dsm.recovery record and dispatches
 * bytes-only payload through Rust JNI (createNfcRecoveryCapsuleEnvelope) → BleEventRelay → WebView.
 */
class NfcRecoveryActivity : Activity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        handleIntent(intent)
    }

    override fun onNewIntent(intent: Intent?) {
        super.onNewIntent(intent)
        if (intent != null) handleIntent(intent)
    }

    private fun handleIntent(intent: Intent) {
        if (NfcAdapter.ACTION_NDEF_DISCOVERED != intent.action) {
            finish(); return
        }
        // Android 13+ (API 33): use type-safe getParcelableArrayExtra(name, Class)
        val messages: List<NdefMessage> = if (android.os.Build.VERSION.SDK_INT >= 33) {
            intent.getParcelableArrayExtra(
                NfcAdapter.EXTRA_NDEF_MESSAGES,
                NdefMessage::class.java
            )?.toList() ?: emptyList()
        } else {
            @Suppress("DEPRECATION")
            val raw = intent.getParcelableArrayExtra(NfcAdapter.EXTRA_NDEF_MESSAGES)
            if (raw == null) emptyList() else raw.mapNotNull { it as? NdefMessage }
        }
        if (messages.isEmpty()) {
            finish(); return
        }
        try {
            val target = extractCapsuleRecord(messages)
            if (target != null) {
                val payload = target.payload // raw bytes
                // Dispatch raw bytes through Rust envelope builder → BleEventRelay transport
                val envelope = UnifiedNativeApi.createNfcRecoveryCapsuleEnvelope(payload)
                if (envelope.isNotEmpty()) BleEventRelay.dispatchEnvelope(envelope)
                Log.i("NfcRecoveryActivity", "Dispatched recovery capsule (${payload.size} bytes)")
            } else {
                Log.w("NfcRecoveryActivity", "No matching NDEF record found")
            }
        } catch (t: Throwable) {
            Log.e("NfcRecoveryActivity", "Failed to parse NDEF", t)
        } finally {
            finish() // Return to previous activity (MainActivity WebView)
        }
    }

    private fun extractCapsuleRecord(messages: List<NdefMessage>): NdefRecord? {
        for (m in messages) {
            for (r in m.records) {
                val tnf = r.tnf
                // Look for text (TNF_WELL_KNOWN + RTD_TEXT) or app mime type
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
}
