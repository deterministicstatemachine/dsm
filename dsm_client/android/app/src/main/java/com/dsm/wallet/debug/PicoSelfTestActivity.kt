// SPDX-License-Identifier: MIT OR Apache-2.0
package com.dsm.wallet.debug

import android.app.Activity
import android.os.Bundle
import android.util.Log
import com.dsm.wallet.bridge.LocalPicoUsb

/**
 * H2 bench self-test (debug bring-up only). Launched by the USB_DEVICE_ATTACHED intent-filter when
 * the Pico anchor is plugged into the phone over USB-OTG — that launch also grants this app USB
 * permission for the attached device, so [LocalPicoUsb] can open it.
 *
 * It sends one STATUS request over that link and logs whether the appliance answered: serving, or
 * unprovisioned and waiting for its owner's provisioning.
 *
 * Kotlin stays opaque: the request frame and expected reply are pre-captured bytes; this class never
 * builds or decodes a TROPIC/protobuf frame. Result goes to logcat under tag "PicoSelfTest".
 */
class PicoSelfTestActivity : Activity() {
    private companion object {
        private const val TAG = "PicoSelfTest"

        /**
         * v2 reach-the-chip probe: LE32 len(2) ++ AnchorRequest{op=STATUS(6)} (field 1, varint).
         * The proof that the phone reached the appliance on real silicon is a real STATUS op: a
         * serving appliance sets `ok` (field 2) to 1, an unprovisioned one answers error 105 (field 3).
         * Opaque, minimal frame.
         */
        private val REQ_FRAME: ByteArray = byteArrayOf(
            0x02, 0x00, 0x00, 0x00, // LE32 body length = 2
            0x08, 0x06,             // op = 6 (STATUS)
        )

        /** True if `hay` contains the byte subsequence `needle`. */
        private fun containsSeq(hay: ByteArray, needle: ByteArray): Boolean {
            if (needle.isEmpty() || hay.size < needle.size) return false
            outer@ for (i in 0..hay.size - needle.size) {
                for (j in needle.indices) if (hay[i + j] != needle[j]) continue@outer
                return true
            }
            return false
        }

        private fun hex(b: ByteArray, max: Int = 40): String {
            val n = minOf(b.size, max)
            val sb = StringBuilder(n * 2)
            for (i in 0 until n) sb.append("%02x".format(b[i]))
            if (b.size > max) sb.append("…")
            return sb.toString()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Log.i(TAG, "=== Pico USB self-test starting ===")
        LocalPicoUsb.init(this)
        // USB bulkTransfer blocks — run off the main thread.
        Thread {
            val resp = try {
                LocalPicoUsb.transceive(REQ_FRAME)
            } catch (e: Exception) {
                Log.e(TAG, "transceive threw (fail-closed): ${e.message}", e)
                ByteArray(0)
            }
            // The appliance answered STATUS: serving (field 2 `ok` set to 1), or unprovisioned and
            // waiting for its owner's provisioning (error = NOT_PROVISIONED 105, field 3).
            val serving = containsSeq(resp, byteArrayOf(0x10, 0x01))
            val unprovisioned = containsSeq(resp, byteArrayOf(0x18, 0x69))
            Log.i(TAG, "resp len=${resp.size} hex=${hex(resp)}")
            when {
                serving -> Log.i(TAG, "*** PASS: the phone reached the serving appliance over USB-OTG ***")
                unprovisioned -> Log.i(TAG, "*** PASS: the phone reached the appliance; it awaits provisioning ***")
                else -> Log.e(TAG, "*** FAIL: no appliance response (see resp above) ***")
            }
            Log.i(TAG, "=== Pico USB self-test done ===")
            finish()
        }.start()
    }
}
