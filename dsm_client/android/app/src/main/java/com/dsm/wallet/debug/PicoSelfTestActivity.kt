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
 * It replays ONE captured `OP_SPI_PASSTHROUGH` round-trip (an L1 GET_RESPONSE) and checks the reply
 * against the vector captured from the SAME chip on the Mac bench. The reply's first spi_response
 * byte is the chip STATUS (0x01 = ready); an echo/loopback/fake cannot produce it. A full match
 * proves the phone's USB path reached the real TROPIC01 — the minimal H2 gate before H3 (the full
 * libtropic counter read over the same transport).
 *
 * Kotlin stays opaque: the request frame and expected reply are pre-captured bytes; this class never
 * builds or decodes a TROPIC/protobuf frame. Result goes to logcat under tag "PicoSelfTest".
 */
class PicoSelfTestActivity : Activity() {
    private companion object {
        private const val TAG = "PicoSelfTest"

        /**
         * v2 reach-the-chip probe: LE32 len(2) ++ AnchorRequest{op=STATUS(6)} (field 1, varint).
         * The Software-Authority rewrite removed the old OP_SPI_PASSTHROUGH relay (op 8), so the v2
         * proof that the phone reached the serving appliance on real silicon is a real STATUS op — a
         * serving appliance replies with ok=true (field 2). Opaque, minimal frame.
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
            // v2 STATUS success = the response carries ok=true (field 2, tag 0x10, value 1).
            val okTrue = containsSeq(resp, byteArrayOf(0x10, 0x01))
            Log.i(TAG, "resp len=${resp.size} hex=${hex(resp)}")
            Log.i(TAG, "v2 STATUS ok=true present (reached serving appliance): $okTrue")
            if (okTrue) {
                Log.i(TAG, "*** H2 PASS (v2 STATUS): phone reached the serving appliance over USB-OTG ***")
                // H3: one attested counter read through the FULL production reader stack
                // (libtropic session -> relay router -> USB transport). Bench chip expects H=1000.
                // Only present in glue-packaged builds; absent symbol = old .so, skip gracefully.
                val h = try {
                    com.dsm.wallet.bridge.Unified.anchorCounterSelfTest()
                } catch (e: UnsatisfiedLinkError) {
                    Log.w(TAG, "anchorCounterSelfTest not in this .so (pre-H3 build): ${e.message}")
                    Long.MIN_VALUE
                }
                when {
                    h >= 0 -> Log.i(TAG, "*** H3 PASS: authenticated counter read H=$h through the phone ***")
                    h == Long.MIN_VALUE -> Log.i(TAG, "H3 self-test skipped (symbol absent)")
                    else -> Log.e(TAG, "*** H3 FAIL: authenticated counter read failed (code $h) ***")
                }
                // READ-ONLY chip status (no writes) — logs under "se-slot".
                try {
                    com.dsm.wallet.bridge.Unified.anchorChipStatus()
                } catch (e: UnsatisfiedLinkError) {
                    Log.w(TAG, "anchorChipStatus not in this .so: ${e.message}")
                }
                // GATED device-setup WRITE — counter birth (mcounter[0] := max). Runs ONLY when
                // explicitly launched with `--ez run_counter_init true --es confirm
                // yes-init-counter-max` (a normal USB-attach launch has neither, so it stays
                // read-only). Present only in on_device_installs-feature .so builds.
                val doCounterInit = intent?.getBooleanExtra("run_counter_init", false) == true
                val confirm = intent?.getStringExtra("confirm")
                if (doCounterInit) {
                    if (confirm == "yes-init-counter-max") {
                        val v = try {
                            com.dsm.wallet.bridge.Unified.counterInitMax()
                        } catch (e: UnsatisfiedLinkError) {
                            Log.e(TAG, "counterInitMax not in this .so (needs on_device_installs): ${e.message}")
                            -2L
                        }
                        Log.i(TAG, "*** counter-init result = $v (max=4294967294) ***")
                    } else {
                        Log.e(TAG, "counter-init REFUSED: confirm must be 'yes-init-counter-max' (got '$confirm')")
                    }
                }
                // GATED sender-transport install (for the 2-phone test): the USB anchor appliance
                // factory — the ONLY v2 device install (the receiver needs no hardware). Runs ONLY
                // when launched with `--ez install_anchor_transport true`. Absent from the default .so.
                if (intent?.getBooleanExtra("install_anchor_transport", false) == true) {
                    val ok = try {
                        com.dsm.wallet.bridge.Unified.installAnchorTransport()
                    } catch (e: UnsatisfiedLinkError) {
                        Log.e(TAG, "installAnchorTransport not in this .so (needs on_device_installs): ${e.message}")
                        false
                    }
                    Log.i(TAG, "*** installAnchorTransport = $ok ***")
                }
                // GATED IRREVERSIBLE slot-0 birth burn. Runs ONLY when launched with
                // `--ez run_birth_cage true --es confirm yes-birth-cage-slot0`. Run LAST in device
                // setup, AFTER counter-init. A normal launch never reaches this.
                if (intent?.getBooleanExtra("run_birth_cage", false) == true) {
                    if (confirm == "yes-birth-cage-slot0") {
                        Log.i(TAG, "*** slot-0 BIRTH CAGE starting (irreversible) ***")
                        val r = try {
                            com.dsm.wallet.bridge.Unified.birthCageSlot0()
                        } catch (e: UnsatisfiedLinkError) {
                            Log.e(TAG, "birthCageSlot0 not in this .so (needs on_device_installs): ${e.message}")
                            -2L
                        }
                        if (r >= 0) Log.i(TAG, "*** BIRTH CAGE OK: slot-0 sealed; immutable H0=$r ***")
                        else Log.e(TAG, "*** BIRTH CAGE FAILED (code $r) ***")
                    } else {
                        Log.e(TAG, "birth-cage REFUSED: confirm must be 'yes-birth-cage-slot0' (got '$confirm')")
                    }
                }
            } else {
                Log.e(TAG, "*** H2 FAIL: no real chip response (see resp above) ***")
            }
            Log.i(TAG, "=== Pico USB self-test done ===")
            finish()
        }.start()
    }
}
