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
         * Captured request frame (266 B): LE32 len(262) ++ ApplianceRequest{op=SpiPassthrough,
         * spi_payload = L1 GET_RESPONSE MOSI [0xAA, 0x80, 0x00*255]}. Head is the only non-zero
         * region; the 255 trailing payload bytes are zero (ByteArray default). Opaque to Kotlin.
         */
        private val REQ_FRAME: ByteArray = ByteArray(266).also {
            byteArrayOf(
                0x06, 0x01, 0x00, 0x00, // LE32 body length = 262
                0x08, 0x08,             // op = 8 (SpiPassthrough)
                0x32, 0x81.toByte(), 0x02, // spi_payload: field 6, len 257
                0xAA.toByte(), 0x80.toByte(), // GET_RESPONSE opcode + L2_CMD_REQ_LEN(128)
            ).copyInto(it)
        }

        /**
         * Expected response body (264 B): ApplianceResponse{ok=true, spi_response = [0x01, 0xFF*256]}.
         * spi_response[0] = 0x01 is the real chip STATUS byte (ready). Captured from the bench chip.
         */
        private val EXPECTED: ByteArray = ByteArray(264).also {
            byteArrayOf(
                0x08, 0x08,             // op = 8
                0x10, 0x01,             // ok = true
                0x62, 0x81.toByte(), 0x02, // spi_response: field 12, len 257
                0x01,                   // spi_response[0] = chip STATUS (ready)
            ).copyInto(it)
            for (i in 8 until it.size) it[i] = 0xFF.toByte() // spi_response[1..256] = 0xFF (NO_RESP)
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
            val full = resp.contentEquals(EXPECTED)
            // Discriminating prefix: ...62 81 02 01 ff ff — the chip STATUS 0x01 right after the length.
            val prefixOk = resp.size >= 9 &&
                resp[6] == 0x62.toByte() && resp[7] == 0x81.toByte() && resp[8] == 0x02.toByte() &&
                resp.size >= 10 && resp[9] == 0x01.toByte()
            Log.i(TAG, "resp len=${resp.size} hex=${hex(resp)}")
            Log.i(TAG, "full match (byte-identical to bench capture): $full")
            Log.i(TAG, "chip-status prefix present (reached real TROPIC01): $prefixOk")
            if (full || prefixOk) {
                Log.i(TAG, "*** H2 PASS: phone reached the real chip over USB-OTG ***")
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
                    h >= 0 -> Log.i(TAG, "*** H3 PASS: attested counter read H=$h through the phone ***")
                    h == Long.MIN_VALUE -> Log.i(TAG, "H3 self-test skipped (symbol absent)")
                    else -> Log.e(TAG, "*** H3 FAIL: attested counter read failed (code $h) ***")
                }
                // READ-ONLY verifier-slot status/preflight (no writes) — logs under "se-slot".
                try {
                    com.dsm.wallet.bridge.Unified.verifierSlotStatus()
                } catch (e: UnsatisfiedLinkError) {
                    Log.w(TAG, "verifierSlotStatus not in this .so: ${e.message}")
                }
                // GATED device-setup WRITE — counter-init to max. Runs ONLY when explicitly launched
                // with `--ez run_counter_init true --es confirm yes-init-counter-max` (a normal
                // USB-attach launch has neither, so it stays read-only). The counterInitMax symbol is
                // present only in on_device_installs-feature .so builds.
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
                // GATED verifier-slot BURN (irreversible). Runs ONLY when launched with
                // `--ez run_slot_commit true --ei slot N --es confirm yes-burn-slot-N`. The confirm
                // MUST name the same slot (mismatch refused). A normal launch never reaches this.
                val doSlotCommit = intent?.getBooleanExtra("run_slot_commit", false) == true
                if (doSlotCommit) {
                    val slot = intent?.getIntExtra("slot", -1) ?: -1
                    if (slot in 1..3 && confirm == "yes-burn-slot-$slot") {
                        Log.i(TAG, "*** slot-$slot BURN starting (irreversible) ***")
                        val r = try {
                            com.dsm.wallet.bridge.Unified.provisionVerifierSlot(slot)
                        } catch (e: UnsatisfiedLinkError) {
                            Log.e(TAG, "provisionVerifierSlot not in this .so (needs on_device_installs): ${e.message}")
                            -2
                        }
                        if (r >= 0) Log.i(TAG, "*** slot-$slot BURN OK: verifier slot $r caged ***")
                        else Log.e(TAG, "*** slot-$slot BURN FAILED (code $r) ***")
                    } else {
                        Log.e(TAG, "slot-commit REFUSED: need --ei slot N (1..3) + --es confirm yes-burn-slot-N (got slot=$slot confirm='$confirm')")
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
