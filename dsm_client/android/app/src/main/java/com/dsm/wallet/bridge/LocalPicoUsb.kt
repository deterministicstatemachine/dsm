// SPDX-License-Identifier: MIT OR Apache-2.0
package com.dsm.wallet.bridge

import android.content.Context
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.util.Log

/**
 * H2 — the Phone->Pico USB-OTG transport (the sender phone A talking to its own Pico A).
 *
 * OPAQUE BYTE TRANSPORT ONLY. This class understands nothing about TROPIC / OP_SPI_PASSTHROUGH /
 * protobuf — Rust builds the request frame and decodes the response. All this does is: open the
 * Pico's USB-CDC endpoints and move a length-prefixed frame across. Contract with the Rust
 * `UsbPicoTransport`:
 *   - input `frame` = `LE32(bodyLen) ++ body` (the request, already framed by Rust). Written verbatim.
 *   - the Pico replies `LE32(bodyLen) ++ body`; we read the 4-byte length, then that many bytes, and
 *     return JUST the body (Rust decodes it). Any failure -> empty ByteArray -> Rust fails closed to
 *     online recovery. No key material passes through here.
 *
 * Bench tuning points (validate on the phone): the Pico VID/PID match, the CDC-data interface +
 * bulk-endpoint discovery, USB permission (grant via requestPermission or the attach intent-filter),
 * and the read timeout. Mirrors the desktop bench `examples/shared/usb.rs::transceive`, in Kotlin.
 */
object LocalPicoUsb {
    private const val TAG = "LocalPicoUsb"

    // The DSM Anchor firmware sets its own CDC-ACM USB descriptor: vendor id 0x1209 (pid.codes
    // community VID), product id 0xD5A1, product string "DSM Anchor" — NOT the bare RP2350 VID
    // 0x2E8A. Matched first by VID; the CDC-data interface scan below is the fallback.
    private const val DSM_ANCHOR_VENDOR_ID = 0x1209
    private const val WRITE_TIMEOUT_MS = 2000
    private const val READ_TIMEOUT_MS = 500
    private const val CONTROL_TIMEOUT_MS = 1000
    // Drain the firmware boot banner / self-test chatter off the CDC before the first transaction
    // (mirrors the desktop bench's usb::open_and_drain). Read until quiet, bounded by poll counts.
    private const val DRAIN_TIMEOUT_MS = 200
    private const val DRAIN_QUIET_POLLS = 4   // ~800ms of silence ends the drain
    private const val DRAIN_MAX_POLLS = 40    // hard cap (~8s worst case) so boot chatter can finish
    // Max idle bulk-IN polls before failing closed (each blocks up to READ_TIMEOUT_MS). Bounds the
    // total read wait deterministically without a wall-clock deadline (repo invariant).
    private const val MAX_EMPTY_POLLS = 16

    @Volatile private var appContext: Context? = null
    private var connection: UsbDeviceConnection? = null
    private var iface: UsbInterface? = null
    private var epIn: UsbEndpoint? = null
    private var epOut: UsbEndpoint? = null

    /** Cache the application context so the static `Unified.picoUsbTransceive` can reach UsbManager. */
    @JvmStatic
    fun init(context: Context) {
        appContext = context.applicationContext
    }

    /** One opaque USB round-trip. Returns the response body, or empty on any failure (fail-closed). */
    @Synchronized
    fun transceive(frame: ByteArray): ByteArray {
        val conn = try {
            ensureOpen()
        } catch (e: Exception) {
            Log.w(TAG, "USB open failed (recover online): ${e.message}")
            return ByteArray(0)
        }
        val out = epOut ?: return resetAndFail()
        val inp = epIn ?: return resetAndFail()

        Log.d(TAG, "passthrough req len=${frame.size}")
        val wrote = conn.bulkTransfer(out, frame, frame.size, WRITE_TIMEOUT_MS)
        if (wrote < frame.size) {
            Log.w(TAG, "USB write short ($wrote/${frame.size}) — recover online")
            return resetAndFail()
        }

        // Read the LE32 length prefix, then that many body bytes.
        val header = readExact(conn, inp, 4) ?: return resetAndFail()
        val bodyLen = (header[0].toInt() and 0xFF) or
            ((header[1].toInt() and 0xFF) shl 8) or
            ((header[2].toInt() and 0xFF) shl 16) or
            ((header[3].toInt() and 0xFF) shl 24)
        if (bodyLen <= 0 || bodyLen > 262_144) {
            Log.w(TAG, "USB response length out of range ($bodyLen) — recover online")
            return resetAndFail()
        }
        val body = readExact(conn, inp, bodyLen) ?: return resetAndFail()
        Log.d(TAG, "passthrough resp len=${body.size}")
        return body
    }

    /** Tear down the cached connection so the next transceive reopens + reconfigures from scratch
     * (a half-open handle with DTR unset must never be reused), and fail closed with empty bytes. */
    private fun resetAndFail(): ByteArray {
        try { iface?.let { connection?.releaseInterface(it) } } catch (_: Exception) {}
        try { connection?.close() } catch (_: Exception) {}
        connection = null; iface = null; epIn = null; epOut = null
        return ByteArray(0)
    }

    /** Read exactly `n` bytes off the bulk-IN endpoint (accumulating across USB packets), or null.
     * Bounded by a poll COUNT (not wall-clock — repo invariant): each `bulkTransfer` already blocks
     * up to `READ_TIMEOUT_MS`, so at most `MAX_EMPTY_POLLS` idle polls elapse before we fail closed. */
    private fun readExact(conn: UsbDeviceConnection, ep: UsbEndpoint, n: Int): ByteArray? {
        val out = ByteArray(n)
        var got = 0
        val buf = ByteArray(ep.maxPacketSize.coerceAtLeast(64))
        var emptyPolls = 0
        while (got < n) {
            val r = conn.bulkTransfer(ep, buf, buf.size, READ_TIMEOUT_MS)
            if (r < 0) {
                emptyPolls++
                if (emptyPolls > MAX_EMPTY_POLLS) {
                    Log.w(TAG, "USB read gave up after $MAX_EMPTY_POLLS idle polls ($got/$n) — recover online")
                    return null
                }
                continue
            }
            emptyPolls = 0
            val take = minOf(r, n - got)
            System.arraycopy(buf, 0, out, got, take)
            got += take
        }
        return out
    }

    private fun ensureOpen(): UsbDeviceConnection {
        connection?.let { return it }
        val ctx = appContext ?: error("LocalPicoUsb.init(context) not called")
        val usb = ctx.getSystemService(Context.USB_SERVICE) as UsbManager

        val device = usb.deviceList.values.firstOrNull { it.vendorId == DSM_ANCHOR_VENDOR_ID }
            ?: usb.deviceList.values.firstOrNull { hasCdcDataInterface(it) }
            ?: error("no Pico USB device found")
        Log.i(TAG, "USB device detected: vid=${device.vendorId} pid=${device.productId} ${device.productName}")

        if (!usb.hasPermission(device)) {
            error("no USB permission for the Pico (grant via requestPermission / attach intent)")
        }
        val (usbInterface, inEp, outEp) = findBulkEndpoints(device)
            ?: error("no CDC-data bulk endpoints on the Pico")
        val conn = usb.openDevice(device) ?: error("openDevice returned null")
        if (!conn.claimInterface(usbInterface, true)) {
            conn.close()
            error("claimInterface failed")
        }
        // A desktop cdc-acm driver asserts DTR on open; Android raw USB does not. Without it the
        // anchor firmware's CDC stays "disconnected", never drains its bulk-OUT FIFO, and the first
        // write fills the FIFO and times out (-1). Assert line coding + DTR/RTS the same way.
        configureCdc(conn, device)
        connection = conn
        iface = usbInterface
        epIn = inEp
        epOut = outEp
        Log.i(TAG, "Pico opened (interface ${usbInterface.id}, in=${inEp.address} out=${outEp.address})")
        // Discard the firmware boot banner / self-test output before the first transaction so the
        // response read frames on the OP_SPI_PASSTHROUGH reply, not on stale boot chatter.
        drainInput(conn, inEp)
        return conn
    }

    /**
     * Bring the CDC-ACM control line up the way a host cdc-acm driver does: SET_LINE_CODING (115200
     * 8N1) then SET_CONTROL_LINE_STATE with DTR|RTS asserted, on the CDC communications interface.
     * Class control transfers (bmRequestType 0x21 = host->device | class | interface). Best-effort:
     * failures are logged, not fatal (some firmwares ignore line state).
     */
    private fun configureCdc(conn: UsbDeviceConnection, device: UsbDevice) {
        val commIface = (0 until device.interfaceCount)
            .map { device.getInterface(it) }
            .firstOrNull { it.interfaceClass == UsbConstants.USB_CLASS_COMM }
        val commId = commIface?.id ?: 0
        val claimed = commIface?.let { conn.claimInterface(it, true) } ?: false
        Log.i(TAG, "comm iface=$commId claim=$claimed (ifaceCount=${device.interfaceCount})")
        var cls = setControlLine(conn, commId)
        if (cls < 0 && claimed && commIface != null) {
            // Some host stacks block class control transfers while the comm interface is claimed by
            // the app; release it and retry (control transfers target endpoint 0, not the interface).
            conn.releaseInterface(commIface)
            Log.i(TAG, "control-line timed out with comm claimed; retrying unclaimed")
            cls = setControlLine(conn, commId)
        }
    }

    /** SET_LINE_CODING (115200 8N1) then SET_CONTROL_LINE_STATE (DTR|RTS) on the comm interface;
     * returns the SET_CONTROL_LINE_STATE result (<0 = failed/timed out). */
    private fun setControlLine(conn: UsbDeviceConnection, commId: Int): Int {
        val lineCoding = byteArrayOf(0x00, 0xC2.toByte(), 0x01, 0x00, 0x00, 0x00, 0x08)
        val lc = conn.controlTransfer(0x21, 0x20, 0, commId, lineCoding, lineCoding.size, CONTROL_TIMEOUT_MS)
        val cls = conn.controlTransfer(0x21, 0x22, 0x03, commId, null, 0, CONTROL_TIMEOUT_MS)
        Log.i(TAG, "CDC line (comm iface $commId): setLineCoding=$lc setControlLineState=$cls")
        return cls
    }

    /** Read and discard pending bulk-IN bytes (the firmware boot banner / self-test log) until the
     * line goes quiet for [DRAIN_QUIET_POLLS] polls, capped at [DRAIN_MAX_POLLS]. */
    private fun drainInput(conn: UsbDeviceConnection, ep: UsbEndpoint) {
        val buf = ByteArray(ep.maxPacketSize.coerceAtLeast(64))
        var quiet = 0
        var polls = 0
        var discarded = 0
        while (quiet < DRAIN_QUIET_POLLS && polls < DRAIN_MAX_POLLS) {
            val r = conn.bulkTransfer(ep, buf, buf.size, DRAIN_TIMEOUT_MS)
            if (r > 0) {
                discarded += r
                quiet = 0
            } else {
                quiet++
            }
            polls++
        }
        Log.i(TAG, "drained $discarded boot/banner bytes before first transaction ($polls polls)")
    }

    private fun hasCdcDataInterface(device: UsbDevice): Boolean {
        for (i in 0 until device.interfaceCount) {
            if (device.getInterface(i).interfaceClass == UsbConstants.USB_CLASS_CDC_DATA) return true
        }
        return false
    }

    /** The CDC-data interface (class 0x0A) with a bulk IN + bulk OUT endpoint. */
    private fun findBulkEndpoints(device: UsbDevice): Triple<UsbInterface, UsbEndpoint, UsbEndpoint>? {
        for (i in 0 until device.interfaceCount) {
            val itf = device.getInterface(i)
            if (itf.interfaceClass != UsbConstants.USB_CLASS_CDC_DATA) continue
            var inEp: UsbEndpoint? = null
            var outEp: UsbEndpoint? = null
            for (e in 0 until itf.endpointCount) {
                val ep = itf.getEndpoint(e)
                if (ep.type != UsbConstants.USB_ENDPOINT_XFER_BULK) continue
                if (ep.direction == UsbConstants.USB_DIR_IN) inEp = ep else outEp = ep
            }
            if (inEp != null && outEp != null) return Triple(itf, inEp, outEp)
        }
        return null
    }
}
