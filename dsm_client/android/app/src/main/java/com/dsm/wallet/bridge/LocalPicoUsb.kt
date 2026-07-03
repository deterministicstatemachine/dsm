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

    // Raspberry Pi / RP2350 USB vendor id (the Pico anchor firmware is a CDC-ACM device). Bench may
    // need to also match the product id or the "dsm_anchor" product string.
    private const val RPI_VENDOR_ID = 0x2E8A
    private const val WRITE_TIMEOUT_MS = 2000
    private const val READ_TIMEOUT_MS = 8000

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
        val out = epOut ?: return ByteArray(0)
        val inp = epIn ?: return ByteArray(0)

        Log.d(TAG, "passthrough req len=${frame.size}")
        val wrote = conn.bulkTransfer(out, frame, frame.size, WRITE_TIMEOUT_MS)
        if (wrote < frame.size) {
            Log.w(TAG, "USB write short ($wrote/${frame.size}) — recover online")
            return ByteArray(0)
        }

        // Read the LE32 length prefix, then that many body bytes.
        val header = readExact(conn, inp, 4) ?: return ByteArray(0)
        val bodyLen = (header[0].toInt() and 0xFF) or
            ((header[1].toInt() and 0xFF) shl 8) or
            ((header[2].toInt() and 0xFF) shl 16) or
            ((header[3].toInt() and 0xFF) shl 24)
        if (bodyLen <= 0 || bodyLen > 262_144) {
            Log.w(TAG, "USB response length out of range ($bodyLen) — recover online")
            return ByteArray(0)
        }
        val body = readExact(conn, inp, bodyLen) ?: return ByteArray(0)
        Log.d(TAG, "passthrough resp len=${body.size}")
        return body
    }

    /** Read exactly `n` bytes off the bulk-IN endpoint (accumulating across USB packets), or null. */
    private fun readExact(conn: UsbDeviceConnection, ep: UsbEndpoint, n: Int): ByteArray? {
        val out = ByteArray(n)
        var got = 0
        val buf = ByteArray(ep.maxPacketSize.coerceAtLeast(64))
        val deadline = System.nanoTime() + READ_TIMEOUT_MS * 1_000_000L
        while (got < n) {
            if (System.nanoTime() > deadline) {
                Log.w(TAG, "USB read timeout ($got/$n) — recover online")
                return null
            }
            val r = conn.bulkTransfer(ep, buf, buf.size, READ_TIMEOUT_MS)
            if (r < 0) continue // no data this poll; loop until deadline
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

        val device = usb.deviceList.values.firstOrNull { it.vendorId == RPI_VENDOR_ID }
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
        connection = conn
        iface = usbInterface
        epIn = inEp
        epOut = outEp
        Log.i(TAG, "Pico opened (interface ${usbInterface.id}, in=${inEp.address} out=${outEp.address})")
        return conn
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
