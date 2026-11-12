// SPDX-License-Identifier: MIT OR Apache-2.0
package com.dsm.wallet.bridge

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.hardware.usb.UsbConstants
import android.hardware.usb.UsbDevice
import android.hardware.usb.UsbDeviceConnection
import android.hardware.usb.UsbEndpoint
import android.hardware.usb.UsbInterface
import android.hardware.usb.UsbManager
import android.hardware.usb.UsbRequest
import android.util.Log
import java.nio.ByteBuffer
import java.util.concurrent.TimeoutException

/**
 * H2 — the Phone->Pico USB-OTG transport: each phone talking to its own Pico, the payer's to release
 * an offline payment and the receiver's to receive it (owner, 2026-11-07: both sides hold a board).
 *
 * OPAQUE BYTE TRANSPORT ONLY. This class understands nothing about TROPIC /
 * protobuf — Rust builds the request frame and decodes the response. All this does is: open the
 * Pico's USB-CDC endpoints and move a length-prefixed frame across. Contract with the Rust
 * `UsbPicoTransport`:
 *   - input `frame` = `LE32(bodyLen) ++ body` (the request, already framed by Rust). Written verbatim.
 *   - the Pico replies `LE32(bodyLen) ++ body`; we read the 4-byte length, then that many bytes, and
 *     return JUST the body (Rust decodes it). Any failure -> empty ByteArray -> Rust fails closed to
 *     online recovery. No key material passes through here.
 *
 * Only the DSM Anchor itself is opened: the device whose descriptor carries the anchor firmware's
 * vendor and product id. Bench tuning points (validate on the phone): the CDC-data interface +
 * bulk-endpoint discovery, USB permission (grant via requestPermission or the attach intent-filter),
 * and the read timeout. Mirrors the desktop bench `examples/shared/usb.rs::transceive`, in Kotlin.
 */
object LocalPicoUsb {
    private const val TAG = "LocalPicoUsb"
    private const val USB_PERMISSION_ACTION = "com.dsm.wallet.USB_PERMISSION"

    // The DSM Anchor firmware sets its own CDC-ACM USB descriptor (crates/dsm-anchor-nonsecure-app
    // `UsbVidPid(0x1209, 0xd5a1)`): vendor id 0x1209 (pid.codes community VID), product id 0xD5A1,
    // product string "DSM Anchor" — NOT the bare RP2350 VID 0x2E8A. Both ids must match: any other
    // CDC device on the OTG port (a serial adapter, another board) is never opened.
    internal const val DSM_ANCHOR_VENDOR_ID = 0x1209
    internal const val DSM_ANCHOR_PRODUCT_ID = 0xD5A1
    private const val WRITE_TIMEOUT_MS = 2000
    // Android's USB host library (libusbhost) refuses one bulk request longer than 16 KiB, its
    // MAX_USBFS_BUFFER_SIZE, outright: the 49,896-byte OP_AUTHORIZE frame (a 4 KiB head and the
    // owner's 49,856-byte SPHINCS+ signature) came back -1 on the phone, at once. A frame goes out
    // in requests no longer than that; the firmware reads a request by its length prefix, never by
    // the USB packets it arrived in.
    internal const val MAX_BULK_REQUEST_BYTES = 16_384
    private const val READ_TIMEOUT_MS = 500
    private const val CONTROL_TIMEOUT_MS = 1000
    // Drain the firmware boot banner / self-test chatter off the CDC before the first transaction
    // (mirrors the desktop bench's usb::open_and_drain). Read until quiet, bounded by poll counts.
    private const val DRAIN_TIMEOUT_MS = 200
    private const val DRAIN_QUIET_POLLS = 4   // ~800ms of silence ends the drain
    private const val DRAIN_MAX_POLLS = 40    // hard cap (~8s worst case) so boot chatter can finish
    // Max waits of READ_TIMEOUT_MS that see no bulk-IN packet before failing closed. Bounds the
    // total read wait by a count, without a wall-clock deadline (repo invariant). The firmware
    // sends nothing while it serves: a try-run is a whole spend and its records around two chip
    // reboots, and an install is that and more. 600 waits x 500ms = ~5 min covers them, and it is
    // only ever spent on an anchor still serving: a hung one is reset by its own watchdog, which
    // drops the device, and a read of a dropped device fails at once. An install this outruns is
    // read back from the anchor (`CoreSDK::anchor_install`), never reported as failed on the wait.
    private const val MAX_QUIET_WAITS = 600

    @Volatile private var appContext: Context? = null
    private var connection: UsbDeviceConnection? = null
    private var iface: UsbInterface? = null
    private var epIn: UsbEndpoint? = null
    private var epOut: UsbEndpoint? = null
    // Bytes pulled off the bulk-IN endpoint that belong to a LATER read. A read hands back one whole
    // USB packet at a time, and the firmware may send the `LE32 len` and the start of the body in one
    // 64-byte packet, so a read for the 4-byte length can over-run into the body. Those surplus
    // bytes MUST be carried to the next read, not discarded — discarding desyncs the stream, the
    // following body read then blocks until timeout, and the response comes back empty.
    // Per-connection; cleared on reset/reopen.
    private var residual = ByteArray(0)
    // The read queued on the bulk-IN endpoint and the buffer it fills: queued once, waited on until
    // a packet completes it, and never cancelled by a wait that sees nothing ([nextPacket]). Null
    // while no read is queued; cancelled and closed with the connection.
    private var inRead: UsbRequest? = null
    private var inBuffer: ByteBuffer? = null

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
        val wrote = writeInRequests(frame) { offset, length ->
            conn.bulkTransfer(out, frame, offset, length, WRITE_TIMEOUT_MS)
        }
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

    /** Writes `frame` through `write(offset, length)` in requests of at most [MAX_BULK_REQUEST_BYTES]
     * each; `write` answers the bytes it took, or a negative error. Answers the bytes written in all,
     * which falls short of `frame.size` as soon as one request takes less than asked or fails. */
    internal fun writeInRequests(frame: ByteArray, write: (offset: Int, length: Int) -> Int): Int {
        var sent = 0
        while (sent < frame.size) {
            val length = minOf(MAX_BULK_REQUEST_BYTES, frame.size - sent)
            val wrote = write(sent, length)
            if (wrote < length) return sent + maxOf(wrote, 0)
            sent += wrote
        }
        return sent
    }

    /** Tear down the cached connection so the next transceive reopens + reconfigures from scratch
     * (a half-open handle with DTR unset must never be reused), and fail closed with empty bytes. */
    private fun resetAndFail(): ByteArray {
        inRead?.let {
            it.cancel()
            it.close()
        }
        inRead = null; inBuffer = null
        try { iface?.let { connection?.releaseInterface(it) } } catch (_: Exception) {}
        try { connection?.close() } catch (_: Exception) {}
        connection = null; iface = null; epIn = null; epOut = null; residual = ByteArray(0)
        return ByteArray(0)
    }

    /** Read exactly `n` bytes off the bulk-IN endpoint (accumulating across USB packets), or null.
     * What a packet brings past `n` is kept in [residual] for the next read ([readExactly]). */
    private fun readExact(conn: UsbDeviceConnection, ep: UsbEndpoint, n: Int): ByteArray? =
        when (val read = readExactly(n, residual, MAX_QUIET_WAITS) { nextPacket(conn, ep) }) {
            is ReadOutcome.Read -> {
                residual = read.carried
                read.bytes
            }
            is ReadOutcome.Unread -> {
                Log.w(TAG, "USB read: ${read.why} — recover online")
                null
            }
        }

    /** One wait on the bulk-IN endpoint: a packet, a wait that saw none (the read stays queued, so a
     * packet arriving next is still received), or a failure. */
    internal sealed interface InPacket {
        class Bytes(val data: ByteArray) : InPacket
        object Quiet : InPacket
        class Failed(val why: String) : InPacket
    }

    /** A read of exactly the bytes asked for, with what came past them (the next read's), or why
     * the bytes were not read. */
    internal sealed interface ReadOutcome {
        class Read(val bytes: ByteArray, val carried: ByteArray) : ReadOutcome
        class Unread(val why: String) : ReadOutcome
    }

    /** Assemble exactly `n` bytes: first those `carried` from an earlier packet, then packets from
     * `next`, one wait at a time. A wait that sees no packet is only a wait, bounded in a row by
     * `maxQuietWaits` (a count, not a clock); a packet that runs past `n` leaves its tail as the next
     * read's. A failure ends the read. */
    internal fun readExactly(
        n: Int,
        carried: ByteArray,
        maxQuietWaits: Int,
        next: () -> InPacket,
    ): ReadOutcome {
        val out = ByteArray(n)
        var got = minOf(carried.size, n)
        System.arraycopy(carried, 0, out, 0, got)
        var surplus = carried.copyOfRange(got, carried.size)
        var quiet = 0
        while (got < n) {
            when (val packet = next()) {
                is InPacket.Quiet -> {
                    quiet += 1
                    if (quiet > maxQuietWaits) {
                        return ReadOutcome.Unread("no packet in $maxQuietWaits waits ($got/$n)")
                    }
                }
                is InPacket.Failed -> return ReadOutcome.Unread("${packet.why} ($got/$n)")
                is InPacket.Bytes -> {
                    quiet = 0
                    val take = minOf(packet.data.size, n - got)
                    System.arraycopy(packet.data, 0, out, got, take)
                    got += take
                    surplus += packet.data.copyOfRange(take, packet.data.size)
                }
            }
        }
        return ReadOutcome.Read(out, surplus)
    }

    /** One wait of [READ_TIMEOUT_MS] for the next bulk-IN packet. The read is queued once and stays
     * queued across waits that see nothing, until a packet completes it. A synchronous
     * `bulkTransfer` with a timeout kills its transfer whenever the timeout passes, and a packet the
     * device completes into a transfer as it is killed is lost. On the rig (2026-11-11) that was a
     * reply's 4-byte length prefix — the first packet the anchor sends after the silence of its
     * work — and the phone read the reply's first four body bytes as its length. */
    private fun nextPacket(conn: UsbDeviceConnection, ep: UsbEndpoint): InPacket {
        val request = inRead ?: queueRead(conn, ep)
            ?: return InPacket.Failed("the bulk-IN read could not be queued")
        val done = try {
            conn.requestWait(READ_TIMEOUT_MS.toLong())
        } catch (nothingYet: TimeoutException) {
            // The wait ended before a packet came: the read stays queued for the next wait.
            return InPacket.Quiet
        } catch (e: RuntimeException) {
            return InPacket.Failed("the bulk-IN read failed: ${e.message}")
        }
        if (done !== request) return InPacket.Failed("a bulk-IN read this transport did not queue completed")
        val buffer = inBuffer ?: return InPacket.Failed("the bulk-IN read lost its buffer")
        inRead = null
        inBuffer = null
        request.close()
        buffer.flip()
        val data = ByteArray(buffer.remaining())
        buffer.get(data)
        return InPacket.Bytes(data)
    }

    /** Queue one read of a packet on the bulk-IN endpoint, or null when Android refuses it. */
    private fun queueRead(conn: UsbDeviceConnection, ep: UsbEndpoint): UsbRequest? {
        val request = UsbRequest()
        if (!request.initialize(conn, ep)) {
            request.close()
            return null
        }
        val buffer = ByteBuffer.allocate(ep.maxPacketSize.coerceAtLeast(64))
        if (!request.queue(buffer)) {
            request.close()
            return null
        }
        inRead = request
        inBuffer = buffer
        return request
    }

    private fun ensureOpen(): UsbDeviceConnection {
        connection?.let { return it }
        val ctx = appContext ?: error("LocalPicoUsb.init(context) not called")
        val usb = ctx.getSystemService(Context.USB_SERVICE) as UsbManager

        val device = usb.deviceList.values.firstOrNull { isDsmAnchor(it.vendorId, it.productId) }
            ?: error("no DSM Anchor on USB (vendor 0x1209, product 0xD5A1)")
        Log.i(TAG, "USB device detected: vid=${device.vendorId} pid=${device.productId} ${device.productName}")

        if (!usb.hasPermission(device)) {
            // Request permission (shows the one-time "Allow DSM to access the USB device?" dialog).
            // This attempt still fails closed; after the user taps Allow, the next call opens the Pico.
            val ctx2 = appContext
            if (ctx2 != null) {
                val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                val pi = PendingIntent.getBroadcast(
                    ctx2, 0, Intent(USB_PERMISSION_ACTION).setPackage(ctx2.packageName), flags
                )
                usb.requestPermission(device, pi)
                Log.i(TAG, "requested USB permission for the Pico — tap Allow, then retry")
            }
            error("no USB permission for the Pico (permission requested; tap Allow and retry)")
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
        // response read frames on the appliance's reply, not on stale boot chatter.
        drainInput(conn, inEp)
        residual = ByteArray(0)
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
        if (cls < 0 && commIface != null && claimed) {
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
        // DTR down and up: the firmware starts a new frame on the rise, so a frame an earlier process
        // left partway is not read against this one.
        conn.controlTransfer(0x21, 0x22, 0x00, commId, null, 0, CONTROL_TIMEOUT_MS)
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

    /** The DSM Anchor's descriptor: its vendor id and its product id, both. */
    internal fun isDsmAnchor(vendorId: Int, productId: Int): Boolean =
        vendorId == DSM_ANCHOR_VENDOR_ID && productId == DSM_ANCHOR_PRODUCT_ID

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
