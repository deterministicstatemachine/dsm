// SPDX-License-Identifier: Apache-2.0
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
import android.util.Log

/**
 * The phone's USB link to a board in BOOTSEL, for the board's one-time burns from the phone alone
 * (owner, 2026-11-11: "Not everyone has a Mac. It has to be doable from the phone").
 *
 * It only moves bytes on the RP2350 bootloader's PICOBOOT interface. The protocol, every check and
 * every burn are Rust's (`dsm-android-anchor`: `picoboot`, `otp_burn`, `board_setup`), which calls
 * these through `Unified`. Each failure is said in [lastError] and never guessed past.
 */
object BootselUsb {
    private const val TAG = "BootselUsb"
    private const val USB_PERMISSION_ACTION = "com.dsm.wallet.BOOTSEL_PERMISSION"

    /** The RP2350's USB bootloader: Raspberry Pi's vendor id and the RP2350 BOOTSEL product id. */
    internal const val RP2350_BOOT_VENDOR_ID = 0x2E8A
    internal const val RP2350_BOOT_PRODUCT_ID = 0x000F

    /** PICOBOOT's vendor requests on its interface (pico-sdk `boot/picoboot.h`). */
    private const val PICOBOOT_IF_RESET = 0x41
    private const val PICOBOOT_IF_CMD_STATUS = 0x42
    /** bmRequestType: vendor, to the interface, host to device / device to host. */
    private const val VENDOR_INTERFACE_OUT = 0x41
    private const val VENDOR_INTERFACE_IN = 0xC1
    /** A standard request on an endpoint: GET_STATUS reads its halt. */
    private const val STANDARD_ENDPOINT_IN = 0x82
    private const val GET_STATUS = 0x00

    /** picotool's bulk timeout; an OTP write or a flash erase answers within it. */
    private const val BULK_TIMEOUT_MS = 10_000
    private const val CONTROL_TIMEOUT_MS = 1_000

    @Volatile private var appContext: Context? = null
    private var connection: UsbDeviceConnection? = null
    private var iface: UsbInterface? = null
    private var epIn: UsbEndpoint? = null
    private var epOut: UsbEndpoint? = null
    @Volatile private var lastError: String = ""

    @JvmStatic
    fun init(context: Context) {
        appContext = context.applicationContext
    }

    /** Why the last call failed. */
    fun lastError(): String = lastError

    private fun fail(why: String): String {
        lastError = why
        Log.w(TAG, why)
        return why
    }

    /** The one RP2350 in BOOTSEL on USB. */
    private fun bootselBoard(usb: UsbManager): UsbDevice? {
        val boards = usb.deviceList.values.filter {
            it.vendorId == RP2350_BOOT_VENDOR_ID && it.productId == RP2350_BOOT_PRODUCT_ID
        }
        if (boards.size > 1) {
            fail("${boards.size} boards are in BOOTSEL on USB: plug in only the one to set up")
            return null
        }
        if (boards.isEmpty()) {
            fail("no board in BOOTSEL on USB: hold its BOOTSEL button while plugging it in")
            return null
        }
        return boards.first()
    }

    /**
     * Open the board in BOOTSEL. Its chip id, as its bootloader names itself (its USB serial
     * number, 16 hexadecimal digits), or null with [lastError] saying why.
     */
    @Synchronized
    fun open(): String? {
        close()
        val ctx = appContext ?: run { fail("BootselUsb.init(context) was not called"); return null }
        val usb = ctx.getSystemService(Context.USB_SERVICE) as? UsbManager
            ?: run { fail("this phone has no USB host service"); return null }
        val device = bootselBoard(usb) ?: return null
        if (!usb.hasPermission(device)) {
            val flags = PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
            val pi = PendingIntent.getBroadcast(
                ctx, 0, Intent(USB_PERMISSION_ACTION).setPackage(ctx.packageName), flags
            )
            usb.requestPermission(device, pi)
            fail("Android has not let DSM use the board yet: tap Allow when it asks, then read the board again")
            return null
        }
        val picoboot = (0 until device.interfaceCount)
            .map { device.getInterface(it) }
            .firstOrNull { it.interfaceClass == UsbConstants.USB_CLASS_VENDOR_SPEC && it.endpointCount == 2 }
            ?: run { fail("the board's bootloader shows no PICOBOOT interface"); return null }
        val endpoints = (0 until picoboot.endpointCount).map { picoboot.getEndpoint(it) }
        val inEp = endpoints.firstOrNull {
            it.type == UsbConstants.USB_ENDPOINT_XFER_BULK && it.direction == UsbConstants.USB_DIR_IN
        }
        val outEp = endpoints.firstOrNull {
            it.type == UsbConstants.USB_ENDPOINT_XFER_BULK && it.direction == UsbConstants.USB_DIR_OUT
        }
        if (inEp == null || outEp == null) {
            fail("the PICOBOOT interface lacks its two bulk endpoints")
            return null
        }
        val conn = usb.openDevice(device) ?: run { fail("Android would not open the board"); return null }
        // Detaching a kernel driver is only ever needed from a class interface a driver can hold; a
        // vendor-specific interface, as PICOBOOT is, has none.
        val detachDriver = picoboot.interfaceClass != UsbConstants.USB_CLASS_VENDOR_SPEC
        if (!conn.claimInterface(picoboot, detachDriver)) {
            conn.close()
            fail("Android would not give DSM the board's PICOBOOT interface")
            return null
        }
        val serial = device.serialNumber
        if (serial == null) {
            conn.releaseInterface(picoboot)
            conn.close()
            fail("the board's bootloader named no serial number")
            return null
        }
        connection = conn
        iface = picoboot
        epIn = inEp
        epOut = outEp
        lastError = ""
        Log.i(TAG, "board in BOOTSEL opened: chip $serial")
        return serial.uppercase()
    }

    /** Send [data] on the bulk OUT endpoint: the bytes sent, or -1. */
    @Synchronized
    fun bulkOut(data: ByteArray): Int {
        val conn = connection ?: run { fail("no board is open"); return -1 }
        val ep = epOut ?: run { fail("no board is open"); return -1 }
        val sent = conn.bulkTransfer(ep, data, data.size, BULK_TIMEOUT_MS)
        if (sent < 0) fail("the bulk OUT transfer failed (stalled or timed out)")
        return sent
    }

    /** One transfer of at most [max] bytes from the bulk IN endpoint, or null. */
    @Synchronized
    fun bulkIn(max: Int): ByteArray? {
        val conn = connection ?: run { fail("no board is open"); return null }
        val ep = epIn ?: run { fail("no board is open"); return null }
        val buffer = ByteArray(max)
        val got = conn.bulkTransfer(ep, buffer, max, BULK_TIMEOUT_MS)
        if (got < 0) {
            fail("the bulk IN transfer failed (stalled or timed out)")
            return null
        }
        return buffer.copyOf(got)
    }

    /**
     * The zero-length packet the bootloader acknowledges an OUT or data-less command with, read as
     * picotool reads it, into a one-byte buffer: 0 when it came, -1 otherwise.
     */
    @Synchronized
    fun ackIn(): Int {
        val conn = connection ?: run { fail("no board is open"); return -1 }
        val ep = epIn ?: run { fail("no board is open"); return -1 }
        val got = conn.bulkTransfer(ep, ByteArray(1), 1, BULK_TIMEOUT_MS)
        return when {
            got == 0 -> 0
            got < 0 -> { fail("no acknowledgement (the bootloader refused or did not answer)"); -1 }
            else -> { fail("$got bytes where the acknowledgement is empty"); -1 }
        }
    }

    /** `PICOBOOT_IF_CMD_STATUS`: the interface's 16-byte status of its last command, or null. */
    @Synchronized
    fun commandStatus(): ByteArray? {
        val conn = connection ?: run { fail("no board is open"); return null }
        val intf = iface ?: run { fail("no board is open"); return null }
        val status = ByteArray(16)
        val got = conn.controlTransfer(
            VENDOR_INTERFACE_IN, PICOBOOT_IF_CMD_STATUS, 0, intf.id, status, status.size, CONTROL_TIMEOUT_MS
        )
        if (got != status.size) {
            fail("the command status read gave $got bytes")
            return null
        }
        return status
    }

    /** The endpoint's GET_STATUS word, whose bit 0 is its halt, or null when it cannot be read. */
    private fun endpointStatus(conn: UsbDeviceConnection, ep: UsbEndpoint): Int? {
        val status = ByteArray(2)
        val got = conn.controlTransfer(
            STANDARD_ENDPOINT_IN, GET_STATUS, 0, ep.address, status, status.size, CONTROL_TIMEOUT_MS
        )
        if (got != status.size) return null
        return (status[0].toInt() and 0xFF) or ((status[1].toInt() and 0xFF) shl 8)
    }

    private const val HALTED = 0x01

    /**
     * The addresses of the PICOBOOT endpoints that report a halt, or null when a status cannot be
     * read. Clearing one is Rust's: through `USBDEVFS_CLEAR_HALT` on [fileDescriptor], as libusb
     * clears a halt, which resets the host's data toggle with the device's. A halt cleared by a
     * plain control request leaves the host's toggle behind, and the next transfer is lost.
     */
    @Synchronized
    fun haltedEndpoints(): IntArray? {
        val conn = connection ?: run { fail("no board is open"); return null }
        val halted = mutableListOf<Int>()
        for (ep in listOfNotNull(epIn, epOut)) {
            val status = endpointStatus(conn, ep)
                ?: run { fail("the status of endpoint ${ep.address} could not be read"); return null }
            if (status and HALTED != 0) halted.add(ep.address)
        }
        return halted.toIntArray()
    }

    /** The open connection's usbfs file descriptor, or -1. */
    @Synchronized
    fun fileDescriptor(): Int = connection?.fileDescriptor ?: run { fail("no board is open"); -1 }

    /** `PICOBOOT_IF_RESET` the interface, as picotool's `picoboot_reset` ends: 0, or -1. */
    @Synchronized
    fun interfaceReset(): Int {
        val conn = connection ?: run { fail("no board is open"); return -1 }
        val intf = iface ?: run { fail("no board is open"); return -1 }
        val done = conn.controlTransfer(VENDOR_INTERFACE_OUT, PICOBOOT_IF_RESET, 0, intf.id, null, 0, CONTROL_TIMEOUT_MS)
        if (done < 0) {
            fail("the PICOBOOT interface would not reset")
            return -1
        }
        return 0
    }

    /** Let the board go: 0. */
    @Synchronized
    fun close(): Int {
        val conn = connection
        val intf = iface
        if (conn != null) {
            if (intf != null) conn.releaseInterface(intf)
            conn.close()
        }
        connection = null
        iface = null
        epIn = null
        epOut = null
        return 0
    }

    /** One file of the production release the app carries, from its assets, or null. */
    fun releaseFile(path: String): ByteArray? {
        val ctx = appContext ?: run { fail("BootselUsb.init(context) was not called"); return null }
        return try {
            ctx.assets.open(path).use { it.readBytes() }
        } catch (absent: java.io.IOException) {
            fail("the app carries no $path: ${absent.message}")
            null
        }
    }
}
