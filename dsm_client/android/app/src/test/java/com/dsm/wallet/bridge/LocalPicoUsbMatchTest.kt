// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.bridge

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Audit 2026-10-15 item 10: the phone opens only the DSM Anchor on USB, by the anchor firmware's
 * own descriptor (crates/dsm-anchor-pico: `UsbVidPid(0x1209, 0xd5a1)`), never any CDC device.
 */
class LocalPicoUsbMatchTest {
    @Test
    fun the_anchor_firmwares_descriptor_is_matched() {
        assertTrue(LocalPicoUsb.isDsmAnchor(0x1209, 0xD5A1))
    }

    @Test
    fun any_other_device_is_not_opened() {
        assertFalse("another pid.codes product", LocalPicoUsb.isDsmAnchor(0x1209, 0x0001))
        assertFalse("a bare RP2350", LocalPicoUsb.isDsmAnchor(0x2E8A, 0xD5A1))
        assertFalse("a bare RP2350 CDC", LocalPicoUsb.isDsmAnchor(0x2E8A, 0x000A))
        assertFalse("an FTDI serial adapter", LocalPicoUsb.isDsmAnchor(0x0403, 0x6001))
    }
}
