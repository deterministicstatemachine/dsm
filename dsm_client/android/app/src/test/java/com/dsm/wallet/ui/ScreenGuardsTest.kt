// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.ui

import android.view.MotionEvent
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Audit 2026-10-15 items 1 and 3: the page's `setScreenGuards` byte names which guards the window
 * holds, and a byte naming anything else is refused rather than read as some guard.
 */
class ScreenGuardsTest {
    @Test
    fun each_bit_is_its_guard() {
        val none = ScreenGuards.parse(byteArrayOf(0))
        assertFalse(none.secret)
        assertFalse(none.confirm)

        val secret = ScreenGuards.parse(byteArrayOf(1))
        assertTrue(secret.secret)
        assertFalse(secret.confirm)

        val confirm = ScreenGuards.parse(byteArrayOf(2))
        assertFalse(confirm.secret)
        assertTrue(confirm.confirm)

        val both = ScreenGuards.parse(byteArrayOf(3))
        assertTrue(both.secret)
        assertTrue(both.confirm)
        assertEquals(3, both.bits)
    }

    @Test
    fun anything_but_one_byte_of_known_bits_is_refused() {
        listOf(ByteArray(0), byteArrayOf(1, 0), byteArrayOf(4), byteArrayOf(0xFF.toByte())).forEach { bytes ->
            assertThrows(IllegalArgumentException::class.java) { ScreenGuards.parse(bytes) }
        }
    }

    /**
     * SA-108: a touch through an overlay is always dropped; one that came while the window was
     * partly covered is dropped while any guard is held, and taken when none is.
     */
    @Test
    fun a_partly_covered_window_takes_no_touch_while_a_guard_is_held() {
        val obscured = MotionEvent.FLAG_WINDOW_IS_OBSCURED
        val partly = MotionEvent.FLAG_WINDOW_IS_PARTIALLY_OBSCURED
        listOf(0, 1, 2, 3).map { ScreenGuards.parse(byteArrayOf(it.toByte())) }.forEach { guards ->
            assertTrue(guards.dropsTouch(obscured))
            assertFalse(guards.dropsTouch(0))
            assertEquals(guards.bits != 0, guards.dropsTouch(partly))
        }
    }
}
