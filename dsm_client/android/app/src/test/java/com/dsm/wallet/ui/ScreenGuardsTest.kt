// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet.ui

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
}
