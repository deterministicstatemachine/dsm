package com.dsm.wallet.bridge

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * A frame goes to the anchor in bulk requests no longer than Android's USB host library takes in
 * one: the 49,896-byte OP_AUTHORIZE frame in four, a 243-byte STATUS in one. A request that takes
 * less than asked ends the write, and the bytes written in all say how far it got.
 */
class LocalPicoUsbWriteTest {
    private fun requestsOf(size: Int): List<Pair<Int, Int>> {
        val frame = ByteArray(size)
        val requests = mutableListOf<Pair<Int, Int>>()
        val wrote = LocalPicoUsb.writeInRequests(frame) { offset, length ->
            requests.add(offset to length)
            length
        }
        assertEquals(size, wrote)
        return requests
    }

    @Test
    fun aShortFrameGoesInOneRequest() {
        assertEquals(listOf(0 to 243), requestsOf(243))
    }

    @Test
    fun theOwnersAuthorizationGoesInFourRequestsNoneOver16KiB() {
        val requests = requestsOf(49_896)
        assertEquals(
            listOf(0 to 16_384, 16_384 to 16_384, 32_768 to 16_384, 49_152 to 744),
            requests,
        )
        assertEquals(16_384, LocalPicoUsb.MAX_BULK_REQUEST_BYTES)
    }

    @Test
    fun aRequestThatTakesLessEndsTheWriteAndTheTotalSaysHowFarItGot() {
        val frame = ByteArray(40_000)
        var asked = 0
        val wrote = LocalPicoUsb.writeInRequests(frame) { _, length ->
            asked += 1
            if (asked == 2) 1_000 else length
        }
        assertEquals(16_384 + 1_000, wrote)
        assertEquals(2, asked)
    }

    @Test
    fun aFailedRequestEndsTheWriteWithWhatWentBefore() {
        val frame = ByteArray(20_000)
        var asked = 0
        val wrote = LocalPicoUsb.writeInRequests(frame) { _, length ->
            asked += 1
            if (asked == 2) -1 else length
        }
        assertEquals(16_384, wrote)
    }
}
