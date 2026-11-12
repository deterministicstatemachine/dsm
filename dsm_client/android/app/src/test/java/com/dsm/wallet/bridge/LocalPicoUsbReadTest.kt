package com.dsm.wallet.bridge

import com.dsm.wallet.bridge.LocalPicoUsb.InPacket
import com.dsm.wallet.bridge.LocalPicoUsb.ReadOutcome
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * A reply comes off the anchor's bulk-IN endpoint one USB packet at a time: its 4-byte length
 * prefix alone, or with the start of the body in the same packet, then the body. A wait that sees
 * no packet is only a wait, however many come before the reply; a packet that runs past the bytes
 * asked for belongs to the next read; a failure ends the read and says how far it got.
 */
class LocalPicoUsbReadTest {
    /** The packets the endpoint gives, in order; asking past the last one fails the test. */
    private fun packets(vararg each: InPacket): () -> InPacket {
        val queue = ArrayDeque(each.toList())
        return { queue.removeFirst() }
    }

    private fun bytes(vararg values: Int) = InPacket.Bytes(ByteArray(values.size) { values[it].toByte() })

    private fun read(outcome: ReadOutcome): ReadOutcome.Read {
        assertTrue("expected the bytes, got $outcome", outcome is ReadOutcome.Read)
        return outcome as ReadOutcome.Read
    }

    private fun unread(outcome: ReadOutcome): String {
        assertTrue("expected no bytes, got $outcome", outcome is ReadOutcome.Unread)
        return (outcome as ReadOutcome.Unread).why
    }

    @Test
    fun aLengthPrefixAloneAfterTheAnchorsSilenceIsReadWhole() {
        val outcome = LocalPicoUsb.readExactly(
            4,
            ByteArray(0),
            600,
            packets(InPacket.Quiet, InPacket.Quiet, InPacket.Quiet, bytes(0x83, 0x01, 0x00, 0x00)),
        )
        val got = read(outcome)
        assertArrayEquals(byteArrayOf(0x83.toByte(), 0x01, 0x00, 0x00), got.bytes)
        assertEquals(0, got.carried.size)
    }

    @Test
    fun aPacketThatRunsPastTheLengthLeavesTheBodysStartToTheNextRead() {
        val packet = ByteArray(64) { it.toByte() }
        val prefix = read(LocalPicoUsb.readExactly(4, ByteArray(0), 600, packets(InPacket.Bytes(packet))))
        assertArrayEquals(packet.copyOfRange(0, 4), prefix.bytes)
        assertArrayEquals(packet.copyOfRange(4, 64), prefix.carried)

        // The body's first 60 bytes are already in hand; only the rest comes off the endpoint.
        val tail = ByteArray(40) { (100 + it).toByte() }
        val body = read(LocalPicoUsb.readExactly(100, prefix.carried, 600, packets(InPacket.Quiet, InPacket.Bytes(tail))))
        assertArrayEquals(packet.copyOfRange(4, 64) + tail, body.bytes)
        assertEquals(0, body.carried.size)
    }

    @Test
    fun aReadServedWhollyFromCarriedBytesAsksTheEndpointForNothing() {
        val carried = ByteArray(10) { it.toByte() }
        val got = read(LocalPicoUsb.readExactly(4, carried, 600, packets()))
        assertArrayEquals(carried.copyOfRange(0, 4), got.bytes)
        assertArrayEquals(carried.copyOfRange(4, 10), got.carried)
    }

    @Test
    fun quietWaitsBetweenPacketsLoseNothing() {
        val got = read(
            LocalPicoUsb.readExactly(
                6,
                ByteArray(0),
                2,
                packets(InPacket.Quiet, InPacket.Quiet, bytes(1, 2), InPacket.Quiet, InPacket.Quiet, bytes(3, 4, 5, 6)),
            ),
        )
        assertArrayEquals(byteArrayOf(1, 2, 3, 4, 5, 6), got.bytes)
    }

    @Test
    fun moreQuietWaitsInARowThanTheBoundEndTheRead() {
        val why = unread(LocalPicoUsb.readExactly(4, ByteArray(0), 3, packets(*Array(4) { InPacket.Quiet })))
        assertTrue(why, why.contains("no packet in 3 waits (0/4)"))
    }

    @Test
    fun aFailureEndsTheReadAndSaysHowFarItGot() {
        val why = unread(
            LocalPicoUsb.readExactly(4, ByteArray(0), 600, packets(bytes(9, 9), InPacket.Failed("the bulk-IN read failed"))),
        )
        assertTrue(why, why.contains("the bulk-IN read failed (2/4)"))
    }
}
