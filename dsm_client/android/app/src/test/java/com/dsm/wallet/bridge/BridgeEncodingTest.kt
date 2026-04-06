package com.dsm.wallet.bridge

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.junit.runners.JUnit4

@RunWith(JUnit4::class)
class BridgeEncodingTest {

    // ── base32CrockfordEncode ──────────────────────────────────────────────

    @Test
    fun encode_emptyByteArray_returnsEmptyString() {
        assertEquals("", BridgeEncoding.base32CrockfordEncode(byteArrayOf()))
    }

    @Test
    fun encode_singleByte_zero() {
        // 0x00 → 00000 000(pad) → "00"
        assertEquals("00", BridgeEncoding.base32CrockfordEncode(byteArrayOf(0)))
    }

    @Test
    fun encode_singleByte_0xFF() {
        // 0xFF = 11111111 → 11111 111(pad 00) → 31,28 → "ZW"
        assertEquals("ZW", BridgeEncoding.base32CrockfordEncode(byteArrayOf(0xFF.toByte())))
    }

    @Test
    fun encode_helloBytes() {
        val input = "Hello".toByteArray(Charsets.US_ASCII)
        val encoded = BridgeEncoding.base32CrockfordEncode(input)
        // Round-trip check: decode must reproduce input
        assertArrayEquals(input, BridgeEncoding.base32CrockfordDecode(encoded))
    }

    @Test
    fun encode_fiveByteAlignedInput() {
        // 5 bytes = 40 bits, divisible by 5 → no padding bits
        val input = byteArrayOf(0x48, 0x65, 0x6C, 0x6C, 0x6F) // "Hello"
        val encoded = BridgeEncoding.base32CrockfordEncode(input)
        assertEquals(8, encoded.length) // 40 bits / 5 = 8 chars
    }

    @Test
    fun encode_usesOnlyCrockfordAlphabet() {
        val crockfordChars = "0123456789ABCDEFGHJKMNPQRSTVWXYZ".toSet()
        val input = ByteArray(256) { it.toByte() }
        val encoded = BridgeEncoding.base32CrockfordEncode(input)
        for (c in encoded) {
            assert(c in crockfordChars) { "Unexpected char '$c' in encoded output" }
        }
    }

    @Test
    fun encode_excludesConfusableLetters() {
        val input = ByteArray(256) { it.toByte() }
        val encoded = BridgeEncoding.base32CrockfordEncode(input)
        // Crockford base32 excludes I, L, O, U
        assert('I' !in encoded)
        assert('L' !in encoded)
        assert('O' !in encoded)
        assert('U' !in encoded)
    }

    // ── base32CrockfordDecode ──────────────────────────────────────────────

    @Test
    fun decode_emptyString_returnsEmptyArray() {
        assertArrayEquals(byteArrayOf(), BridgeEncoding.base32CrockfordDecode(""))
    }

    @Test
    fun decode_caseInsensitive() {
        val upper = BridgeEncoding.base32CrockfordDecode("ABCD")
        val lower = BridgeEncoding.base32CrockfordDecode("abcd")
        assertArrayEquals(upper, lower)
    }

    @Test
    fun decode_skipsInvalidCharacters() {
        // Characters outside the lookup table (e.g. spaces, punctuation) are ignored
        val clean = BridgeEncoding.base32CrockfordDecode("91")
        val withGarbage = BridgeEncoding.base32CrockfordDecode("9 -!1")
        assertArrayEquals(clean, withGarbage)
    }

    @Test
    fun decode_highAsciiCharsIgnored() {
        // Chars with code >= 128 are outside lookup bounds and skipped
        val normal = BridgeEncoding.base32CrockfordDecode("AA")
        val withUnicode = BridgeEncoding.base32CrockfordDecode("A\u00FFA")
        assertArrayEquals(normal, withUnicode)
    }

    // ── Round-trip ─────────────────────────────────────────────────────────

    @Test
    fun roundTrip_allSingleBytes() {
        for (b in 0..255) {
            val input = byteArrayOf(b.toByte())
            val encoded = BridgeEncoding.base32CrockfordEncode(input)
            val decoded = BridgeEncoding.base32CrockfordDecode(encoded)
            assertArrayEquals("Round-trip failed for byte $b", input, decoded)
        }
    }

    @Test
    fun roundTrip_variousLengths() {
        for (len in 0..20) {
            val input = ByteArray(len) { (it * 37 + 13).toByte() }
            val encoded = BridgeEncoding.base32CrockfordEncode(input)
            val decoded = BridgeEncoding.base32CrockfordDecode(encoded)
            assertArrayEquals("Round-trip failed for length $len", input, decoded)
        }
    }

    @Test
    fun roundTrip_32Bytes_typicalDeviceId() {
        val deviceId = ByteArray(32) { (it * 7 + 0xAB).toByte() }
        val encoded = BridgeEncoding.base32CrockfordEncode(deviceId)
        val decoded = BridgeEncoding.base32CrockfordDecode(encoded)
        assertArrayEquals(deviceId, decoded)
    }

    @Test
    fun roundTrip_largePayload() {
        val payload = ByteArray(1024) { (it xor 0x5A).toByte() }
        val decoded = BridgeEncoding.base32CrockfordDecode(
            BridgeEncoding.base32CrockfordEncode(payload)
        )
        assertArrayEquals(payload, decoded)
    }

    // ── Encoding length ───────────────────────────────────────────────────

    @Test
    fun encode_outputLengthIsCorrect() {
        // ceil(n * 8 / 5) characters
        for (n in 0..20) {
            val input = ByteArray(n) { 0x42 }
            val encoded = BridgeEncoding.base32CrockfordEncode(input)
            val expectedLen = if (n == 0) 0 else ((n * 8) + 4) / 5
            assertEquals("Wrong encoded length for $n bytes", expectedLen, encoded.length)
        }
    }
}
