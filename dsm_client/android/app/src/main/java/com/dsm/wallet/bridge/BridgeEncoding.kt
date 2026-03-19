package com.dsm.wallet.bridge

internal object BridgeEncoding {

    fun base32CrockfordEncode(bytes: ByteArray): String {
        val alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        val result = StringBuilder()
        var buffer = 0
        var bitsLeft = 0

        for (byte in bytes) {
            buffer = (buffer shl 8) or (byte.toInt() and 0xFF)
            bitsLeft += 8
            while (bitsLeft >= 5) {
                result.append(alphabet[(buffer shr (bitsLeft - 5)) and 0x1F])
                bitsLeft -= 5
            }
        }

        if (bitsLeft > 0) {
            result.append(alphabet[(buffer shl (5 - bitsLeft)) and 0x1F])
        }

        return result.toString()
    }

    fun base32CrockfordDecode(str: String): ByteArray {
        val lookup = IntArray(128) { -1 }
        val alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        alphabet.forEachIndexed { i, c -> lookup[c.code] = i }
        alphabet.lowercase().forEachIndexed { i, c -> lookup[c.code] = i }

        val result = mutableListOf<Byte>()
        var buffer = 0
        var bitsLeft = 0

        for (c in str) {
            val value = lookup.getOrNull(c.code) ?: continue
            if (value < 0) continue

            buffer = (buffer shl 5) or value
            bitsLeft += 5

            if (bitsLeft >= 8) {
                result.add(((buffer shr (bitsLeft - 8)) and 0xFF).toByte())
                bitsLeft -= 8
            }
        }

        return result.toByteArray()
    }
}
