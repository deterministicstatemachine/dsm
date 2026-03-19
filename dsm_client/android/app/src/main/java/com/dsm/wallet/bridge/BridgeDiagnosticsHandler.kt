package com.dsm.wallet.bridge

internal object BridgeDiagnosticsHandler {

    private fun encodeVarint32(valueIn: Int): ByteArray {
        var v = valueIn
        val baos = java.io.ByteArrayOutputStream()
        while (true) {
            if (v and 0x7F.inv() == 0) {
                baos.write(v)
                break
            } else {
                baos.write((v and 0x7F) or 0x80)
                v = v ushr 7
            }
        }
        return baos.toByteArray()
    }

    private fun writeTag(out: java.io.ByteArrayOutputStream, fieldNumber: Int, wireType: Int) {
        val key = (fieldNumber shl 3) or wireType
        out.write(encodeVarint32(key))
    }

    private fun writeStringField(out: java.io.ByteArrayOutputStream, fieldNumber: Int, value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        writeTag(out, fieldNumber, 2)
        out.write(encodeVarint32(bytes.size))
        out.write(bytes)
    }

    private fun writeInt32Field(out: java.io.ByteArrayOutputStream, fieldNumber: Int, value: Int) {
        writeTag(out, fieldNumber, 0)
        out.write(encodeVarint32(value))
    }

    private fun buildArchitectureInfoProto(
        status: String,
        deviceArch: String,
        supportedAbis: String,
        message: String,
        recommendation: String
    ): ByteArray {
        val out = java.io.ByteArrayOutputStream()
        writeStringField(out, 1, status)
        writeStringField(out, 2, deviceArch)
        writeStringField(out, 3, supportedAbis)
        writeStringField(out, 4, message)
        writeStringField(out, 5, recommendation)
        return out.toByteArray()
    }

    fun getArchitectureInfo(escapeForString: (String) -> String): ByteArray {
        return try {
            val compat = com.dsm.wallet.diagnostics.ArchitectureChecker.checkCompatibility()
            buildArchitectureInfoProto(
                compat.status.name,
                escapeForString(compat.deviceArch),
                escapeForString(compat.supportedAbis.joinToString(", ")),
                escapeForString(compat.message),
                escapeForString(compat.recommendation)
            )
        } catch (_: Exception) {
            buildArchitectureInfoProto(
                "UNKNOWN",
                "unavailable",
                "",
                "Architecture check error",
                ""
            )
        }
    }
}
