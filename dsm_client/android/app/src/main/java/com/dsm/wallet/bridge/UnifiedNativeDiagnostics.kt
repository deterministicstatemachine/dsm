package com.dsm.wallet.bridge

internal object UnifiedNativeDiagnostics {

    /**
     * Calls appRouterInvokeFramed and propagates exceptions to callers.
     * Rust returns Envelope v3 (0x03 framed) for both success and error; no status-byte
     * framing is applied. A null return indicates a JNI-level panic caught by jni_catch_unwind.
     * Callers use try/catch for error handling.
     */
    fun appRouterInvokeFramedSafe(framedRequest: ByteArray): ByteArray {
        val result = Unified.appRouterInvokeFramed(framedRequest)
            ?: throw IllegalStateException("native panic: null return from appRouterInvokeFramed")
        return result
    }

    /**
     * Calls appRouterQueryFramed and propagates exceptions to callers.
     * Rust returns Envelope v3 (0x03 framed) for both success and error; no status-byte
     * framing is applied. A null return indicates a JNI-level panic.
     * Callers use try/catch for error handling.
     */
    fun appRouterQueryFramedSafe(framedRequest: ByteArray): ByteArray {
        val result = Unified.appRouterQueryFramed(framedRequest)
            ?: throw IllegalStateException("native panic: null return from appRouterQueryFramed")
        return result
    }

    /**
     * Binary self-test report. Format per entry:
     *   [u16BE nameLen][name_utf8][ok_byte 0/1][u16BE detailLen][detail_utf8]
     * Prefixed by [u32BE entryCount].
     */
    fun runNativeBridgeSelfTest(): ByteArray {
        data class R(val name: String, val ok: Boolean, val detail: String = "")
        val results = mutableListOf<R>()
        fun add(name: String, ok: Boolean, detail: String = "") { results += R(name, ok, detail) }
        try {
            try {
                val st = Unified.getTransportHeadersV3Status()
                add("getTransportHeadersV3Status", st.toInt() >= 0, "status=$st")
            } catch (t: Throwable) { add("getTransportHeadersV3Status", false, t.message ?: "err") }
            try { Unified.setManualAcceptEnabled(false); add("setManualAcceptEnabled", true) } catch (t: Throwable) { add("setManualAcceptEnabled", false, t.message ?: "err") }
            try {
                val resp = Unified.processEnvelopeV3(ByteArray(0))
                add("processEnvelopeV3(empty)", true, "bytes=${resp.size}")
            } catch (t: Throwable) { add("processEnvelopeV3(empty)", false, t.message ?: "err") }
            try {
                val arr = Unified.chunkEnvelopeForBle(ByteArray(0), 1)
                add("chunkEnvelopeForBle(empty)", true, "chunks=${arr.size}")
            } catch (t: Throwable) { add("chunkEnvelopeForBle(empty)", false, t.message ?: "err") }
            try {
                val proc = Unified.processBleChunk("SELFTEST", ByteArray(0))
                add("processBleChunk(empty)", true, "bytes=${proc.size}")
            } catch (t: Throwable) { add("processBleChunk(empty)", false, t.message ?: "err") }
            try {
                val hdr = Unified.getTransportHeadersV3()
                add("getTransportHeadersV3", true, "bytes=${hdr.size}")
            } catch (t: Throwable) { add("getTransportHeadersV3", false, t.message ?: "err") }
        } catch (_: Throwable) { /* global guard */ }
        // Binary encoding: [u32BE count] then per entry [u16BE nameLen][name][ok_byte][u16BE detailLen][detail]
        val buf = java.io.ByteArrayOutputStream()
        val count = results.size
        buf.write(byteArrayOf(
            (count shr 24).toByte(), (count shr 16).toByte(),
            (count shr 8).toByte(), count.toByte()
        ))
        for (r in results) {
            val nameBytes = r.name.toByteArray(Charsets.UTF_8)
            buf.write(byteArrayOf((nameBytes.size shr 8).toByte(), nameBytes.size.toByte()))
            buf.write(nameBytes)
            buf.write(if (r.ok) 1 else 0)
            val detailBytes = r.detail.toByteArray(Charsets.UTF_8)
            buf.write(byteArrayOf((detailBytes.size shr 8).toByte(), detailBytes.size.toByte()))
            buf.write(detailBytes)
        }
        return buf.toByteArray()
    }
}
