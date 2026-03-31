package com.dsm.wallet.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SinglePathWebViewBridgeStrictRawTest {

    @Test
    fun handleBinaryRpcRawStrictThrowsDecodedBridgeError() {
        val err = try {
            SinglePathWebViewBridge.handleBinaryRpcRawStrict("createGenesisBin", ByteArray(0))
            null
        } catch (e: IllegalStateException) {
            e
        }

        assertNotNull("expected strict raw bridge call to throw", err)
        assertTrue(
            "expected bridge not initialized message, got: ${err?.message}",
            err?.message?.contains("Bridge not initialized") == true
        )
    }

    @Test
    fun decodeBridgeRpcErrorParsesMessageAndCode() {
        val response = BridgeEnvelopeCodec.createErrorResponse(7, "router not ready") { "" }
        val (isSuccess, payload) = BridgeEnvelopeCodec.parseEnvelopeResponse(response)
        val err = BridgeEnvelopeCodec.decodeBridgeRpcError(payload)

        assertEquals(false, isSuccess)
        assertNotNull("expected decoded bridge error", err)
        assertEquals(7, err?.errorCode)
        assertEquals("router not ready", err?.message)
    }
}
