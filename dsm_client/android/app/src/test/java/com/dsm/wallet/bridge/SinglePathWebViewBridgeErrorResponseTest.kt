package com.dsm.wallet.bridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SinglePathWebViewBridgeErrorResponseTest {

    @Test
    fun aFailedDispatchAnswersADecodableErrorWithItsReason() {
        // No bridge instance exists in a unit test: the dispatcher answers ERROR_BRIDGE_NOT_INITIALIZED.
        val response = SinglePathWebViewBridge.handleBinaryRpc("nativeBoundaryIngress", ByteArray(0))
        val (isSuccess, payload) = BridgeEnvelopeCodec.parseEnvelopeResponse(response)
        val err = BridgeEnvelopeCodec.decodeBridgeRpcError(payload)

        assertEquals(false, isSuccess)
        assertNotNull("expected a decodable bridge error", err)
        assertEquals(1, err?.errorCode)
        assertTrue(
            "expected the reason in the message, got: ${err?.message}",
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
