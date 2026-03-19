package com.dsm.wallet.bridge

import android.util.Log

internal object BridgePayloadValidator {

    private const val TAG = "SinglePathWebViewBridge"

    fun validate(method: String, payload: ByteArray): Boolean {
        return when (method) {
            "hasNativeQrScanner", "getDeviceIdBin", "getGenesisHashBin", "getSigningPublicKeyBin",
            "startPairingAll", "stopPairingAll",
            "requestBlePermissions" -> {
                payload.isEmpty()
            }
            "getPreference" -> {
                val parsed = BridgeEnvelopeCodec.decodePreferencePayload(payload)
                parsed?.key?.isNotBlank() == true
            }
            "setPreference" -> {
                val parsed = BridgeEnvelopeCodec.decodePreferencePayload(payload)
                parsed?.key?.isNotBlank() == true
            }
            "appRouterInvoke", "appRouterQuery" -> {
                val parsed = BridgeEnvelopeCodec.decodeAppRouterPayload(payload)
                parsed?.methodName?.isNotBlank() == true
            }
            "resolveBleAddressForDeviceId" -> payload.size == 32
            "createGenesisBin" -> payload.isNotEmpty()
            "setBleIdentityForAdvertising" -> payload.isNotEmpty()
            "rejectBilateralByCommitment" -> {
                BridgeEnvelopeCodec.decodeBilateralPayload(payload) != null
            }
            "getTransportHeadersV3Bin" -> payload.isEmpty()
            else -> {
                Log.w(TAG, "validateBridgePayload: unknown method '$method' with ${payload.size} bytes")
                true
            }
        }
    }
}
