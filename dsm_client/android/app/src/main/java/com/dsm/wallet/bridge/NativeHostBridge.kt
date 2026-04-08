package com.dsm.wallet.bridge

import android.Manifest
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.util.Log
import androidx.core.content.ContextCompat
import com.google.protobuf.ByteString
import com.google.protobuf.InvalidProtocolBufferException
import com.dsm.wallet.bridge.ble.BleCoordinator
import com.dsm.wallet.ui.MainActivity
import dsm.types.proto.BiometricAuthorizePayload
import dsm.types.proto.BleTransportSendChunksPayload
import dsm.types.proto.BleTransportSendChunksResult
import dsm.types.proto.DeviceBindingCapturePayload
import dsm.types.proto.HostPermissionsRequestPayload
import dsm.types.proto.HostPermissionsResult
import dsm.types.proto.NativeHostAck
import dsm.types.proto.NativeHostCapabilities
import dsm.types.proto.NativeHostRequest
import dsm.types.proto.NativeHostRequestKind
import dsm.types.proto.NativeHostResponse
import dsm.types.proto.NfcTagReadPayload
import dsm.types.proto.NfcTagReadResult
import dsm.types.proto.NfcTagWritePayload
import dsm.types.proto.NfcTagWriteResult
import java.util.concurrent.atomic.AtomicBoolean

internal object NativeHostBridge {
    private const val TAG = "NativeHostBridge"

    fun hostRequest(
        context: Context,
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        keyDbrwSalt: String,
        requestBytes: ByteArray,
    ): ByteArray {
        val request = try {
            NativeHostRequest.parseFrom(requestBytes)
        } catch (e: InvalidProtocolBufferException) {
            return errorResponse(400, "nativeHostRequest: invalid protobuf payload: ${e.message}").toByteArray()
        }

        val response = try {
            handleRequest(
                context = context,
                prefs = prefs,
                sdkContextInitialized = sdkContextInitialized,
                logTag = logTag,
                keyDeviceId = keyDeviceId,
                keyGenesisHash = keyGenesisHash,
                keyGenesisEnvelope = keyGenesisEnvelope,
                keyDbrwSalt = keyDbrwSalt,
                request = request,
            )
        } catch (t: Throwable) {
            Log.e(TAG, "hostRequest failed for ${request.kind}", t)
            errorResponse(500, t.message ?: "native host request failed")
        }

        return response.toByteArray()
    }

    private fun handleRequest(
        context: Context,
        prefs: SharedPreferences,
        sdkContextInitialized: AtomicBoolean,
        logTag: String,
        keyDeviceId: String,
        keyGenesisHash: String,
        keyGenesisEnvelope: String,
        keyDbrwSalt: String,
        request: NativeHostRequest,
    ): NativeHostResponse {
        return when (request.kind) {
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_CAPABILITIES_GET -> {
                NativeHostResponse.newBuilder()
                    .setCapabilities(
                        NativeHostCapabilities.newBuilder()
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_CAPABILITIES_GET)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_QR_START_SCAN)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_QR_STOP_SCAN)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_BLE_SCAN_START)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_BLE_SCAN_STOP)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_BLE_ADVERTISE_START)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_BLE_ADVERTISE_STOP)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_NFC_READER_START)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_NFC_READER_STOP)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_PERMISSIONS_REQUEST)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_DEVICE_BINDING_CAPTURE)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_BIOMETRIC_AUTHORIZE)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_NFC_TAG_READ_PAYLOAD)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_NFC_TAG_WRITE_PAYLOAD)
                            .addSupportedRequests(NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_BLE_TRANSPORT_SEND_CHUNKS)
                            .build()
                    )
                    .build()
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_QR_START_SCAN -> {
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "QR scanner unavailable: no active activity")
                act.runOnUiThread {
                    act.launchNativeQrScanner { qrText: String? ->
                        act.dispatchQrScanResult(qrText)
                    }
                    act.publishCurrentSessionState("host_control.qr.start_scan")
                }
                okAck()
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_QR_STOP_SCAN -> {
                MainActivity.getActiveInstance()?.runOnUiThread {
                    MainActivity.getActiveInstance()?.publishCurrentSessionState("host_control.qr.stop_scan")
                }
                okAck()
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_BLE_SCAN_START -> {
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "BLE unavailable: no active activity")
                val ctx = act.baseContext
                val ok = BleCoordinator.getInstance(ctx).startScanning()
                Log.i(logTag, "host_control.ble.scan.start: result=$ok")
                act.runOnUiThread { act.publishCurrentSessionState("host_control.ble.scan.start") }
                okAck(ok)
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_BLE_SCAN_STOP -> {
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "BLE unavailable: no active activity")
                BleCoordinator.getInstance(act.baseContext).stopScanning()
                Log.i(logTag, "host_control.ble.scan.stop")
                act.runOnUiThread { act.publishCurrentSessionState("host_control.ble.scan.stop") }
                okAck()
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_BLE_ADVERTISE_START -> {
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "BLE unavailable: no active activity")
                val ok = BleCoordinator.getInstance(act.baseContext).startAdvertising()
                if (ok) {
                    act.setBleAdvertisingDesired(true)
                }
                Log.i(logTag, "host_control.ble.advertise.start: result=$ok")
                act.runOnUiThread { act.publishCurrentSessionState("host_control.ble.advertise.start") }
                okAck(ok)
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_BLE_ADVERTISE_STOP -> {
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "BLE unavailable: no active activity")
                BleCoordinator.getInstance(act.baseContext).stopAdvertising()
                act.setBleAdvertisingDesired(false)
                Log.i(logTag, "host_control.ble.advertise.stop")
                act.runOnUiThread { act.publishCurrentSessionState("host_control.ble.advertise.stop") }
                okAck()
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_NFC_READER_START -> {
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "NFC unavailable: no active activity")
                act.startNfcReader()
                okBytes(
                    NfcTagReadResult.newBuilder()
                        .setReaderStarted(true)
                        .build()
                        .toByteArray()
                )
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_NFC_READER_STOP -> {
                MainActivity.getActiveInstance()?.stopNfcReader()
                okAck()
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_HOST_CONTROL_PERMISSIONS_REQUEST -> {
                val payload = try {
                    HostPermissionsRequestPayload.parseFrom(request.payload)
                } catch (e: InvalidProtocolBufferException) {
                    return errorResponse(400, "permissions.request: invalid payload: ${e.message}")
                }
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "permissions.request: no active activity")
                val requested = payload.permissionsList
                val grantedNow = requested.filter { permission ->
                    ContextCompat.checkSelfPermission(act, permission) == PackageManager.PERMISSION_GRANTED
                }
                val wantsBluetooth = requested.any { it == Manifest.permission.BLUETOOTH_SCAN || it == Manifest.permission.BLUETOOTH_CONNECT || it == Manifest.permission.BLUETOOTH_ADVERTISE }
                val wantsCamera = requested.any { it == Manifest.permission.CAMERA }
                act.runOnUiThread {
                    if (wantsBluetooth) {
                        act.requestBlePermissionsFromUi()
                    }
                    if (wantsCamera) {
                        act.requestNamedPermissionsFromUi(arrayOf(Manifest.permission.CAMERA))
                    }
                }
                okBytes(
                    HostPermissionsResult.newBuilder()
                        .addAllGrantedPermissions(grantedNow)
                        .setAllGranted(grantedNow.size == requested.size)
                        .build()
                        .toByteArray()
                )
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_DEVICE_BINDING_CAPTURE -> {
                val payload = try {
                    DeviceBindingCapturePayload.parseFrom(request.payload)
                } catch (e: InvalidProtocolBufferException) {
                    return errorResponse(400, "device_binding.capture: invalid payload: ${e.message}")
                }
                val result = BridgeIdentityHandler.captureDeviceBindingForGenesisEnvelope(
                    context = context,
                    prefs = prefs,
                    sdkContextInitialized = sdkContextInitialized,
                    logTag = logTag,
                    keyDeviceId = keyDeviceId,
                    keyGenesisHash = keyGenesisHash,
                    keyGenesisEnvelope = keyGenesisEnvelope,
                    keyDbrwSalt = keyDbrwSalt,
                    genesisEnvelopeBytes = payload.genesisEnvelope.toByteArray(),
                )
                okBytes(result.toByteArray())
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_BIOMETRIC_AUTHORIZE -> {
                val payload = try {
                    BiometricAuthorizePayload.parseFrom(request.payload)
                } catch (e: InvalidProtocolBufferException) {
                    return errorResponse(400, "biometric.authorize: invalid payload: ${e.message}")
                }
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "biometric.authorize: no active activity")
                act.runOnUiThread {
                    act.showBiometricPrompt(
                        payload.promptTitle,
                        payload.promptSubtitle,
                        payload.negativeText,
                    )
                }
                okAck()
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_NFC_TAG_READ_PAYLOAD -> {
                try {
                    NfcTagReadPayload.parseFrom(request.payload)
                } catch (e: InvalidProtocolBufferException) {
                    return errorResponse(400, "nfc.tag.read_payload: invalid payload: ${e.message}")
                }
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "nfc.tag.read_payload: no active activity")
                act.startNfcReader()
                okBytes(
                    NfcTagReadResult.newBuilder()
                        .setReaderStarted(true)
                        .build()
                        .toByteArray()
                )
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_NFC_TAG_WRITE_PAYLOAD -> {
                try {
                    NfcTagWritePayload.parseFrom(request.payload)
                } catch (e: InvalidProtocolBufferException) {
                    return errorResponse(400, "nfc.tag.write_payload: invalid payload: ${e.message}")
                }
                val act = MainActivity.getActiveInstance()
                    ?: return errorResponse(503, "nfc.tag.write_payload: no active activity")
                act.runOnUiThread {
                    val intent = Intent(act, com.dsm.wallet.recovery.NfcWriteActivity::class.java)
                    act.startActivity(intent)
                }
                okBytes(
                    NfcTagWriteResult.newBuilder()
                        .setLaunched(true)
                        .build()
                        .toByteArray()
                )
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_BLE_TRANSPORT_SEND_CHUNKS -> {
                val payload = try {
                    BleTransportSendChunksPayload.parseFrom(request.payload)
                } catch (e: InvalidProtocolBufferException) {
                    return errorResponse(400, "ble.transport.send_chunks: invalid payload: ${e.message}")
                }
                val responseEnvelope = Unified.bilateralOfflineSendSafe(
                    payload.bleAddress,
                    payload.envelopeBytes.toByteArray(),
                )
                okBytes(
                    BleTransportSendChunksResult.newBuilder()
                        .setResponseEnvelope(ByteString.copyFrom(responseEnvelope))
                        .build()
                        .toByteArray()
                )
            }

            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_SECURE_HARDWARE_GENERATE_KEY,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_SECURE_HARDWARE_SIGN,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_BLE_TRANSPORT_OPEN,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_PLATFORM_PRIMITIVE_BLE_TRANSPORT_CLOSE,
            NativeHostRequestKind.UNRECOGNIZED,
            NativeHostRequestKind.NATIVE_HOST_REQUEST_KIND_UNSPECIFIED -> {
                errorResponse(501, "unsupported native host request kind: ${request.kind}")
            }
        }
    }

    private fun okAck(success: Boolean = true): NativeHostResponse {
        return okBytes(
            NativeHostAck.newBuilder()
                .setSuccess(success)
                .build()
                .toByteArray()
        )
    }

    private fun okBytes(bytes: ByteArray): NativeHostResponse {
        return NativeHostResponse.newBuilder()
            .setOkBytes(ByteString.copyFrom(bytes))
            .build()
    }

    private fun errorResponse(code: Int, message: String): NativeHostResponse {
        return NativeHostResponse.newBuilder()
            .setError(
                dsm.types.proto.Error.newBuilder()
                    .setCode(code)
                    .setMessage(message)
                    .setIsRecoverable(true)
                    .build()
            )
            .build()
    }
}
