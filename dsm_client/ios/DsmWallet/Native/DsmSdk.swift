// SPDX-License-Identifier: MIT OR Apache-2.0

import DsmSdk
import Foundation

/// The Rust SDK, as Swift calls it: every `dsm_ffi_*` function of
/// `include/dsm_sdk.h` behind a Swift signature, bytes in and out as `Data`.
/// Nothing here interprets a byte; the shapes are Rust's and the page's.
///
/// A function whose Rust twin answers nothing-or-why answers `String?` here:
/// `nil` when it did its work, the reason when it did not. A function that
/// answers an envelope answers its bytes, which may be an error envelope
/// (`errorCode(of:)`).
enum DsmSdk {
    /// What a `DsmBytes` carried, copied out; the Rust buffer is freed here.
    static func take(_ bytes: DsmBytes) -> Data {
        defer { dsm_bytes_free(bytes) }
        guard let ptr = bytes.ptr, bytes.len > 0 else { return Data() }
        return Data(bytes: ptr, count: bytes.len)
    }

    /// A void-twin's answer: `nil` for no bytes, else the UTF-8 reason.
    static func reason(_ bytes: DsmBytes) -> String? {
        let data = take(bytes)
        if data.isEmpty { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// Run `body` on the bytes of `data`; an empty `Data` passes a null pointer, which Rust reads as no bytes.
    private static func withBytes<T>(_ data: Data, _ body: (UnsafePointer<UInt8>?, Int) -> T) -> T {
        data.withUnsafeBytes { raw in
            body(raw.baseAddress?.assumingMemoryBound(to: UInt8.self), raw.count)
        }
    }

    // MARK: Startup and ingress

    static func startup(_ request: Data) -> Data {
        take(withBytes(request) { dsm_ffi_startup($0, $1) })
    }

    static func ingress(_ request: Data) -> Data {
        take(withBytes(request) { dsm_ffi_ingress($0, $1) })
    }

    static func initStorageBaseDir(_ path: String) -> String? {
        reason(dsm_ffi_init_storage_base_dir(path))
    }

    static func initDsmSdk(configPath: String) -> String? {
        reason(dsm_ffi_init_dsm_sdk(configPath))
    }

    static func initSdk(baseDir: String) -> String? {
        reason(dsm_ffi_init_sdk(baseDir))
    }

    /// 0 no identity, 1 identity but the runtime is not ready, 3 ready.
    static func transportHeadersStatus() -> Int32 {
        dsm_ffi_transport_headers_status()
    }

    static func transportHeaders() -> Data {
        take(dsm_ffi_transport_headers())
    }

    // MARK: Identity

    static func deviceId() -> Data {
        take(dsm_ffi_device_id())
    }

    static func genesisHash() -> Data {
        take(dsm_ffi_genesis_hash())
    }

    /// Whether Rust holds a 32-byte identity for this device.
    static func hasIdentity() -> Bool {
        deviceId().count == 32
    }

    static func restoreIdentityContext(deviceId: Data, genesisHash: Data) -> String? {
        guard deviceId.count == 32, genesisHash.count == 32 else {
            return "the persisted identity is \(deviceId.count) and \(genesisHash.count) bytes, not 32 and 32"
        }
        return withBytes(deviceId) { device, _ in
            withBytes(genesisHash) { genesis, _ in
                reason(dsm_ffi_restore_identity_context(device, genesis))
            }
        }
    }

    // MARK: Envelopes

    /// The code of a framed or bare Error envelope; 0 for anything else.
    static func errorCode(of envelope: Data) -> UInt32 {
        withBytes(envelope) { dsm_ffi_error_code_of($0, $1) }
    }

    static func processEnvelopeV3(_ envelope: Data) -> Data {
        take(withBytes(envelope) { dsm_ffi_process_envelope_v3($0, $1) })
    }

    static func balancesStrict() -> Data {
        take(dsm_ffi_balances_strict())
    }

    // MARK: Lifecycle and routing state

    /// Rust's answer on backgrounding: whether it still has work the host
    /// would be killing (it is informational on iOS, which has no service to keep).
    static func onAppBackgrounded() -> Int32 {
        dsm_ffi_on_app_backgrounded()
    }

    static func ensureAppRouterInstalled() -> Int32 {
        dsm_ffi_ensure_app_router_installed()
    }

    static func appRouterStatus() -> Int32 {
        dsm_ffi_app_router_status()
    }

    // MARK: Session state

    static func sessionSnapshot() -> Data {
        take(dsm_ffi_session_snapshot())
    }

    static func updateSessionHardwareFacts(_ facts: DsmHardwareFacts) -> Data {
        take(dsm_ffi_update_session_hardware_facts(facts))
    }

    static func setSessionFatalError(_ message: String) -> Data {
        take(dsm_ffi_set_session_fatal_error(message))
    }

    static func clearSessionFatalError() -> Data {
        take(dsm_ffi_clear_session_fatal_error())
    }

    // MARK: The bridge's wire shapes (codec)

    /// The method of a `BridgeRpcRequest`, or `nil` when Rust refuses the request.
    static func bridgeRequestMethod(_ request: Data) -> String? {
        let method = take(withBytes(request) { dsm_ffi_bridge_request_method($0, $1) })
        if method.isEmpty { return nil }
        return String(decoding: method, as: UTF8.self)
    }

    /// Why a `BridgeRpcRequest` is refused, or `nil` when it is valid.
    static func bridgeRequestRefusal(_ request: Data) -> String? {
        reason(withBytes(request) { dsm_ffi_bridge_request_refusal($0, $1) })
    }

    static func bridgeRequestPayload(_ request: Data) -> Data {
        take(withBytes(request) { dsm_ffi_bridge_request_payload($0, $1) })
    }

    static func bridgeSuccess(_ data: Data) -> Data {
        take(withBytes(data) { dsm_ffi_bridge_success($0, $1) })
    }

    static func bridgeError(code: UInt32, message: String) -> Data {
        take(dsm_ffi_bridge_error(code, message))
    }

    static func qrScanResultEvent(text: String) -> Data {
        take(dsm_ffi_qr_scan_result_event(text))
    }

    /// The picked contact's event; every field `nil` for "none picked".
    static func phoneContactPickedEvent(displayName: String?, email: String?, phone: String?, lookupKey: String?) -> Data {
        take(dsm_ffi_phone_contact_picked_event(displayName, email, phone, lookupKey))
    }

    static func nativeHostRequestKind(_ request: Data) -> Int32 {
        withBytes(request) { dsm_ffi_native_host_request_kind($0, $1) }
    }

    /// The response to a host request: code 0 acknowledges, any other refuses with `message`.
    static func nativeHostResponse(code: UInt32, message: String?) -> Data {
        take(dsm_ffi_native_host_response(code, message))
    }

    static func preferenceKey(_ payload: Data) -> String? {
        let key = take(withBytes(payload) { dsm_ffi_preference_key($0, $1) })
        if key.isEmpty { return nil }
        return String(decoding: key, as: UTF8.self)
    }

    static func preferenceHasValue(_ payload: Data) -> Bool {
        withBytes(payload) { dsm_ffi_preference_has_value($0, $1) } != 0
    }

    static func preferenceValue(_ payload: Data) -> String {
        String(decoding: take(withBytes(payload) { dsm_ffi_preference_value($0, $1) }), as: UTF8.self)
    }

    /// The 32-byte commitment of a `BilateralPayload`, or `nil`.
    static func bilateralCommitment(_ payload: Data) -> Data? {
        let commitment = take(withBytes(payload) { dsm_ffi_bilateral_commitment($0, $1) })
        return commitment.count == 32 ? commitment : nil
    }

    static func bilateralReason(_ payload: Data) -> String {
        String(decoding: take(withBytes(payload) { dsm_ffi_bilateral_reason($0, $1) }), as: UTF8.self)
    }

    /// The identity a `GenesisCreated` envelope installs: (device id, genesis hash), or `nil`.
    static func genesisCreatedIdentity(_ envelope: Data) -> (deviceId: Data, genesisHash: Data)? {
        let identity = take(withBytes(envelope) { dsm_ffi_genesis_created_identity($0, $1) })
        guard identity.count == 64 else { return nil }
        return (identity.prefix(32), identity.suffix(32))
    }

    static func resultPackBody(_ pack: Data) -> Data {
        take(withBytes(pack) { dsm_ffi_result_pack_body($0, $1) })
    }

    static func argPack(body: Data) -> Data {
        take(withBytes(body) { dsm_ffi_arg_pack($0, $1) })
    }

    static func routerInvokeRequest(method: String, args: Data) -> Data {
        take(withBytes(args) { dsm_ffi_router_invoke_request(method, $0, $1) })
    }

    static func routerQueryRequest(method: String, args: Data) -> Data {
        take(withBytes(args) { dsm_ffi_router_query_request(method, $0, $1) })
    }

    static func ingressOkBytes(_ response: Data) -> Data {
        take(withBytes(response) { dsm_ffi_ingress_ok_bytes($0, $1) })
    }

    /// Why an `IngressResponse` is not an answer, or `nil` when it is ok.
    static func ingressErrorMessage(_ response: Data) -> String? {
        reason(withBytes(response) { dsm_ffi_ingress_error_message($0, $1) })
    }

    /// Why a `StartupResponse` is not an answer, or `nil` when it is ok.
    static func startupErrorMessage(_ response: Data) -> String? {
        reason(withBytes(response) { dsm_ffi_startup_error_message($0, $1) })
    }

    /// The diagnostics screen's picture of this device, framed by Rust.
    static func architectureInfo(status: String, deviceArch: String, supportedAbis: String, message: String, recommendation: String) -> Data {
        take(dsm_ffi_architecture_info(status, deviceArch, supportedAbis, message, recommendation))
    }

    // MARK: The radio (DSM Amendment A27)

    /// What a radio event came to: records to write back on the link, or why
    /// the bytes were refused (the link then closes).
    enum RadioAnswer {
        case reply([Data])
        case refused(String)
    }

    private static func radioAnswer(_ answer: DsmRadioAnswer) -> RadioAnswer {
        let refusal = reason(answer.refusal)
        let framed = take(answer.reply)
        if let refusal { return .refused(refusal) }
        guard let records = RecordFraming.split(framed) else {
            return .refused("Rust answered records whose framing is torn")
        }
        return .reply(records)
    }

    /// A GATT link came up; `target` is the contact the client reached for, or `nil`.
    static func bleLinkOpened(address: String, role: Int32, target: Data?) -> RadioAnswer {
        guard target == nil || target?.count == 32 else {
            return .refused("the link's target is \(target?.count ?? 0) bytes, not 32")
        }
        if let target {
            return withBytes(target) { ptr, _ in radioAnswer(dsm_ffi_ble_link_opened(address, role, ptr)) }
        }
        return radioAnswer(dsm_ffi_ble_link_opened(address, role, nil))
    }

    /// A GATT link closed. `nil`, or why the close was not taken.
    static func bleLinkClosed(address: String, role: Int32) -> String? {
        reason(dsm_ffi_ble_link_closed(address, role))
    }

    /// Bytes a peer wrote on the link.
    static func bleInbound(address: String, role: Int32, bytes: Data) -> RadioAnswer {
        withBytes(bytes) { ptr, len in radioAnswer(dsm_ffi_ble_inbound(address, role, ptr, len)) }
    }

    static func bleAccept(commitment: Data) -> Data {
        withBytes(commitment) { ptr, _ in take(dsm_ffi_ble_accept(ptr)) }
    }

    static func bleReject(commitment: Data, reason: String) -> Data {
        withBytes(commitment) { ptr, _ in take(dsm_ffi_ble_reject(ptr, reason)) }
    }

    static func bleCancel(commitment: Data, reason: String) -> Data {
        withBytes(commitment) { ptr, _ in take(dsm_ffi_ble_cancel(ptr, reason)) }
    }

    /// Mark the bilateral runtime ready; `nil`, or why it is not ready yet.
    static func initializeBilateralSdk() -> String? {
        reason(dsm_ffi_initialize_bilateral_sdk())
    }

    static func bleStackReady() -> Bool {
        dsm_ffi_ble_stack_ready() != 0
    }

    /// A radio state event for the page: the scan (1) or advertising (2), started or stopped.
    static func bleRadioEvent(kind: Int32, on: Bool) -> Data {
        take(dsm_ffi_ble_radio_event(kind, on ? 1 : 0))
    }

    /// A device event for the page: found (1, with name and rssi), connected (2), disconnected (3).
    static func bleDeviceEvent(kind: Int32, address: String, name: String?, rssi: Int32) -> Data {
        take(dsm_ffi_ble_device_event(kind, address, name, rssi))
    }

    static func blePermissionDeniedEvent(operation: String) -> Data {
        take(dsm_ffi_ble_permission_denied_event(operation))
    }

    // MARK: Routes, as the Kotlin identity handler crosses them

    /// A router query through the shared ingress: the ok bytes, or the reason thrown.
    static func routerQuery(_ method: String, args: Data = Data()) throws -> Data {
        let response = ingress(routerQueryRequest(method: method, args: args))
        if let why = ingressErrorMessage(response) { throw DsmSdkError.refused("\(method): \(why)") }
        return ingressOkBytes(response)
    }

    /// A router invoke (a route that changes state) through the shared ingress.
    static func routerInvoke(_ method: String, args: Data = Data()) throws -> Data {
        let response = ingress(routerInvokeRequest(method: method, args: args))
        if let why = ingressErrorMessage(response) { throw DsmSdkError.refused("\(method): \(why)") }
        return ingressOkBytes(response)
    }
}

/// Rust answered no: the request reached it and it refused.
enum DsmSdkError: Error, CustomStringConvertible {
    case refused(String)

    var description: String {
        switch self {
        case .refused(let why): return why
        }
    }
}
