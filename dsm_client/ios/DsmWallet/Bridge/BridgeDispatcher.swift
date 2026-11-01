// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import UIKit

/// The page's requests, routed: the arms of `SinglePathWebViewBridge
/// .handleBinaryRpcInternal`, one for one, each ending in Rust or in the one
/// platform action it names. A method no arm handles is refused by name.
/// Requests run off the main thread; wallet creation on its own serial queue,
/// so a long genesis never starves the rest.
final class BridgeDispatcher {
    static let shared = BridgeDispatcher()

    private let general = DispatchQueue(label: "com.dsm.wallet.bridge", qos: .userInitiated, attributes: .concurrent)
    private let genesis = DispatchQueue(label: "com.dsm.wallet.genesis", qos: .userInitiated)

    /// Answer `method` with `payload` on the queue it belongs on; `completion`
    /// runs on that queue.
    func dispatch(method: String, payload: Data, completion: @escaping (Result<Data, BridgeFailure>) -> Void) {
        let queue = method == "createGenesisV2" ? genesis : general
        queue.async {
            let outcome = self.answer(method: method, payload: payload)
            BridgeLogger.logBridgeCall(method: method, payloadBytes: payload.count, outcome: outcome.map(\.count).mapError { $0 as Error })
            if method == "createGenesisV2" {
                // The wallet exists now: the page sees phase=wallet_ready from
                // a fresh snapshot, as it does on Android.
                DispatchQueue.main.async { SessionFacts.shared.publish(method) }
            }
            completion(outcome)
        }
    }

    private func answer(method: String, payload: Data) -> Result<Data, BridgeFailure> {
        do {
            return .success(try handle(method: method, payload: payload))
        } catch let failure as BridgeFailure {
            return .failure(failure)
        } catch let refused as DsmSdkError {
            return .failure(.native(refused.description))
        } catch {
            return .failure(.native("Unexpected error: \(error)"))
        }
    }

    /// The active screen, which the platform actions need.
    private func screen(_ what: String) throws -> WalletViewController {
        var found: WalletViewController?
        if Thread.isMainThread {
            found = WalletViewController.active
        } else {
            DispatchQueue.main.sync { found = WalletViewController.active }
        }
        guard let found else { throw BridgeFailure.invalidState("\(what): no active screen") }
        return found
    }

    private func utf8(_ payload: Data) -> String {
        String(decoding: payload, as: UTF8.self)
    }

    private func handle(method: String, payload: Data) throws -> Data {
        switch method {
        case "generateMnemonic":
            return try IdentityHandler.shared.generateMnemonic()

        case "createGenesisV2":
            return try IdentityHandler.shared.createGenesisV2(request: payload)

        case "getAllBalancesStrict":
            return DsmSdk.balancesStrict()

        case "diagnosticsLog":
            BridgeLogger.logDiagnosticsPayload(payload)
            return Data()

        case "getDiagnosticsLog":
            return BridgeLogger.readLogBytes()

        case "returnToConnectCaller":
            // After an approved connect that a link brought: back to the app
            // that sent it. One byte: 1 when the wallet stepped back, 0 when no
            // link opened it. The owner's ruling (2026-11-01) is an automatic
            // return by a validated return URL bound to the Connect session;
            // Rust does not yet bind one, so when a link did open the wallet
            // there is nothing validated to open, and that is said rather
            // than answered as a step back or as no link.
            let screen = try screen("returnToConnectCaller")
            var opened: String?
            DispatchQueue.main.sync { opened = screen.takeConnectLinkOpened() }
            guard opened != nil else { return Data([0]) }
            throw BridgeFailure.invalidState("returnToConnectCaller: no validated return URL is bound to the Connect session yet; the step back is not built")

        case "shareText":
            let text = utf8(payload)
            guard !text.isEmpty, text.count <= 4096 else {
                throw BridgeFailure.invalidPayload("shareText: a text to share is 1 to 4096 characters")
            }
            let screen = try screen("shareText")
            DispatchQueue.main.async { screen.shareText(text) }
            return Data()

        case "pickPhoneContact":
            let screen = try screen("pickPhoneContact")
            DispatchQueue.main.async { screen.pickPhoneContact() }
            return Data()

        case "phoneContactPhoto":
            return PhoneContacts.photo(identifier: utf8(payload))

        case "setSystemBars":
            let look = utf8(payload)
            guard ["light", "dark", "device"].contains(look) else {
                throw BridgeFailure.invalidPayload("setSystemBars: no look named \(look)")
            }
            let screen = try screen("setSystemBars")
            DispatchQueue.main.async { screen.setSystemBars(look) }
            return Data()

        case "setScreenGuards":
            let guards = try ScreenGuards.parse(payload)
            let screen = try screen("setScreenGuards")
            DispatchQueue.main.async { screen.setScreenGuards(guards) }
            return Data()

        case "buildType":
            #if DEBUG
            return Data("debug".utf8)
            #else
            return Data("release".utf8)
            #endif

        case "shareDiagnosticsReport":
            let report = try DiagnosticsReport.write(summary: utf8(payload))
            let size = try FileManager.default.attributesOfItem(atPath: report.path)[.size] as? NSNumber
            let screen = try screen("shareDiagnosticsReport")
            DispatchQueue.main.async { DiagnosticsReport.share(report, from: screen) }
            return Data(String(size?.intValue ?? -1).utf8)

        case "getArchitectureInfo":
            return DsmSdk.architectureInfo(
                status: "COMPATIBLE",
                deviceArch: DeviceFacts.architecture,
                supportedAbis: DeviceFacts.architecture,
                message: "This device runs DSM as a native \(DeviceFacts.architecture) binary (\(DeviceFacts.model)).",
                recommendation: "An iOS build carries one native architecture; there is no ABI to choose."
            )

        case "getPreference":
            return try Preferences.getPreference(payload: payload)

        case "setPreference":
            return try Preferences.setPreference(payload: payload)

        case "nativeBoundaryIngress":
            return DsmSdk.ingress(payload)

        case "nativeHostRequest":
            return try hostRequest(payload)

        case "getTransportHeadersV3Bin":
            // The headers are needed early (identity, QR, faucet). No bytes
            // means Rust reports NO_IDENTITY; a failure to restore the identity
            // or read the status is this dispatcher's error.
            if !IdentityHandler.shared.sdkContextInitialized, !IdentityHandler.shared.bootstrapFromDefaults() {
                DsmLog.info("BridgeDispatcher", "getTransportHeadersV3Bin: no identity restorable yet")
            }
            return DsmSdk.transportHeadersStatus() >= 1 ? DsmSdk.transportHeaders() : Data()

        case "requestBlePermissions":
            let screen = try screen("requestBlePermissions")
            DispatchQueue.main.async { screen.requestBlePermissions() }
            return Data()

        case "openBluetoothSettings":
            // iOS opens an app's own settings page and nothing deeper.
            guard let settings = URL(string: UIApplication.openSettingsURLString) else {
                throw BridgeFailure.invalidState("openBluetoothSettings: the settings URL is not a URL")
            }
            DispatchQueue.main.async { UIApplication.shared.open(settings) }
            return Data()

        case "acceptBilateralByCommitment":
            guard payload.count == 32 else {
                throw BridgeFailure.invalidPayload("acceptBilateralByCommitment: expected 32 bytes, got \(payload.count)")
            }
            return DsmSdk.bleAccept(commitment: payload)

        case "rejectBilateralByCommitment":
            guard let commitment = DsmSdk.bilateralCommitment(payload) else {
                throw BridgeFailure.invalidPayload("rejectBilateralByCommitment: payload is not a BilateralPayload")
            }
            return DsmSdk.bleReject(commitment: commitment, reason: DsmSdk.bilateralReason(payload))

        case "cancelBilateralByCommitment":
            guard let commitment = DsmSdk.bilateralCommitment(payload) else {
                throw BridgeFailure.invalidPayload("cancelBilateralByCommitment: payload is not a BilateralPayload")
            }
            return DsmSdk.bleCancel(commitment: commitment, reason: DsmSdk.bilateralReason(payload))

        default:
            throw BridgeFailure.unknownMethod("Unknown binary RPC method: \(method)")
        }
    }

    /// The private host boundary: of the request kinds the page can send,
    /// this host carries out the QR scan start; every other kind is answered
    /// as unsupported, as `NativeHostBridge.kt` answers it.
    private func hostRequest(_ payload: Data) throws -> Data {
        let kind = DsmSdk.nativeHostRequestKind(payload)
        switch kind {
        case 0:
            return DsmSdk.nativeHostResponse(code: 400, message: "nativeHostRequest: invalid protobuf payload")
        case 2:
            let screen = try screen("QR scanner")
            DispatchQueue.main.async {
                screen.launchNativeQrScanner()
                SessionFacts.shared.publish("host_control.qr.start_scan")
            }
            return DsmSdk.nativeHostResponse(code: 0, message: nil)
        default:
            return DsmSdk.nativeHostResponse(code: 501, message: "unsupported native host request kind: \(kind)")
        }
    }
}

/// What the page asks the window to guard while it shows what it shows: the
/// one byte of the `setScreenGuards` bridge call. `secret`: a recovery
/// phrase is on screen or being typed. `confirm`: an irreversible
/// confirmation (a connect approval, a send) is on screen.
struct ScreenGuards: Equatable {
    static let secretBit: UInt8 = 1
    static let confirmBit: UInt8 = 2
    static let none = ScreenGuards(bits: 0)

    let bits: UInt8

    var secret: Bool { bits & ScreenGuards.secretBit != 0 }
    var confirm: Bool { bits & ScreenGuards.confirmBit != 0 }

    static func parse(_ payload: Data) throws -> ScreenGuards {
        guard payload.count == 1 else {
            throw BridgeFailure.invalidPayload("setScreenGuards: one byte of guards, not \(payload.count)")
        }
        let bits = payload[payload.startIndex]
        guard bits & ~(secretBit | confirmBit) == 0 else {
            throw BridgeFailure.invalidPayload("setScreenGuards: no guard has bits \(bits)")
        }
        return ScreenGuards(bits: bits)
    }
}
