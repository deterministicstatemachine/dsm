// SPDX-License-Identifier: MIT OR Apache-2.0

import AVFoundation
import DsmSdk
import Foundation
import UIKit

/// Where the QR scanner's round trip stands, so the wallet does not lock
/// while the scanner is on top: the host is inactive then, and the result
/// callback can report the app in the background with no scan running before
/// the host has settled again (`QrLockRoundTripState.kt`).
enum QrRoundTrip {
    case idle
    /// The scanner is on top.
    case scanning
    /// The scanner returned; the host has not settled yet.
    case resumePending

    var effectiveQrActive: Bool { self != .idle }

    func scannerLaunched() -> QrRoundTrip { .scanning }
    func scannerLaunchFailed() -> QrRoundTrip { .idle }
    func scannerReturned() -> QrRoundTrip { .resumePending }
    func resumeSettled() -> QrRoundTrip { .idle }
}

/// What the host measures of the phone, handed to Rust, which decides the
/// session (phase, lock, pairing). The host collects and relays; it never
/// decodes or alters the session state Rust answers.
final class SessionFacts {
    static let shared = SessionFacts()

    /// Whether the app is active, as the scene reports it.
    var appForeground: Bool
    var qrRoundTrip = QrRoundTrip.idle
    private var lastBatteryLevelPercent: UInt32

    private init() {
        appForeground = UIApplication.shared.applicationState == .active
        let device = UIDevice.current
        // Monitoring is turned on while the state is still unknown, which is
        // the state before monitoring; a device already monitored stays so.
        device.isBatteryMonitoringEnabled = device.batteryState == .unknown || device.isBatteryMonitoringEnabled
        lastBatteryLevelPercent = SessionFacts.batteryPercent(device) ?? 100
    }

    /// The battery's level in percent, when the device reports one.
    private static func batteryPercent(_ device: UIDevice) -> UInt32? {
        let level = device.batteryLevel
        guard level >= 0 else { return nil }
        return UInt32((level * 100).rounded()).clamped(to: 0...100)
    }

    /// The facts, measured now. A battery level the device does not report
    /// (the simulator reports none) keeps the last one reported, as the
    /// Android host keeps its last intent's; the wire has no "unknown".
    func collect() -> DsmHardwareFacts {
        let device = UIDevice.current
        if let percent = SessionFacts.batteryPercent(device) {
            lastBatteryLevelPercent = percent
        }
        let charging = device.batteryState == .charging || device.batteryState == .full
        let radio = BleCoordinator.shared
        let cameraAuthorized = AVCaptureDevice.authorizationStatus(for: .video) == .authorized
        let camera = AVCaptureDevice.default(for: .video)
        return DsmHardwareFacts(
            app_foreground: appForeground ? 1 : 0,
            ble_enabled: radio.radioOn ? 1 : 0,
            ble_permissions: radio.permitted ? 1 : 0,
            ble_scanning: radio.scanning ? 1 : 0,
            ble_advertising: radio.advertising ? 1 : 0,
            qr_available: camera == nil ? 0 : 1,
            qr_active: qrRoundTrip.effectiveQrActive ? 1 : 0,
            camera_permission: cameraAuthorized ? 1 : 0,
            battery_charging: charging ? 1 : 0,
            battery_level_percent: lastBatteryLevelPercent
        )
    }

    /// Collect, hand to Rust, relay Rust's snapshot to the page.
    func publish(_ reason: String) {
        let snapshot = DsmSdk.updateSessionHardwareFacts(collect())
        let bytes: Data
        if DsmSdk.errorCode(of: snapshot) != 0 {
            DsmLog.error("SessionFacts", "updateSessionHardwareFacts refused the facts (\(reason)); publishing the snapshot as it stands")
            bytes = DsmSdk.sessionSnapshot()
        } else {
            bytes = snapshot
        }
        DsmLog.info("SessionFacts", "publish reason=\(reason) bytes=\(bytes.count)")
        EventRelay.shared.post(topic: "session.state", payload: bytes)
    }
}

private extension UInt32 {
    func clamped(to range: ClosedRange<UInt32>) -> UInt32 {
        Swift.min(Swift.max(self, range.lowerBound), range.upperBound)
    }
}
