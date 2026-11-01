// SPDX-License-Identifier: MIT OR Apache-2.0

import DsmSdk
import Foundation
import UserNotifications

/// This app as the SDK's host: the C callbacks Rust calls for everything it
/// asks of the platform (`crate::host::HostBridge`), registered once at
/// launch. Each callback answers 0 when it did what was asked and another
/// code when it did not; Rust reports the code. Rust calls from its own
/// threads; each callback hops to the queue its work belongs on.
enum HostBridge {
    /// Whether the system lets this app put a count on its icon, as the
    /// system answered the launch-time request; the badge callback reads it
    /// and cannot wait for an answer still pending.
    enum BadgeAuthorization { case pending, granted, denied }
    static var badgeAuthorization = BadgeAuthorization.pending

    /// Registers the callbacks with Rust. Answers `nil`, or why Rust refused
    /// (a host was already installed).
    static func install() -> String? {
        let callbacks = DsmHostCallbacks(
            post_event: { topic, payload, len in
                guard let topic else { return 2 }
                let name = String(cString: topic)
                let bytes = payload.map { Data(bytes: $0, count: len) } ?? Data()
                EventRelay.shared.post(topic: name, payload: bytes)
                return 0
            },
            show_money_received: { count in
                guard HostBridge.badgeAuthorization == .granted else { return 1 }
                UNUserNotificationCenter.current().setBadgeCount(Int(count)) { error in
                    if let error { DsmLog.warn("HostBridge", "the icon count was not set: \(error)") }
                }
                return 0
            },
            write_on_link: { address, role, records, len in
                guard let address else { return -2 }
                let framed = records.map { Data(bytes: $0, count: len) } ?? Data()
                guard let split = RecordFraming.split(framed) else { return -3 }
                return BleCoordinator.shared.writeOnLink(address: String(cString: address), role: role, records: split)
            },
            request_connect: { deviceId, hint in
                guard let deviceId else { return 2 }
                let id = Data(bytes: deviceId, count: 32)
                let hintText = hint.map { String(cString: $0) } ?? ""
                return BleCoordinator.shared.requestConnect(deviceId: id, addressHint: hintText)
            },
            start_advertising: { BleCoordinator.shared.startAdvertising() },
            start_scan: { BleCoordinator.shared.startScanning() },
            stop_scan: { BleCoordinator.shared.stopScanning() },
            seal_seed: { input, len, out in
                HostBridge.transform(input, len, out, "seal") { try SeedVault.seal($0) }
            },
            open_seed: { input, len, out in
                HostBridge.transform(input, len, out, "open") { try SeedVault.open($0) }
            },
            log_line: { level, target, message in
                let category = target.map { String(cString: $0) } ?? "dsm_sdk"
                let text = message.map { String(cString: $0) } ?? ""
                switch level {
                case 1: DsmLog.error(category, text)
                case 2: DsmLog.warn(category, text)
                default: DsmLog.info(category, text)
                }
            }
        )
        return DsmSdk.reason(dsm_ffi_install_host(callbacks))
    }

    /// Run a seal/open on the input and hand the result to Rust in a buffer
    /// Rust owns. Answers 0, or 1 when the transform threw (logged).
    private static func transform(
        _ input: UnsafePointer<UInt8>?,
        _ len: Int,
        _ out: UnsafeMutablePointer<DsmBytes>?,
        _ what: String,
        _ run: (Data) throws -> Data
    ) -> Int32 {
        guard let out else { return 2 }
        let bytes = input.map { Data(bytes: $0, count: len) } ?? Data()
        do {
            let result = try run(bytes)
            var buffer = dsm_bytes_alloc(result.count)
            if let ptr = buffer.ptr {
                result.copyBytes(to: ptr, count: result.count)
            }
            buffer.len = result.count
            out.pointee = buffer
            return 0
        } catch {
            DsmLog.error("SeedVault", "the seed vault did not \(what): \(error)")
            return 1
        }
    }
}

/// Records as the C ABI frames them: each behind its big-endian u32 length.
enum RecordFraming {
    /// The records, or `nil` when the framing is torn.
    static func split(_ framed: Data) -> [Data]? {
        var records: [Data] = []
        var index = framed.startIndex
        while index < framed.endIndex {
            guard framed.endIndex - index >= 4 else { return nil }
            let length = framed[index..<index + 4].reduce(0) { ($0 << 8) | Int($1) }
            index += 4
            guard framed.endIndex - index >= length else { return nil }
            records.append(Data(framed[index..<index + length]))
            index += length
        }
        return records
    }
}
