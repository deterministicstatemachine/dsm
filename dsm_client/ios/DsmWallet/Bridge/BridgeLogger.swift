// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

/// The persisted bridge log the diagnostics report exports, as
/// `BridgeLogger.kt` keeps it: one line per bridge call naming the method,
/// the sizes and a failure, never a byte of the payload or the answer (a
/// payload can be the wallet's mnemonic). Capped at 5 MB, the oldest lines
/// trimmed. Lines are stamped with the process's uptime, never the clock.
enum BridgeLogger {
    private static let maxLogBytes = 5 * 1024 * 1024
    private static let lock = NSLock()
    private static var file: URL?

    static func setLogFile(_ url: URL) {
        lock.lock()
        file = url
        lock.unlock()
    }

    /// The log's last bytes, at most `maxBytes`.
    static func readLogBytes(maxBytes: Int = maxLogBytes) -> Data {
        lock.lock()
        defer { lock.unlock() }
        guard let file, FileManager.default.fileExists(atPath: file.path) else { return Data() }
        do {
            let data = try Data(contentsOf: file)
            return data.count <= maxBytes ? data : data.suffix(maxBytes)
        } catch {
            DsmLog.warn("BridgeLogger", "the bridge log is unreadable: \(error)")
            return Data()
        }
    }

    static func logDiagnosticsPayload(_ payload: Data) {
        let preview = payload.count <= 64
            ? Base32Crockford.encode(payload)
            : Base32Crockford.encode(payload.prefix(64)) + "..."
        appendLine("DIAGNOSTICS: payload=\(payload.count)b b32=\(preview)")
    }

    /// One event handed to the page: its topic or kind and size, and whether
    /// the page took it; never its bytes. Android writes the same to logcat,
    /// which iOS has no way to read off a device without root.
    static func logEventDelivery(_ event: EventRelay.Event, taken: Bool) {
        let what: String
        switch event {
        case .topic(let topic, let payload): what = "\(topic) \(payload.count)b"
        case .nativeHost(let bytes): what = "nativeHost \(bytes.count)b"
        }
        appendLine("EVENT: \(what) -> \(taken ? "taken" : "kept")")
    }

    static func logBridgeCall(method: String, payloadBytes: Int, outcome: Result<Int, Error>) {
        let result: String
        switch outcome {
        case .success(let bytes): result = "\(bytes)b"
        case .failure(let error): result = "ERROR: \(error)"
        }
        let line = "BRIDGE: \(method)(payload=\(payloadBytes)b) -> \(result)"
        #if DEBUG
        DsmLog.info("SinglePathWebViewBridge", line)
        #endif
        appendLine(line)
    }

    private static func appendLine(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        guard let file else { return }
        let uptimeMs = Int(ProcessInfo.processInfo.systemUptime * 1000)
        let line = Data("\(uptimeMs) \(message)\n".utf8)
        do {
            if !FileManager.default.fileExists(atPath: file.path) {
                try line.write(to: file, options: .atomic)
            } else {
                let handle = try FileHandle(forWritingTo: file)
                try handle.seekToEnd()
                try handle.write(contentsOf: line)
                try handle.close()
            }
            try trim(file)
        } catch {
            DsmLog.warn("BridgeLogger", "the bridge log was not appended: \(error)")
        }
    }

    private static func trim(_ file: URL) throws {
        let data = try Data(contentsOf: file)
        guard data.count > maxLogBytes else { return }
        try data.suffix(maxLogBytes).write(to: file, options: .atomic)
    }
}
