// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import OSLog
import UIKit

/// The beta debug report: what the app measured, the app's log (Rust's
/// included, since Rust logs through the host) and the bridge log, in one
/// text file the user sends through the share sheet.
///
/// Android keeps a rolling `logcat` capture on disk because its buffer holds
/// minutes; iOS keeps the unified log itself, and the report reads this
/// process's entries back from it.
enum DiagnosticsReport {
    private static let dir = "diagnostics"
    private static let reportName = "dsm-diagnostics.txt"

    /// Writes the report into the caches directory and answers its file.
    static func write(summary: String) throws -> URL {
        guard let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first else {
            throw BridgeFailure.invalidState("shareDiagnosticsReport: this app has no caches directory")
        }
        let folder = caches.appendingPathComponent(dir)
        let parentMissing = !FileManager.default.fileExists(atPath: caches.path)
        try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: parentMissing)
        let out = folder.appendingPathComponent(reportName)
        var text = "=== DSM debug report ===\n"
        text += header()
        text += "\n=== What the app measured ===\n\(summary)\n"
        text += "\n=== App log of this process, oldest first ===\n"
        text += processLog()
        text += "\n=== Bridge log ===\n"
        text += String(decoding: BridgeLogger.readLogBytes(), as: UTF8.self)
        try Data(text.utf8).write(to: out, options: .atomic)
        return out
    }

    /// Opens the share sheet with the report; the user picks where it goes.
    static func share(_ report: URL, from controller: UIViewController) {
        let sheet = UIActivityViewController(activityItems: [report], applicationActivities: nil)
        sheet.popoverPresentationController?.sourceView = controller.view
        controller.present(sheet, animated: controller.isViewLoaded)
    }

    private static func header() -> String {
        let bundle = Bundle.main
        let version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
        let build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String
        let device = UIDevice.current
        return "app=\(bundle.bundleIdentifier ?? "?") version=\(version ?? "?") build=\(build ?? "?")\n"
            + "device=\(DeviceFacts.model) ios=\(device.systemVersion) arch=\(DeviceFacts.architecture)\n"
    }

    private static func processLog() -> String {
        do {
            let store = try OSLogStore(scope: .currentProcessIdentifier)
            let entries = try store.getEntries(matching: NSPredicate(format: "subsystem == %@", DsmLog.subsystem))
            var text = ""
            for entry in entries {
                guard let log = entry as? OSLogEntryLog else { continue }
                text += "\(log.category): \(log.composedMessage)\n"
            }
            return text.isEmpty ? "(no entries under \(DsmLog.subsystem))\n" : text
        } catch {
            return "(the log store did not answer: \(error))\n"
        }
    }
}

/// The device, as the diagnostics report and the architecture check describe it.
enum DeviceFacts {
    /// The hardware model identifier (`iPhone17,1`, `arm64` in the simulator).
    static var model: String {
        var systemInfo = utsname()
        uname(&systemInfo)
        return withUnsafePointer(to: &systemInfo.machine) { pointer in
            pointer.withMemoryRebound(to: CChar.self, capacity: Int(_SYS_NAMELEN)) { String(cString: $0) }
        }
    }

    /// The architecture this binary runs as.
    static var architecture: String {
        #if arch(arm64)
        return "arm64"
        #elseif arch(x86_64)
        return "x86_64"
        #else
        return "unknown"
        #endif
    }
}
