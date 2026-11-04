// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import os

/// The app's log: the unified log under the app's subsystem, one category per
/// tag, as `Log.i(tag, …)` names them on Android. `DiagnosticsReport` reads
/// it back from the log store for the debug report.
enum DsmLog {
    static let subsystem = "com.dsm.wallet"

    private static var loggers: [String: Logger] = [:]
    private static let lock = NSLock()

    private static func logger(_ tag: String) -> Logger {
        lock.lock()
        defer { lock.unlock() }
        if let known = loggers[tag] { return known }
        let made = Logger(subsystem: subsystem, category: tag)
        loggers[tag] = made
        return made
    }

    static func info(_ tag: String, _ message: String) {
        logger(tag).info("\(message, privacy: .public)")
    }

    static func warn(_ tag: String, _ message: String) {
        logger(tag).warning("\(message, privacy: .public)")
    }

    static func error(_ tag: String, _ message: String) {
        logger(tag).error("\(message, privacy: .public)")
    }
}
