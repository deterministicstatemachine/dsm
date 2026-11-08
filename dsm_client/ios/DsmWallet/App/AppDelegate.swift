// SPDX-License-Identifier: MIT OR Apache-2.0

import UIKit
import UserNotifications

/// Process start: this app becomes the SDK's host before anything asks Rust
/// for anything, the storage directory is set (a path and a mkdir; the rest
/// of native init runs on the screen's own thread), and the bridge log file
/// is named.
@main
final class AppDelegate: UIResponder, UIApplicationDelegate {
    /// Where the SDK keeps its files: the app's own support directory, which
    /// no other app reads and which stays out of backups (the wallet's state
    /// is this device's; a restore onto another device is not a wallet).
    static let storageBaseDir: URL = {
        let support = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSTemporaryDirectory())
        return support.appendingPathComponent("dsm")
    }()

    func application(_ application: UIApplication, didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        let tag = "AppDelegate"
        let hostRefusal = HostBridge.install()
        if let hostRefusal {
            DsmLog.error(tag, "the host was not installed: \(hostRefusal)")
        }
        var dir = AppDelegate.storageBaseDir
        do {
            // The support directory itself may not exist on a fresh install:
            // the parents are created when they are missing.
            let parentMissing = !FileManager.default.fileExists(atPath: dir.deletingLastPathComponent().path)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: parentMissing)
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try dir.setResourceValues(values)
        } catch {
            DsmLog.error(tag, "the storage directory was not prepared: \(error)")
        }
        if let why = DsmSdk.initStorageBaseDir(dir.path) {
            DsmLog.error(tag, "initStorageBaseDir: \(why)")
        }
        BridgeLogger.setLogFile(dir.appendingPathComponent("bridge_diagnostics.log"))

        // The icon count of received transfers needs the badge permission;
        // the answer is kept for the callback Rust calls, which cannot wait.
        UNUserNotificationCenter.current().requestAuthorization(options: [.badge]) { granted, error in
            HostBridge.badgeAuthorization = granted ? .granted : .denied
            if let error { DsmLog.warn(tag, "the badge permission request failed: \(error)") }
        }
        // The app can carry on only as the SDK's host.
        return hostRefusal == nil
    }

    func application(_ application: UIApplication, configurationForConnecting session: UISceneSession, options: UIScene.ConnectionOptions) -> UISceneConfiguration {
        let configuration = UISceneConfiguration(name: "Wallet", sessionRole: session.role)
        configuration.delegateClass = SceneDelegate.self
        return configuration
    }
}
