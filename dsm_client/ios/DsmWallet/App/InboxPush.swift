// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation
import UIKit

/// The storage nodes' doorbell on this iPhone: the Apple Push Notification
/// service. Rust puts the doorbells up on the nodes with the device token
/// handed over here, and a node sends one background push when something
/// lands for this wallet. The push carries nothing; Rust runs the sync a
/// wait's answer runs, and reads and verifies what landed as always.
///
/// Without push (registration failed) Rust is told so and keeps its waits
/// while the app is open, as before. Swift decides nothing else.
enum InboxPush {
    private static let tag = "InboxPush"

    /// How long a push's sync may take before the system is answered: iOS
    /// gives a background push about 30 s, and suspends the app once it is
    /// answered.
    static let syncWaitMs: UInt32 = 25_000

    /// What Rust answers a wake (`dsm_ffi_on_push_wake`).
    private static let notStarted: Int32 = 0
    private static let synced: Int32 = 1

    static func tokenIssued(_ device: Data) {
        if let why = DsmSdk.setApnsDeviceToken(device) {
            DsmLog.warn(tag, "the APNs device token was not taken: \(why)")
        } else {
            DsmLog.info(tag, "APNs device token in hand: the storage nodes ring this phone")
        }
    }

    static func registrationFailed(_ error: Error) {
        DsmLog.warn(tag, "no push on this phone: \(error); the app keeps its waits while open")
        DsmSdk.pushUnavailable("APNs registration failed: \(error.localizedDescription)")
    }

    /// A storage node rang. The wallet is started first when iOS launched
    /// this process for the push; the system is answered once the sync has
    /// ended or its time is up.
    static func rang(_ answer: @escaping (UIBackgroundFetchResult) -> Void) {
        DsmLog.info(tag, "a storage node rang")
        DispatchQueue.global(qos: .utility).async {
            var woken = DsmSdk.onPushWake(waitMs: syncWaitMs)
            if woken == notStarted {
                guard HeadlessWallet.start() else {
                    DsmLog.warn(tag, "the wallet could not be started for the push; it reads its inbox when opened")
                    answer(.failed)
                    return
                }
                woken = DsmSdk.onPushWake(waitMs: syncWaitMs)
            }
            answer(woken == synced ? .newData : .failed)
        }
    }
}

/// The wallet started with no screen, in a process iOS launched for a push
/// from a storage node: the same Rust startup the wallet screen runs, in the
/// same order, without its page. It runs once per process; the screen, shown
/// later in the same process, runs its startup as it always does, which Rust
/// is made to run again for the same identity.
///
/// The env config is the one the screen wrote when the app was last opened;
/// a phone that never opened the app holds no doorbell to be rung.
enum HeadlessWallet {
    private static let tag = "HeadlessWallet"
    private static let lock = NSLock()
    private static var startedHere = Started.no

    private enum Started {
        case no
        case yes
    }

    /// Start the wallet for a push. Answers whether it is started; on a
    /// failure the reason is in the log, and the push is lost: the app reads
    /// its inbox when it is next opened.
    static func start() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        if startedHere == .yes { return startedHere == .yes }
        let config = AppDelegate.storageBaseDir.appendingPathComponent("dsm_env_config.toml")
        guard FileManager.default.isReadableFile(atPath: config.path) else {
            DsmLog.warn(tag, "no env config at \(config.path): the app was never opened, nothing to start")
            return startedHere == .yes
        }
        if let why = DsmSdk.initDsmSdk(configPath: config.path) {
            DsmLog.error(tag, "initDsmSdk: \(why)")
            return startedHere == .yes
        }
        if let why = DsmSdk.initSdk(baseDir: AppDelegate.storageBaseDir.path) {
            DsmLog.error(tag, "initSdk: \(why)")
            return startedHere == .yes
        }
        guard IdentityHandler.shared.bootstrapFromDefaults() else {
            DsmLog.warn(tag, "no identity to restore: nothing to start")
            return startedHere == .yes
        }
        if let why = DsmSdk.initializeBilateralSdk() {
            DsmLog.warn(tag, "the bilateral runtime is not ready yet: \(why)")
        }
        guard DsmSdk.ensureAppRouterInstalled() != 0 else {
            DsmLog.error(tag, "the wallet's router is not installed: the push is not served")
            return startedHere == .yes
        }
        startedHere = .yes
        DsmLog.info(tag, "wallet started for a push, with no screen")
        return startedHere == .yes
    }
}
