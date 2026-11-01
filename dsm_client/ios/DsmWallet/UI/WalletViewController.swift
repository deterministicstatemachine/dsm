// SPDX-License-Identifier: MIT OR Apache-2.0

import AVFoundation
import UIKit
import WebKit

/// The wallet's one screen: the web view container and the host actions the
/// page asks for, as `MainActivity.kt` holds them. It initializes the SDK on
/// its own thread when it appears, signals the page when the bridge is up,
/// collects the hardware facts Rust decides the session from, and carries
/// out the platform actions (share sheet, contact picker, QR scanner, bars,
/// guards) that the page cannot do for itself.
final class WalletViewController: UIViewController, WKNavigationDelegate, WKUIDelegate {
    /// The screen on top, for the dispatcher's platform actions.
    private(set) static weak var active: WalletViewController?

    private let tag = "WalletViewController"
    private var webView: WalletWebView?
    /// A black cover over the page while a guarded screen must not be seen:
    /// in the app switcher's snapshot, or while the screen is being recorded.
    private let guardCover = UIView()
    private var guards = ScreenGuards.none
    /// How the page meets the phone's bars: `edge` (the Game Boy, under the
    /// bars) or `fit` (the Modern skin, between them).
    private enum BarFit { case edge, fit }
    private var barFit = BarFit.edge
    private var statusBarStyle = UIStatusBarStyle.lightContent
    /// A connect link a launch handed over (DSM Amendment A11), held until the page can take it.
    private var pendingConnectLink: ConnectLink?
    /// The connect link that opened the wallet, until the player answers it.
    private var connectLinkOpened: String?
    private var contactPicker: PhoneContacts?
    private let background = DispatchQueue(label: "com.dsm.wallet.host", qos: .userInitiated)

    /// A connect link and the app the system named as having opened it.
    struct ConnectLink {
        let sender: String?
        let text: String
    }

    override var preferredStatusBarStyle: UIStatusBarStyle { statusBarStyle }

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = UIColor(red: 0x0D / 255, green: 0x0D / 255, blue: 0x0D / 255, alpha: 1)
        WalletViewController.active = self

        guard let wwwRoot = Bundle.main.url(forResource: "www", withExtension: nil),
              let bootstrapURL = Bundle.main.url(forResource: "bridge_bootstrap", withExtension: "js") else {
            // The bundle carries no page: nothing renders, and the reason is in the log.
            DsmLog.error(tag, "the app bundle has no www/ or no bridge_bootstrap.js: the page cannot load")
            return
        }
        let bootstrap: String
        do {
            bootstrap = try String(contentsOf: bootstrapURL, encoding: .utf8)
        } catch {
            DsmLog.error(tag, "bridge_bootstrap.js is unreadable: \(error); the page cannot load")
            return
        }
        let web = WalletWebView(wwwRoot: wwwRoot, bootstrap: bootstrap)
        web.navigationDelegate = self
        web.uiDelegate = self
        view.addSubview(web)
        webView = web
        EventRelay.shared.attach { [weak web] event in
            // A page that is gone takes nothing; the relay keeps the event.
            let taken = web?.deliver(event) ?? (web != nil)
            // As Android's dispatcher: a wallet-refresh hint from Rust (publication
            // completed, the inbox moved) also refreshes the session snapshot the
            // page renders its phase from.
            if taken, case .topic(let topic, _) = event, WalletViewController.sessionHintTopics.contains(topic) {
                DispatchQueue.main.async { SessionFacts.shared.publish("walletRefresh") }
            }
            return taken
        }

        guardCover.backgroundColor = .black
        guardCover.isHidden = !coverRequired()
        view.addSubview(guardCover)

        let center = NotificationCenter.default
        center.addObserver(self, selector: #selector(appWillResignActive), name: UIApplication.willResignActiveNotification, object: nil)
        center.addObserver(self, selector: #selector(appDidBecomeActive), name: UIApplication.didBecomeActiveNotification, object: nil)
        center.addObserver(self, selector: #selector(screenCaptureChanged), name: UIScreen.capturedDidChangeNotification, object: nil)

        web.load(URLRequest(url: WebNavigationPolicy.indexURL))
        initDsmAndSignalReady()
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        let frame = barFit == .fit ? view.bounds.inset(by: view.safeAreaInsets) : view.bounds
        webView?.frame = frame
        guardCover.frame = view.bounds
        view.bringSubviewToFront(guardCover)
    }

    // MARK: Startup

    /// The topics after which the session snapshot is republished, as Android's
    /// `dispatchDsmEventOnUiNow` republishes it.
    private static let sessionHintTopics: Set<String> = ["dsm-wallet-refresh", "inbox.updated"]

    private var baseDir: URL { AppDelegate.storageBaseDir }

    /// The environment config the SDK reads: the bundled one, copied beside
    /// the fleet's CA into the storage directory on every start; a developer's
    /// override is honoured in debug builds only (the Documents folder is
    /// writable by anyone holding the phone, and the storage nodes a wallet
    /// trusts are not theirs to name).
    private func materializeEnvConfig() -> URL? {
        let assetName = "dsm_env_config.toml"
        let files = baseDir
        materializeAssetIfBundled("ca.crt", into: files)
        #if DEBUG
        if let documents = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first {
            let override = documents.appendingPathComponent(assetName)
            if FileManager.default.fileExists(atPath: override.path) {
                do {
                    let size = try FileManager.default.attributesOfItem(atPath: override.path)[.size] as? NSNumber
                    if let size, size.intValue > 0 {
                        DsmLog.info(tag, "using the developer override env config at \(override.path)")
                        return override
                    }
                    DsmLog.warn(tag, "the override config at \(override.path) is empty; ignoring it")
                } catch {
                    DsmLog.warn(tag, "the override config at \(override.path) is unreadable: \(error); ignoring it")
                }
            }
        }
        #endif
        let bytes: Data
        do {
            guard let bundled = Bundle.main.url(forResource: "www", withExtension: nil)?.appendingPathComponent(assetName) else {
                throw CocoaError(.fileNoSuchFile)
            }
            bytes = try Data(contentsOf: bundled)
        } catch {
            reportEnvConfigFailure(kind: "ASSET_NOT_FOUND",
                                   message: "Configuration file not found: \(error). Please ensure dsm_env_config.toml is in the app bundle before launching.",
                                   help: "The configuration file is missing from the app bundle. Reinstall the app.")
            return nil
        }
        guard !bytes.isEmpty else {
            reportEnvConfigFailure(kind: "EMPTY_CONFIG", message: "Configuration file is empty.", help: "Redeploy the configuration file into the app bundle.")
            return nil
        }
        let out = files.appendingPathComponent(assetName)
        do {
            try bytes.write(to: out, options: .atomic)
        } catch {
            reportEnvConfigFailure(kind: "IO_ERROR", message: "Failed to load configuration: \(error)", help: "Cannot write the configuration file. Check device storage space.")
            return nil
        }
        return out
    }

    /// A bundled asset the SDK reads from the storage directory (the fleet's
    /// CA); a build without it bundles nothing of that name, and that is not a
    /// failure.
    private func materializeAssetIfBundled(_ name: String, into dir: URL) {
        guard let source = Bundle.main.url(forResource: "www", withExtension: nil)?.appendingPathComponent(name),
              FileManager.default.fileExists(atPath: source.path) else { return }
        do {
            let bytes = try Data(contentsOf: source)
            try bytes.write(to: dir.appendingPathComponent(name), options: .atomic)
        } catch {
            DsmLog.warn(tag, "the bundled \(name) was not copied: \(error)")
        }
    }

    private func reportEnvConfigFailure(kind: String, message: String, help: String) {
        DsmLog.error(tag, "\(kind): \(message)")
        let snapshot = DsmSdk.setSessionFatalError(message)
        EventRelay.shared.post(topic: "session.state", payload: snapshot)
        EventRelay.shared.post(topic: "dsm-env-config-error", payload: Data("\(kind)|\(message)|\(help)".utf8))
    }

    /// Native initialization on its own thread, as `initDsmAndSignalReady`
    /// runs it on Android: the env config, shared startup, the identity
    /// restored from the pointers the host kept, the bilateral runtime, then
    /// the signals the page waits for.
    private func initDsmAndSignalReady() {
        background.async { [tag] in
            guard let config = self.materializeEnvConfig() else { return }
            let afterConfig: Data
            if let why = DsmSdk.initDsmSdk(configPath: config.path) {
                DsmLog.error(tag, "initDsmSdk: \(why)")
                afterConfig = DsmSdk.setSessionFatalError(why)
            } else {
                afterConfig = DsmSdk.clearSessionFatalError()
            }
            EventRelay.shared.post(topic: "session.state", payload: afterConfig)
            if let why = DsmSdk.initSdk(baseDir: self.baseDir.path) {
                // A failed startup is Rust's to report: it records the reason
                // as the session's fatal error, and the page shows it.
                DsmLog.error(tag, "initSdk: \(why)")
            }
            DsmLog.info(tag, "app router status \(DsmSdk.appRouterStatus())")
            let bootstrapped = IdentityHandler.shared.bootstrapFromDefaults()
            if bootstrapped, let why = DsmSdk.initializeBilateralSdk() {
                DsmLog.warn(tag, "the bilateral runtime is not ready yet: \(why)")
            }
            let identity = DsmSdk.hasIdentity() && DsmSdk.genesisHash().count == 32
            DispatchQueue.main.async {
                if bootstrapped {
                    EventRelay.shared.post(topic: "dsm-identity-ready", payload: Data())
                    self.routerInvokeInBackground("inbox.startPoller")
                }
                if identity {
                    self.startBleForIdentity()
                } else {
                    DsmLog.info(tag, "no identity yet; the radio stays down until genesis")
                }
                SessionFacts.shared.publish("initComplete")
            }
        }
    }

    private func routerInvokeInBackground(_ method: String) {
        background.async { [tag] in
            do {
                let answer = try DsmSdk.routerInvoke(method)
                DsmLog.info(tag, "\(method) answered \(answer.count) bytes")
            } catch {
                DsmLog.warn(tag, "\(method) failed: \(error)")
            }
        }
    }

    private func signalBridgeReady() {
        EventRelay.shared.markReady()
        EventRelay.shared.post(topic: "dsm-bridge-ready", payload: Data())
        deliverConnectLink()
        // The snapshot at 100 ms, 500 ms and 1500 ms: redundant deliveries are
        // harmless, and the later one wins a race with a page not yet listening.
        for (delay, reason) in [(0.1, "bridgeReady"), (0.5, "bridgeReady.r1"), (1.5, "bridgeReady.r2")] {
            DispatchQueue.main.asyncAfter(deadline: .now() + delay) { SessionFacts.shared.publish(reason) }
        }
    }

    // MARK: Lifecycle, from the scene

    func sceneDidBecomeActive() {
        WalletViewController.active = self
        SessionFacts.shared.appForeground = UIApplication.shared.applicationState == .active
        SessionFacts.shared.publish("resume")
        if SessionFacts.shared.qrRoundTrip == .resumePending {
            SessionFacts.shared.qrRoundTrip = SessionFacts.shared.qrRoundTrip.resumeSettled()
            SessionFacts.shared.publish("qrResumeSettled")
        }
        if DsmSdk.hasIdentity() {
            routerInvokeInBackground("inbox.resume")
            // Bluetooth runs while the app is open (owner, 2026-11-01): the
            // radio follows the identity again now.
            BleCoordinator.shared.refreshAdvertising()
        }
    }

    func sceneWillResignActive() {
        SessionFacts.shared.appForeground = UIApplication.shared.applicationState == .active
        // Rust receives the app as not in the foreground and decides the lock policy.
        SessionFacts.shared.publish("pause")
    }

    func sceneDidEnterBackground() {
        // Rust stops the inbox poller unless something is still owed; its
        // answer is informational here, since iOS has no service to keep.
        let keepAlive = DsmSdk.onAppBackgrounded()
        DsmLog.info(tag, "backgrounded: Rust answered keep-alive=\(keepAlive)")
        // Bluetooth only while the app is open: the radio stops with the screen.
        BleCoordinator.shared.radioToBackground()
    }

    // MARK: Guards

    /// The cover is required while a secret is on screen and either the app
    /// is leaving the foreground (the switcher's snapshot is taken then) or
    /// the screen is being recorded or mirrored.
    private func coverRequired() -> Bool {
        guards.secret && (UIApplication.shared.applicationState != .active || UIScreen.main.isCaptured)
    }

    @objc private func appWillResignActive() {
        // The snapshot is taken after this notification: the state is still
        // active here, so the cover is decided by the secret alone.
        guardCover.isHidden = !guards.secret
    }

    @objc private func appDidBecomeActive() {
        guardCover.isHidden = !coverRequired()
    }

    @objc private func screenCaptureChanged() {
        guardCover.isHidden = !coverRequired()
    }

    /// What the page shows asks the window to guard (`setScreenGuards`). iOS
    /// cannot refuse a screenshot or a recording, so while a recovery phrase
    /// is on screen the page is covered in the app switcher's snapshot and
    /// while the screen is being recorded or mirrored. An overlay window of
    /// another app does not exist on iOS; the confirm guard has nothing to do.
    func setScreenGuards(_ next: ScreenGuards) {
        guards = next
        guardCover.isHidden = !coverRequired()
    }

    // MARK: Bars

    /// The phone's bars for what the page shows: `device` is the Game Boy,
    /// which runs edge to edge under dark bars; `light` and `dark` are the
    /// Modern skin, which stops at the bars, the bars in the page's own
    /// colour behind them.
    func setSystemBars(_ look: String) {
        let colour: UIColor
        switch look {
        case "light": colour = .white
        case "dark": colour = UIColor(red: 0x0A / 255, green: 0x0A / 255, blue: 0x0A / 255, alpha: 1)
        default: colour = UIColor(red: 0x0D / 255, green: 0x0D / 255, blue: 0x0D / 255, alpha: 1)
        }
        statusBarStyle = look == "light" ? .darkContent : .lightContent
        view.backgroundColor = colour
        barFit = look == "device" ? .edge : .fit
        view.setNeedsLayout()
        setNeedsStatusBarAppearanceUpdate()
    }

    // MARK: Platform actions

    func shareText(_ text: String) {
        let sheet = UIActivityViewController(activityItems: [text], applicationActivities: nil)
        sheet.popoverPresentationController?.sourceView = view
        present(sheet, animated: isViewLoaded)
    }

    func pickPhoneContact() {
        let picker = PhoneContacts { [weak self] event in
            EventRelay.shared.post(nativeHostEvent: event)
            self?.contactPicker = nil
        }
        contactPicker = picker
        picker.present(from: self)
    }

    /// Opens the native scanner; its result reaches the page as a QR_SCAN_RESULT host event.
    func launchNativeQrScanner() {
        SessionFacts.shared.qrRoundTrip = SessionFacts.shared.qrRoundTrip.scannerLaunched()
        SessionFacts.shared.publish("qrStart")
        let scanner = QrScannerViewController { [weak self] text in
            SessionFacts.shared.qrRoundTrip = SessionFacts.shared.qrRoundTrip.scannerReturned()
            SessionFacts.shared.publish("qrResult")
            EventRelay.shared.post(nativeHostEvent: DsmSdk.qrScanResultEvent(text: text ?? ""))
            if self?.view.window != nil {
                SessionFacts.shared.qrRoundTrip = SessionFacts.shared.qrRoundTrip.resumeSettled()
                SessionFacts.shared.publish("qrResumeSettled")
            }
        }
        present(scanner, animated: isViewLoaded)
    }

    func requestBlePermissions() {
        BleCoordinator.shared.promptForPermission()
        SessionFacts.shared.publish("blePermissions")
    }

    /// The appliance has an identity: the radio follows it (the GATT server
    /// up and advertising on). Called when init finds the identity and when
    /// genesis creates it.
    func startBleForIdentity() {
        BleCoordinator.shared.refreshAdvertising()
    }

    // MARK: DSM Connect (Amendment A11)

    /// A `dsm:connect/v1:` link opened the wallet: hold its text for the
    /// page. Routing only: Rust reads the code when the player asks it to.
    func takeConnectLink(_ url: URL, sender: String?) {
        let link = url.absoluteString
        guard url.scheme == "dsm", link.hasPrefix("dsm:connect/v1:") else { return }
        pendingConnectLink = ConnectLink(sender: sender, text: link)
        connectLinkOpened = link
        deliverConnectLink()
    }

    /// Hands a held connect link to the page once it is ready, as UTF-8
    /// "sender\nlink": the app the system named as the link's sender (empty
    /// when it named none), then the link as it came.
    private func deliverConnectLink() {
        guard let link = pendingConnectLink, webView?.url != nil else { return }
        pendingConnectLink = nil
        EventRelay.shared.post(topic: "connect.link", payload: Data("\(link.sender ?? "")\n\(link.text)".utf8))
    }

    /// The connect link that opened the wallet, taken once (the player has
    /// answered it); `nil` when no link opened it.
    func takeConnectLinkOpened() -> String? {
        let opened = connectLinkOpened
        connectLinkOpened = nil
        return opened
    }

    // MARK: WKNavigationDelegate

    func webView(_ webView: WKWebView, decidePolicyFor action: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        guard let url = action.request.url else {
            decisionHandler(.cancel)
            return
        }
        switch WebNavigationPolicy.decide(url) {
        case .app:
            decisionHandler(.allow)
        case .nativeQr:
            DsmLog.info(tag, "the page asked for the native QR scanner")
            launchNativeQrScanner()
            decisionHandler(.cancel)
        case .issueForm:
            openOutside(url)
            decisionHandler(.cancel)
        case .refused:
            DsmLog.warn(tag, "refused navigation to \(url.scheme ?? "")://\(url.host ?? "")")
            decisionHandler(.cancel)
        }
    }

    func webView(_ webView: WKWebView, didFinish navigation: WKNavigation!) {
        signalBridgeReady()
    }

    func webView(_ webView: WKWebView, didFail navigation: WKNavigation!, withError error: Error) {
        DsmLog.error(tag, "the page did not load: \(error)")
    }

    func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation!, withError error: Error) {
        DsmLog.error(tag, "the page did not start loading: \(error)")
    }

    /// A page asked to leave the app. Only the beta issue form goes, to
    /// Safari; every other address is refused (pre-audit item 13).
    private func openOutside(_ url: URL) {
        switch WebNavigationPolicy.decide(url) {
        case .issueForm:
            UIApplication.shared.open(url)
        case .app, .nativeQr, .refused:
            DsmLog.warn(tag, "refused to open \(url.scheme ?? "")://\(url.host ?? "") outside the app")
        }
    }

    // MARK: WKUIDelegate

    /// `window.open`: the address goes through the policy; no child web view is made.
    func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        if let url = navigationAction.request.url { openOutside(url) }
        return nil
    }

    /// Only the camera, and only when the system allows it, as the Android
    /// host grants only video capture: the page never reaches the microphone.
    func webView(_ webView: WKWebView, requestMediaCapturePermissionFor origin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo, type: WKMediaCaptureType, decisionHandler: @escaping (WKPermissionDecision) -> Void) {
        let cameraAllowed = AVCaptureDevice.authorizationStatus(for: .video) == .authorized
        decisionHandler(type == .camera && cameraAllowed ? .grant : .deny)
    }
}
