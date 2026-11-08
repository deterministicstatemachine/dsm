// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

/// Where a navigation the page asks for may go.
enum WebNavigation: Equatable {
    /// The app's own packaged page: it loads in the web view.
    case app
    /// The page's one link to the native QR scanner.
    case nativeQr
    /// The release repository's new-issue form, opened in Safari.
    case issueForm
    /// Anything else: never loaded in the web view, never handed to another app.
    case refused
}

/// The web view's navigation policy, as `WebNavigationPolicy.kt` decides it
/// (pre-audit item 13). The page is the app's packaged origin and nothing
/// else: it loads only its own assets, asks for the native QR scanner by its
/// one link, and sends the user to one outside page, the beta bug and
/// feedback form. Every other address is refused: another site, the app's
/// origin outside its assets, and every other scheme, so an injected link can
/// neither replace the page nor launch another app with the page's data.
///
/// Android serves the assets at `https://appassets.androidplatform.net/assets/`.
/// WebKit cannot intercept `https`, so the iOS host serves the same files at
/// its own scheme, `dsm-app://wallet/assets/`, through `BundleSchemeHandler`.
enum WebNavigationPolicy {
    static let appScheme = "dsm-app"
    static let appHost = "wallet"
    static let appPathPrefix = "/assets/"
    static let appOrigin = URL(string: "\(appScheme)://\(appHost)")!
    static let indexURL = URL(string: "\(appScheme)://\(appHost)\(appPathPrefix)index.html")!
    private static let issueFormHost = "github.com"
    private static let issueFormPath = "/deterministicstatemachine/dsm/issues/new"

    static func decide(_ url: URL) -> WebNavigation {
        let scheme = url.scheme?.lowercased()
        let host = url.host?.lowercased()
        let path = url.path
        if scheme == appScheme, host == appHost, path.hasPrefix(appPathPrefix) {
            return .app
        }
        if scheme == "dsm", host == "native", path == "/qr/start" {
            return .nativeQr
        }
        if scheme == "https", host == issueFormHost, path == issueFormPath {
            return .issueForm
        }
        return .refused
    }
}
