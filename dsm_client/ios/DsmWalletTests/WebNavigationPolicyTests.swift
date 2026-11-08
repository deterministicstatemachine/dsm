// SPDX-License-Identifier: MIT OR Apache-2.0

import XCTest
@testable import DsmWallet

final class WebNavigationPolicyTests: XCTestCase {
    private func decide(_ text: String) -> WebNavigation {
        WebNavigationPolicy.decide(URL(string: text)!)
    }

    /// The page is the app's packaged origin and nothing else (pre-audit
    /// item 13): its own assets load, the QR link and the issue form are
    /// handled natively, and every other address, scheme or path is refused.
    func testOnlyTheAppsOwnAssetsLoad() {
        XCTAssertEqual(decide("dsm-app://wallet/assets/index.html"), .app)
        XCTAssertEqual(decide("dsm-app://wallet/assets/js/main.js"), .app)
        XCTAssertEqual(decide("dsm-app://wallet/other/index.html"), .refused)
        XCTAssertEqual(decide("dsm-app://elsewhere/assets/index.html"), .refused)
        XCTAssertEqual(decide("https://appassets.androidplatform.net/assets/index.html"), .refused)
        XCTAssertEqual(decide("file:///etc/passwd"), .refused)
        XCTAssertEqual(decide("javascript:alert(1)"), .refused)
        XCTAssertEqual(decide("https://example.com/"), .refused)
    }

    func testTheQrLinkAndTheIssueFormAreTheirOwnNavigations() {
        XCTAssertEqual(decide("dsm://native/qr/start"), .nativeQr)
        XCTAssertEqual(decide("dsm://native/qr/stop"), .refused)
        XCTAssertEqual(decide("https://github.com/deterministicstatemachine/dsm/issues/new"), .issueForm)
        XCTAssertEqual(decide("https://github.com/deterministicstatemachine/dsm/issues"), .refused)
        XCTAssertEqual(decide("http://github.com/deterministicstatemachine/dsm/issues/new"), .refused)
    }
}
