// SPDX-License-Identifier: MIT OR Apache-2.0

import XCTest
@testable import DsmWallet

final class BridgeWireTests: XCTestCase {
    /// Records framed by Rust (each behind its big-endian u32 length) split
    /// back, and torn framing is refused rather than read short.
    func testRecordFramingSplitsAndRefusesTornBytes() {
        var framed = Data()
        let first = Data(repeating: 6, count: 501)
        for record in [first, Data(), Data([7, 7, 7])] {
            let length = UInt32(record.count)
            framed += Data([UInt8(length >> 24), UInt8((length >> 16) & 0xFF), UInt8((length >> 8) & 0xFF), UInt8(length & 0xFF)])
            framed += record
        }
        XCTAssertEqual(RecordFraming.split(framed), [first, Data(), Data([7, 7, 7])])
        XCTAssertNil(RecordFraming.split(framed.prefix(3)))
        XCTAssertNil(RecordFraming.split(framed.prefix(4 + 500)))
        XCTAssertEqual(RecordFraming.split(Data()), [])
    }

    /// The one byte of guards parses as `ScreenGuards.kt` parses it: two
    /// bits, and nothing else.
    func testScreenGuardsParseTheirByte() throws {
        XCTAssertEqual(try ScreenGuards.parse(Data([0])), .none)
        XCTAssertEqual(try ScreenGuards.parse(Data([1])).secret, try ScreenGuards.parse(Data([3])).secret)
        XCTAssertEqual(try ScreenGuards.parse(Data([2])).confirm, try ScreenGuards.parse(Data([3])).confirm)
        XCTAssertEqual(try ScreenGuards.parse(Data([1])).confirm, ScreenGuards.none.confirm)
        XCTAssertThrowsError(try ScreenGuards.parse(Data([4])))
        XCTAssertThrowsError(try ScreenGuards.parse(Data([1, 1])))
        XCTAssertThrowsError(try ScreenGuards.parse(Data()))
    }

    /// Event topics are the characters Android's host admits, no others.
    func testTopicsAreSanitized() {
        XCTAssertEqual(WalletWebView.safeTopic("session.state"), "session.state")
        XCTAssertEqual(WalletWebView.safeTopic("dsm-wallet-refresh"), "dsm-wallet-refresh")
        XCTAssertNil(WalletWebView.safeTopic("a topic"))
        XCTAssertNil(WalletWebView.safeTopic("x\");alert(1);//"))
        XCTAssertNil(WalletWebView.safeTopic(""))
    }
}
