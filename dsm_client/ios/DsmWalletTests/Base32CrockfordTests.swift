// SPDX-License-Identifier: MIT OR Apache-2.0

import XCTest
@testable import DsmWallet

final class Base32CrockfordTests: XCTestCase {
    /// The page and the host agree on every byte that crosses the string
    /// channel: bytes round-trip, and the alphabet is Crockford's.
    func testBytesRoundTripAndTheAlphabetIsCrockford() {
        let bytes = Data((0...255).map { UInt8($0) })
        let text = Base32Crockford.encode(bytes)
        XCTAssertEqual(Base32Crockford.decode(text), bytes)
        XCTAssertNil(text.first { !"0123456789ABCDEFGHJKMNPQRSTVWXYZ".contains($0) })
        XCTAssertEqual(Base32Crockford.encode(Data()), "")
        XCTAssertEqual(Base32Crockford.decode(""), Data())
    }

    /// The encoding Kotlin's `BridgeEncoding` writes for a 32-byte id is 52
    /// characters and decodes on this side to the same id.
    func testADeviceIdIsFiftyTwoCharacters() {
        let id = Data(repeating: 0x7A, count: 32)
        let text = Base32Crockford.encode(id)
        XCTAssertEqual(text.count, 52)
        XCTAssertEqual(Base32Crockford.decode(text), id)
        XCTAssertEqual(Base32Crockford.decode(text.lowercased()), id)
    }
}
