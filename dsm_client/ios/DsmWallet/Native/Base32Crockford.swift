// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

/// Base32 Crockford, the one textual form bytes take at DSM's display edges
/// and across the page's string-only message channel. The same alphabet and
/// bit packing as `BridgeEncoding.kt`; decoding skips characters outside the
/// alphabet, as it does.
enum Base32Crockford {
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ".utf8)

    private static let lookup: [UInt8: UInt32] = {
        var table: [UInt8: UInt32] = [:]
        for (index, letter) in alphabet.enumerated() {
            table[letter] = UInt32(index)
            let lower = Character(UnicodeScalar(letter)).lowercased().utf8.first
            if let lower { table[lower] = UInt32(index) }
        }
        return table
    }()

    static func encode(_ bytes: Data) -> String {
        var out = [UInt8]()
        out.reserveCapacity((bytes.count * 8 + 4) / 5)
        var buffer: UInt32 = 0
        var bitsLeft = 0
        for byte in bytes {
            buffer = (buffer << 8) | UInt32(byte)
            bitsLeft += 8
            while bitsLeft >= 5 {
                out.append(alphabet[Int((buffer >> UInt32(bitsLeft - 5)) & 0x1F)])
                bitsLeft -= 5
            }
        }
        if bitsLeft > 0 {
            out.append(alphabet[Int((buffer << UInt32(5 - bitsLeft)) & 0x1F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    static func decode(_ text: String) -> Data {
        var out = Data()
        out.reserveCapacity(text.utf8.count * 5 / 8)
        var buffer: UInt32 = 0
        var bitsLeft = 0
        for letter in text.utf8 {
            guard let value = lookup[letter] else { continue }
            buffer = (buffer << 5) | value
            bitsLeft += 5
            if bitsLeft >= 8 {
                out.append(UInt8((buffer >> UInt32(bitsLeft - 8)) & 0xFF))
                bitsLeft -= 8
            }
        }
        return out
    }
}
