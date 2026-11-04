// SPDX-License-Identifier: MIT OR Apache-2.0

import Foundation

/// Why a bridge request was not answered with data: the codes the page reads
/// in a `BridgeRpcResponse` error, as `SinglePathWebViewBridge.kt` numbers them.
enum BridgeFailure: Error, CustomStringConvertible {
    case notInitialized(String)
    case invalidPayload(String)
    case native(String)
    case network(String)
    case permissionDenied(String)
    case invalidState(String)
    case timeout(String)
    case unknownMethod(String)

    var code: UInt32 {
        switch self {
        case .notInitialized: return 1
        case .invalidPayload: return 2
        case .native: return 3
        case .network: return 4
        case .permissionDenied: return 5
        case .invalidState: return 6
        case .timeout: return 7
        case .unknownMethod: return 8
        }
    }

    var description: String {
        switch self {
        case .notInitialized(let m): return m
        case .invalidPayload(let m): return "Invalid payload: \(m)"
        case .native(let m): return "Native error: \(m)"
        case .network(let m): return "Network error: \(m)"
        case .permissionDenied(let m): return "Permission denied: \(m)"
        case .invalidState(let m): return "Invalid state: \(m)"
        case .timeout(let m): return "Network timeout: \(m)"
        case .unknownMethod(let m): return m
        }
    }
}
