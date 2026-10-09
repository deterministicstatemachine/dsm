// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

internal object UnifiedContactBridge {

    fun hasContactForDeviceId(deviceId: ByteArray): Boolean {
        return try { Unified.hasContactForDeviceId(deviceId) } catch (_: Throwable) { false }
    }
}
