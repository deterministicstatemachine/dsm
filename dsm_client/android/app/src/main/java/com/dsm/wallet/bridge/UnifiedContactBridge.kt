// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

internal object UnifiedContactBridge {

    fun removeContact(contactId: String): Byte {
        return try { Unified.removeContact(contactId) } catch (_: Throwable) { 0 }
    }

    fun hasContactForDeviceId(deviceId: ByteArray): Boolean {
        return try { Unified.hasContactForDeviceId(deviceId) } catch (_: Throwable) { false }
    }
}
