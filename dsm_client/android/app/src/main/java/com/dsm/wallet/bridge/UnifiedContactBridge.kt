package com.dsm.wallet.bridge

internal object UnifiedContactBridge {

    fun resolveBleAddressForDeviceIdBin(deviceId: ByteArray): ByteArray {
        return try { Unified.resolveBleAddressForDeviceIdBin(deviceId) } catch (_: Throwable) { ByteArray(0) }
    }

    fun handleContactQrV3(bytes: ByteArray): ByteArray {
        return try { Unified.handleContactQrV3(bytes) } catch (_: Throwable) { ByteArray(0) }
    }

    fun removeContact(contactId: String): Byte {
        return try { Unified.removeContact(contactId) } catch (_: Throwable) { 0 }
    }

    fun hasContactForDeviceId(deviceId: ByteArray): Boolean {
        return try { Unified.hasContactForDeviceId(deviceId) } catch (_: Throwable) { false }
    }

    fun isBleAddressPaired(address: String): Boolean {
        return try { Unified.isBleAddressPaired(address) } catch (_: Throwable) { false }
    }

    fun hasUnpairedContacts(): Boolean {
        return try { Unified.hasUnpairedContacts() } catch (_: Throwable) { false }
    }
}
