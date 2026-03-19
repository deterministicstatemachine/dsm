package com.dsm.wallet.bridge.ble

/**
 * Events emitted by GattClientSession to communicate state changes to BleCoordinator.
 * This replaces direct atomic variable access to eliminate split-brain concurrency issues.
 */
sealed class BleSessionEvent {
    abstract val deviceAddress: String

    data class Connected(override val deviceAddress: String) : BleSessionEvent()
    data class Disconnected(override val deviceAddress: String, val status: Int) : BleSessionEvent()
    data class MtuNegotiated(override val deviceAddress: String, val mtu: Int) : BleSessionEvent()
    data class ServiceDiscoveryCompleted(override val deviceAddress: String, val success: Boolean) : BleSessionEvent()
    data class IdentityReadCompleted(override val deviceAddress: String, val data: ByteArray?) : BleSessionEvent()
    data class TransactionWriteCompleted(override val deviceAddress: String, val success: Boolean) : BleSessionEvent()
    data class ResponseReceived(override val deviceAddress: String, val data: ByteArray) : BleSessionEvent()
    /** Advertiser confirmed it processed our identity — bilateral pairing can complete. */
    data class PairingAckReceived(override val deviceAddress: String, val data: ByteArray) : BleSessionEvent()
    /** Scanner's BlePairingConfirm write to the advertiser was acknowledged by the BLE stack.
     *  Only after this fires is it safe to allow session eviction. */
    data class PairingConfirmWritten(override val deviceAddress: String) : BleSessionEvent()
    data class ErrorOccurred(override val deviceAddress: String, val category: BleErrorCategory, val details: String, val status: Int? = null) : BleSessionEvent()
}