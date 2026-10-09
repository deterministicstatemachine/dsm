// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge.ble

/**
 * What [BleCoordinator] reports about the radio. Each call states something the
 * radio itself answered: a start the stack confirmed, a stop, a scan that ended,
 * a permission the system refused. The coordinator derives every call from the
 * advertiser's and scanner's own results and callbacks; nothing here decides
 * anything.
 */
internal interface BleRadioEvents {
    fun advertisingStarted()
    fun advertisingStopped()
    fun scanStarted()
    fun scanStopped()
    fun permissionDenied(operation: String)
}

/** The production sink: each event goes to Rust, which frames it for the WebView. */
internal object UnifiedRadioEvents : BleRadioEvents {
    override fun advertisingStarted() = com.dsm.wallet.bridge.Unified.onAdvertisingStarted()
    override fun advertisingStopped() = com.dsm.wallet.bridge.Unified.onAdvertisingStopped()
    override fun scanStarted() = com.dsm.wallet.bridge.Unified.onScanStarted()
    override fun scanStopped() = com.dsm.wallet.bridge.Unified.onScanStopped()
    override fun permissionDenied(operation: String) {
        val envelope = com.dsm.wallet.bridge.UnifiedNativeApi.createBlePermissionDeniedEnvelope(operation)
        if (envelope.isNotEmpty()) com.dsm.wallet.bridge.BleEventRelay.dispatchEnvelope(envelope)
    }
}
