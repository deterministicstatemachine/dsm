package com.dsm.wallet.ui

/**
 * Tracks the QR scanner round-trip window that must not trigger wallet auto-lock.
 *
 * MainActivity pauses while QrScannerActivity is on top. The wallet must remain
 * exempt from lock-on-pause until MainActivity has resumed and settled after the
 * scan result callback, otherwise the result callback can briefly publish
 * app_foreground=false with qr_active=false and Rust will lock the session.
 */
internal data class QrLockRoundTripState(
    val scannerActive: Boolean = false,
    val resumePending: Boolean = false,
) {
    fun effectiveQrActive(): Boolean = scannerActive || resumePending

    fun onScannerLaunch(): QrLockRoundTripState =
        copy(scannerActive = true, resumePending = true)

    fun onScannerLaunchFailure(): QrLockRoundTripState =
        copy(scannerActive = false, resumePending = false)

    fun onScannerResult(): QrLockRoundTripState =
        copy(scannerActive = false)

    fun onResumeSettled(): QrLockRoundTripState =
        copy(scannerActive = false, resumePending = false)
}
