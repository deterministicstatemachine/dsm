package com.dsm.wallet.ui

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QrLockRoundTripStateTest {
    @Test
    fun scanner_round_trip_keeps_qr_active_until_resume_settles() {
        val launched = QrLockRoundTripState().onScannerLaunch()
        assertTrue(launched.effectiveQrActive())

        val resultDelivered = launched.onScannerResult()
        assertFalse(resultDelivered.scannerActive)
        assertTrue(resultDelivered.resumePending)
        assertTrue(resultDelivered.effectiveQrActive())

        val settled = resultDelivered.onResumeSettled()
        assertFalse(settled.scannerActive)
        assertFalse(settled.resumePending)
        assertFalse(settled.effectiveQrActive())
    }

    @Test
    fun launch_failure_clears_qr_lock_bypass() {
        val failed = QrLockRoundTripState().onScannerLaunch().onScannerLaunchFailure()
        assertFalse(failed.scannerActive)
        assertFalse(failed.resumePending)
        assertFalse(failed.effectiveQrActive())
    }
}
