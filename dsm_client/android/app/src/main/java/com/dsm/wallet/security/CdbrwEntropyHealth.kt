package com.dsm.wallet.security

import android.util.Log

/**
 * C-DBRW Entropy Health Test.
 *
 * Base 3-condition health test (Definition 4.15):
 *   1. H_hat >= 0.45 (Shannon entropy)
 *   2. |rho_hat| <= 0.3 (lag-1 autocorrelation)
 *   3. L_hat >= 0.45 (LZ78 compressibility)
 *
 * Resonant health tier (C-DBRW spec sections 4.5.4, 4.6, 7, 8.1):
 *   PASS     — all 3 conditions met
 *   RESONANT — rho exceeds threshold but h0_eff >= h_min; thermal coupling
 *              strengthens fingerprint per Theorem 8.1(ii)
 *   ADAPTED  — h0_eff below h_min but compensable with longer orbits (Remark 4.6)
 *   FAIL     — fundamental entropy collapse
 *
 * Manufacturing gate:
 *   sigma_device = std(H_bar) / max(H_bar) >= 0.04
 */
object CdbrwEntropyHealth {
    private const val TAG = "CdbrwEntropyHealth"

    init {
        System.loadLibrary("dsm_entropy_health_jni")
    }

    const val HEALTH_N = 4096
    const val H_HAT_MIN = 0.45f
    const val RHO_HAT_MAX = 0.30f
    const val L_HAT_MIN = 0.45f
    const val SIGMA_DEV_MIN = 0.04f
    /** C-DBRW spec section 4.5.5: minimum entropy rate h_min = 0.5 bits/sample */
    const val H_MIN = 0.5f
    /** C-DBRW spec Remark 4.6: adapted mixing floor */
    const val H0_ADAPTED_FLOOR = 0.25f

    /** 4-tier resonant health status per C-DBRW spec section 7. */
    enum class ResonantStatus { PASS, RESONANT, ADAPTED, FAIL }

    data class HealthResult(
        val hHat: Float,
        val rhoHat: Float,
        val lHat: Float,
        val passed: Boolean,
        /** Effective entropy rate: hHat * (1 - |rhoHat|) per Proposition 4.23. */
        val h0Eff: Float,
        /** Resonant health tier per tri-layer assessment (section 7). */
        val resonantStatus: ResonantStatus,
    )

    data class ManufacturingGateResult(
        val sigmaDevice: Float,
        val passed: Boolean
    )

    /**
     * Run 3-condition health test on orbit timing samples.
     *
     * @param samples Raw timing values (nanoseconds), should have HEALTH_N entries
     * @param bins Histogram bins for entropy calculation (default 256)
     * @return HealthResult with all three metrics and pass/fail
     */
    @JvmStatic
    fun healthTest(samples: LongArray, bins: Int = 256): HealthResult {
        if (samples.size < HEALTH_N) {
            Log.w(TAG, "Only ${samples.size} samples provided, expected $HEALTH_N")
        }
        val result = nativeHealthTest(samples, bins)
            ?: return HealthResult(0f, 0f, 0f, false, 0f, ResonantStatus.FAIL)
        val hHat = result[0]
        val rhoHat = result[1]
        val lHat = result[2]
        val basePass = result[3] > 0.5f
        val h0Eff = hHat * (1f - kotlin.math.abs(rhoHat))
        val entropyOk = hHat >= H_HAT_MIN && lHat >= L_HAT_MIN

        val resonantStatus = when {
            basePass -> ResonantStatus.PASS
            entropyOk && h0Eff >= H_MIN -> ResonantStatus.RESONANT
            entropyOk && h0Eff >= H0_ADAPTED_FLOOR -> ResonantStatus.ADAPTED
            else -> ResonantStatus.FAIL
        }

        return HealthResult(
            hHat = hHat,
            rhoHat = rhoHat,
            lHat = lHat,
            passed = resonantStatus != ResonantStatus.FAIL,
            h0Eff = h0Eff,
            resonantStatus = resonantStatus,
        )
    }

    /**
     * Evaluate manufacturing gate from enrollment entropy values.
     *
     * @param hBars Per-trial entropy values from enrollment
     * @return ManufacturingGateResult with sigma_device and pass/fail
     */
    @JvmStatic
    fun manufacturingGate(hBars: FloatArray): ManufacturingGateResult {
        if (hBars.size < 2) {
            return ManufacturingGateResult(0f, false)
        }
        val result = nativeManufacturingGate(hBars)
            ?: return ManufacturingGateResult(0f, false)
        return ManufacturingGateResult(
            sigmaDevice = result[0],
            passed = result[1] > 0.5f
        )
    }

    @JvmStatic
    private external fun nativeHealthTest(samples: LongArray, bins: Int): FloatArray?

    @JvmStatic
    private external fun nativeManufacturingGate(hBars: FloatArray): FloatArray?
}
