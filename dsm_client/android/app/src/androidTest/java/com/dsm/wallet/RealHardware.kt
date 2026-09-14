// SPDX-License-Identifier: Apache-2.0
package com.dsm.wallet

/**
 * Marks an instrumented test that needs real hardware: two paired phones and
 * the live storage fleet (the SoFi cross-device and real-hardware trade
 * harnesses). CI runs the instrumented suite on a Gradle managed device with
 * `notAnnotation=com.dsm.wallet.RealHardware`, so these compile in CI and run
 * only from a hands-on four-phone session.
 */
@Retention(AnnotationRetention.RUNTIME)
@Target(AnnotationTarget.CLASS, AnnotationTarget.FUNCTION)
annotation class RealHardware
