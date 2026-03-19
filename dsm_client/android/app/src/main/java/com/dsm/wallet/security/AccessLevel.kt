package com.dsm.wallet.security

/**
 * Access level enum for tiered trust system.
 */
enum class AccessLevel {
    FULL_ACCESS,
    PIN_REQUIRED,
    READ_ONLY,
    BLOCKED;

    companion object {
        fun minOf(a: AccessLevel, b: AccessLevel): AccessLevel {
            return if (a.ordinal < b.ordinal) a else b
        }
    }
}