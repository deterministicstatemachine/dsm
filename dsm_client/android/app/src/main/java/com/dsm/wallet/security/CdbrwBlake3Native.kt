package com.dsm.wallet.security

import com.dsm.wallet.bridge.UnifiedNativeApi

/**
 * Rust-backed bridge for DSM domain-separated BLAKE3 hashing.
 *
 * All DSM hashing uses: BLAKE3-256("DSM/<domain>\0" || data)
 * The NUL byte is part of the hash preimage per DSM spec.
 */
object CdbrwBlake3Native {
    /**
     * Compute BLAKE3-256(tag || data) where tag includes NUL terminator.
     *
     * @param tag Domain tag bytes including trailing NUL (e.g., "DSM/dbrw-bind\0".toByteArray())
     * @param data Payload bytes
     * @return 32-byte BLAKE3 hash
     */
    @JvmStatic
    fun nativeBlake3DomainHash(tag: ByteArray, data: ByteArray): ByteArray? =
        UnifiedNativeApi.cdbrwDomainHash(tag, data)

    /**
     * Convenience: domain hash with string tag. Appends NUL automatically.
     *
     * @param domain Domain string (e.g., "DSM/dbrw-bind")
     * @param data Payload bytes
     * @return 32-byte BLAKE3 hash
     */
    @JvmStatic
    fun domainHash(domain: String, data: ByteArray): ByteArray {
        // Tag = domain string bytes + NUL terminator
        val domainBytes = domain.toByteArray(Charsets.UTF_8)
        val tag = ByteArray(domainBytes.size + 1)
        System.arraycopy(domainBytes, 0, tag, 0, domainBytes.size)
        // tag[domainBytes.size] is already 0 (NUL)
        return nativeBlake3DomainHash(tag, data)
            ?: throw IllegalStateException("Rust BLAKE3 hash returned null")
    }
}
