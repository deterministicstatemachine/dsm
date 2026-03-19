package com.dsm.wallet.bridge.ble

/**
 * Lightweight structured BLE event for in-app diagnostics (line-based export – purposely not JSON).
 * Format when serialized: ts|phase|device|frameType|status|detail|bytes|chunkIndex|chunkTotal
 */
data class BleDiagEvent(
    val ts: Long = 0L, // Deterministic sequence number (not wall clock)
    val phase: String,
    val device: String? = null,
    val frameType: Int? = null,
    val status: Int? = null,
    val detail: String? = null,
    val bytes: Int? = null,
    val chunkIndex: Int? = null,
    val chunkTotal: Int? = null,
) {
    fun serialize(): String {
        fun esc(v: String?): String = v?.replace('|', '/') ?: ""
        return listOf(
            ts.toString(),
            esc(phase),
            esc(device),
            frameType?.toString() ?: "",
            status?.toString() ?: "",
            esc(detail),
            bytes?.toString() ?: "",
            chunkIndex?.toString() ?: "",
            chunkTotal?.toString() ?: "",
        ).joinToString("|")
    }
}