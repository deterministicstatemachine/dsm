package com.dsm.wallet.security

import android.content.Context
import android.util.Log
import java.io.File
import java.io.FileWriter
import java.util.concurrent.Executors

/**
 * Decoupled diagnostics observer for silicon fingerprint drift logging.
 * Runs logging operations asynchronously to prevent I/O failures from blocking security operations.
 * Only logs safe digests of sensitive data, never raw bytes.
 */
class DriftDiagnosticsObserver(private val context: Context) {

    private val executor = Executors.newSingleThreadExecutor()
    private val logFile: File by lazy {
        File(context.getExternalFilesDir(null), "drift_diagnostics.log")
    }
    private var entryCounter = 0L

    companion object {
        private const val TAG = "DriftDiagnostics"
    }

    /**
     * Asynchronously log a drift entry with safe digests.
     * All sensitive data is hashed before logging to prevent information leakage.
     */
    fun logDriftEntryAsync(
        entryId: String,
        result: String,
        baselineHwDigest: String?,
        baselineEnvDigest: String?,
        enrolledHwDigest: String?,
        currentHwDigest: String?,
        enrolledEnvDigest: String?,
        currentEnvDigest: String?
    ) {
        executor.execute {
            try {
                val entrySeq = entryCounter++
                val entry = buildString {
                    append("$entrySeq|$entryId|$result|")
                    append("${baselineHwDigest ?: "null"}|")
                    append("${baselineEnvDigest ?: "null"}|")
                    append("${enrolledHwDigest ?: "null"}|")
                    append("${currentHwDigest ?: "null"}|")
                    append("${enrolledEnvDigest ?: "null"}|")
                    append("${currentEnvDigest ?: "null"}")
                }

                synchronized(this) {
                    FileWriter(logFile, true).use { writer ->
                        writer.appendLine(entry)
                    }
                }

                Log.d(TAG, "Logged drift entry: $entryId - $result")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to log drift entry asynchronously", e)
                // Don't throw - logging failure should not affect security operations
            }
        }
    }

    /**
     * Create a safe digest of sensitive data for logging.
     * Uses domain-separated BLAKE3 to create a non-reversible digest that can be safely logged.
     */
    fun createSafeDigest(data: ByteArray?): String? {
        if (data == null) return null
        return try {
            val digest = CdbrwBlake3Native.domainHash("DSM/diagnostics/drift", data)
            digest.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to create safe digest", e)
            null
        }
    }

    private fun countBitDifferences(a: ByteArray, b: ByteArray): Int {
        if (a.size != b.size) return Int.MAX_VALUE
        var differences = 0
        for (i in a.indices) {
            val xor = a[i].toInt() xor b[i].toInt()
            differences += Integer.bitCount(xor)
        }
        return differences
    }

    /**
     * Data class for drift metrics (used only for diagnostics).
     */
    data class DriftMetrics(
        val totalDrift: Int,
        val maxByteDrift: Int,
        val changedBytes: Int,
        val totalBytes: Int,
        val percentBytesChanged: Float,
        val avgDriftPerByte: Float,
        val driftDistribution: IntArray
    )
}