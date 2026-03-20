package com.dsm.wallet.bridge

import android.os.SystemClock
import android.util.Log
import com.dsm.wallet.BuildConfig
import java.io.File
import java.io.FileOutputStream
import java.io.PrintWriter

internal object BridgeLogger {

    private const val TAG = "SinglePathWebViewBridge"
    private const val MAX_LOG_BYTES: Long = 5L * 1024L * 1024L
    private var logFile: File? = null

    fun setLogFile(file: File) {
        logFile = file
    }

    fun readLogBytes(maxBytes: Long = MAX_LOG_BYTES): ByteArray {
        val file = logFile ?: return ByteArray(0)
        return try {
            if (!file.exists()) return ByteArray(0)
            val len = file.length()
            if (len <= 0) return ByteArray(0)
            val readLen = if (len > maxBytes) maxBytes else len
            java.io.RandomAccessFile(file, "r").use { raf ->
                if (len > readLen) raf.seek(len - readLen)
                val buf = ByteArray(readLen.toInt())
                raf.readFully(buf)
                buf
            }
        } catch (_: Exception) {
            ByteArray(0)
        }
    }

    fun logDiagnosticsPayload(payload: ByteArray) {
        val preview = if (payload.size <= 64) {
            BridgeEncoding.base32CrockfordEncode(payload)
        } else {
            BridgeEncoding.base32CrockfordEncode(payload.copyOfRange(0, 64)) + "..."
        }
        appendLine("DIAGNOSTICS: payload=${payload.size}b b32=$preview")
    }

    fun logBridgeCall(method: String, payload: ByteArray, response: ByteArray?, error: Throwable?) {
        // Always log to file for Beta diagnostics, even if !DEBUG
        val payloadPreview = if (payload.size <= 32) {
            BridgeEncoding.base32CrockfordEncode(payload)
        } else {
            BridgeEncoding.base32CrockfordEncode(payload.copyOfRange(0, 32)) + "..."
        }

        val responsePreview = when {
            error != null -> "ERROR: ${error.message}"
            response == null -> "null"
            response.size <= 32 -> BridgeEncoding.base32CrockfordEncode(response)
            else -> BridgeEncoding.base32CrockfordEncode(response.copyOfRange(0, 32)) + "..."
        }

        val msg = "BRIDGE: $method(payload=${payload.size}b b32=$payloadPreview) -> $responsePreview"
        if (BuildConfig.DEBUG) {
            Log.d(TAG, msg)
        }
        appendLine(msg)
    }

    private fun appendLine(message: String) {
        logFile?.let { file ->
            try {
                val unix_ts = SystemClock.elapsedRealtime()
                PrintWriter(FileOutputStream(file, true)).use { writer ->
                    writer.println("$unix_ts $message")
                }
                trimLogFile(file)
            } catch (_: Exception) {
                // Fail silently to avoid crash loops
            }
        }
    }

    private fun trimLogFile(file: File) {
        try {
            val len = file.length()
            if (len <= MAX_LOG_BYTES) return
            val buf = java.io.RandomAccessFile(file, "r").use { raf ->
                val start = len - MAX_LOG_BYTES
                raf.seek(start)
                val b = ByteArray(MAX_LOG_BYTES.toInt())
                raf.readFully(b)
                b
            }
            java.io.RandomAccessFile(file, "rw").use { out ->
                out.setLength(0)
                out.write(buf)
            }
        } catch (_: Exception) {
            // ignore trim errors
        }
    }
}
