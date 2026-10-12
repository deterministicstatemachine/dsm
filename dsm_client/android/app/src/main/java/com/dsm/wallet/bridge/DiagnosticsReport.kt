// SPDX-License-Identifier: MIT OR Apache-2.0

package com.dsm.wallet.bridge

import android.app.Activity
import android.content.ClipData
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.content.FileProvider
import androidx.core.content.pm.PackageInfoCompat
import java.io.File
import java.io.IOException
import java.io.Writer

/**
 * The beta debug report: what the app measured, the app's own log and the
 * bridge log, in one text file the user sends through the Android share
 * sheet. A WebView cannot save a file itself, so the report is written and
 * shared here.
 *
 * logcat's buffer holds minutes of this app's log, and a report is often
 * asked for long after the failure it describes. [startRollingLog] keeps the
 * app's log on disk from process start, rotated at [ROTATE_KB] KB across
 * [ROTATE_FILES] files.
 */
internal object DiagnosticsReport {
    private const val TAG = "DiagnosticsReport"
    private const val DIR = "diagnostics"
    private const val ROLLING_NAME = "app.log"
    private const val REPORT_NAME = "dsm-diagnostics.txt"
    private const val ROTATE_KB = "1024"
    private const val ROTATE_FILES = "8"

    /** The FileProvider authority the manifest declares for the report. */
    fun authority(context: Context): String = "${context.packageName}.diagnostics"

    // The WebView's compositor writes these under the app's pid about ten times
    // a second; they say nothing about the wallet and would bury it.
    private val NOISE_TAGS = listOf("View", "GPUAUX", "BufferQueueProducer")
    private val NOISE_TEXT = listOf("setRequestedFrameRate", "GuiExtAuxCheckAuxPath", "BufferQueueProducer")

    @Volatile private var rolling: Process? = null
    @Volatile private var rollingFailure: String? = null

    /**
     * Starts the on-disk log once per process: a `logcat` child reading this
     * app's own lines (an app reads only its own) into `files/diagnostics/`.
     * The wallet's Rust log at Info and every other tag at Info, the
     * compositor's tags silenced. A start that fails is kept and stated in
     * the report.
     */
    fun startRollingLog(context: Context) {
        synchronized(this) {
            if (rolling != null) return
            val dir = File(context.filesDir, DIR)
            dir.mkdirs()
            val spec = mutableListOf(
                "logcat", "-v", "threadtime", "-T", "1",
                "-f", File(dir, ROLLING_NAME).absolutePath,
                "-r", ROTATE_KB, "-n", ROTATE_FILES,
                "DSM_RUST:I",
            )
            NOISE_TAGS.forEach { spec.add("$it:S") }
            spec.add("*:I")
            try {
                rolling = Runtime.getRuntime().exec(spec.toTypedArray())
                rollingFailure = null
            } catch (e: IOException) {
                rollingFailure = e.message ?: e.javaClass.simpleName
                Log.w(TAG, "the on-disk app log did not start", e)
            }
        }
    }

    /** Writes the report into the cache and answers its file. */
    fun write(context: Context, summary: String): File {
        val dir = File(context.cacheDir, DIR)
        dir.mkdirs()
        val out = File(dir, REPORT_NAME)
        out.bufferedWriter().use { w ->
            w.appendLine("=== DSM debug report ===")
            writeHeader(context, w)
            w.appendLine()
            w.appendLine("=== What the app measured ===")
            w.appendLine(summary)
            w.appendLine()
            w.appendLine("=== App log kept on disk, oldest first ===")
            writeRollingLog(context, w)
            w.appendLine()
            w.appendLine("=== App log in logcat's buffer now ===")
            writeLiveBuffer(w)
            w.appendLine()
            w.appendLine("=== Bridge log ===")
            w.append(String(BridgeLogger.readLogBytes(), Charsets.UTF_8))
        }
        return out
    }

    /** Opens the share sheet with the report; the user picks where it goes. */
    fun share(activity: Activity, report: File) {
        val uri = FileProvider.getUriForFile(activity, authority(activity), report)
        val send = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            putExtra(Intent.EXTRA_SUBJECT, "DSM debug report")
            clipData = ClipData.newRawUri(REPORT_NAME, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        val chooser = Intent.createChooser(send, "Send the DSM debug report").apply {
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        activity.runOnUiThread {
            try {
                activity.startActivity(chooser)
            } catch (t: Throwable) {
                // The launch runs after this answer went out; the UI thread can only log it.
                Log.w(TAG, "the share sheet did not open", t)
            }
        }
    }

    private fun writeHeader(context: Context, w: Writer) {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        w.appendLine(
            "app=${context.packageName} version=${info.versionName} code=${PackageInfoCompat.getLongVersionCode(info)} " +
                "installed=${info.firstInstallTime} updated=${info.lastUpdateTime}"
        )
        w.appendLine(
            "device=${Build.MANUFACTURER} ${Build.MODEL} android=${Build.VERSION.RELEASE} " +
                "sdk=${Build.VERSION.SDK_INT} abis=${Build.SUPPORTED_ABIS.joinToString(",")}"
        )
        val proc = rolling
        val state = when {
            proc == null -> "not running: ${rollingFailure ?: "never started in this process"}"
            proc.isAlive -> "running"
            else -> "exited with ${proc.exitValue()}"
        }
        w.appendLine("on-disk log=$state")
    }

    private fun writeRollingLog(context: Context, w: Writer) {
        val dir = File(context.filesDir, DIR)
        val files = dir.listFiles { f -> f.name == ROLLING_NAME || f.name.startsWith("$ROLLING_NAME.") }
        if (files == null || files.isEmpty()) {
            w.appendLine("(no file in ${dir.absolutePath})")
            return
        }
        // logcat rotates app.log to app.log.1, app.log.1 to app.log.2 and so on:
        // the highest number is the oldest, app.log the newest.
        files.sortedByDescending { rotationIndex(it.name) }.forEach { f ->
            f.forEachLine { line -> w.appendLine(line) }
        }
    }

    private fun rotationIndex(name: String): Int =
        if (name == ROLLING_NAME) 0 else name.substringAfterLast('.').toInt()

    private fun writeLiveBuffer(w: Writer) {
        val proc = Runtime.getRuntime().exec(arrayOf("logcat", "-d", "-v", "threadtime"))
        proc.inputStream.bufferedReader().useLines { lines ->
            lines.filter { line -> NOISE_TEXT.none { line.contains(it) } }
                .forEach { w.appendLine(it) }
        }
        val code = proc.waitFor()
        if (code != 0) {
            w.appendLine("(logcat -d exited with $code: ${proc.errorStream.bufferedReader().readText().trim()})")
        }
    }
}
