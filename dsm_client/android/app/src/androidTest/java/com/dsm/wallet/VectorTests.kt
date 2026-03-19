package com.dsm.wallet

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import java.io.BufferedReader
import java.io.InputStreamReader
import com.dsm.wallet.bridge.Unified
import com.dsm.wallet.bridge.UnifiedNativeApi

@RunWith(AndroidJUnit4::class)
class VectorTests {

    enum class RejectCode(val wire: String) {
        ACCEPT("ACCEPT"),
        DECODE_ERROR("DECODE_ERROR"),
        PROOF_TOO_LARGE("PROOF_TOO_LARGE"),
        INVALID_PROOF("INVALID_PROOF"),
        MISSING_WITNESS("MISSING_WITNESS"),
        MODAL_CONFLICT_PENDING_ONLINE("MODAL_CONFLICT_PENDING_ONLINE"),
        STORAGE_ERROR("STORAGE_ERROR"),
        UNKNOWN_REJECT("UNKNOWN_REJECT");

        companion object {
            fun parse(s: String): RejectCode {
                val t = s.trim()
                return values().firstOrNull { it.wire == t }
                    ?: throw IllegalArgumentException("unknown RejectCode: $t")
            }
        }
    }

    private fun readExpectedCode(ctx: Context, path: String): RejectCode {
        ctx.assets.open(path).use { input ->
            BufferedReader(InputStreamReader(input)).useLines { lines ->
                for (raw in lines) {
                    val line = raw.trim()
                    if (line.isEmpty() || line.startsWith("#")) continue
                    val idx = line.indexOf('=')
                    if (idx <= 0) continue
                    val k = line.substring(0, idx).trim()
                    val v = line.substring(idx + 1).trim()
                    if (k == "code") return RejectCode.parse(v)
                }
            }
        }
        throw IllegalArgumentException("expected.kv missing code=...")
    }

    private fun readBytes(ctx: Context, path: String): ByteArray =
        ctx.assets.open(path).use { it.readBytes() }

    private fun processWireOnMobile(wire: ByteArray): RejectCode {
        val response = Unified.processEnvelopeV3(wire)
        val errorCode = UnifiedNativeApi.isErrorEnvelope(response)
        if (errorCode == 0) {
            return RejectCode.ACCEPT
        }
        return when (errorCode) {
            400 -> RejectCode.DECODE_ERROR
            470 -> RejectCode.PROOF_TOO_LARGE
            471 -> RejectCode.INVALID_PROOF
            472 -> RejectCode.MISSING_WITNESS
            473 -> RejectCode.MODAL_CONFLICT_PENDING_ONLINE
            474 -> RejectCode.STORAGE_ERROR
            else -> RejectCode.UNKNOWN_REJECT
        }
    }

    @Test
    fun vectorsV1() {
        val ctx = InstrumentationRegistry.getInstrumentation().context
        val base = "vectors/v1"

        val manifestPath = "$base/manifest.txt"
        val caseIds = ctx.assets.open(manifestPath).use { input ->
            BufferedReader(InputStreamReader(input)).readLines()
                .map { it.trim() }
                .filter { it.isNotEmpty() && !it.startsWith("#") }
        }

        for (caseId in caseIds) {
            val reqPath = "$base/$caseId/request.bin"
            val expPath = "$base/$caseId/expected.kv"

            val wire = readBytes(ctx, reqPath)
            val expected = readExpectedCode(ctx, expPath)
            val got = processWireOnMobile(wire)

            assertEquals("case=$caseId", expected, got)
        }
    }
}
