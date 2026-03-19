package com.dsm.wallet.security

import android.content.Context
import android.util.Log

/**
 * C-DBRW Attractor Envelope Test (Def. 6.3).
 *
 * Computes m=8 statistical moments of the orbit density histogram,
 * commits each via BLAKE3("DSM/moment\0" || ...), and assembles into
 * a binary Merkle tree. The root serves as a compact envelope commitment.
 *
 * The Merkle proof for any individual moment can be extracted for
 * selective disclosure during verification.
 */
object CdbrwEnvelopeTest {
    private const val TAG = "CdbrwEnvelope"
    const val NUM_MOMENTS = 8
    const val PROOF_DEPTH = 3 // log2(NUM_MOMENTS)

    init {
        System.loadLibrary("dsm_moments_jni")
    }

    data class EnvelopeResult(
        val moments: DoubleArray,            // 8 raw moments
        val commitments: Array<ByteArray>,    // 8 x 32-byte commitments
        val merkleRoot: ByteArray,            // 32-byte Merkle root
        val merkleTree: ByteArray             // Full tree (15 * 32 bytes) for proof extraction
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is EnvelopeResult) return false
            return moments.contentEquals(other.moments) &&
                    merkleRoot.contentEquals(other.merkleRoot)
        }
        override fun hashCode(): Int {
            return moments.contentHashCode() * 31 + merkleRoot.contentHashCode()
        }
    }

    data class MerkleProof(
        val leafIndex: Int,
        val leafCommitment: ByteArray,
        val siblings: Array<ByteArray> // PROOF_DEPTH siblings
    )

    /**
     * Run the full envelope test: capture orbit, compute moments, build Merkle tree.
     *
     * @param context Android context
     * @param siliconFp SiliconFingerprint instance (uses its config)
     * @return EnvelopeResult with moments, commitments, and Merkle root
     */
    @JvmStatic
    fun runEnvelopeTest(context: Context, siliconFp: SiliconFingerprint = SiliconFingerprint()): EnvelopeResult {
        Log.d(TAG, "Running attractor envelope test...")

        // Capture orbit density
        val env = environmentBytes(context)
        val rawTimings = SiliconFingerprintNative.captureOrbitDensity(
            envBytes = env,
            arenaBytes = siliconFp.config.arenaBytes,
            probes = siliconFp.config.probes,
            stepsPerProbe = siliconFp.config.stepsPerProbe,
            warmupRounds = siliconFp.config.warmupRounds,
            rotationBits = siliconFp.config.rotationBits
        ) ?: throw IllegalStateException("Orbit capture failed")

        // Build histogram
        val histogram = CdbrwMath.buildHistogram(rawTimings, siliconFp.config.histogramBins)

        // Compute moments + commitments + Merkle tree via native code
        val result = nativeEnvelopeTest(histogram, siliconFp.config.histogramBins)
            ?: throw IllegalStateException("Native envelope test failed")

        // Parse result: [moments (8 doubles as bytes), commitments (8*32), root (32), tree (15*32)]
        val moments = DoubleArray(NUM_MOMENTS)
        val commitments = Array(NUM_MOMENTS) { ByteArray(32) }
        val merkleRoot = ByteArray(32)
        val treeSize = (2 * NUM_MOMENTS - 1) * 32
        val merkleTree = ByteArray(treeSize)

        var off = 0
        // Moments: 8 * 8 bytes (IEEE 754 doubles, little-endian)
        val momentBytes = ByteArray(8)
        for (i in 0 until NUM_MOMENTS) {
            System.arraycopy(result, off, momentBytes, 0, 8)
            moments[i] = java.lang.Double.longBitsToDouble(
                (momentBytes[0].toLong() and 0xFF) or
                ((momentBytes[1].toLong() and 0xFF) shl 8) or
                ((momentBytes[2].toLong() and 0xFF) shl 16) or
                ((momentBytes[3].toLong() and 0xFF) shl 24) or
                ((momentBytes[4].toLong() and 0xFF) shl 32) or
                ((momentBytes[5].toLong() and 0xFF) shl 40) or
                ((momentBytes[6].toLong() and 0xFF) shl 48) or
                ((momentBytes[7].toLong() and 0xFF) shl 56)
            )
            off += 8
        }
        // Commitments: 8 * 32 bytes
        for (i in 0 until NUM_MOMENTS) {
            System.arraycopy(result, off, commitments[i], 0, 32)
            off += 32
        }
        // Root: 32 bytes
        System.arraycopy(result, off, merkleRoot, 0, 32)
        off += 32
        // Tree: 15 * 32 bytes
        System.arraycopy(result, off, merkleTree, 0, treeSize)

        Log.d(TAG, "Envelope test complete. Root: ${merkleRoot.take(4).joinToString("") { "%02x".format(it) }}...")
        return EnvelopeResult(moments, commitments, merkleRoot, merkleTree)
    }

    /**
     * Extract Merkle proof for a specific moment.
     */
    @JvmStatic
    fun extractProof(envelope: EnvelopeResult, momentIndex: Int): MerkleProof {
        require(momentIndex in 0 until NUM_MOMENTS) { "momentIndex out of range" }

        val siblings = Array(PROOF_DEPTH) { d ->
            val siblingIdx = if ((momentIndex shr d) % 2 == 0) {
                (momentIndex shr d) + 1
            } else {
                (momentIndex shr d) - 1
            }
            // Find the sibling in the tree
            var levelStart = 0
            var levelSize = NUM_MOMENTS
            for (i in 0 until d) {
                levelStart += levelSize
                levelSize /= 2
            }
            val treeIdx = levelStart + siblingIdx
            val sibling = ByteArray(32)
            System.arraycopy(envelope.merkleTree, treeIdx * 32, sibling, 0, 32)
            sibling
        }

        return MerkleProof(
            leafIndex = momentIndex,
            leafCommitment = envelope.commitments[momentIndex],
            siblings = siblings
        )
    }

    @Suppress("DEPRECATION")
    private fun environmentBytes(context: Context): ByteArray {
        val s = buildString {
            append("DSM/silicon_env/v2\u0000")
            append(android.os.Build.BOARD); append('|')
            append(android.os.Build.BRAND); append('|')
            append(android.os.Build.DEVICE); append('|')
            append(android.os.Build.HARDWARE); append('|')
            append(android.os.Build.MANUFACTURER); append('|')
            append(android.os.Build.MODEL); append('|')
            if (android.os.Build.VERSION.SDK_INT >= 31) {
                try {
                    val socModel = android.os.Build::class.java.getField("SOC_MODEL").get(null) as? String
                    append(socModel ?: "unknown")
                } catch (_: Throwable) { append("unavailable") }
            } else { append("pre31") }
            append('|')
            append(context.packageName)
        }
        return s.toByteArray(Charsets.UTF_8)
    }

    @JvmStatic
    private external fun nativeEnvelopeTest(histogram: FloatArray, bins: Int): ByteArray?
}
