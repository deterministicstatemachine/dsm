// JNI bridge for C-DBRW attractor envelope test (moments + Merkle tree).

#include <jni.h>
#include <string.h>
#include "cdbrw_moments.h"

extern "C"
JNIEXPORT jbyteArray JNICALL
Java_com_dsm_wallet_security_CdbrwEnvelopeTest_nativeEnvelopeTest(
        JNIEnv *env, jclass,
        jfloatArray jHistogram,
        jint bins
) {
    if (!jHistogram || bins <= 0) return nullptr;
    jsize hist_len = env->GetArrayLength(jHistogram);
    if (hist_len != bins) return nullptr;

    jfloat *hist = env->GetFloatArrayElements(jHistogram, nullptr);
    if (!hist) return nullptr;

    // Step 1: Compute moments
    double moments[CDBRW_NUM_MOMENTS];
    cdbrw_compute_moments(hist, (size_t)bins, moments);

    env->ReleaseFloatArrayElements(jHistogram, hist, JNI_ABORT);

    // Step 2: Commit moments
    uint8_t commitments[CDBRW_NUM_MOMENTS * 32];
    cdbrw_commit_moments(moments, commitments);

    // Step 3: Build Merkle tree
    const int total_nodes = 2 * CDBRW_NUM_MOMENTS - 1; // 15
    uint8_t tree[total_nodes * 32];
    uint8_t root[32];
    cdbrw_merkle_moments(commitments, root, tree);

    // Pack result: moments (64 bytes) + commitments (256 bytes) + root (32 bytes) + tree (480 bytes)
    const int result_size = CDBRW_NUM_MOMENTS * 8 + CDBRW_NUM_MOMENTS * 32 + 32 + total_nodes * 32;
    jbyteArray result = env->NewByteArray(result_size);
    if (!result) return nullptr;

    int off = 0;

    // Moments as LE64 doubles
    uint8_t moment_bytes[CDBRW_NUM_MOMENTS * 8];
    for (int i = 0; i < CDBRW_NUM_MOMENTS; i++) {
        uint64_t bits;
        memcpy(&bits, &moments[i], sizeof(uint64_t));
        for (int b = 0; b < 8; b++) {
            moment_bytes[i * 8 + b] = (uint8_t)(bits >> (b * 8));
        }
    }
    env->SetByteArrayRegion(result, off, CDBRW_NUM_MOMENTS * 8, reinterpret_cast<const jbyte *>(moment_bytes));
    off += CDBRW_NUM_MOMENTS * 8;

    // Commitments
    env->SetByteArrayRegion(result, off, CDBRW_NUM_MOMENTS * 32, reinterpret_cast<const jbyte *>(commitments));
    off += CDBRW_NUM_MOMENTS * 32;

    // Root
    env->SetByteArrayRegion(result, off, 32, reinterpret_cast<const jbyte *>(root));
    off += 32;

    // Full tree
    env->SetByteArrayRegion(result, off, total_nodes * 32, reinterpret_cast<const jbyte *>(tree));

    return result;
}
