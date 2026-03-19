// JNI bridge for C-DBRW entropy health test and manufacturing gate.

#include <jni.h>
#include "cdbrw_entropy_health.h"

extern "C"
JNIEXPORT jfloatArray JNICALL
Java_com_dsm_wallet_security_CdbrwEntropyHealth_nativeHealthTest(
        JNIEnv *env, jclass,
        jlongArray jSamples,
        jint bins
) {
    if (!jSamples) return nullptr;
    jsize n = env->GetArrayLength(jSamples);
    if (n <= 0 || bins <= 0) return nullptr;

    jlong *samples = env->GetLongArrayElements(jSamples, nullptr);
    if (!samples) return nullptr;

    cdbrw_health_result_t result = cdbrw_health_test(
        reinterpret_cast<const int64_t *>(samples), (size_t)n, (size_t)bins
    );

    env->ReleaseLongArrayElements(jSamples, samples, JNI_ABORT);

    // Return [h_hat, rho_hat, l_hat, passed (0.0 or 1.0)]
    jfloatArray ret = env->NewFloatArray(4);
    if (!ret) return nullptr;
    float values[4] = { result.h_hat, result.rho_hat, result.l_hat, result.passed ? 1.0f : 0.0f };
    env->SetFloatArrayRegion(ret, 0, 4, values);
    return ret;
}

extern "C"
JNIEXPORT jfloatArray JNICALL
Java_com_dsm_wallet_security_CdbrwEntropyHealth_nativeManufacturingGate(
        JNIEnv *env, jclass,
        jfloatArray jHbars
) {
    if (!jHbars) return nullptr;
    jsize n = env->GetArrayLength(jHbars);
    if (n < 2) return nullptr;

    jfloat *h_bars = env->GetFloatArrayElements(jHbars, nullptr);
    if (!h_bars) return nullptr;

    cdbrw_mfg_gate_result_t result = cdbrw_manufacturing_gate(h_bars, (size_t)n);

    env->ReleaseFloatArrayElements(jHbars, h_bars, JNI_ABORT);

    // Return [sigma_device, passed (0.0 or 1.0)]
    jfloatArray ret = env->NewFloatArray(2);
    if (!ret) return nullptr;
    float values[2] = { result.sigma_device, result.passed ? 1.0f : 0.0f };
    env->SetFloatArrayRegion(ret, 0, 2, values);
    return ret;
}
