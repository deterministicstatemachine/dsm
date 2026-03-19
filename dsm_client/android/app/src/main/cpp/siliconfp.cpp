#include <jni.h>
#include <android/log.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define LOG_TAG "SiliconFP"
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

static inline uint64_t thread_cpu_time_nanos() {
    timespec ts;
    // Per-thread CPU time: excludes time when descheduled.
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static inline uint32_t rotl32(uint32_t x, uint32_t r) {
    return (x << r) | (x >> (32u - r));
}

static uint32_t seed32_from_env(const uint8_t* env, size_t env_len) {
    // Deterministic, not cryptographic: stable seed for deterministic filling and probe layout.
    // FNV-1a 32-bit.
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < env_len; i++) {
        h ^= (uint32_t)env[i];
        h *= 16777619u;
    }
    // Mix.
    h ^= rotl32(h, 13);
    h *= 0x85ebca6bu;
    h ^= rotl32(h, 17);
    h *= 0xc2b2ae35u;
    h ^= rotl32(h, 16);
    return h;
}

static void best_effort_pin_thread() {
    // Best-effort: pin to current CPU to reduce migration noise.
    // If it fails, proceed anyway.
    int cpu = sched_getcpu();
    if (cpu < 0) return;

    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    // Android uses sched_setaffinity instead of pthread_setaffinity_np
    // Use 0 for current thread (gettid() equivalent)
    (void)sched_setaffinity(0, sizeof(set), &set);
}

static void* mmap_arena(size_t bytes) {
    void* p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return nullptr;

    // Encourage hugepage/THP behavior where applicable; ignore failures.
#ifdef MADV_HUGEPAGE
    (void)madvise(p, bytes, MADV_HUGEPAGE);
#endif
    // Encourage residency; ignore failures.
#ifdef MADV_WILLNEED
    (void)madvise(p, bytes, MADV_WILLNEED);
#endif
    return p;
}

static void munmap_arena(void* p, size_t bytes) {
    if (p && p != MAP_FAILED) {
        (void)munmap(p, bytes);
    }
}

static void fill_deterministic(uint8_t* arena, size_t bytes, uint32_t seed) {
    // xorshift32 stream
    uint32_t x = seed ? seed : 0xA5A5A5A5u;
    for (size_t i = 0; i < bytes; i++) {
        x ^= (x << 13);
        x ^= (x >> 17);
        x ^= (x << 5);
        arena[i] = (uint8_t)(x & 0xffu);
    }
}

static void build_probe_starts(std::vector<uint32_t>& starts, uint32_t seed, uint32_t arena_mask) {
    // Deterministic probe start indices distributed across arena.
    uint32_t x = seed ^ 0x9E3779B9u;
    for (size_t i = 0; i < starts.size(); i++) {
        x = x * 1103515245u + 12345u;
        uint32_t idx = (x >> 1) & arena_mask;
        // Light alignment bias to vary cacheline mapping without forcing strict alignment.
        starts[i] = idx;
    }
}

extern "C"
JNIEXPORT jlongArray JNICALL
Java_com_dsm_wallet_security_SiliconFingerprintNative_captureOrbitDensity(
        JNIEnv* env,
        jclass,
        jbyteArray envBytes,
        jint arenaBytes,
        jint probes,
        jint stepsPerProbe,
        jint warmupRounds,
        jint rotationBits
) {
    if (arenaBytes <= 0 || probes <= 0 || stepsPerProbe <= 0 || warmupRounds < 0) {
        return nullptr;
    }
    if (rotationBits <= 0 || rotationBits >= 32) {
        return nullptr;
    }
    // arenaBytes must be power-of-two for masking.
    const uint32_t ab = (uint32_t)arenaBytes;
    if ((ab & (ab - 1u)) != 0u) {
        return nullptr;
    }
    if ((probes % 8) != 0) {
        return nullptr;
    }

    jsize envLen = env->GetArrayLength(envBytes);
    std::vector<uint8_t> envVec((size_t)envLen);
    env->GetByteArrayRegion(envBytes, 0, envLen, reinterpret_cast<jbyte*>(envVec.data()));

    const uint32_t seed = seed32_from_env(envVec.data(), envVec.size());
    const uint32_t arena_mask = ab - 1u;

    best_effort_pin_thread();

    void* mem = mmap_arena((size_t)ab);
    if (!mem) {
        ALOGE("mmap failed errno=%d", errno);
        return nullptr;
    }
    uint8_t* arena = reinterpret_cast<uint8_t*>(mem);

    // Warmup: reduce cold-start effects (page faults, cache coldness).
    for (int w = 0; w < warmupRounds; w++) {
        fill_deterministic(arena, (size_t)ab, seed ^ (uint32_t)w);
        volatile uint32_t sink = 0;
        for (uint32_t i = 0; i < ab; i += 64) {
            sink ^= arena[i];
        }
        if (sink == 0xFFFFFFFFu) {
            // unreachable; prevents optimizer assumptions
            ALOGE("unreachable sink");
        }
    }

    // Deterministic fill and probe starts for this capture.
    fill_deterministic(arena, (size_t)ab, seed);

    std::vector<uint32_t> starts((size_t)probes);
    build_probe_starts(starts, seed, arena_mask);

    std::vector<uint64_t> deltas((size_t)probes);
    deltas.assign((size_t)probes, 0ull);

    // Pointer chase with canonical C-DBRW ARX recurrence.
    uint32_t idx = seed & arena_mask;
    uint32_t x = seed ^ 0xCDB70AA7u;
    const uint32_t r = static_cast<uint32_t>(rotationBits);

    for (int p = 0; p < probes; p++) {
        idx = starts[(size_t)p] & arena_mask;

        const uint64_t t0 = thread_cpu_time_nanos();

        // Fixed step budget per probe.
        for (int s = 0; s < stepsPerProbe; s++) {
            // Read-dependent address update to defeat prefetching.
            const uint8_t mu = arena[idx];

            // Canonical recurrence from paper:
            // x_{n+1} = (x_n + ROL(x_n, r) XOR mu_n) mod 2^32
            x = (x + rotl32(x, r)) ^ static_cast<uint32_t>(mu);

            // Project state back into arena index space.
            idx = (idx + x) & arena_mask;
        }

        const uint64_t t1 = thread_cpu_time_nanos();
        deltas[(size_t)p] = (t1 >= t0) ? (t1 - t0) : 0ull;
    }

    munmap_arena(mem, (size_t)ab);

    // Use state so compiler can't throw away the loop.
    if (x == 0x7FFFFFFFu) {
        ALOGE("unreachable state");
    }

    jlongArray ret = env->NewLongArray((jsize)probes);
    if (!ret) return nullptr;
    env->SetLongArrayRegion(ret, 0, (jsize)probes, reinterpret_cast<const jlong*>(deltas.data()));
    return ret;
}
