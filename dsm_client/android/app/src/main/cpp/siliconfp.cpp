// SPDX-License-Identifier: MIT OR Apache-2.0
//
// C-DBRW silicon fingerprint NDK probe.
//
// Implements cdbrw.instructions.md Def 9.1 + Alg 1 on Android userspace.
//
// On real Samsung / hardened-OEM Android, /sys/class/thermal/*/temp and
// /sys/class/power_supply/*/voltage_now are SELinux-blocked for app
// contexts. We therefore route thermal sampling through PowerManager
// (in Kotlin) and consume the resulting 16-byte payload here as the
// "t / status" component of S. cpufreq, perf_event_open, and CNTVCT_EL0
// remain readable from native code without root and supply the remaining
// substrate channels (DVFS state, microarchitectural state, cycle counter).
// All channels are folded via the canonical DSM domain hash to produce
// µ_n; if every channel is degenerate the orbit refuses to run rather
// than fall back to a software PRNG (Def 9.1(b) hard constraint).
//
// Alg 1 step 1: x_0 = H("DSM/cdbrw-seed\0" || challenge || K_DBRW) mod 2^32
// delegated to the Rust source of truth via dsm_seed_orbit from libdsm_sdk.so.

#include <jni.h>
#include <android/log.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <linux/perf_event.h>

#define LOG_TAG "SiliconFP"
#define ALOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)
#define ALOGI(...) __android_log_print(ANDROID_LOG_INFO,  LOG_TAG, __VA_ARGS__)
#define ALOGW(...) __android_log_print(ANDROID_LOG_WARN,  LOG_TAG, __VA_ARGS__)

// ---------------------------------------------------------------------------
// C exports from libdsm_sdk.so (dsm_sdk/src/cdbrw_native_exports.rs).
// ---------------------------------------------------------------------------
extern "C" {
    bool dsm_blake3_keyed(const char* tag, const uint8_t* data, size_t data_len, uint8_t out32[32]);
    uint32_t dsm_seed_orbit(const uint8_t challenge[32], const uint8_t kdbrw[32]);
    bool dsm_get_cdbrw_binding_key(uint8_t out32[32]);
}

// ---------------------------------------------------------------------------
// Cycle counter — CNTVCT_EL0 on ARMv8 userspace (always allowed, no perm).
// ---------------------------------------------------------------------------
static inline uint64_t read_cycle_counter() {
#if defined(__aarch64__)
    uint64_t v;
    asm volatile("isb\n\tmrs %0, cntvct_el0" : "=r"(v) :: "memory");
    return v;
#elif defined(__x86_64__) || defined(__i386__)
    unsigned hi, lo;
    asm volatile("mfence\n\tlfence\n\trdtsc" : "=a"(lo), "=d"(hi) :: "memory");
    return ((uint64_t)hi << 32) | lo;
#else
    timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
#endif
}

static inline void serializing_barrier() {
#if defined(__aarch64__)
    asm volatile("isb" ::: "memory");
#elif defined(__x86_64__) || defined(__i386__)
    asm volatile("mfence\n\tlfence" ::: "memory");
#else
    __sync_synchronize();
#endif
}

static inline uint32_t rotl32(uint32_t x, uint32_t r) {
    return (x << r) | (x >> (32u - r));
}

// ---------------------------------------------------------------------------
// Sensors that ARE accessible from a stock Android app sandbox.
//   - cpufreq (DVFS state per CPU)
//   - perf_event_open (cycles, cache misses)
//   - CNTVCT_EL0 (per-read, no FD)
// Thermal byte comes from PowerManager via the JNI `thermalBytes` argument.
// ---------------------------------------------------------------------------
struct PhysicalSensors {
    static constexpr int MAX_FDS = 8;
    int cpufreq_fds[MAX_FDS];
    int n_cpufreq;
    int perf_cycles_fd;
    int perf_misses_fd;
    bool initialized;
    bool perf_available;
};

static PhysicalSensors g_sensors = {};

static long perf_event_open_syscall(struct perf_event_attr* attr, pid_t pid, int cpu,
                                     int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int open_perf_counter(uint32_t type, uint64_t config) {
    struct perf_event_attr pe = {};
    pe.type = type;
    pe.size = sizeof(pe);
    pe.config = config;
    pe.disabled = 0;
    pe.exclude_kernel = 1;
    pe.exclude_hv = 1;
    int fd = (int)perf_event_open_syscall(&pe, 0, -1, -1, 0);
    if (fd < 0) return -1;
    return fd;
}

static int collect_all_matches(const char* dir, const char* prefix, const char* suffix,
                               int* out_fds, int max_fds) {
    DIR* d = opendir(dir);
    if (!d) return 0;
    struct dirent* ent;
    char path[256];
    int n = 0;
    while ((ent = readdir(d)) && n < max_fds) {
        if (strncmp(ent->d_name, prefix, strlen(prefix)) != 0) continue;
        snprintf(path, sizeof(path), "%s/%s/%s", dir, ent->d_name, suffix);
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            out_fds[n++] = fd;
        }
    }
    closedir(d);
    return n;
}

static void sensors_init() {
    if (g_sensors.initialized) return;

    g_sensors.n_cpufreq = collect_all_matches(
        "/sys/devices/system/cpu", "cpu", "cpufreq/scaling_cur_freq",
        g_sensors.cpufreq_fds, PhysicalSensors::MAX_FDS);

    g_sensors.perf_cycles_fd = open_perf_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES);
    g_sensors.perf_misses_fd = open_perf_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES);
    g_sensors.perf_available = (g_sensors.perf_cycles_fd >= 0);

    ALOGI("sensors_init: cpufreq=%d perf=%s",
          g_sensors.n_cpufreq, g_sensors.perf_available ? "yes" : "no");

    g_sensors.initialized = true;
}

static int32_t read_int_from_fd(int fd) {
    if (fd < 0) return 0;
    char buf[32];
    ssize_t n = pread(fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return 0;
    buf[n] = '\0';
    return (int32_t)atol(buf);
}

static uint64_t read_perf_counter(int fd) {
    if (fd < 0) return 0;
    uint64_t v = 0;
    ssize_t n = read(fd, &v, sizeof(v));
    if (n <= 0) return 0;
    return v;
}

// ---------------------------------------------------------------------------
// Sample the silicon substrate once per probe — folds:
//   - Kotlin-supplied PowerManager thermal HAL bytes (t / status)
//   - DVFS current frequency per CPU
//   - perf HW counters (cycles + cache misses) — microarchitectural state
//   - CNTVCT_EL0 reading
// into a 32-byte digest via the canonical DSM domain hash. Spec Def 9.1(c)
// names "microsecond intervals" for substrate reads; per-probe sampling
// matches that, per-step would oversample (and turn each ARX step into a
// syscall storm).
// ---------------------------------------------------------------------------
static void sample_substrate_digest(uint64_t probe_idx,
                                    const uint8_t* thermal_bytes,
                                    size_t thermal_bytes_len,
                                    uint8_t out_digest[32]) {
    int32_t freq_khz = 0;
    if (g_sensors.n_cpufreq > 0) {
        freq_khz = read_int_from_fd(
            g_sensors.cpufreq_fds[probe_idx % (uint64_t)g_sensors.n_cpufreq]);
    }
    uint64_t cycles = read_perf_counter(g_sensors.perf_cycles_fd);
    uint64_t misses = read_perf_counter(g_sensors.perf_misses_fd);

    serializing_barrier();
    uint64_t cntvct = read_cycle_counter();

    uint8_t pre[8 + 32 + 4 + 8 + 8 + 8] = {};
    std::memcpy(pre + 0,  &probe_idx, 8);
    if (thermal_bytes && thermal_bytes_len > 0) {
        size_t copy = std::min<size_t>(32, thermal_bytes_len);
        std::memcpy(pre + 8, thermal_bytes, copy);
    }
    std::memcpy(pre + 40, &freq_khz, 4);
    std::memcpy(pre + 44, &cycles,   8);
    std::memcpy(pre + 52, &misses,   8);
    std::memcpy(pre + 60, &cntvct,   8);

    if (!dsm_blake3_keyed("DSM/cdbrw-thermal", pre, sizeof(pre), out_digest)) {
        ALOGE("dsm_blake3_keyed failed in sample_substrate_digest");
        std::memset(out_digest, 0, 32);
    }
}

// Per-step µ_n derivation (inside the hot ARX loop). Folds:
//   - the per-probe substrate digest (32 bytes of real hardware state)
//   - the CNTVCT_EL0 cycle counter at this iteration (sub-nanosecond
//     variation reflects real cache hit/miss / DRAM refresh timing)
// This keeps the µ_n stream substrate-driven without paying a syscall per
// step.
static inline uint8_t derive_step_mu(const uint8_t substrate_digest[32], int step_idx) {
    uint64_t cntvct;
#if defined(__aarch64__)
    asm volatile("mrs %0, cntvct_el0" : "=r"(cntvct));
#else
    cntvct = read_cycle_counter();
#endif
    // Mix CNTVCT into one of 32 digest bytes — keeps the stream fresh per
    // step without re-hashing (each step is < 100ns, vs. ~1µs for BLAKE3).
    uint8_t base = substrate_digest[step_idx & 31];
    return (uint8_t)(base ^ (uint8_t)cntvct ^ (uint8_t)(cntvct >> 8));
}

// ---------------------------------------------------------------------------
// Best-effort soft real-time on the capture thread.
//
// requested_cpu >= 0 pins to that exact core and verifies the pin (used by the
// extractor-sweep "lane" knob — per-core capture). requested_cpu < 0 keeps the
// legacy behaviour (pin to whatever core the thread is currently on). Returns
// false only when an explicit per-core pin was requested and could not be
// verified, so the caller can refuse rather than silently run on the wrong core.
// ---------------------------------------------------------------------------
static bool best_effort_isolate_thread_core(int requested_cpu) {
    // CPU pinning reduces scheduler noise without escalating priority.
    int cpu = (requested_cpu >= 0) ? requested_cpu : sched_getcpu();
    if (cpu >= 0) {
        cpu_set_t set;
        CPU_ZERO(&set);
        CPU_SET(cpu, &set);
        if (sched_setaffinity(0, sizeof(set), &set) != 0) {
            ALOGW("sched_setaffinity(cpu=%d) failed errno=%d", cpu, errno);
            if (requested_cpu >= 0) return false;
        } else if (requested_cpu >= 0) {
            sched_yield();
            if (sched_getcpu() != requested_cpu) {
                ALOGW("pin verify failed: wanted cpu=%d got cpu=%d", requested_cpu, sched_getcpu());
                return false;
            }
        }
    }
    // mlockall is page-pressure mitigation, not an RT escalation.
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        ALOGW("mlockall failed errno=%d (continuing)", errno);
    }
    // SCHED_FIFO removed: Android's foreground-app cgroup grants it implicitly
    // via Process.THREAD_PRIORITY_URGENT_AUDIO (set on the Kotlin side). Doing
    // it again in C++ has caused the kernel watchdog to kill the test process
    // mid-orbit on long-running enroll trials. The Kotlin promotion is the
    // closest userspace approximation the spec's Def 9.1(a) clause permits;
    // residual jitter is caught by the entropy health test.
    return true;
}

static void best_effort_isolate_thread() {
    (void)best_effort_isolate_thread_core(-1);
}

static void best_effort_release_thread() {
    (void)munlockall();
}

static void* mmap_arena(size_t bytes) {
    void* p = mmap(nullptr, bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) return nullptr;
#ifdef MADV_HUGEPAGE
    (void)madvise(p, bytes, MADV_HUGEPAGE);
#endif
#ifdef MADV_WILLNEED
    (void)madvise(p, bytes, MADV_WILLNEED);
#endif
    return p;
}

static void munmap_arena(void* p, size_t bytes) {
    if (p && p != MAP_FAILED) (void)munmap(p, bytes);
}

static bool fill_arena_from_urandom(uint8_t* arena, size_t bytes) {
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    size_t off = 0;
    while (off < bytes) {
        ssize_t n = read(fd, arena + off, bytes - off);
        if (n <= 0) {
            close(fd);
            return false;
        }
        off += (size_t)n;
    }
    close(fd);
    return true;
}

// ---------------------------------------------------------------------------
// Extractor-sweep raw capture.
//
// captureOrbitDensity bakes in injection-every-step, current-core pinning, and
// returns only per-probe timing. To search the EXTRACTOR (not just the bin
// scale) for the strongest same-model separation, this entry exposes the knobs
// that genuinely change the walk and emits the richest raw observable so the
// host can derive every summary offline:
//   - rotationBits r        — ARX rotation constant (sweep {5,7,11,13,17})
//   - injectionCadence k    — inject µ every k ARX steps; pure ARX rounds in
//                             between (sweep {1,2,4,8}); tests whether the map
//                             is too mixing-heavy and washing out structure
//   - cpuCore               — pin+verify to a specific core for per-core lanes
//                             (>=0), or -1 for current-core (merged) behaviour
// Returns a jlongArray of length (2*probes + 256):
//   [0, probes)            per-probe CNTVCT timing deltas (digital timing channel)
//   [probes, 2*probes)     per-probe perf CPU-cycle deltas — paired with the
//                          CNTVCT delta gives the TWO-CLOCK RATIO (realized CPU
//                          freq / reference freq), an analog-side observable that
//                          is frequency-normalized by construction
//   [2*probes, 2*probes+256) µ-byte histogram ν_D counts (host confirms it is null)
// Host derives: two-clock ratio trajectory, bin-scale re-binning (multi-scale
// surface), N truncation, burn-in, transition/signed deltas, moments, per-core
// lanes & cross-core deltas. cpuCore<0 returns null only if an explicit pin was
// requested and could not be verified.
// ---------------------------------------------------------------------------
extern "C"
JNIEXPORT jlongArray JNICALL
Java_com_dsm_wallet_security_SiliconFingerprintNative_captureOrbitRaw(
        JNIEnv* env,
        jclass,
        jbyteArray /* envBytes — kept for ABI symmetry */,
        jbyteArray challengeBytes,
        jbyteArray thermalBytesArr,
        jint arenaBytes,
        jint probes,
        jint stepsPerProbe,
        jint warmupRounds,
        jint rotationBits,
        jint injectionCadence,
        jint cpuCore
) {
    if (arenaBytes <= 0 || probes <= 0 || stepsPerProbe <= 0 || warmupRounds < 0) {
        return nullptr;
    }
    if (rotationBits <= 0 || rotationBits >= 32) return nullptr;
    if (injectionCadence <= 0) return nullptr;
    const uint32_t ab = (uint32_t)arenaBytes;
    if ((ab & (ab - 1u)) != 0u) return nullptr;
    if ((probes % 8) != 0) return nullptr;
    if (!challengeBytes || env->GetArrayLength(challengeBytes) != 32) {
        ALOGE("captureOrbitRaw: challenge must be 32 bytes");
        return nullptr;
    }
    uint8_t challenge[32];
    env->GetByteArrayRegion(challengeBytes, 0, 32, reinterpret_cast<jbyte*>(challenge));

    uint8_t thermal_buf[32] = {};
    size_t thermal_len = 0;
    if (thermalBytesArr) {
        jsize tl = env->GetArrayLength(thermalBytesArr);
        thermal_len = (tl > 0 && tl <= (jsize)sizeof(thermal_buf)) ? (size_t)tl : 0;
        if (thermal_len > 0) {
            env->GetByteArrayRegion(thermalBytesArr, 0, (jsize)thermal_len,
                                    reinterpret_cast<jbyte*>(thermal_buf));
        }
    }

    uint8_t kdbrw[32] = {};
    (void)dsm_get_cdbrw_binding_key(kdbrw);
    sensors_init();

    if (thermal_len == 0) {
        ALOGE("captureOrbitRaw: thermal bytes required");
        return nullptr;
    }
    if (g_sensors.n_cpufreq == 0 && !g_sensors.perf_available) {
        ALOGE("captureOrbitRaw: no cpufreq or perf substrate channel");
        return nullptr;
    }

    if (!best_effort_isolate_thread_core(cpuCore)) {
        ALOGE("captureOrbitRaw: pin to cpu=%d failed — refusing", cpuCore);
        return nullptr;
    }

    void* mem = mmap_arena((size_t)ab);
    if (!mem) { best_effort_release_thread(); return nullptr; }
    uint8_t* arena = reinterpret_cast<uint8_t*>(mem);
    if (!fill_arena_from_urandom(arena, (size_t)ab)) {
        munmap_arena(mem, (size_t)ab);
        best_effort_release_thread();
        return nullptr;
    }

    const uint32_t arena_mask = ab - 1u;
    const uint32_t r = (uint32_t)rotationBits;
    const int k = (int)injectionCadence;
    uint32_t x = dsm_seed_orbit(challenge, kdbrw);
    uint32_t idx = x & arena_mask;

    for (int w = 0; w < warmupRounds; w++) {
        volatile uint8_t sink = 0;
        for (uint32_t i = 0; i < ab; i += 64) sink ^= arena[i];
        if (sink == 0xFFu) ALOGE("unreachable warmup sink");
    }

    // Layout: [probes CNTVCT deltas][probes perf-cycle deltas][256 µ counts].
    // The per-probe perf-cycle count alongside the CNTVCT (fixed-frequency
    // system counter) delta lets the host form the TWO-CLOCK RATIO
    // cycles/cntvct = realized CPU frequency / reference frequency — an
    // analog-side observable (PLL/oscillator realized frequency, frequency-
    // normalized by construction, so it cancels the DVFS setpoint).
    std::vector<uint64_t> out((size_t)(2 * probes) + 256, 0ull);
    uint64_t* deltas = out.data();
    uint64_t* cycles = out.data() + probes;
    uint64_t* mu_hist = out.data() + (size_t)(2 * probes);

    constexpr int N_SUBSTRATE_REFRESH = 16;
    uint8_t substrates[N_SUBSTRATE_REFRESH][32];
    const int steps_per_substrate =
        (stepsPerProbe + N_SUBSTRATE_REFRESH - 1) / N_SUBSTRATE_REFRESH;

    for (int p = 0; p < probes; p++) {
        for (int kk = 0; kk < N_SUBSTRATE_REFRESH; kk++) {
            const uint64_t si = (uint64_t)p * (uint64_t)N_SUBSTRATE_REFRESH + (uint64_t)kk;
            sample_substrate_digest(si, thermal_buf, thermal_len, substrates[kk]);
        }
        // perf-cycle reads bracket the timed region but sit OUTSIDE the CNTVCT
        // window so the read() syscall does not pollute the timing channel.
        const uint64_t c0 = read_perf_counter(g_sensors.perf_cycles_fd);
        serializing_barrier();
        const uint64_t t0 = read_cycle_counter();
        for (int s = 0; s < stepsPerProbe; s++) {
            int sub_idx = s / steps_per_substrate;
            if (sub_idx >= N_SUBSTRATE_REFRESH) sub_idx = N_SUBSTRATE_REFRESH - 1;
            volatile uint8_t _touch = arena[idx];
            (void)_touch;
            // Inject µ only every k steps; pure ARX rounds (µ=0) in between.
            uint32_t mu = 0;
            if ((s % k) == 0) {
                mu = (uint32_t)derive_step_mu(substrates[sub_idx], s);
                mu_hist[mu & 0xff]++;
            }
            x = (x + rotl32(x, r)) ^ mu;
            idx = (idx + x) & arena_mask;
        }
        serializing_barrier();
        const uint64_t t1 = read_cycle_counter();
        const uint64_t c1 = read_perf_counter(g_sensors.perf_cycles_fd);
        deltas[(size_t)p] = (t1 >= t0) ? (t1 - t0) : 0ull;
        cycles[(size_t)p] = (c1 >= c0) ? (c1 - c0) : 0ull;
    }

    munmap_arena(mem, (size_t)ab);
    best_effort_release_thread();
    if (x == 0x7FFFFFFFu) ALOGE("unreachable state");

    const jsize out_len = (jsize)(2 * probes + 256);
    jlongArray ret = env->NewLongArray(out_len);
    if (!ret) return nullptr;
    env->SetLongArrayRegion(ret, 0, out_len,
                            reinterpret_cast<const jlong*>(out.data()));
    return ret;
}

// ---------------------------------------------------------------------------
// JNI entry point.
// ---------------------------------------------------------------------------
extern "C"
JNIEXPORT jlongArray JNICALL
Java_com_dsm_wallet_security_SiliconFingerprintNative_captureOrbitDensity(
        JNIEnv* env,
        jclass,
        jbyteArray /* envBytes — kept for ABI stability */,
        jbyteArray challengeBytes,
        jbyteArray thermalBytesArr,
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
    const uint32_t ab = (uint32_t)arenaBytes;
    if ((ab & (ab - 1u)) != 0u) {
        return nullptr;
    }
    if ((probes % 8) != 0) {
        return nullptr;
    }
    if (!challengeBytes || env->GetArrayLength(challengeBytes) != 32) {
        ALOGE("captureOrbitDensity: challenge must be 32 bytes");
        return nullptr;
    }
    uint8_t challenge[32];
    env->GetByteArrayRegion(challengeBytes, 0, 32, reinterpret_cast<jbyte*>(challenge));

    // Thermal HAL bytes from Kotlin PowerManager. May be empty if the caller
    // is on a pre-Q device; that drops one channel from the substrate fold,
    // but cpufreq + perf + CNTVCT remain.
    uint8_t thermal_buf[32] = {};
    size_t thermal_len = 0;
    if (thermalBytesArr) {
        jsize tl = env->GetArrayLength(thermalBytesArr);
        thermal_len = (tl > 0 && tl <= (jsize)sizeof(thermal_buf)) ? (size_t)tl : 0;
        if (thermal_len > 0) {
            env->GetByteArrayRegion(thermalBytesArr, 0, (jsize)thermal_len,
                                    reinterpret_cast<jbyte*>(thermal_buf));
        }
    }

    uint8_t kdbrw[32] = {};
    (void)dsm_get_cdbrw_binding_key(kdbrw);

    sensors_init();

    // Spec gate (strict, post Phase 2): thermal HAL bytes from Kotlin are
    // MANDATORY. If the caller does not supply a thermal payload, refuse to
    // run rather than silently fall back to cpufreq+perf alone (which would
    // re-introduce a hidden divergence from Def 9.1(b)). This makes the
    // Kotlin-side PowerManager sample load-bearing for every orbit, and
    // gives Phase 2's `orbit_refuses_without_thermal_bytes` test a hard
    // failure to assert.
    if (thermal_len == 0) {
        ALOGE("captureOrbitDensity: thermal bytes required — refusing to run without PowerManager HAL sample");
        return nullptr;
    }
    // Defense in depth: every other substrate channel also degenerate.
    if (g_sensors.n_cpufreq == 0 && !g_sensors.perf_available) {
        ALOGE("captureOrbitDensity: no cpufreq or perf substrate channel available");
        return nullptr;
    }

    best_effort_isolate_thread();

    void* mem = mmap_arena((size_t)ab);
    if (!mem) {
        ALOGE("mmap failed errno=%d", errno);
        best_effort_release_thread();
        return nullptr;
    }
    uint8_t* arena = reinterpret_cast<uint8_t*>(mem);
    if (!fill_arena_from_urandom(arena, (size_t)ab)) {
        ALOGE("urandom arena fill failed errno=%d", errno);
        munmap_arena(mem, (size_t)ab);
        best_effort_release_thread();
        return nullptr;
    }

    const uint32_t arena_mask = ab - 1u;
    const uint32_t r = (uint32_t)rotationBits;

    uint32_t x = dsm_seed_orbit(challenge, kdbrw);
    uint32_t idx = x & arena_mask;

    for (int w = 0; w < warmupRounds; w++) {
        volatile uint8_t sink = 0;
        for (uint32_t i = 0; i < ab; i += 64) {
            sink ^= arena[i];
        }
        if (sink == 0xFFu) ALOGE("unreachable warmup sink");
    }

    std::vector<uint64_t> deltas((size_t)probes, 0ull);

    // Hybrid substrate-refresh cadence (Phase 2.1 fix for the falsifying
    // delta test failure). Spec Def 3.4 demands per-step substrate
    // sampling; PR #351 hoisted to per-probe to dodge syscall storm; the
    // falsifying test then confirmed thermal contribution was below the
    // noise floor. The middle ground: pre-sample N_SUBSTRATE_PER_PROBE
    // substrate digests UPFRONT (each is its own fresh BLAKE3 over real
    // thermal/cpufreq/perf/cntvct reads, spaced by syscall-latency
    // microseconds), then the timed inner loop indexes through them
    // sequentially. This gives N_SUBSTRATE_PER_PROBE distinct
    // thermal-influenced digests per probe (was 1) without putting any
    // syscalls inside the timed region.
    constexpr int N_SUBSTRATE_PER_PROBE = 16;
    uint8_t substrates[N_SUBSTRATE_PER_PROBE][32];
    const int steps_per_substrate =
        (stepsPerProbe + N_SUBSTRATE_PER_PROBE - 1) / N_SUBSTRATE_PER_PROBE;

    for (int p = 0; p < probes; p++) {
        // Pre-sample substrate digests for this probe — outside the timed
        // region so syscall latency does not pollute orbit timings.
        for (int k = 0; k < N_SUBSTRATE_PER_PROBE; k++) {
            const uint64_t substrate_idx =
                (uint64_t)p * (uint64_t)N_SUBSTRATE_PER_PROBE + (uint64_t)k;
            sample_substrate_digest(substrate_idx, thermal_buf, thermal_len,
                                    substrates[k]);
        }

        serializing_barrier();
        const uint64_t t0 = read_cycle_counter();

        for (int s = 0; s < stepsPerProbe; s++) {
            // Pick the substrate that covers this step. Index switches every
            // steps_per_substrate iterations so thermal/cpufreq/perf contribute
            // to µ_n N_SUBSTRATE_PER_PROBE times per probe instead of once.
            const uint8_t* substrate = substrates[s / steps_per_substrate];

            // Arena access for cache topology pressure — NOT used as µ_n.
            volatile uint8_t _arena_touch = arena[idx];
            (void)_arena_touch;

            uint8_t mu = derive_step_mu(substrate, s);

            // Canonical ARX recurrence (Def 3.4).
            x = (x + rotl32(x, r)) ^ (uint32_t)mu;
            idx = (idx + x) & arena_mask;
        }

        serializing_barrier();
        const uint64_t t1 = read_cycle_counter();
        deltas[(size_t)p] = (t1 >= t0) ? (t1 - t0) : 0ull;
    }

    munmap_arena(mem, (size_t)ab);
    best_effort_release_thread();

    if (x == 0x7FFFFFFFu) ALOGE("unreachable state");

    jlongArray ret = env->NewLongArray((jsize)probes);
    if (!ret) return nullptr;
    env->SetLongArrayRegion(ret, 0, (jsize)probes, reinterpret_cast<const jlong*>(deltas.data()));
    return ret;
}
