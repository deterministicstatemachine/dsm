# C-DBRW Implementation — Known Spec Deviations

The implementation of C-DBRW in this repository deviates from the literal
text of [`cdbrw.instructions.md`](../.github/instructions/cdbrw.instructions.md)
in three places. This document is the single source of truth for those
deviations. Each section quotes the spec verbatim, describes what the
implementation actually does, and explains why.

Status as of PR #351 + Phase 2 follow-ups, verified on Samsung Galaxy A54
(SM-A546W, Android 16, SDK 36).

---

## Deviation 1 — Def 9.1(a) interrupt masking

**Spec text:**

> Definition 9.1(a). The ARX inner loop MUST execute on a single pinned
> core with interrupts masked for the duration of the orbit.

**Implementation:**

The orbit runs on a pinned core (`sched_setaffinity` in
[siliconfp.cpp](../dsm_client/android/app/src/main/cpp/siliconfp.cpp)) with
the address space locked (`mlockall(MCL_CURRENT | MCL_FUTURE)`). The Kotlin
caller promotes the capture thread to `Process.THREAD_PRIORITY_URGENT_AUDIO`
before each orbit, which on Android is the closest userspace priority class
to soft real-time. **Interrupts are NOT masked.**

**Why we deviate:**

Userspace processes on Android cannot mask interrupts — that is a kernel
privilege. Strict compliance would require a kernel module or rooted
device, neither of which is acceptable for a consumer wallet. We tried
escalating to `SCHED_FIFO` max priority in C++ via `pthread_setschedparam`
and were killed by the kernel watchdog mid-orbit on long-running enrollment
runs (this is the actual cause of the test-process death documented during
Phase 1 instrumentation).

**Mitigation:**

The spec itself provides the gate that catches what interrupt-masking would
prevent: the **entropy health test** (`Ĥ ≥ 0.45 ∧ |ρ̂| ≤ 0.3 ∧ L̂ ≥ 0.45`).
If preemption noise dominates the thermal signal, autocorrelation rises and
the health test fails — the access gate sits in `PinRequired` and writes
are blocked. The implementation is fail-closed against the failure mode
interrupt-masking was meant to prevent.

**Residual risk:**

An adversary who can induce a precisely-timed preemption schedule that
biases timings without tripping the autocorrelation gate could in principle
manipulate µ_n. We have no evidence such an attack is practical on
Android; flagged as an open question.

---

## Deviation 2 — Def 9.1(b) `/sys/class/thermal` direct read

**Spec text:**

> Definition 9.1(b). Thermal byte extraction MUST use platform-specific
> hardware counters (e.g., THERMAL_STATUS MSR on x86, `/sys/class/thermal`
> on ARM) and MUST NOT use software PRNG fallbacks.

**Implementation:**

We do not read `/sys/class/thermal/thermal_zone*/temp` directly. We use
[`PowerManager.getThermalHeadroom(0)`](https://developer.android.com/reference/android/os/PowerManager#getThermalHeadroom\(int\))
and `currentThermalStatus` from the Android thermal HAL, sampled in
[AntiCloneGate.kt](../dsm_client/android/app/src/main/java/com/dsm/wallet/security/AntiCloneGate.kt)
on the Kotlin side and threaded into the C++ orbit as a 16-byte payload.
We also read `/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq` (DVFS
state) and `perf_event_open` (`PERF_COUNT_HW_CPU_CYCLES`,
`PERF_COUNT_HW_CACHE_MISSES`) directly from C++ — both are accessible to
the app sandbox on stock Android.

**Why we deviate:**

On modern Samsung (and most non-AOSP) builds, SELinux denies app-context
reads of `/sys/class/thermal/*/temp`. Verified on Galaxy A54 / Android 16
(SDK 36):

```
$ adb shell cat /sys/class/thermal/thermal_zone0/temp
cat: ... Permission denied
$ adb shell run-as com.dsm.wallet ls /sys/class/thermal/
ls: ... Permission denied
```

The directive is illustrative ("e.g.") not exhaustive. PowerManager is the
Android-sanctioned userspace path to the same kernel thermal sensors,
mediated by the HAL. It is **not** a software PRNG — the values trace
back to physical thermal_zone sensor reads.

We use `getThermalHeadroom(0)` (current headroom) twice with
`currentThermalStatus` between them, never `getThermalHeadroom(n)` for
`n > 0`. The (n) forecast variant returns a HAL-modeled forward
projection of throttle ETA — that would conflate modeled output with raw
sensor data and is explicitly excluded.

**Mitigation:**

The Phase 2 falsifying delta test
([`thermal_channel_is_load_bearing`](../dsm_client/android/app/src/androidTest/java/com/dsm/wallet/security/SiliconFingerprintRealHwTest.kt))
compares orbit histograms with real PowerManager bytes against orbit
histograms with zero thermal bytes, asserting a measurable Wasserstein-1
divergence. If the test fails, the PowerManager channel is not
load-bearing in the orbit and this section MUST be updated to demote the
"thermal-driven" framing.

The Phase 2 strict guard in
[siliconfp.cpp](../dsm_client/android/app/src/main/cpp/siliconfp.cpp)
refuses to run the orbit if `thermal_len == 0`, making the Kotlin
PowerManager sample mandatory for every probe. A regression that stops
sampling will trip
[`orbit_refuses_without_thermal_bytes`](../dsm_client/android/app/src/androidTest/java/com/dsm/wallet/security/SiliconFingerprintRealHwTest.kt)
immediately.

**Residual risk:**

PowerManager values are HAL-mediated — they could in principle be cached
or smoothed by the HAL implementation on a given OEM. The
two-sample-bracket pattern (`headroom_0 / status / headroom_0`) captures
inter-read scheduler jitter as a partial mitigation. If a future OEM ships
a HAL that returns identical bytes across both reads regardless of
substrate state, the channel degrades to status-only.

---

## Deviation 3 — Def 3.2 per-step µ_n sampling

**Spec text:**

> Definition 3.2 (Thermal Control Parameter). The thermal control
> parameter µ_n ∈ {0,1}^8 at iteration n is a byte sampled from an entropy
> register driven by the instantaneous substrate state S_n.

**Implementation:**

We sample substrate state **N times per probe** (Phase 2.1 hybrid
refresh: `N_SUBSTRATE_PER_PROBE = 16`) and derive per-step µ_n inside
the ARX loop as:

```
substrate = substrates[s / steps_per_substrate]   // refreshes every ~256 steps
µ_n = substrate[s & 31] XOR (cntvct_el0 & 0xFF) XOR ((cntvct_el0 >> 8) & 0xFF)
```

where each entry in `substrates[]` is its own 32-byte BLAKE3 fold of
fresh real-time reads (`thermal_bytes ‖ cpufreq ‖ perf_cycles ‖
perf_cache_misses ‖ cntvct`), pre-sampled at the start of each probe
(outside the timed region so syscall latency does not pollute orbit
timings). `cntvct_el0` is then read per step via `mrs cntvct_el0`.

This gives N=16 distinct thermal-influenced substrate digests per probe
× 16384 probes = 262144 substrate samples per orbit. That cadence
(~microsecond-class refresh) approximates the spec's Def 9.1(c) wording
"microsecond intervals" much more closely than the original per-probe
(1× per 16384) sampling.

**Why we deviate from strict per-step sampling:**

Literal per-step substrate sampling (5 syscalls per ARX step × ~67M
steps per orbit × 16 enrollment trials) is unkillable-by-anything-but-
the-watchdog. The 16× hybrid refresh is the most aggressive cadence
that keeps the timed region syscall-free while still empirically
satisfying the falsifying delta test (see Verification status table).

**Mitigation:**

CNTVCT_EL0 read at sub-nanosecond resolution reflects per-step cache hit
vs. miss latency and DRAM refresh interleaving — both physical phenomena
of the silicon substrate. The per-step µ_n therefore retains a fresh
substrate component on every iteration; it is **derived** rather than
**sampled**, but the source is still physical.

**Residual risk — open question:**

Theorem 4.5 (uniform ergodicity of the ARX random dynamical system) is
proven in the spec under the assumption that µ_n is i.i.d. sampled from
a distribution with non-degenerate support and bounded autocorrelation.
The per-step *derivation* used here does not satisfy "i.i.d. sampled" in
the literal sense — the bytes are deterministic functions of two
deterministic inputs (the per-probe digest and CNTVCT). Whether the
ergodicity proof carries to the derived construction is **not formally
established**. Flagged for formal analysis as a follow-up workstream.

In practice, the entropy health test (Def 4.15) is the empirical gate:
if the derived µ stream fails `|ρ̂| ≤ 0.3` autocorrelation or `L̂ ≥ 0.45`
compressibility on real device timings, the access gate sits in
`PinRequired` and the orbit's output is downstream-rejected.

**Measured impact on inter-orbit divergence (Phase 2.1):**

The hybrid 16×-refresh design passes both falsifying tests on Galaxy
A54 (Android 16, SDK 36):

- `thermal_channel_is_load_bearing`: W1(H_real, H_zero) > 0.001 with
  N=5 aggregated trials per condition. Initial single-refresh design
  failed at W1 ≈ 0.0009; with 16× refresh the thermal channel clears
  the threshold reliably.
- `different_challenges_produce_different_orbits`: W1(H_A, H_B) > 0.001
  with N=5 aggregated trials per challenge. Same aggregated pattern as
  the thermal test (single-probe L1 comparison was too noisy to draw
  signal from cache/scheduler variance).

Both metrics confirm thermal HAL AND the challenge channel
non-trivially influence the orbit under the hybrid derivation. Wall
time cost: ~70 seconds for the full 6-test instrumentation suite (was
30 seconds with the original per-probe-only refresh).

---

## What this document does NOT cover

- **"PUF" terminology.** Spec §7.1 Def 7.1 explicitly accepts
  "cache-miss timing or dynamic voltage fluctuation measurements" as the
  substrate the PUF measures. Our implementation samples that exact
  substrate (CNTVCT cache-miss timings + DVFS state). Calling the result
  a PUF is defensible per the spec's own definition — narrower
  doping-irregularities definitions of PUF would exclude our
  implementation, but they would also exclude every C-DBRW implementation
  ever, since C-DBRW is defined to use cache-timing.

- **The `voltage_now` HAL gap.** Spec Def 3.1 names `v` (supply voltage)
  as part of `S = (t, v, τ)`. Android does not expose CPU supply voltage
  to apps; `voltage_now` under `/sys/class/power_supply/battery/` is
  SELinux-denied for the same reason as `thermal_zone`. The DVFS frequency
  (`scaling_cur_freq`) is a close proxy because DVFS voltage rails track
  frequency, but it is not the raw rail voltage. Documented here for
  completeness; mitigation is identical to Deviation 2.

---

## Verification status

| Deviation | Test | Status |
|---|---|---|
| Def 9.1(a) interrupt masking | Entropy health test (`cdbrw_ffi::health_test`) | Implemented; gates access |
| Def 9.1(b) `/sys/class/thermal` | `orbit_refuses_without_thermal_bytes` | Phase 2 |
| Def 9.1(b) thermal load-bearing | `thermal_channel_is_load_bearing` | Passing on Galaxy A54 with Phase 2.1 16×-per-probe hybrid refresh; original per-probe-only design failed this test (W1 ≈ 0.0009 at noise floor) |
| Def 3.2 per-step sampling vs derivation | (no direct formal test) | Hybrid 16× refresh approximates per-step cadence; full formal analysis pending |
| **Cross-device anti-cloning (spec's load-bearing property)** | `cross_device_histogram_capture` + host-side W1 | **VERIFIED on 3 devices** with pairwise W1 ranging 40–75× same-device noise floor: Galaxy A54 (Samsung Exynos 1380) ↔ Galaxy A16 (MediaTek Helio G99) W1=0.0747. A54 ↔ UMIDIGI G9T (Unisoc UMS9230) W1=0.0749. A16 ↔ G9T W1=0.0395. Three OEMs, three SoC families (Samsung 5nm / TSMC 6nm / SMIC 12nm), three structurally distinct attractor shapes — Exynos concentrated in bin 0 (95%), Helio bimodal (bin 0 + bin 5-7), Unisoc spread across bins 1-4. Spec Theorem 4.24 holds on real silicon. |

The full instrumentation test suite (`SiliconFingerprintRealHwTest`) runs
in approximately 30 seconds on a Galaxy A54 and is the canonical
verification surface for the on-device physical layer.
