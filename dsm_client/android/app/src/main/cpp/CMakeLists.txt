# File: app/CMakeLists.txt
# ------------------------------------------------------------------
# DSM Android JNI Integration: Uses pre-built Rust DSM SDK directly
# ------------------------------------------------------------------
cmake_minimum_required(VERSION 3.22.1)
project("dsm_android")

# Import the pre-built Rust DSM SDK library
# The library is built by cargo ndk and placed in jniLibs by Gradle
add_library(dsm_sdk SHARED IMPORTED)

# Set the import location for each ABI
set_target_properties(dsm_sdk PROPERTIES
    IMPORTED_LOCATION ${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libdsm_sdk.so
)

# ------------------------------------------------------------------
# Silicon Fingerprint: NDK-based hardware PUF for C-DBRW anti-cloning
# ------------------------------------------------------------------
add_library(
    siliconfp
    SHARED
    siliconfp.cpp
)

find_library(
    log-lib
    log
)

target_compile_features(siliconfp PRIVATE cxx_std_17)

# Conservative flags: correctness > cleverness
target_compile_options(siliconfp PRIVATE
    -O2
    -fno-exceptions
    -fno-rtti
    -Wall
    -Wextra
    -Werror
)

target_link_libraries(
    siliconfp
    ${log-lib}
)

# ------------------------------------------------------------------
# C-DBRW native surface (entropy health, moments, BLAKE3 static lib)
# was removed when Protocol 6.2 collapsed into the single-path router.
# All histogram math, Wasserstein distance, entropy health, and anchor
# commitment live in Rust (`dsm_sdk/src/security/cdbrw_*`). The only
# native library the Kotlin side still loads is `libsiliconfp.so`,
# which provides the raw NDK orbit-density probe consumed by
# `SiliconFingerprintNative.captureOrbitDensity`.
# ------------------------------------------------------------------

# No C++ wrapper needed — Rust library exports JNI functions directly
# through `libdsm_sdk.so`. Unified JNI surface only.
