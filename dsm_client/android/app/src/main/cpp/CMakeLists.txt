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
# C-DBRW Entropy Health JNI: 3-condition health test + manufacturing gate
# ------------------------------------------------------------------
add_library(
    dsm_entropy_health_jni
    SHARED
    cdbrw_entropy_health_jni.cpp
    cdbrw_entropy_health.c
)

target_include_directories(dsm_entropy_health_jni PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(dsm_entropy_health_jni PRIVATE cxx_std_17)

target_compile_options(dsm_entropy_health_jni PRIVATE
    -O2
    -fno-exceptions
    -fno-rtti
    -Wall
    -Wextra
    -Werror
)

target_link_libraries(
    dsm_entropy_health_jni
    ${log-lib}
    m
)

# ------------------------------------------------------------------
# BLAKE3: Static library for C-DBRW moments hashing
# ------------------------------------------------------------------
add_library(
    blake3_static
    STATIC
    blake3/blake3.c
)

target_include_directories(blake3_static PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/blake3
)

target_compile_options(blake3_static PRIVATE
    -O2
    -DBLAKE3_NO_SSE2
    -DBLAKE3_NO_SSE41
    -DBLAKE3_NO_AVX2
    -DBLAKE3_NO_AVX512
)

# ------------------------------------------------------------------
# C-DBRW Moments JNI: Attractor envelope test (Def. 6.3)
# ------------------------------------------------------------------
add_library(
    dsm_moments_jni
    SHARED
    cdbrw_moments_jni.cpp
    cdbrw_moments.c
)

target_include_directories(dsm_moments_jni PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_compile_features(dsm_moments_jni PRIVATE cxx_std_17)

target_compile_options(dsm_moments_jni PRIVATE
    -O2
    -fno-exceptions
    -fno-rtti
    -Wall
    -Wextra
    -Werror
)

target_link_libraries(
    dsm_moments_jni
    blake3_static
    ${log-lib}
    m
)

# No C++ wrapper needed - Rust library exports JNI functions directly
# Unified JNI surface only; no legacy DsmNative usage.
