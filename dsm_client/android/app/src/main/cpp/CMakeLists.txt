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
# No native C++ wrapper. The silicon-fingerprint PUF library (siliconfp.cpp)
# was removed with C-DBRW: Genesis v2 is mnemonic-rooted and there is no
# silicon anti-clone. Anti-clone (offline bearer only) is the Boot Fenced
# Fused Anchor (separate secure-element firmware). The Rust SDK
# (libdsm_sdk.so) exports the JNI surface directly — single-path router.
# ------------------------------------------------------------------
