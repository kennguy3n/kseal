cmake_minimum_required(VERSION 3.22.1)
project(kseal_jni C)

# Path to sdk/rust-core, passed by Gradle (-DKSEAL_RUST_CORE_DIR=...).
if(NOT DEFINED KSEAL_RUST_CORE_DIR)
    message(FATAL_ERROR "KSEAL_RUST_CORE_DIR must be set (path to sdk/rust-core).")
endif()

set(KSEAL_FFI_INCLUDE "${KSEAL_RUST_CORE_DIR}/kseal-ffi/include")

# The Rust trust core (.so) is cross-compiled per ABI by cargo-ndk into
# jniLibs (see scripts/build-rust-android.sh). AGP also packages it into the
# AAR; we link against it here so the JNI bridge resolves the kseal_* symbols.
set(KSEAL_FFI_SO "${CMAKE_CURRENT_SOURCE_DIR}/../jniLibs/${ANDROID_ABI}/libkseal_ffi.so")

add_library(kseal_ffi SHARED IMPORTED)
set_target_properties(kseal_ffi PROPERTIES IMPORTED_LOCATION "${KSEAL_FFI_SO}")

add_library(kseal_jni SHARED kseal_jni.c)

target_include_directories(kseal_jni PRIVATE "${KSEAL_FFI_INCLUDE}")

target_compile_options(kseal_jni PRIVATE -Wall -Wextra -fvisibility=hidden)

find_library(log-lib log)

target_link_libraries(kseal_jni kseal_ffi ${log-lib})
