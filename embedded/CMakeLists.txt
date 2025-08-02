cmake_minimum_required(VERSION 3.13)

# Set Pico SDK path
if(NOT DEFINED PICO_SDK_PATH)
  set(PICO_SDK_PATH "$ENV{HOME}/pico-sdk" CACHE PATH "Path to the Pico SDK")
endif()

# 🔥 Critical: Skip toolchain test BEFORE project()
set(PICO_SKIP_TOOLCHAIN_TEST 1)

# Include Pico SDK before project()
include(${PICO_SDK_PATH}/pico_sdk_init.cmake)

# Project definition comes AFTER skip and sdk include
project(sst_embedded_project C CXX ASM)

# Initialize Pico SDK
pico_sdk_init()

# === mbedTLS Setup ===
set(ENABLE_PROGRAMS OFF CACHE BOOL "")
set(ENABLE_TESTING OFF CACHE BOOL "")
set(ENABLE_CRYPTO_DRIVERS OFF CACHE BOOL "")
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "")
set(MBEDTLS_CONFIG_FILE "\"mbedtls_config.h\"") # Note the quotes
add_definitions(-DMBEDTLS_NO_PLATFORM_ENTROPY)

add_subdirectory(
    lib/mbedtls
    ${CMAKE_BINARY_DIR}/mbedtls_build
    EXCLUDE_FROM_ALL
)

# Add our config folder to mbedcrypto's include directories
target_include_directories(mbedcrypto INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/config)

# === Patch mbedcrypto for Pico Time Support ===
target_sources(mbedcrypto PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls/library/mbedtls_time_alt.c)
target_include_directories(mbedcrypto PRIVATE
    ${PICO_SDK_PATH}/src/common/pico_base/include
    ${PICO_SDK_PATH}/src/rp2_common/pico_time/include
)

# === Build shared embedded crypto library ===
add_library(sst_embedded
    src/sst_crypto_embedded.c
)

target_include_directories(sst_embedded PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls/include
)

target_link_libraries(sst_embedded PUBLIC mbedcrypto)

# === Add submodules ===
add_subdirectory(sender)
add_subdirectory(receiver)
