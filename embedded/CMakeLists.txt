cmake_minimum_required(VERSION 3.13)

# === Pico SDK Setup ===
set(PICO_SDK_PATH "/home/josef/pico-sdk" CACHE PATH "")
include(${PICO_SDK_PATH}/pico_sdk_init.cmake)

project(sst_embedded C CXX ASM)
pico_sdk_init()

# === mbedTLS Setup ===
set(ENABLE_PROGRAMS OFF CACHE BOOL "")
set(ENABLE_TESTING OFF CACHE BOOL "")
set(ENABLE_CRYPTO_DRIVERS OFF CACHE BOOL "")
set(USE_SHARED_MBEDTLS_LIBRARY OFF CACHE BOOL "")
set(MBEDTLS_CONFIG_FILE "\"mbedtls_config.h\"")
add_definitions(-DMBEDTLS_NO_PLATFORM_ENTROPY)

# NOTE: You must clone mbedtls into: embedded/lib/mbedtls
add_subdirectory(lib/mbedtls EXCLUDE_FROM_ALL)

# Manually add mbedtls_time_alt.c to mbedcrypto and give it Pico headers
foreach(target IN LISTS target_libraries)
    if(${target} MATCHES "mbedcrypto")
        target_sources(${target} PRIVATE lib/mbedtls/library/mbedtls_time_alt.c)
        target_include_directories(${target} PRIVATE
            ${PICO_SDK_PATH}/src/common/pico_base/include
            ${PICO_SDK_PATH}/src/rp2_common/pico_time/include
        )
    endif()
endforeach()


# === Fix: Add Pico SDK includes for mbedcrypto (for mbedtls_time_alt.c) ===
target_include_directories(mbedcrypto PRIVATE
    ${PICO_SDK_PATH}/src/common/pico_base/include
    ${PICO_SDK_PATH}/src/rp2_common/pico_time/include
)

# === Add Executable ===
add_executable(pico_encrypt
    src/c_crypto_embedded.c
    examples/pico_test_encrypt.c
)

# === Include Paths ===
target_include_directories(pico_encrypt PRIVATE
    include
    config
    lib/mbedtls/include
    ${PICO_SDK_PATH}/src/common/pico_base/include
)

# === Link Libraries ===
target_link_libraries(pico_encrypt PRIVATE
    pico_stdlib
    pico_rand
    mbedcrypto
)

# === USB or UART STDIO ===
pico_enable_stdio_usb(pico_encrypt 1)
pico_enable_stdio_uart(pico_encrypt 0)

# === Output UF2 ===
pico_add_extra_outputs(pico_encrypt)
