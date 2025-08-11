cmake_minimum_required(VERSION 3.13)

# === Pico SDK Setup ===
if(DEFINED ENV{PICO_SDK_PATH})
  set(PICO_SDK_PATH "$ENV{PICO_SDK_PATH}" CACHE PATH "Path to the Pico SDK")
  set(PICO_SKIP_TOOLCHAIN_TEST 1)
  # We provide our own mbedTLS build
  set(PICO_SDK_DISABLE_MBEDTLS 1)
  include(${PICO_SDK_PATH}/pico_sdk_init.cmake)
  set(HAS_PICO_SDK TRUE)
else()
  set(HAS_PICO_SDK FALSE)
endif()

project(sst_embedded_project C CXX ASM)
if(HAS_PICO_SDK)
  pico_sdk_init()
endif()

# === Resolve mbedTLS location (vendored first, else Pico SDK copy) ===
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls/library/aes.c)
  set(MBEDTLS_DIR ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls)
elseif(HAS_PICO_SDK AND EXISTS ${PICO_SDK_PATH}/lib/mbedtls/library/aes.c)
  set(MBEDTLS_DIR ${PICO_SDK_PATH}/lib/mbedtls)
else()
  message(FATAL_ERROR "mbedTLS not found. Expected either:
   - ${CMAKE_CURRENT_SOURCE_DIR}/lib/mbedtls, or
   - ${PICO_SDK_PATH}/lib/mbedtls")
endif()
message(STATUS "Using mbedTLS from: ${MBEDTLS_DIR}")

# === Sanity check the mbedTLS sources we require ===
foreach(f aes.c gcm.c sha256.c sha512.c cipher.c cipher_wrap.c platform.c platform_util.c ctr_drbg.c constant_time.c)
  if(NOT EXISTS ${MBEDTLS_DIR}/library/${f})
    message(FATAL_ERROR "Missing mbedTLS source: ${MBEDTLS_DIR}/library/${f}")
  endif()
endforeach()

# === mbedcrypto (lean AES+GCM+Cipher; no MD/Entropy) ===
add_library(mbedcrypto
  ${MBEDTLS_DIR}/library/aes.c
  ${MBEDTLS_DIR}/library/gcm.c
  ${MBEDTLS_DIR}/library/sha256.c
  ${MBEDTLS_DIR}/library/sha512.c
  ${MBEDTLS_DIR}/library/cipher.c
  ${MBEDTLS_DIR}/library/cipher_wrap.c
  ${MBEDTLS_DIR}/library/platform.c
  ${MBEDTLS_DIR}/library/platform_util.c
  ${MBEDTLS_DIR}/library/ctr_drbg.c
  ${MBEDTLS_DIR}/library/constant_time.c
)

# Put repo root and config first so it wins over the SDK defaults
target_include_directories(mbedcrypto
  PUBLIC
    ${CMAKE_SOURCE_DIR}          # <-- allows "config/mbedtls_config.h"
    ${MBEDTLS_DIR}/include
  PRIVATE
    ${CMAKE_SOURCE_DIR}/include
)

# Force everyone (lib + dependents) to include config file explicitly
target_compile_definitions(mbedcrypto
  PUBLIC MBEDTLS_CONFIG_FILE="config/mbedtls_config.h"
)

# Belt & suspenders: truly UNDEFINE unwanted SDK cipher modules for this lib
target_compile_options(mbedcrypto PRIVATE
  -UMBEDTLS_ARIA_C
  -UMBEDTLS_CAMELLIA_C
  -UMBEDTLS_DES_C
  -UMBEDTLS_NIST_KW_C
  -UMBEDTLS_CCM_C
  -UMBEDTLS_CHACHA20_C
  -UMBEDTLS_POLY1305_C
  -UMBEDTLS_CHACHAPOLY_C
  -UMBEDTLS_MD_C
  -UMBEDTLS_ENTROPY_C
)

# Pico-only: provide ms-time hook and stdlib linkage
if(HAS_PICO_SDK)
  target_sources(mbedcrypto PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src/mbedtls_time_alt.c)
  target_link_libraries(mbedcrypto PRIVATE pico_stdlib)
endif()

# === Platform-Specific RAM Handler ===
if(HAS_PICO_SDK)
  add_library(ram_handler src/pico_handler.c src/cmd_handler.c)
  target_include_directories(ram_handler PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${MBEDTLS_DIR}/include
  )
  target_link_libraries(ram_handler PRIVATE pico_stdlib pico_rand pico_stdio_usb mbedcrypto hardware_adc)
else()
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/pi_handler.c)
    add_library(ram_handler src/pi_handler.c)
  else()
    add_library(ram_handler INTERFACE)
  endif()
endif()

# === Embedded SST Crypto Wrapper === use for both pico and pi 4 builds
add_library(sst_embedded
  src/sst_crypto_embedded.c
)

target_include_directories(sst_embedded PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${MBEDTLS_DIR}/include
)

target_link_libraries(sst_embedded PUBLIC mbedcrypto)
if(HAS_PICO_SDK)
  target_link_libraries(sst_embedded PRIVATE pico_stdlib)
endif()
target_link_libraries(sst_embedded PRIVATE ram_handler)

# === Add sender/receiver subprojects ===
if(HAS_PICO_SDK)
  add_subdirectory(sender)
else()
  add_subdirectory(receiver)
endif()
